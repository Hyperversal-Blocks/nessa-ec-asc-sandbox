#!/usr/bin/env python3
"""
Privacy-preserving API gateway integration for NESSA qFold-EC.

Demonstrates the end-to-end flow described in the NESSA conversation:
a fintech payment gateway that authorizes high-value transfers where the
user's mobile wallet proves policy compliance without revealing *which*
specific security factors were completed.

Components
----------
* **GatewayPolicy**    — configurable authorization policy (factors, scope, rate window)
* **GatewayProver**    — client-side: builds wallet, applies events, generates proof bundle
* **GatewayVerifier**  — server-side: receives bundle, runs VerifyFolded, enforces rate/replay
* **PrivacyRedactor**  — strips privacy-leaking fields from bundles before transmission
* **run_gateway_demo** — full narrative: enroll → MFA → device → delegate → prove → verify →
                         consume → re-prove → exhaust → reject
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL_DIR = ROOT / "impl"
if str(IMPL_DIR) not in sys.path:
    sys.path.insert(0, str(IMPL_DIR))

# Import from app.py (parent directory)
sys.path.insert(0, str(ROOT))
from app import (
    APP_VERSION,
    AccessRequest,
    NessaAccessWallet,
    VerificationOutcome,
    VerifyFolded,
    policy_payload,
    public_request_payload,
    request_context_digest,
    save_bundle,
)


# ──────────────────────────────────────────────────────────────
# Gateway policy
# ──────────────────────────────────────────────────────────────


@dataclass
class GatewayPolicy:
    """Server-side policy configuration for the payment gateway."""

    gateway_id: str
    scope: str
    required_factor_count: int = 4
    usage_budget: int = 3
    rate_window_seconds: float = 300.0
    max_proofs_per_window: int = 10

    def describe(self) -> str:
        return (
            f"gateway={self.gateway_id} scope={self.scope} "
            f"factors≥{self.required_factor_count} budget={self.usage_budget} "
            f"rate={self.max_proofs_per_window}/{self.rate_window_seconds}s"
        )


# ──────────────────────────────────────────────────────────────
# Privacy redactor
# ──────────────────────────────────────────────────────────────

REDACTED_FIELDS = {
    "checkpoint_count",
    "snapshot_kind",
    "material_preview",
    "selected_checkpoint_count",
}


class PrivacyRedactor:
    """Strip privacy-leaking metadata from proof bundles before wire transmission."""

    def __init__(self, extra_fields: set[str] | None = None):
        self.strip_fields = REDACTED_FIELDS | (extra_fields or set())

    def redact(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Return a deep copy with privacy-sensitive fields removed."""
        redacted = json.loads(json.dumps(bundle))
        fo = redacted.get("folded_object", {})
        for key in list(fo.keys()):
            if key in self.strip_fields:
                del fo[key]
        if "user_summary" in redacted:
            summary = redacted["user_summary"]
            if isinstance(summary, dict) and "integrator_metadata" in summary:
                meta = summary["integrator_metadata"]
                for key in list(meta.keys()):
                    if key in self.strip_fields:
                        del meta[key]
        if "reason_codes" in redacted and not redacted.get("allowed", True):
            redacted["reason_codes"] = ["denied"]
        return redacted

    def audit_report(self, original: dict[str, Any], redacted: dict[str, Any]) -> list[str]:
        """List fields that were stripped (for local audit log)."""
        report: list[str] = []
        orig_fo = original.get("folded_object", {})
        red_fo = redacted.get("folded_object", {})
        for key in self.strip_fields:
            if key in orig_fo and key not in red_fo:
                report.append(f"redacted folded_object.{key}")
        if not original.get("allowed", True):
            orig_reasons = original.get("reason_codes", [])
            red_reasons = redacted.get("reason_codes", [])
            if orig_reasons != red_reasons:
                report.append(f"redacted {len(orig_reasons)} denial reason(s) → opaque 'denied'")
        return report


# ──────────────────────────────────────────────────────────────
# Gateway prover (client-side)
# ──────────────────────────────────────────────────────────────


@dataclass
class ProverReadiness:
    """Pre-flight check result — shown to user locally, never sent to verifier."""

    ready: bool
    missing_factors: list[str]
    remaining_uses: int
    user_message: str


class GatewayProver:
    """Client-side component: wallet + proof generation with privacy safeguards."""

    def __init__(self, wallet: NessaAccessWallet, redactor: PrivacyRedactor | None = None):
        self.wallet = wallet
        self.redactor = redactor or PrivacyRedactor()

    @classmethod
    def create(
        cls,
        subject: str,
        device: str,
        scope: str,
        verifier: str,
        usage_limit: int = 3,
    ) -> "GatewayProver":
        wallet = NessaAccessWallet.create(subject, device, scope, verifier, usage_limit)
        return cls(wallet)

    def apply_event(self, event_type: str, detail: str = "", **kwargs: Any) -> None:
        self.wallet.apply_event(event_type, detail, **kwargs)

    def readiness(self, resource: str, action: str, verifier: str) -> ProverReadiness:
        """Pre-flight: tell the user what's missing (locally only)."""
        request = AccessRequest(resource, action, verifier, "")
        reasons = self.wallet.denial_reasons(request)
        missing: list[str] = []
        for r in reasons:
            if r == "mfa_missing":
                missing.append("Complete multi-factor authentication")
            elif r == "device_untrusted":
                missing.append("Pass device posture check")
            elif r == "delegation_missing_or_revoked":
                missing.append("Obtain delegation for this scope")
            elif r == "usage_limit_exhausted":
                missing.append("Usage budget exhausted — request renewal")
            elif r == "scope_not_delegated":
                missing.append(f"Scope {resource} not delegated")
            elif r == "verifier_not_delegated":
                missing.append(f"Verifier {verifier} not delegated")
        remaining = max(0, self.wallet.state.usage_limit - self.wallet.state.usage_used)
        ready = len(reasons) == 0
        if ready:
            msg = f"Ready — {remaining} use(s) remaining for {resource}"
        else:
            msg = f"Not ready — {len(missing)} factor(s) missing"
        return ProverReadiness(
            ready=ready,
            missing_factors=missing,
            remaining_uses=remaining,
            user_message=msg,
        )

    def prove(
        self,
        resource: str,
        action: str,
        verifier: str,
        context_label: str,
        server_nonce: str = "",
        deterministic: bool = False,
    ) -> dict[str, Any]:
        """Build a proof bundle, bind to server nonce, and redact before returning."""
        full_context = f"{context_label}|nonce={server_nonce}" if server_nonce else context_label
        request = AccessRequest(resource, action, verifier, full_context)
        raw_bundle = self.wallet.prove_access(request, deterministic=deterministic)
        if server_nonce and raw_bundle.get("allowed"):
            raw_bundle.setdefault("gateway_meta", {})["server_nonce"] = server_nonce
        wire_bundle = self.redactor.redact(raw_bundle)
        return wire_bundle

    def user_narrative(self, bundle: dict[str, Any]) -> str:
        """Human-readable proof status for the UI."""
        if bundle.get("allowed"):
            size = bundle.get("folded_object", {}).get("proof_size_bytes", 0)
            return f"Your payment proof is ready — policy satisfied, {size} bytes on wire."
        return "Authorization denied — check your wallet status."


# ──────────────────────────────────────────────────────────────
# Gateway verifier (server-side)
# ──────────────────────────────────────────────────────────────


@dataclass
class VerifierReceipt:
    """Returned to the prover after successful verification."""

    authorized: bool
    receipt_id: str
    timestamp: float
    reason: str


class GatewayVerifier:
    """Server-side component: policy enforcement, replay protection, rate limiting."""

    def __init__(self, policy: GatewayPolicy):
        self.policy = policy
        self._used_nonces: set[str] = set()
        self._usage_count: int = 0
        self._rate_log: list[float] = []

    def issue_nonce(self) -> str:
        """Issue a fresh server nonce for the next proof request."""
        nonce = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        return nonce

    def verify(self, wire_bundle: dict[str, Any], expected_nonce: str | None = None) -> VerifierReceipt:
        """
        Full server-side verification:
        1. Check proof cryptographically via VerifyFolded
        2. Enforce replay protection (nonce uniqueness)
        3. Enforce rate limits
        4. Enforce usage budget
        Returns an opaque authorized/denied receipt.
        """
        now = time.time()
        receipt_id = hashlib.sha256(os.urandom(16) + str(now).encode()).hexdigest()[:24]

        if not wire_bundle.get("allowed"):
            return VerifierReceipt(False, receipt_id, now, "denied")

        if expected_nonce is not None:
            bundle_nonce = wire_bundle.get("gateway_meta", {}).get("server_nonce", "")
            if bundle_nonce != expected_nonce:
                return VerifierReceipt(False, receipt_id, now, "nonce_mismatch")
            if expected_nonce in self._used_nonces:
                return VerifierReceipt(False, receipt_id, now, "replay_detected")

        # Rate limit check
        window_start = now - self.policy.rate_window_seconds
        self._rate_log = [t for t in self._rate_log if t > window_start]
        if len(self._rate_log) >= self.policy.max_proofs_per_window:
            return VerifierReceipt(False, receipt_id, now, "rate_limited")

        # Usage budget check (server-side)
        if self._usage_count >= self.policy.usage_budget:
            return VerifierReceipt(False, receipt_id, now, "budget_exhausted")

        # Cryptographic verification
        outcome = VerifyFolded(
            wire_bundle["policy"],
            wire_bundle["folded_object"],
            wire_bundle["proof"],
            expected_request=wire_bundle.get("request"),
        )

        if not outcome.allowed:
            return VerifierReceipt(False, receipt_id, now, "proof_invalid")

        # All checks passed — record nonce and usage
        if expected_nonce is not None:
            self._used_nonces.add(expected_nonce)
        self._usage_count += 1
        self._rate_log.append(now)

        return VerifierReceipt(True, receipt_id, now, "authorized")

    @property
    def remaining_budget(self) -> int:
        return max(0, self.policy.usage_budget - self._usage_count)

    def status_summary(self) -> dict[str, Any]:
        return {
            "gateway_id": self.policy.gateway_id,
            "usage": f"{self._usage_count}/{self.policy.usage_budget}",
            "nonces_seen": len(self._used_nonces),
            "remaining_budget": self.remaining_budget,
        }


# ──────────────────────────────────────────────────────────────
# Gateway session (reusable for interactive CLI)
# ──────────────────────────────────────────────────────────────


class GatewaySession:
    """Wraps prover + verifier + nonce lifecycle for step-by-step driving."""

    def __init__(
        self,
        subject: str = "alice@mobile",
        device: str = "device:iphone-15",
        scope: str = "api://payments",
        gateway_id: str = "gateway://payments",
        usage_budget: int = 3,
        prover_usage_limit: int = 5,
    ):
        self.policy = GatewayPolicy(
            gateway_id=gateway_id,
            scope=scope,
            usage_budget=usage_budget,
        )
        self.verifier = GatewayVerifier(self.policy)
        self.prover = GatewayProver.create(
            subject, device, scope, gateway_id, prover_usage_limit,
        )
        self._last_nonce: str | None = None
        self._proof_count: int = 0

    def apply_event(self, event_type: str, detail: str = "", **kwargs: Any) -> None:
        self.prover.apply_event(event_type, detail, **kwargs)

    def readiness(self) -> ProverReadiness:
        return self.prover.readiness(
            self.policy.scope, "transfer", self.policy.gateway_id,
        )

    def prove_and_verify(
        self,
        action: str = "transfer",
        context_label: str = "device-posture=healthy|window=5m",
        deterministic: bool = False,
    ) -> tuple[dict[str, Any], VerifierReceipt]:
        """Single prove→verify round. Returns (wire_bundle, receipt)."""
        self._proof_count += 1
        nonce = self.verifier.issue_nonce()
        self._last_nonce = nonce
        bundle = self.prover.prove(
            self.policy.scope,
            action,
            self.policy.gateway_id,
            f"{context_label}|seq={self._proof_count}",
            server_nonce=nonce,
            deterministic=deterministic,
        )
        receipt = self.verifier.verify(bundle, expected_nonce=nonce)
        return bundle, receipt

    def raw_bundle_for_privacy_panel(
        self,
        action: str = "transfer",
        context_label: str = "privacy-panel-check",
        deterministic: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return (raw_bundle, redacted_bundle) for privacy comparison."""
        request = AccessRequest(
            self.policy.scope, action, self.policy.gateway_id, context_label,
        )
        raw = self.prover.wallet.prove_access(request, deterministic=deterministic)
        redacted = self.prover.redactor.redact(raw)
        return raw, redacted

    @property
    def wallet(self) -> "NessaAccessWallet":
        return self.prover.wallet

    @property
    def remaining_budget(self) -> int:
        return self.verifier.remaining_budget


# ──────────────────────────────────────────────────────────────
# Privacy checklist
# ──────────────────────────────────────────────────────────────

PRIVACY_CHECKLIST = [
    ("Opaque denial", "Gateway returns {authorized: false} with no per-factor breakdown"),
    ("Redacted bundle", "checkpoint_count, snapshot_kind, material_preview stripped before wire"),
    ("Nonce binding", "proof_context_label includes server nonce → proofs are session-bound"),
    ("Replay protection", "Verifier rejects reused nonces"),
    ("Server-side budget", "Usage counter incremented by gateway after verification, not by prover"),
    ("Proof freshness", "Each proof embeds unique context; verifier rejects duplicates"),
    ("Minimal envelope", "Only resource + action + context_digest cross the wire"),
    ("Witness hiding", "Raw factor bits never leave the prover — only Pedersen commitments"),
    ("Subject blinding", "Subject/device hashed through H2S with domain-separated DST"),
    ("Context binding", "proof_context_label = SHA-512(CBOR(request context)) — opaque to verifier"),
]


def print_privacy_checklist() -> None:
    print("\n  Privacy safeguards checklist:")
    for i, (name, desc) in enumerate(PRIVACY_CHECKLIST, 1):
        print(f"    [{i:2d}] {name}: {desc}")


# ──────────────────────────────────────────────────────────────
# End-to-end demo
# ──────────────────────────────────────────────────────────────


def run_gateway_demo(deterministic: bool = False, verbose: bool = True) -> dict[str, Any]:
    """
    Full lifecycle:
      enroll → key-rotate → MFA → device-ok → delegate → key-rotate → MFA
      → prove(1) → verify(1) ✓
      → prove(2) → verify(2) ✓
      → prove(3) → verify(3) ✓
      → prove(4) → verify(4) ✗ (budget exhausted)
      → replay(nonce from proof 1) → ✗ (replay detected)
      → denial test (revoke delegation → opaque rejection)
    """
    results: dict[str, Any] = {"steps": [], "receipts": []}

    def log(msg: str) -> None:
        if verbose:
            print(f"  {msg}")
        results["steps"].append(msg)

    # ── Setup ──
    policy = GatewayPolicy(
        gateway_id="gateway://payments.example",
        scope="api://payments",
        usage_budget=3,
        rate_window_seconds=300.0,
        max_proofs_per_window=10,
    )
    verifier = GatewayVerifier(policy)
    prover = GatewayProver.create(
        "alice@mobile",
        "device:iphone-15",
        "api://payments",
        "gateway://payments.example",
        usage_limit=5,
    )

    log(f"Policy: {policy.describe()}")
    log("")

    # ── Enrollment lifecycle ──
    log("── Enrollment lifecycle ──")
    for evt, detail in [
        ("enroll", "initial enrollment"),
        ("key-rotate", "session key refresh"),
        ("mfa", "user completed TOTP challenge"),
        ("device-ok", "device posture check passed"),
        ("delegate", "delegated access to payments API"),
        ("key-rotate", "forward-secure key refresh"),
        ("mfa", "fresh MFA before high-value transfer"),
    ]:
        prover.apply_event(evt, detail)
        log(f"  event: {evt} — {detail}")

    # ── Pre-flight readiness ──
    log("")
    log("── Pre-flight readiness (local only, never sent to verifier) ──")
    readiness = prover.readiness("api://payments", "transfer", "gateway://payments.example")
    log(f"  {readiness.user_message}")
    log(f"  remaining uses: {readiness.remaining_uses}")
    results["readiness"] = asdict(readiness)

    # ── Successful proofs (3 uses = full budget) ──
    log("")
    log("── Authorization proofs ──")
    saved_nonces: list[str] = []
    for i in range(1, 4):
        nonce = verifier.issue_nonce()
        saved_nonces.append(nonce)
        bundle = prover.prove(
            "api://payments",
            "transfer",
            "gateway://payments.example",
            f"device-posture=healthy|window=5m|seq={i}",
            server_nonce=nonce,
            deterministic=deterministic,
        )
        receipt = verifier.verify(bundle, expected_nonce=nonce)
        log(f"  proof {i}: nonce={nonce[:12]}… → {receipt.reason} (receipt={receipt.receipt_id[:12]}…)")
        results["receipts"].append({
            "proof_num": i,
            "authorized": receipt.authorized,
            "reason": receipt.reason,
            "receipt_id": receipt.receipt_id,
            "proof_size_bytes": bundle.get("folded_object", {}).get("proof_size_bytes", 0),
        })
        narrative = prover.user_narrative(bundle)
        log(f"    user: {narrative}")

    # ── Budget exhaustion ──
    log("")
    log("── Budget exhaustion ──")
    nonce4 = verifier.issue_nonce()
    bundle4 = prover.prove(
        "api://payments",
        "transfer",
        "gateway://payments.example",
        "device-posture=healthy|window=5m|seq=4",
        server_nonce=nonce4,
        deterministic=deterministic,
    )
    receipt4 = verifier.verify(bundle4, expected_nonce=nonce4)
    log(f"  proof 4: {receipt4.reason}")
    results["receipts"].append({
        "proof_num": 4,
        "authorized": receipt4.authorized,
        "reason": receipt4.reason,
    })

    # ── Replay rejection ──
    log("")
    log("── Replay rejection ──")
    replay_bundle = prover.prove(
        "api://payments",
        "transfer",
        "gateway://payments.example",
        f"device-posture=healthy|window=5m|seq=1",
        server_nonce=saved_nonces[0],
        deterministic=deterministic,
    )
    replay_receipt = verifier.verify(replay_bundle, expected_nonce=saved_nonces[0])
    log(f"  replay nonce={saved_nonces[0][:12]}… → {replay_receipt.reason}")
    results["receipts"].append({
        "proof_num": "replay",
        "authorized": replay_receipt.authorized,
        "reason": replay_receipt.reason,
    })

    # ── Opaque denial (revoke delegation) ──
    log("")
    log("── Opaque denial (delegation revoked) ──")
    prover.apply_event("revoke", "admin revoked delegation")
    nonce_deny = verifier.issue_nonce()
    denied_bundle = prover.prove(
        "api://payments",
        "transfer",
        "gateway://payments.example",
        "device-posture=healthy|window=5m|seq=deny",
        server_nonce=nonce_deny,
        deterministic=deterministic,
    )
    log(f"  bundle allowed={denied_bundle.get('allowed')}")
    log(f"  reason_codes on wire={denied_bundle.get('reason_codes')}")
    has_detail = any(r not in ("denied",) for r in denied_bundle.get("reason_codes", []))
    log(f"  per-factor detail leaked? {'YES ⚠' if has_detail else 'NO ✓ (opaque)'}")
    results["denial_opaque"] = not has_detail

    # ── Redaction audit ──
    log("")
    log("── Redaction audit ──")
    redactor = PrivacyRedactor()
    sample_raw = prover.wallet.prove_access(
        AccessRequest("api://payments", "transfer", "gateway://payments.example", "audit-check"),
        deterministic=deterministic,
    )
    sample_redacted = redactor.redact(sample_raw)
    audit = redactor.audit_report(sample_raw, sample_redacted)
    for entry in audit:
        log(f"  {entry}")
    results["redaction_audit"] = audit

    # ── Verifier status ──
    log("")
    log("── Verifier status ──")
    status = verifier.status_summary()
    for k, v in status.items():
        log(f"  {k}: {v}")
    results["verifier_status"] = status

    # ── Privacy checklist ──
    if verbose:
        print_privacy_checklist()

    results["privacy_checks"] = len(PRIVACY_CHECKLIST)

    return results


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="integration-gateway")
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    args = parser.parse_args(argv)

    print("\n  NESSA Payment Gateway Integration Demo")
    print("  " + "=" * 42 + "\n")
    results = run_gateway_demo(deterministic=args.deterministic, verbose=not args.quiet)
    if args.json:
        print("\n" + json.dumps(results, indent=2, default=str))
    print("\n  Done.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
