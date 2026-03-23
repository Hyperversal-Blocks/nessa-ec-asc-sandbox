from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
IMPL_DIR = ROOT / "impl"
if str(IMPL_DIR) not in sys.path:
    sys.path.insert(0, str(IMPL_DIR))

from nessa_qfold import (
    NessaProof,
    ProofConsLinear,
    ProofLink,
    build_tags,
    build_transcript,
    cbor_encode,
    compute_tags_hash,
    derive_generators,
    fold_commitments,
    fold_weight_sum,
    h2s,
    linear_constraint_W,
    compressed_linear_terms,
    run_protocol_flow,
    scalar_to_int,
    verify_cons_linear,
    verify_link,
)

APP_VERSION = "nessa-auth-wallet-v1"
ENGINE = "qFold-EC"
ENCODING_ID = "nessa_auth_checkpoint_v1"
POLICY_ID = "private_access_grant_v1"
POLICY_FACTORS = ["mfa", "device", "delegation", "usage_ok"]
LINEAR_COEFFS = [1, 1, 1, 1, -4, 0, 0]
LINEAR_TARGET = 0
COORD_BITS = [1, 1, 1, 1, 1, 253, 253]
D = 7
MAX_SELECTED_CHECKPOINTS = 8


@dataclass
class SecurityCheckpoint:
    seq: int
    event_type: str
    detail: str
    scope: str
    verifier: str
    mfa_ok: bool
    device_ok: bool
    delegation_ok: bool
    usage_ok: bool


@dataclass
class WalletState:
    version: str
    subject: str
    device: str
    scope: str
    verifier: str
    usage_limit: int = 3
    usage_used: int = 0
    mfa_ok: bool = False
    device_ok: bool = False
    delegation_ok: bool = False
    revoked: bool = False
    checkpoints: list[SecurityCheckpoint] = field(default_factory=list)


@dataclass
class AccessRequest:
    resource: str
    action: str
    verifier: str
    context_label: str


@dataclass
class VerificationOutcome:
    allowed: bool
    reason_codes: list[str]
    details: dict[str, Any] = field(default_factory=dict)


class NessaAccessWallet:
    def __init__(self, state: WalletState):
        self.state = state

    @classmethod
    def create(cls, subject: str, device: str, scope: str, verifier: str, usage_limit: int) -> "NessaAccessWallet":
        return cls(
            WalletState(
                version=APP_VERSION,
                subject=subject,
                device=device,
                scope=scope,
                verifier=verifier,
                usage_limit=usage_limit,
            )
        )

    @classmethod
    def load(cls, path: Path) -> "NessaAccessWallet":
        payload = json.loads(path.read_text(encoding="utf-8"))
        checkpoints = [SecurityCheckpoint(**item) for item in payload.get("checkpoints", [])]
        state = WalletState(
            version=payload["version"],
            subject=payload["subject"],
            device=payload["device"],
            scope=payload["scope"],
            verifier=payload["verifier"],
            usage_limit=payload.get("usage_limit", 3),
            usage_used=payload.get("usage_used", 0),
            mfa_ok=payload.get("mfa_ok", False),
            device_ok=payload.get("device_ok", False),
            delegation_ok=payload.get("delegation_ok", False),
            revoked=payload.get("revoked", False),
            checkpoints=checkpoints,
        )
        return cls(state)

    def save(self, path: Path) -> None:
        payload = asdict(self.state)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def usage_ok(self) -> bool:
        return (not self.state.revoked) and self.state.usage_used < self.state.usage_limit

    def current_bits(self) -> tuple[bool, bool, bool, bool]:
        delegation_ok = self.state.delegation_ok and not self.state.revoked
        return self.state.mfa_ok, self.state.device_ok, delegation_ok, self.usage_ok()

    def record_checkpoint(self, event_type: str, detail: str, scope: str | None = None, verifier: str | None = None) -> None:
        mfa_ok, device_ok, delegation_ok, usage_ok = self.current_bits()
        self.state.checkpoints.append(
            SecurityCheckpoint(
                seq=len(self.state.checkpoints) + 1,
                event_type=event_type,
                detail=detail,
                scope=scope or self.state.scope,
                verifier=verifier or self.state.verifier,
                mfa_ok=mfa_ok,
                device_ok=device_ok,
                delegation_ok=delegation_ok,
                usage_ok=usage_ok,
            )
        )

    def apply_event(
        self,
        event_type: str,
        detail: str = "",
        scope: str | None = None,
        verifier: str | None = None,
        usage_limit: int | None = None,
    ) -> None:
        if scope is not None:
            self.state.scope = scope
        if verifier is not None:
            self.state.verifier = verifier
        if usage_limit is not None:
            self.state.usage_limit = usage_limit
        if event_type == "mfa":
            self.state.mfa_ok = True
        elif event_type == "clear-mfa":
            self.state.mfa_ok = False
        elif event_type == "device-ok":
            self.state.device_ok = True
        elif event_type == "device-fail":
            self.state.device_ok = False
        elif event_type == "delegate":
            self.state.delegation_ok = True
            self.state.revoked = False
        elif event_type == "revoke":
            self.state.revoked = True
            self.state.delegation_ok = False
        elif event_type == "restore":
            self.state.revoked = False
        elif event_type == "consume":
            self.state.usage_used += 1
        elif event_type == "reset-usage":
            self.state.usage_used = 0
        elif event_type in {"enroll", "key-rotate"}:
            pass
        else:
            raise ValueError(f"unsupported event type: {event_type}")
        self.record_checkpoint(event_type, detail or event_type)

    def denial_reasons(self, request: AccessRequest) -> list[str]:
        reasons: list[str] = []
        if request.resource != self.state.scope:
            reasons.append("scope_not_delegated")
        if request.verifier != self.state.verifier:
            reasons.append("verifier_not_delegated")
        if not self.state.mfa_ok:
            reasons.append("mfa_missing")
        if not self.state.device_ok:
            reasons.append("device_untrusted")
        if not self.state.delegation_ok or self.state.revoked:
            reasons.append("delegation_missing_or_revoked")
        if not self.usage_ok():
            reasons.append("usage_limit_exhausted")
        return reasons

    def selected_checkpoints(self, request: AccessRequest) -> list[SecurityCheckpoint]:
        return [
            checkpoint
            for checkpoint in self.state.checkpoints
            if checkpoint.scope == request.resource
            and checkpoint.verifier == request.verifier
            and checkpoint.mfa_ok
            and checkpoint.device_ok
            and checkpoint.delegation_ok
            and checkpoint.usage_ok
        ][-MAX_SELECTED_CHECKPOINTS:]

    def current_proof_row(self, request: AccessRequest) -> list[int]:
        """
        Build a proof row from the wallet's current authorization snapshot.

        This demo intentionally proves the *current local state* rather than a
        repeated synthetic row per historical checkpoint.
        """
        mfa_ok, device_ok, delegation_ok, usage_ok = self.current_bits()
        subject_scalar = string_scalar(b"NESSA-APP:v1:subject", self.state.subject, self.state.device)
        scope_scalar = string_scalar(
            b"NESSA-APP:v1:scope",
            request.resource,
            request.action,
            request.verifier,
        )
        return [
            int(mfa_ok),
            int(device_ok),
            int(delegation_ok),
            int(usage_ok),
            1,
            scope_scalar,
            subject_scalar,
        ]

    def prove_access(self, request: AccessRequest, deterministic: bool = False) -> dict[str, Any]:
        reasons = self.denial_reasons(request)
        if reasons:
            return {
                "version": APP_VERSION,
                "engine": ENGINE,
                "allowed": False,
                "reason_codes": reasons,
                "request": public_request_payload(request),
                "policy": policy_payload(),
            }
        rows = [self.current_proof_row(request)]
        context_digest = request_context_digest(request)
        deterministic_seed = hashlib.sha512(cbor_encode([APP_VERSION, self.state.subject, request.resource, request.action, request.verifier, context_digest])).digest() if deterministic else None
        flow = run_protocol_flow(
            N=len(rows),
            d=D,
            include_nonlinear=False,
            event_values=rows,
            linear_constraint_coeffs=LINEAR_COEFFS,
            linear_constraint_target=LINEAR_TARGET,
            coordinate_bit_lengths=COORD_BITS,
            deterministic_seed=deterministic_seed,
            encoding_id=ENCODING_ID,
            policy_id=POLICY_ID,
            proof_context_label=context_digest,
        )
        return {
            "version": APP_VERSION,
            "engine": ENGINE,
            "allowed": True,
            "reason_codes": [],
            "request": public_request_payload(request),
            "policy": policy_payload(),
            "folded_object": {
                "N": flow.result.N,
                "d": D,
                "tags": encode_tags(flow.tags),
                "commitments": [point.hex() for point in flow.commitments],
                "tags_hash": flow.tags_hash.hex(),
                "policy_compiled": flow.policy_compiled.hex(),
                "final_root": flow.transcript_roots[-1].hex(),
                "C_star": flow.C_star.hex(),
                "V_list": [point.hex() for point in flow.V_list],
                "proof_context_label": flow.proof_context_label.hex(),
                "proof_size_bytes": flow.result.proof_size_bytes,
                "snapshot_kind": "current_wallet_state_v1",
                "checkpoint_count": len(self.state.checkpoints),
            },
            "proof": serialize_linear_proof(flow.proof),
        }


def policy_payload() -> dict[str, Any]:
    return {
        "name": POLICY_ID,
        "encoding_id": ENCODING_ID,
        "required_factors": POLICY_FACTORS,
        "linear_constraint_coeffs": LINEAR_COEFFS,
        "linear_constraint_target": LINEAR_TARGET,
    }


def encode_tags(tags: dict[int, Any]) -> dict[str, Any]:
    encoded: dict[str, Any] = {}
    for key, value in tags.items():
        if isinstance(value, bytes):
            encoded[str(key)] = value.hex()
        else:
            encoded[str(key)] = value
    return encoded


def decode_tags(payload: dict[str, Any]) -> dict[int, Any]:
    decoded: dict[int, Any] = {}
    for key, value in payload.items():
        int_key = int(key)
        if int_key in {4, 7, 9} and isinstance(value, str):
            decoded[int_key] = bytes.fromhex(value)
        else:
            decoded[int_key] = value
    return decoded


def public_request_payload(request: AccessRequest) -> dict[str, Any]:
    return {
        "resource": request.resource,
        "action": request.action,
        "verifier": request.verifier,
        "context_digest": request_context_digest(request).hex(),
    }


def request_context_digest(request: AccessRequest) -> bytes:
    return hashlib.sha512(
        cbor_encode([APP_VERSION, request.resource, request.action, request.verifier, request.context_label])
    ).digest()


def string_scalar(dst: bytes, *parts: str) -> int:
    msg = cbor_encode(list(parts))
    return scalar_to_int(h2s(dst, msg))


def serialize_linear_proof(proof: NessaProof) -> dict[str, Any]:
    if proof.pi_cons_linear is None:
        raise ValueError("expected a linear proof")
    return {
        "N": proof.N,
        "d": proof.d,
        "pi_link": {
            "T_commit": proof.pi_link.T_commit.hex(),
            "T_policy": [point.hex() for point in proof.pi_link.T_policy],
            "z_m": [value.hex() for value in proof.pi_link.z_m],
            "z_rho": [value.hex() for value in proof.pi_link.z_rho],
            "z_gamma": [value.hex() for value in proof.pi_link.z_gamma],
            "challenge": proof.pi_link.challenge.hex(),
        },
        "pi_cons_linear": {
            "T": proof.pi_cons_linear.T.hex(),
            "z": proof.pi_cons_linear.z.hex(),
            "challenge": proof.pi_cons_linear.challenge.hex(),
        },
    }


def deserialize_linear_proof(folded_object: dict[str, Any], payload: dict[str, Any]) -> NessaProof:
    pi_link_payload = payload["pi_link"]
    pi_link = ProofLink(
        T_commit=bytes.fromhex(pi_link_payload["T_commit"]),
        T_policy=[bytes.fromhex(point) for point in pi_link_payload["T_policy"]],
        z_m=[bytes.fromhex(value) for value in pi_link_payload["z_m"]],
        z_rho=[bytes.fromhex(value) for value in pi_link_payload["z_rho"]],
        z_gamma=[bytes.fromhex(value) for value in pi_link_payload["z_gamma"]],
        challenge=bytes.fromhex(pi_link_payload["challenge"]),
    )
    pi_cons_payload = payload["pi_cons_linear"]
    pi_cons_linear = ProofConsLinear(
        T=bytes.fromhex(pi_cons_payload["T"]),
        z=bytes.fromhex(pi_cons_payload["z"]),
        challenge=bytes.fromhex(pi_cons_payload["challenge"]),
    )
    return NessaProof(
        C_star=bytes.fromhex(folded_object["C_star"]),
        V_list=[bytes.fromhex(point) for point in folded_object["V_list"]],
        pi_link=pi_link,
        pi_cons_linear=pi_cons_linear,
        N=payload["N"],
        d=payload["d"],
    )


def VerifyFolded(
    policy: dict[str, Any],
    folded_object: dict[str, Any],
    proof_payload: dict[str, Any],
    expected_request: dict[str, Any] | None = None,
) -> VerificationOutcome:
    reasons: list[str] = []
    d = folded_object["d"]
    commitments = [bytes.fromhex(point) for point in folded_object["commitments"]]
    policy_compiled = bytes.fromhex(folded_object["policy_compiled"])
    policy_hash = hashlib.sha512(policy_compiled).digest()
    tags = decode_tags(folded_object["tags"])
    transcript_seed = tags.get(9)
    expected_tags = build_tags(
        encoding_id=policy["encoding_id"],
        policy_id=policy["name"],
        d=d,
        policy_hash=policy_hash,
        k_rows=1,
        transcript_seed=transcript_seed,
    )
    if tags != expected_tags:
        reasons.append("tags_mismatch")
    tags_hash = compute_tags_hash(
        encoding_id=policy["encoding_id"],
        policy_id=policy["name"],
        d=d,
        policy_hash=policy_hash,
        k_rows=1,
        transcript_seed=transcript_seed,
    )
    ts = build_transcript(tags, commitments)
    C_star = fold_commitments(commitments, ts.alphas)
    context_label = bytes.fromhex(folded_object["proof_context_label"])
    if expected_request is not None:
        expected_context = expected_request.get("context_digest")
        if isinstance(expected_context, str):
            if expected_context != context_label.hex():
                reasons.append("request_context_mismatch")
        else:
            reasons.append("request_context_missing")
    if tags_hash.hex() != folded_object["tags_hash"]:
        reasons.append("tags_hash_mismatch")
    if ts.roots[-1].hex() != folded_object["final_root"]:
        reasons.append("transcript_root_mismatch")
    if C_star.hex() != folded_object["C_star"]:
        reasons.append("folded_commitment_mismatch")
    proof = deserialize_linear_proof(folded_object, proof_payload)
    gens = derive_generators(d)
    link_ok = verify_link(proof.pi_link, C_star, proof.V_list, gens, tags_hash, ts.roots[-1])
    if not link_ok:
        reasons.append("pi_link_invalid")
    _, compressed_coeffs, compressed_target = compressed_linear_terms(policy_compiled, ts.roots[-1], fold_weight_sum(ts.alphas))
    W = linear_constraint_W(proof.V_list, compressed_coeffs, compressed_target, gens["H_pol"])
    cons_ok = proof.pi_cons_linear is not None and verify_cons_linear(proof.pi_cons_linear, W, gens["G_pol"], tags_hash, ts.roots[-1], policy_hash)
    if not cons_ok:
        reasons.append("pi_cons_linear_invalid")
    return VerificationOutcome(
        allowed=not reasons,
        reason_codes=reasons,
        details={
            "N": folded_object["N"],
            "d": d,
            "proof_size_bytes": proof.byte_size(),
            "checkpoint_count": folded_object.get("checkpoint_count", 0),
            "snapshot_kind": folded_object.get("snapshot_kind", "unknown"),
        },
    )


def load_bundle(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_bundle(path: Path, bundle: dict[str, Any]) -> None:
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")


def build_demo_wallet() -> NessaAccessWallet:
    wallet = NessaAccessWallet.create("alice@local", "device:laptop-7", "api://payments", "gateway://payments", 3)
    wallet.apply_event("enroll", "initial enrollment")
    wallet.apply_event("key-rotate", "session key refresh")
    wallet.apply_event("mfa", "user completed MFA")
    wallet.apply_event("device-ok", "device posture healthy")
    wallet.apply_event("delegate", "delegated access for payments API")
    wallet.apply_event("key-rotate", "forward-secure refresh while access remains valid")
    wallet.apply_event("mfa", "fresh MFA before high-value action")
    return wallet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nessa-app")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init")
    init_cmd.add_argument("--state", type=Path, required=True)
    init_cmd.add_argument("--subject", required=True)
    init_cmd.add_argument("--device", required=True)
    init_cmd.add_argument("--scope", required=True)
    init_cmd.add_argument("--verifier", required=True)
    init_cmd.add_argument("--usage-limit", type=int, default=3)

    event_cmd = sub.add_parser("event")
    event_cmd.add_argument("--state", type=Path, required=True)
    event_cmd.add_argument("--type", required=True, choices=["enroll", "key-rotate", "mfa", "clear-mfa", "device-ok", "device-fail", "delegate", "revoke", "restore", "consume", "reset-usage"])
    event_cmd.add_argument("--detail", default="")
    event_cmd.add_argument("--scope")
    event_cmd.add_argument("--verifier")
    event_cmd.add_argument("--usage-limit", type=int)

    prove_cmd = sub.add_parser("prove")
    prove_cmd.add_argument("--state", type=Path, required=True)
    prove_cmd.add_argument("--bundle", type=Path, required=True)
    prove_cmd.add_argument("--resource", required=True)
    prove_cmd.add_argument("--action", required=True)
    prove_cmd.add_argument("--verifier", required=True)
    prove_cmd.add_argument("--context", required=True)
    prove_cmd.add_argument("--deterministic", action="store_true")

    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("--bundle", type=Path, required=True)

    demo_cmd = sub.add_parser("demo")
    demo_cmd.add_argument("--state", type=Path)
    demo_cmd.add_argument("--bundle", type=Path)
    demo_cmd.add_argument("--deterministic", action="store_true")

    interactive_cmd = sub.add_parser("interactive", help="Launch interactive privacy-centric CLI")
    interactive_cmd.add_argument("--deterministic", action="store_true")

    gw_cmd = sub.add_parser("gateway-demo")
    gw_cmd.add_argument("--deterministic", action="store_true")
    gw_cmd.add_argument("--quiet", "-q", action="store_true")
    gw_cmd.add_argument("--json", action="store_true", help="Emit JSON summary")

    docs_cmd = sub.add_parser("docs-bundle")
    docs_cmd.add_argument("--deterministic", action="store_true")
    docs_cmd.add_argument("--benchmark", action="store_true")
    docs_cmd.add_argument("--json", action="store_true", help="Emit docs bundle manifest as JSON")
    docs_cmd.add_argument("--docs-dir", type=Path, default=None, help="Directory for the generated docs bundle (default: docs)")

    asc_cmd = sub.add_parser("asc-ad-demo")
    asc_cmd.add_argument("--deterministic", action="store_true")
    asc_cmd.add_argument("--benchmark", action="store_true")
    asc_cmd.add_argument("--json", action="store_true", help="Emit JSON summary")
    asc_cmd.add_argument("--artifacts-dir", type=Path, default=None, help="Directory for ASC audit JSON artifacts (default: docs/generated/asc_ad_demo/audit)")
    asc_cmd.add_argument("--root-artifacts", action="store_true", help="Write the full ASC audit JSON artifact set to the default docs tree")
    asc_cmd.add_argument("--report", type=Path, default=None, help="Directory or file prefix for report outputs (default: docs/generated/asc_ad_demo/reports when artifact mode is enabled)")

    uc_cmd = sub.add_parser("usecase-flows")
    uc_cmd.add_argument("--deterministic", action="store_true")
    uc_cmd.add_argument("--verbose", "-v", action="store_true", help="Per-flow user story + integrator checklist.")
    uc_cmd.add_argument("--json-summary", action="store_true", help="Emit machine-readable summaries for all flows.")
    uc_cmd.add_argument("--story", action="store_true", help="Print full Markdown user story for the login flow only.")
    uc_cmd.add_argument(
        "--verify-sample",
        action="store_true",
        help="Run app.VerifyFolded on the login-session demo bundle (sanity check).",
    )
    uc_cmd.add_argument(
        "--actor-cache",
        type=Path,
        default=None,
        help="JSON file for multi-actor story (default: docs/generated/usecase_flows/actor_cache/nessa_usecase_actors.json).",
    )
    uc_cmd.add_argument(
        "--init-actor-cache",
        action="store_true",
        help="Write default actor JSON; use --force to overwrite.",
    )
    uc_cmd.add_argument("--force", action="store_true", help="With --init-actor-cache, overwrite existing file.")
    uc_cmd.add_argument(
        "--multi-user-story",
        action="store_true",
        help="Run repeatable multi-actor narrative; bumps run_counter in cache.",
    )
    uc_cmd.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="With --multi-user-story: prompt each actor’s fields, then pause before each proof (multi-user terminal).",
    )

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "init":
        wallet = NessaAccessWallet.create(args.subject, args.device, args.scope, args.verifier, args.usage_limit)
        wallet.save(args.state)
        print(f"initialized {args.state}")
        return
    if args.command == "event":
        wallet = NessaAccessWallet.load(args.state)
        wallet.apply_event(args.type, args.detail, scope=args.scope, verifier=args.verifier, usage_limit=args.usage_limit)
        wallet.save(args.state)
        print(json.dumps({"checkpoints": len(wallet.state.checkpoints), "scope": wallet.state.scope, "verifier": wallet.state.verifier, "usage_used": wallet.state.usage_used, "revoked": wallet.state.revoked}, indent=2))
        return
    if args.command == "prove":
        wallet = NessaAccessWallet.load(args.state)
        request = AccessRequest(args.resource, args.action, args.verifier, args.context)
        bundle = wallet.prove_access(request, deterministic=args.deterministic)
        save_bundle(args.bundle, bundle)
        print(json.dumps({"allowed": bundle["allowed"], "reason_codes": bundle["reason_codes"], "bundle": str(args.bundle)}, indent=2))
        return
    if args.command == "verify":
        bundle = load_bundle(args.bundle)
        if not bundle.get("allowed"):
            print(json.dumps({"allowed": False, "reason_codes": bundle.get("reason_codes", [])}, indent=2))
            return
        outcome = VerifyFolded(
            bundle["policy"],
            bundle["folded_object"],
            bundle["proof"],
            expected_request=bundle.get("request"),
        )
        print(json.dumps(asdict(outcome), indent=2))
        return
    if args.command == "demo":
        wallet = build_demo_wallet()
        if args.state is not None:
            wallet.save(args.state)
        request = AccessRequest("api://payments", "transfer", "gateway://payments", "device-posture=healthy|window=5m")
        bundle = wallet.prove_access(request, deterministic=args.deterministic)
        if args.bundle is not None:
            save_bundle(args.bundle, bundle)
        outcome = VerifyFolded(bundle["policy"], bundle["folded_object"], bundle["proof"]) if bundle["allowed"] else VerificationOutcome(False, bundle["reason_codes"])
        print(
            json.dumps(
                {
                    "bundle_allowed": bundle["allowed"],
                    "snapshot_kind": bundle.get("folded_object", {}).get("snapshot_kind", "unknown"),
                    "checkpoint_count": bundle.get("folded_object", {}).get("checkpoint_count", 0),
                    "proof_size_bytes": bundle.get("folded_object", {}).get("proof_size_bytes", 0),
                    "verify_allowed": outcome.allowed,
                    "verify_reason_codes": outcome.reason_codes,
                },
                indent=2,
            )
        )
        return
    if args.command == "interactive":
        from nessa_cli import main_interactive

        raise SystemExit(main_interactive(deterministic=args.deterministic))
    if args.command == "gateway-demo":
        from integration_gateway import main as gw_main

        gw_args: list[str] = []
        if args.deterministic:
            gw_args.append("--deterministic")
        if args.quiet:
            gw_args.append("--quiet")
        if args.json:
            gw_args.append("--json")
        raise SystemExit(gw_main(gw_args))
    if args.command == "docs-bundle":
        from docs_bundle import main as docs_main

        docs_args: list[str] = []
        if args.deterministic:
            docs_args.append("--deterministic")
        if args.benchmark:
            docs_args.append("--benchmark")
        if args.json:
            docs_args.append("--json")
        if args.docs_dir is not None:
            docs_args.extend(["--docs-dir", str(args.docs_dir)])
        raise SystemExit(docs_main(docs_args))
    if args.command == "asc-ad-demo":
        from asc_ad_demo import main as asc_main

        asc_args: list[str] = []
        if args.deterministic:
            asc_args.append("--deterministic")
        if args.benchmark:
            asc_args.append("--benchmark")
        if args.json:
            asc_args.append("--json")
        if args.artifacts_dir is not None:
            asc_args.extend(["--artifacts-dir", str(args.artifacts_dir)])
        if args.root_artifacts:
            asc_args.append("--root-artifacts")
        if args.report is not None:
            asc_args.extend(["--report", str(args.report)])
        raise SystemExit(asc_main(asc_args))
    if args.command == "usecase-flows":
        import usecase_flows

        if args.verify_sample:
            seed = usecase_flows.deterministic_seed_for_demo("login", args.deterministic)
            result = usecase_flows.prove_login_session(
                usecase_flows.LoginSessionMaterial("pk:demo-session", "rp://payments", 1700000000, 0x10),
                deterministic_seed=seed,
            )
            bundle = usecase_flows.flow_to_wallet_bundle(result)
            outcome = VerifyFolded(bundle["policy"], bundle["folded_object"], bundle["proof"])
            print(
                json.dumps(
                    {
                        "flow": "login",
                        "verify_allowed": outcome.allowed,
                        "verify_reason_codes": outcome.reason_codes,
                        "proof_size_bytes": bundle["folded_object"].get("proof_size_bytes"),
                    },
                    indent=2,
                )
            )
            return
        uc_args: list[str] = []
        if args.deterministic:
            uc_args.append("--deterministic")
        if args.verbose:
            uc_args.append("--verbose")
        if args.json_summary:
            uc_args.append("--json-summary")
        if args.story:
            uc_args.append("--story")
        if args.init_actor_cache:
            uc_args.append("--init-actor-cache")
        if args.force:
            uc_args.append("--force")
        if args.multi_user_story:
            uc_args.append("--multi-user-story")
        if args.interactive:
            uc_args.append("--interactive")
        if args.actor_cache is not None:
            uc_args.extend(["--actor-cache", str(args.actor_cache)])
        raise SystemExit(usecase_flows.main(uc_args))


if __name__ == "__main__":
    main()
