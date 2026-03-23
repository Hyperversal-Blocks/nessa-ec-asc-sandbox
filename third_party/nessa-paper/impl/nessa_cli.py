#!/usr/bin/env python3
"""
NESSA interactive CLI — privacy-centric, menu-driven application.

Zero extra dependencies: ANSI escape codes for color, input() for prompts.
Launch via: python app.py interactive
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL_DIR = ROOT / "impl"
if str(IMPL_DIR) not in sys.path:
    sys.path.insert(0, str(IMPL_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import (
    NessaAccessWallet,
    AccessRequest,
    VerificationOutcome,
    VerifyFolded,
    WalletState,
)
from integration_gateway import (
    GatewaySession,
    GatewayProver,
    GatewayVerifier,
    GatewayPolicy,
    PrivacyRedactor,
    VerifierReceipt,
    PRIVACY_CHECKLIST,
    run_gateway_demo,
)


# ──────────────────────────────────────────────────────────────
# ANSI helpers (no dependencies)
# ──────────────────────────────────────────────────────────────

_COLORS = sys.stdout.isatty()

def _esc(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLORS else text

def bold(t: str) -> str: return _esc("1", t)
def dim(t: str) -> str: return _esc("2", t)
def green(t: str) -> str: return _esc("32", t)
def red(t: str) -> str: return _esc("31", t)
def yellow(t: str) -> str: return _esc("33", t)
def cyan(t: str) -> str: return _esc("36", t)
def magenta(t: str) -> str: return _esc("35", t)

def header(title: str) -> None:
    w = max(len(title) + 6, 44)
    border = "═" * (w - 2)
    print(f"\n  ╔{border}╗")
    print(f"  ║{title.center(w - 2)}║")
    print(f"  ╚{border}╝\n")

def section(title: str) -> None:
    print(f"\n  {bold('── ' + title + ' ' + '─' * max(0, 40 - len(title)))}\n")

def divider() -> None:
    print(f"  {'─' * 44}")

def ok(msg: str) -> None:
    print(f"  {green('✓')} {msg}")

def fail(msg: str) -> None:
    print(f"  {red('✗')} {msg}")

def info(msg: str) -> None:
    print(f"  {cyan('•')} {msg}")

def warn(msg: str) -> None:
    print(f"  {yellow('!')} {msg}")

def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {label}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val or default

def prompt_int(label: str, default: int) -> int:
    val = prompt(label, str(default))
    try:
        return int(val)
    except ValueError:
        return default

def menu_choice(options: list[tuple[str, str]], title: str = "Choice") -> str:
    for key, label in options:
        print(f"  [{bold(key)}] {label}")
    print()
    while True:
        choice = prompt(title).lower()
        valid = {k.lower() for k, _ in options}
        if choice in valid:
            return choice
        print(f"  {dim('Invalid choice. Try again.')}")


# ──────────────────────────────────────────────────────────────
# Privacy panel
# ──────────────────────────────────────────────────────────────

def show_privacy_panel(raw_bundle: dict[str, Any] | None = None, redacted_bundle: dict[str, Any] | None = None) -> None:
    section("Privacy Panel")
    left_title = bold("LOCAL ONLY (never sent)")
    right_title = bold("ON WIRE (verifier sees)")
    left_items = [
        "factor bits (mfa, device, …)",
        "subject identity string",
        "device identifier",
        "checkpoint history",
        "blinding randomness ρ, γ",
        "Schnorr nonces",
        "wallet state file",
        "denial reason details",
    ]
    right_items = [
        "C⋆ folded commitment (32 B)",
        "V_list policy commitments",
        "π_link Schnorr proof",
        "π_cons linear constraint proof",
        "context_digest (SHA-512)",
        "encoding_id, policy_id",
        "N, d (public parameters)",
        "opaque 'denied' (if denied)",
    ]
    print(f"  ┌{'─' * 32}┬{'─' * 32}┐")
    print(f"  │ {left_title:<39}│ {right_title:<39}│")
    print(f"  ├{'─' * 32}┼{'─' * 32}┤")
    for l_item, r_item in zip(left_items, right_items):
        l_col = f"{dim('•')} {l_item}"
        r_col = f"{dim('•')} {r_item}"
        print(f"  │ {l_col:<39}│ {r_col:<39}│")
    print(f"  └{'─' * 32}┴{'─' * 32}┘")

    if raw_bundle and redacted_bundle:
        raw_fo = raw_bundle.get("folded_object", {})
        red_fo = redacted_bundle.get("folded_object", {})
        stripped = [k for k in raw_fo if k not in red_fo]
        if stripped:
            info(f"Redacted from wire: {', '.join(stripped)}")
        proof_bytes = red_fo.get("proof_size_bytes", 0)
        if proof_bytes:
            info(f"Proof size on wire: {bold(str(proof_bytes))} bytes")

    print()
    print(f"  {green('Verifier learns:')} policy constraint satisfied (sum of factors = required count)")
    print(f"  {red('Verifier does NOT learn:')} which factors, who you are, event history, device id")
    print()


# ──────────────────────────────────────────────────────────────
# Wallet inspector
# ──────────────────────────────────────────────────────────────

def inspect_wallet(wallet: NessaAccessWallet) -> None:
    section("Wallet State")
    s = wallet.state
    info(f"Subject: {bold(s.subject)}")
    info(f"Device:  {bold(s.device)}")
    info(f"Scope:   {bold(s.scope)}")
    info(f"Verifier:{bold(s.verifier)}")
    divider()

    mfa, dev, deleg, usage = wallet.current_bits()
    factors = [
        ("MFA", mfa),
        ("Device", dev),
        ("Delegation", deleg),
        ("Usage OK", usage),
    ]
    factor_line = "  "
    for name, val in factors:
        mark = green("✓") if val else red("✗")
        factor_line += f"{mark} {name:<14}"
    print(factor_line)

    used = s.usage_used
    limit = s.usage_limit
    remaining = max(0, limit - used)
    bar_len = 20
    filled = int(bar_len * remaining / limit) if limit > 0 else 0
    bar = green("█" * filled) + dim("░" * (bar_len - filled))
    print(f"  Budget: [{bar}] {remaining}/{limit} remaining")

    if s.revoked:
        print(f"  {red(bold('REVOKED'))}")

    if s.checkpoints:
        divider()
        print(f"  {bold('Recent checkpoints')} ({len(s.checkpoints)} total):")
        for cp in s.checkpoints[-6:]:
            flags = ""
            flags += green("M") if cp.mfa_ok else red("m")
            flags += green("D") if cp.device_ok else red("d")
            flags += green("L") if cp.delegation_ok else red("l")
            flags += green("U") if cp.usage_ok else red("u")
            print(f"    [{flags}] #{cp.seq} {cp.event_type}: {dim(cp.detail[:50])}")
    print()


# ──────────────────────────────────────────────────────────────
# Proof inspector
# ──────────────────────────────────────────────────────────────

def inspect_proof_bundle(bundle: dict[str, Any]) -> None:
    section("Proof Bundle Inspector")
    info(f"Version: {bundle.get('version', '?')}")
    info(f"Engine:  {bundle.get('engine', '?')}")
    info(f"Allowed: {green('yes') if bundle.get('allowed') else red('no')}")

    if not bundle.get("allowed"):
        codes = bundle.get("reason_codes", [])
        info(f"Reason:  {', '.join(codes)}")
        return

    fo = bundle.get("folded_object", {})
    info(f"N={fo.get('N', '?')}  d={fo.get('d', '?')}  proof_size={fo.get('proof_size_bytes', '?')} bytes")

    divider()
    print(f"  {bold('Cleartext on wire')} (verifier can read):")
    req = bundle.get("request", {})
    if req:
        print(f"    resource:       {req.get('resource', '?')}")
        print(f"    action:         {req.get('action', '?')}")
        print(f"    context_digest: {dim(req.get('context_digest', '?')[:32] + '…')}")

    divider()
    print(f"  {bold('Opaque on wire')} (verifier cannot invert):")
    c_star = fo.get("C_star", "")
    print(f"    C⋆:             {dim(c_star[:32] + '…' if len(c_star) > 32 else c_star)}")
    v_count = len(fo.get("V_list", []))
    print(f"    V_list:         {v_count} policy commitments")
    proof = bundle.get("proof", {})
    print(f"    π_link:         challenge={dim((proof.get('pi_link', {}).get('challenge', ''))[:16] + '…')}")
    pi_cons = proof.get("pi_cons_linear", {})
    if pi_cons:
        print(f"    π_cons_linear:  challenge={dim(pi_cons.get('challenge', '')[:16] + '…')}")

    privacy_leaks = []
    for field in ["checkpoint_count", "snapshot_kind", "material_preview"]:
        if field in fo:
            privacy_leaks.append(field)
    if privacy_leaks:
        warn(f"Privacy-leaking fields present: {', '.join(privacy_leaks)}")
        warn("Use PrivacyRedactor before transmitting")
    else:
        ok("No privacy-leaking metadata fields detected")
    print()


# ──────────────────────────────────────────────────────────────
# Gateway authorization flow
# ──────────────────────────────────────────────────────────────

EVENT_MENU = [
    ("1", "enroll"),
    ("2", "mfa"),
    ("3", "device-ok"),
    ("4", "delegate"),
    ("5", "key-rotate"),
    ("6", "revoke"),
    ("7", "restore"),
    ("8", "consume"),
    ("9", "clear-mfa"),
    ("0", "device-fail"),
    ("d", "done → proceed to proving"),
]

def run_gateway_interactive(deterministic: bool = False) -> None:
    section("Gateway Authorization Session")

    subject = prompt("Subject", "alice@mobile")
    device = prompt("Device", "device:iphone-15")
    scope = prompt("Scope", "api://payments")
    gateway = prompt("Gateway", "gateway://payments")
    budget = prompt_int("Usage budget", 3)

    session = GatewaySession(
        subject=subject,
        device=device,
        scope=scope,
        gateway_id=gateway,
        usage_budget=budget,
    )
    ok(f"Session created — gateway: {bold(gateway)}, budget: {budget}")

    # Event application loop
    section("Apply Security Events")
    print(f"  {dim('Apply events to build up your authorization state.')}")
    print(f"  {dim('You need: enroll + mfa + device-ok + delegate to prove.')}\n")

    while True:
        for key, label in EVENT_MENU:
            mark = ""
            if label == "mfa" and session.wallet.state.mfa_ok:
                mark = f" {green('✓')}"
            elif label == "device-ok" and session.wallet.state.device_ok:
                mark = f" {green('✓')}"
            elif label == "delegate" and session.wallet.state.delegation_ok:
                mark = f" {green('✓')}"
            print(f"  [{bold(key)}] {label}{mark}")
        print()

        choice = prompt("Event").lower()
        if choice == "d":
            break

        event_map = {k: v for k, v in EVENT_MENU if k != "d"}
        if choice not in event_map:
            warn("Invalid choice")
            continue

        evt = event_map[choice]
        session.apply_event(evt, f"interactive: {evt}")
        ok(f"{evt} recorded ({len(session.wallet.state.checkpoints)} checkpoints)")
        print()

    # Readiness check
    section("Pre-flight Readiness")
    readiness = session.readiness()
    mfa, dev, deleg, usage = session.wallet.current_bits()
    factors = [("MFA", mfa), ("Device", dev), ("Delegation", deleg), ("Usage OK", usage)]
    for name, val in factors:
        mark = green("✓") if val else red("✗")
        print(f"  {mark} {name}")

    if readiness.ready:
        ok(readiness.user_message)
    else:
        fail(readiness.user_message)
        for m in readiness.missing_factors:
            warn(m)
        print(f"\n  {dim('Proceeding anyway — proof will show denial handling.')}")

    # Prove/verify loop
    section("Authorization Proofs")
    while True:
        print(f"  {dim(f'Budget remaining: {session.remaining_budget}/{budget}')}")
        choice = menu_choice([
            ("p", "Prove & verify"),
            ("w", "Inspect wallet"),
            ("v", "Privacy panel"),
            ("b", "Back to main menu"),
        ], "Action")

        if choice == "b":
            break

        if choice == "w":
            inspect_wallet(session.wallet)
            continue

        if choice == "v":
            if session.readiness().ready:
                raw, redacted = session.raw_bundle_for_privacy_panel(deterministic=deterministic)
                show_privacy_panel(raw, redacted)
            else:
                show_privacy_panel()
            continue

        if choice == "p":
            t0 = time.perf_counter()
            bundle, receipt = session.prove_and_verify(deterministic=deterministic)
            elapsed = (time.perf_counter() - t0) * 1000

            if receipt.authorized:
                ok(f"authorized — receipt: {dim(receipt.receipt_id[:16] + '…')}")
            else:
                fail(f"{receipt.reason}")

            proof_bytes = bundle.get("folded_object", {}).get("proof_size_bytes", 0)
            info(f"Proof: {proof_bytes} bytes, {elapsed:.1f}ms")
            info(f"Budget: {session.remaining_budget}/{budget}")

            narrative = session.prover.user_narrative(bundle)
            print(f"\n  {dim(narrative)}\n")

            if bundle.get("allowed"):
                show_privacy_panel(
                    *session.raw_bundle_for_privacy_panel(deterministic=deterministic)
                )


# ──────────────────────────────────────────────────────────────
# Use-case flows
# ──────────────────────────────────────────────────────────────

def run_usecase_interactive(deterministic: bool = False) -> None:
    section("Use-Case Flows")
    print(f"  {dim('These demonstrate NESSA binding/packing for 7 real-world scenarios.')}")
    print(f"  {dim('Each flow commits domain-specific labels into a qFold-EC proof.')}\n")

    scenarios = [
        ("1", "Login / session proof-of-control"),
        ("2", "Delegation (parent → child key)"),
        ("3", "Selective credential disclosure"),
        ("4", "Revocation / usage-limited credential"),
        ("5", "Device attestation / context lock"),
        ("6", "TLS / OAuth handshake binding"),
        ("7", "IVC step-chain aggregation"),
        ("a", "Run ALL demos"),
        ("b", "Back"),
    ]
    choice = menu_choice(scenarios, "Scenario")
    if choice == "b":
        return

    try:
        from usecase_flows import (
            run_all_demos,
            verify_flow_locally,
            verify_flow_like_app,
            integrator_checklist,
        )
    except ImportError as e:
        fail(f"Could not import usecase_flows: {e}")
        return

    if choice == "a":
        flows = run_all_demos(deterministic=deterministic)
    else:
        flows = run_all_demos(deterministic=deterministic)
        idx = int(choice) - 1
        if 0 <= idx < len(flows):
            flows = [flows[idx]]
        else:
            warn("Invalid index")
            return

    for name, result in flows:
        flow = result.flow
        ok_local = verify_flow_locally(flow)
        ok_app, reasons = verify_flow_like_app(flow.encoding_id, flow)

        section(f"{result.story.title}")
        print(f"  {dim(result.story.one_line)}\n")

        status_mark = green("✓ PASS") if ok_app else red("✗ FAIL")
        info(f"Status: {status_mark}")
        info(f"N={flow.result.N}  d={flow.result.d}  proof={flow.result.proof_size_bytes} bytes")
        info(f"encoding_id: {flow.encoding_id}")

        if not ok_app:
            for r in reasons:
                fail(r)

        hints = result.integrator_metadata.get("user_visible_hints", ())
        if hints:
            divider()
            print(f"  {bold('Hints:')}")
            for h in hints:
                print(f"    {dim(h)}")

        divider()
        print(f"  {bold('Integrator checklist:')}")
        for phase, action in integrator_checklist(result):
            print(f"    [{cyan(phase)}] {action}")
        print()


# ──────────────────────────────────────────────────────────────
# Scripted demo (colored version)
# ──────────────────────────────────────────────────────────────

def run_scripted_demo(deterministic: bool = False) -> None:
    section("Scripted Gateway Demo")
    print(f"  {dim('Running the full lifecycle narrative with colored output…')}\n")
    results = run_gateway_demo(deterministic=deterministic, verbose=True)

    section("Privacy Checklist")
    for i, (name, desc) in enumerate(PRIVACY_CHECKLIST, 1):
        print(f"  [{green(f'{i:2d}')}] {bold(name)}: {desc}")

    print(f"\n  {bold(f'{len(PRIVACY_CHECKLIST)} safeguards documented')}\n")


# ──────────────────────────────────────────────────────────────
# Main menu
# ──────────────────────────────────────────────────────────────

def main_interactive(deterministic: bool = False) -> int:
    header("NESSA — Privacy-Preserving Auth CLI")
    print(f"  {dim('Engine: qFold-EC  •  v1  •  Zero-knowledge authorization')}")
    print(f"  {dim('Prove policy compliance without revealing which factors you have.')}\n")

    while True:
        divider()
        choice = menu_choice([
            ("1", "Gateway Authorization (interactive)"),
            ("2", "Use-Case Flows (7 scenarios)"),
            ("3", "Privacy Dashboard"),
            ("4", "Proof Inspector (load bundle JSON)"),
            ("5", "Wallet Inspector (load state JSON)"),
            ("6", "Run Scripted Demo"),
            ("q", "Exit"),
        ], "Menu")

        if choice == "q":
            print(f"\n  {dim('Goodbye.')}\n")
            return 0

        if choice == "1":
            run_gateway_interactive(deterministic=deterministic)

        elif choice == "2":
            run_usecase_interactive(deterministic=deterministic)

        elif choice == "3":
            show_privacy_panel()

        elif choice == "4":
            path = prompt("Bundle JSON path", "")
            if not path:
                warn("No path provided")
                continue
            p = Path(path)
            if not p.is_file():
                fail(f"File not found: {p}")
                continue
            try:
                bundle = json.loads(p.read_text(encoding="utf-8"))
                inspect_proof_bundle(bundle)
            except Exception as e:
                fail(f"Error loading bundle: {e}")

        elif choice == "5":
            path = prompt("Wallet state JSON path", "")
            if not path:
                warn("No path provided")
                continue
            p = Path(path)
            if not p.is_file():
                fail(f"File not found: {p}")
                continue
            try:
                wallet = NessaAccessWallet.load(p)
                inspect_wallet(wallet)
            except Exception as e:
                fail(f"Error loading wallet: {e}")

        elif choice == "6":
            run_scripted_demo(deterministic=deterministic)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="nessa-interactive")
    parser.add_argument("--deterministic", action="store_true")
    args = parser.parse_args(argv)
    return main_interactive(deterministic=args.deterministic)


if __name__ == "__main__":
    raise SystemExit(main())
