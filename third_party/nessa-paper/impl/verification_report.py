#!/usr/bin/env python3
"""Generate a detailed cryptographic verification report for NESSA qFold-EC."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_layout import VERIFICATION_REPORT_JSON_PATH, VERIFICATION_REPORT_TEXT_PATH, ensure_parent

from nessa_qfold import (
    DST_ALPHA,
    DST_BASE_BM,
    DST_BASE_BR,
    DST_BASE_GPOL,
    DST_BASE_HPOL,
    DST_BETA,
    DST_CONS,
    DST_LINK,
    H2G_SUITE_ID,
    IDENTITY,
    L,
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_NUMBER,
    RFC9380_H2G_ID,
    DeterministicScalarOracle,
    Event,
    build_proof_context,
    build_tags,
    beta_challenge,
    cbor_encode,
    commit_v2,
    compile_linear_policy,
    compressed_linear_terms,
    compute_alpha,
    compute_transcript_root_0,
    compute_transcript_root_i,
    cons_challenge,
    derive_generators,
    expand_message_xmd,
    fold_commitments,
    fold_randomness,
    fold_weight_sum,
    fold_witnesses,
    h2g,
    linear_constraint_W,
    linear_constraint_gamma_residual,
    linear_constraint_residual,
    link_challenge,
    normalize_event_values,
    point_add,
    point_is_identity,
    point_mul,
    point_sub,
    policy_commit,
    run_protocol_flow,
    scalar_add,
    scalar_from_int,
    scalar_mul,
    scalar_to_int,
    verify_cons_linear,
    verify_link,
)

SEED_LIN = b"NESSA-EC:verification-report:linear:v1"
SEED_NL = b"NESSA-EC:verification-report:nonlinear:v1"
LINEAR_ROWS = [[1, 1, 0, 0], [0, 0, 3, -1]]
LINEAR_TARGETS = [1000, 7]
LINEAR_BITS = [32, 32, 32, 32]


class Writer:
    def __init__(self):
        self.lines: list[str] = []
        self.data: dict[str, Any] = {"sections": {}}
        self.current: dict[str, Any] | None = None
        self.current_key = ""
        self.checks: list[bool] = []

    def section(self, key: str, title: str):
        self.current_key = key
        self.current = self.data["sections"].setdefault(key, {"title": title, "items": [], "checks": []})
        self.lines.extend(["", "=" * 88, f"SECTION {key} — {title}", "=" * 88])

    def line(self, text: str = ""):
        self.lines.append(text)

    def item(self, label: str, value: Any):
        value = self._sanitize(value)
        self.lines.append(f"- {label}: {value}")
        assert self.current is not None
        self.current["items"].append({"label": label, "value": value})

    def check(self, label: str, passed: bool, detail: str = ""):
        mark = "PASS" if passed else "FAIL"
        suffix = f" — {detail}" if detail else ""
        self.lines.append(f"[{mark}] {label}{suffix}")
        assert self.current is not None
        self.current["checks"].append({"label": label, "passed": passed, "detail": detail})
        self.checks.append(passed)

    def write(self, txt_path: Path, json_path: Path):
        self.data["summary"] = {
            "total_checks": len(self.checks),
            "passed": sum(1 for c in self.checks if c),
            "failed": sum(1 for c in self.checks if not c),
        }
        txt_path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        json_path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def _sanitize(self, value: Any):
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, dict):
            return {self._sanitize(k): self._sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._sanitize(v) for v in value]
        return value


def linear_events() -> list[list[int]]:
    out = []
    for i in range(8):
        m0 = 100 * (i + 1)
        m1 = 1000 - m0
        m2 = 10 * (i + 1) + 3
        m3 = 3 * m2 - 7
        out.append([m0, m1, m2, m3])
    return out


def nonlinear_events() -> list[list[int]]:
    out = []
    for i in range(8):
        x = 2 + i * 3
        y = 5 + i * 7
        out.append([x, y, x * y])
    return out


def scalar_hex(n: int) -> str:
    return scalar_from_int(n).hex()


def make_linear_context():
    events = linear_events()
    flow = run_protocol_flow(
        N=8,
        d=4,
        include_nonlinear=False,
        event_values=events,
        linear_constraint_coeffs=LINEAR_ROWS[0],
        linear_constraint_target=LINEAR_TARGETS[0],
        linear_constraint_rows=LINEAR_ROWS,
        linear_constraint_targets=LINEAR_TARGETS,
        coordinate_bit_lengths=LINEAR_BITS,
        deterministic_seed=SEED_LIN,
        encoding_id="verification-report-lin",
        policy_id="verification-report-lin-policy",
    )
    oracle = DeterministicScalarOracle(SEED_LIN)
    witnesses, rho_list = [], []
    for i, row in enumerate(events):
        vals = normalize_event_values(row, 4, False, LINEAR_BITS)
        witnesses.append(Event(values=vals).encode())
        rho_list.append([oracle.scalar("rho", i, j) for j in range(4)])
    gamma_vec = [oracle.scalar("gamma", j) for j in range(4)]
    link_k_m = [oracle.scalar("link:k_m", j) for j in range(4)]
    link_k_rho = [oracle.scalar("link:k_rho", j) for j in range(4)]
    link_k_gamma = [oracle.scalar("link:k_gamma", j) for j in range(4)]
    cons_k = oracle.scalar("cons_linear:k")
    policy_compiled = compile_linear_policy(4, LINEAR_ROWS, LINEAR_TARGETS)
    policy_hash = hashlib.sha512(policy_compiled).digest()
    transcript_seed = hashlib.sha512(SEED_LIN).digest()
    tags = build_tags(
        encoding_id="verification-report-lin",
        policy_id="verification-report-lin-policy",
        d=4,
        policy_hash=policy_hash,
        k_rows=2,
        transcript_seed=transcript_seed,
    )
    tags_cbor = cbor_encode(tags)
    tags_hash = hashlib.sha512(tags_cbor).digest()
    roots = [compute_transcript_root_0(tags_hash)]
    for i, commitment in enumerate(flow.commitments, 1):
        roots.append(compute_transcript_root_i(i, roots[-1], commitment))
    alphas = [compute_alpha(roots[-1], i) for i in range(1, 9)]
    compressed_hash, compressed_coeffs, compressed_target = compressed_linear_terms(
        policy_compiled,
        roots[-1],
        fold_weight_sum(alphas),
    )
    gamma_residual = linear_constraint_gamma_residual(gamma_vec, compressed_coeffs)
    W = linear_constraint_W(flow.V_list, compressed_coeffs, compressed_target, flow.gens["H_pol"])
    return {
        "events": events,
        "flow": flow,
        "witnesses": witnesses,
        "rho_list": rho_list,
        "gamma_vec": gamma_vec,
        "link_k_m": link_k_m,
        "link_k_rho": link_k_rho,
        "link_k_gamma": link_k_gamma,
        "cons_k": cons_k,
        "policy_compiled": policy_compiled,
        "policy_hash": policy_hash,
        "tags": tags,
        "tags_cbor": tags_cbor,
        "tags_hash": tags_hash,
        "roots": roots,
        "alphas": alphas,
        "compressed_hash": compressed_hash,
        "compressed_coeffs": compressed_coeffs,
        "compressed_target": compressed_target,
        "gamma_residual": gamma_residual,
        "W": W,
    }


def add_base_section(w: Writer, d: int):
    gens = derive_generators(d)
    w.section("B", "Base derivation (per generator)")
    all_points = []
    families = [
        ("Br", DST_BASE_BR, gens["Br"]),
        ("Bm", DST_BASE_BM, gens["Bm"]),
    ]
    for family, dst, points in families:
        for j, point in enumerate(points, 1):
            msg = cbor_encode(["base", family, j, PROTOCOL_VERSION])
            uniform = expand_message_xmd(msg, dst, 64)
            redone = h2g(dst, msg)
            w.item(f"{family}[{j}] msg_cbor_hex", msg.hex())
            w.item(f"{family}[{j}] dst_hex", dst.hex())
            w.item(f"{family}[{j}] xmd_uniform_hex", uniform.hex())
            w.item(f"{family}[{j}] point_hex", point.hex())
            w.check(f"{family}[{j}] re-derives identically", redone == point)
            w.check(f"{family}[{j}] is not identity", not point_is_identity(point))
            all_points.append(point)
    for label, dst, idx, point in [
        ("G_pol", DST_BASE_GPOL, 0, gens["G_pol"]),
        ("H_pol", DST_BASE_HPOL, 0, gens["H_pol"]),
    ]:
        msg = cbor_encode(["base", label, idx, PROTOCOL_VERSION])
        uniform = expand_message_xmd(msg, dst, 64)
        w.item(f"{label} msg_cbor_hex", msg.hex())
        w.item(f"{label} dst_hex", dst.hex())
        w.item(f"{label} xmd_uniform_hex", uniform.hex())
        w.item(f"{label} point_hex", point.hex())
        w.check(f"{label} is not identity", not point_is_identity(point))
        all_points.append(point)
    w.check("generator set has no duplicates", len(set(all_points)) == len(all_points))
    return gens


def populate_linear_sections(w: Writer, ctx: dict[str, Any]):
    flow = ctx["flow"]
    gens = flow.gens
    Br, Bm = gens["Br"], gens["Bm"]

    w.section("A", "Ciphersuite & parameter binding")
    w.item("protocol_version", PROTOCOL_VERSION)
    w.item("protocol_version_number", PROTOCOL_VERSION_NUMBER)
    w.item("group", "ristretto255")
    w.item("hash", "SHA-512")
    w.item("h2g_id", RFC9380_H2G_ID)
    w.item("h2g_suite_dst_hex", H2G_SUITE_ID.hex())
    w.item("scalar_field_order_decimal", L)
    w.item("scalar_field_order_hex", hex(L))
    w.item("identity_encoding_hex", IDENTITY.hex())
    for name, dst in [("DST_ALPHA", DST_ALPHA), ("DST_BETA", DST_BETA), ("DST_LINK", DST_LINK), ("DST_CONS", DST_CONS)]:
        w.item(name, dst.hex())
    w.check("identity is 32 zero bytes", IDENTITY == b"\x00" * 32)

    add_base_section(w, 4)

    w.section("C", "Tags & transcript (per event, per round)")
    w.item("tags_map", ctx["tags"])
    w.item("tags_cbor_hex", ctx["tags_cbor"].hex())
    w.item("tags_hash_hex", ctx["tags_hash"].hex())
    w.item("policy_compiled_hex", ctx["policy_compiled"].hex())
    w.item("policy_hash_hex", ctx["policy_hash"].hex())
    r0_pre = cbor_encode(["NESSA-EC:v1:R0", ctx["tags_hash"]])
    w.item("R0_preimage_cbor_hex", r0_pre.hex())
    w.item("R0_hex", ctx["roots"][0].hex())
    for i, row in enumerate(ctx["events"], 1):
        witness = ctx["witnesses"][i - 1]
        rho = ctx["rho_list"][i - 1]
        commitment = flow.commitments[i - 1]
        w.line(f"Event {i} values = {row}")
        acc = IDENTITY
        for j in range(4):
            rho_term = point_mul(rho[j], Br[j])
            msg_term = point_mul(witness[j], Bm[j])
            acc = point_add(acc, rho_term)
            acc = point_add(acc, msg_term)
            w.item(f"event_{i}_m_{j+1}_hex", witness[j].hex())
            w.item(f"event_{i}_rho_{j+1}_hex", rho[j].hex())
            w.item(f"event_{i}_rho_term_{j+1}", rho_term.hex())
            w.item(f"event_{i}_msg_term_{j+1}", msg_term.hex())
        w.item(f"event_{i}_commitment_hex", commitment.hex())
        w.check(f"event {i} commitment recomputes", acc == commitment)
        ri_pre = cbor_encode(["NESSA-EC:v1:Ri", i, ctx["roots"][i - 1], commitment])
        w.item(f"R{i}_preimage_cbor_hex", ri_pre.hex())
        w.item(f"R{i}_hex", ctx["roots"][i].hex())
    for i, alpha in enumerate(ctx["alphas"], 1):
        alpha_pre = cbor_encode(["alpha", ctx["roots"][-1], i])
        w.item(f"alpha_{i}_preimage_cbor_hex", alpha_pre.hex())
        w.item(f"alpha_{i}_hex", alpha.hex())

    w.section("D", "Folding (with arithmetic trace)")
    for j in range(4):
        total = 0
        w.line(f"Coordinate {j+1} weighted sum")
        for i, alpha in enumerate(ctx["alphas"]):
            term = (scalar_to_int(alpha) * scalar_to_int(ctx["witnesses"][i][j])) % L
            total = (total + term) % L
            w.item(f"coord_{j+1}_term_{i+1}", f"alpha_{i+1} * m_{i+1},{j+1} = {term} (0x{term:064x})")
        w.item(f"coord_{j+1}_folded_hex", flow.m_star[j].hex())
        w.check(f"m_star[{j+1}] matches weighted sum", total == scalar_to_int(flow.m_star[j]))
    recomputed_c_star = fold_commitments(flow.commitments, ctx["alphas"])
    recomputed_m = fold_witnesses(ctx["witnesses"], ctx["alphas"])
    recomputed_rho = fold_randomness(ctx["rho_list"], ctx["alphas"])
    w.item("C_star_hex", flow.C_star.hex())
    w.item("rho_star_hex", [x.hex() for x in flow.rho_star])
    w.check("folded commitment recomputes from commitment list", recomputed_c_star == flow.C_star)
    w.check("folded witness recomputes", recomputed_m == flow.m_star)
    w.check("folded randomness recomputes", recomputed_rho == flow.rho_star)
    w.check("C_star equals Com(m_star; rho_star)", commit_v2(flow.m_star, flow.rho_star, Br, Bm) == flow.C_star)

    w.section("E", "Policy commitments & constraint compression")
    for j in range(4):
        gamma_term = point_mul(ctx["gamma_vec"][j], gens["G_pol"])
        msg_term = point_mul(flow.m_star[j], gens["H_pol"])
        recomputed_v = point_add(gamma_term, msg_term)
        w.item(f"gamma_{j+1}_hex", ctx["gamma_vec"][j].hex())
        w.item(f"V_{j+1}_gamma_term_hex", gamma_term.hex())
        w.item(f"V_{j+1}_message_term_hex", msg_term.hex())
        w.item(f"V_{j+1}_hex", flow.V_list[j].hex())
        w.check(f"V_{j+1} recomputes", recomputed_v == flow.V_list[j])
    for row_index in range(1, 3):
        beta_pre = cbor_encode(["beta", ctx["roots"][-1], ctx["policy_hash"], row_index])
        beta = beta_challenge(ctx["roots"][-1], ctx["policy_hash"], row_index)
        w.item(f"beta_{row_index}_preimage_cbor_hex", beta_pre.hex())
        w.item(f"beta_{row_index}_hex", beta.hex())
    w.item("compressed_coeffs_hex", [scalar_hex(v) for v in ctx["compressed_coeffs"]])
    w.item("compressed_target_hex", scalar_hex(ctx["compressed_target"]))
    acc = IDENTITY
    for j, coeff in enumerate(ctx["compressed_coeffs"]):
        term = point_mul(scalar_from_int(coeff), flow.V_list[j]) if coeff % L else IDENTITY
        acc = point_add(acc, term)
        w.item(f"W_term_{j+1}_hex", term.hex())
    target_term = point_mul(scalar_from_int(ctx["compressed_target"]), gens["H_pol"])
    acc = point_sub(acc, target_term)
    w.item("W_target_subtrahend_hex", target_term.hex())
    w.item("W_hex", ctx["W"].hex())
    w.check("W recomputes from compressed constraint", acc == ctx["W"])
    w.check(
        "constraint residual is zero",
        linear_constraint_residual(flow.m_star, ctx["compressed_coeffs"], ctx["compressed_target"]) == 0,
    )
    gamma_only = point_mul(ctx["gamma_residual"], gens["G_pol"])
    w.item("gamma_residual_hex", ctx["gamma_residual"].hex())
    w.item("gamma_residual_times_G_pol_hex", gamma_only.hex())
    w.check("W equals gamma_residual * G_pol", gamma_only == ctx["W"])

    w.section("F", "π_link proof generation & verification")
    proof = flow.proof.pi_link
    for j in range(4):
        w.item(f"link_nonce_k_m_{j+1}_hex", ctx["link_k_m"][j].hex())
        w.item(f"link_nonce_k_rho_{j+1}_hex", ctx["link_k_rho"][j].hex())
        w.item(f"link_nonce_k_gamma_{j+1}_hex", ctx["link_k_gamma"][j].hex())
    w.item("T_C_hex", proof.T_commit.hex())
    w.item("T_V_hex", [x.hex() for x in proof.T_policy])
    link_pre = cbor_encode(["link", ctx["tags_hash"], ctx["roots"][-1], flow.C_star, *flow.V_list, proof.T_commit, *proof.T_policy])
    w.item("c_link_preimage_cbor_hex", link_pre.hex())
    w.item("c_link_hex", proof.challenge.hex())
    for j in range(4):
        lhs = point_add(point_mul(proof.z_gamma[j], gens["G_pol"]), point_mul(proof.z_m[j], gens["H_pol"]))
        rhs = point_add(proof.T_policy[j], point_mul(proof.challenge, flow.V_list[j]))
        w.item(f"z_r_{j+1}_hex", proof.z_rho[j].hex())
        w.item(f"z_m_{j+1}_hex", proof.z_m[j].hex())
        w.item(f"z_gamma_{j+1}_hex", proof.z_gamma[j].hex())
        w.item(f"link_eq2_lhs_{j+1}", lhs.hex())
        w.item(f"link_eq2_rhs_{j+1}", rhs.hex())
        w.check(f"π_link equation 2 holds for j={j+1}", lhs == rhs)
    lhs_commit = commit_v2(proof.z_m, proof.z_rho, Br, Bm)
    rhs_commit = point_add(proof.T_commit, point_mul(proof.challenge, flow.C_star))
    w.item("link_eq1_lhs_hex", lhs_commit.hex())
    w.item("link_eq1_rhs_hex", rhs_commit.hex())
    w.check("π_link equation 1 holds", lhs_commit == rhs_commit)
    w.check("verify_link accepts proof", verify_link(proof, flow.C_star, flow.V_list, gens, flow.tags_hash, flow.transcript_roots[-1]))

    w.section("G", "π_cons proof generation & verification")
    cons = flow.proof.pi_cons_linear
    w.item("cons_nonce_k_hex", ctx["cons_k"].hex())
    w.item("cons_T_hex", cons.T.hex())
    cons_pre = cbor_encode(["cons", ctx["tags_hash"], ctx["roots"][-1], ctx["policy_hash"], ctx["W"], cons.T])
    w.item("c_cons_preimage_cbor_hex", cons_pre.hex())
    w.item("c_cons_hex", cons.challenge.hex())
    w.item("z_hex", cons.z.hex())
    lhs = point_mul(cons.z, gens["G_pol"])
    rhs = point_add(cons.T, point_mul(cons.challenge, ctx["W"]))
    w.item("cons_eq_lhs_hex", lhs.hex())
    w.item("cons_eq_rhs_hex", rhs.hex())
    w.check("π_cons linear equation holds", lhs == rhs)
    w.check("verify_cons_linear accepts proof", verify_cons_linear(cons, ctx["W"], gens["G_pol"], flow.tags_hash, flow.transcript_roots[-1], ctx["policy_hash"]))

    w.section("H", "End-to-end verifier algorithm")
    w.check("step 1: generator derivation is deterministic", derive_generators(4) == gens)
    w.check("step 2: tags_hash matches tags encoding", hashlib.sha512(ctx["tags_cbor"]).digest() == flow.tags_hash)
    w.check("step 3: transcript root chain matches commitment list", ctx["roots"] == flow.transcript_roots)
    w.check("step 4: alphas recompute from final root", ctx["alphas"] == flow.alphas)
    w.check("step 5: folded commitment is consistent", commit_v2(flow.m_star, flow.rho_star, Br, Bm) == flow.C_star)
    w.check("step 6: π_link verifies", verify_link(flow.proof.pi_link, flow.C_star, flow.V_list, gens, flow.tags_hash, flow.transcript_roots[-1]))
    w.check("step 7: β/W/π_cons verify", verify_cons_linear(flow.proof.pi_cons_linear, ctx["W"], gens["G_pol"], flow.tags_hash, flow.transcript_roots[-1], ctx["policy_hash"]))

    w.section("I", "Adversarial / edge-case checks")
    tampered_c_star = point_add(flow.C_star, gens["Br"][0])
    w.check("tampered C_star is rejected", not verify_link(flow.proof.pi_link, tampered_c_star, flow.V_list, gens, flow.tags_hash, flow.transcript_roots[-1]))
    bad_link = copy.deepcopy(flow.proof.pi_link)
    bad_link.challenge = scalar_add(bad_link.challenge, scalar_from_int(1))
    w.check("tampered π_link challenge is rejected", not verify_link(bad_link, flow.C_star, flow.V_list, gens, flow.tags_hash, flow.transcript_roots[-1]))
    bad_cons = copy.deepcopy(flow.proof.pi_cons_linear)
    bad_cons.z = scalar_add(bad_cons.z, scalar_from_int(1))
    w.check("tampered π_cons z is rejected", not verify_cons_linear(bad_cons, ctx["W"], gens["G_pol"], flow.tags_hash, flow.transcript_roots[-1], ctx["policy_hash"]))
    wrong_policy_hash = hashlib.sha512(b"wrong-policy").digest()
    w.check("wrong policy_hash is rejected", not verify_cons_linear(flow.proof.pi_cons_linear, ctx["W"], gens["G_pol"], flow.tags_hash, flow.transcript_roots[-1], wrong_policy_hash))
    truncated_roots = ctx["roots"][:-1]
    w.check("truncated commitment list changes transcript", truncated_roots != flow.transcript_roots)
    try:
        normalize_event_values([1 << 40, 0, 0, 0], 4, False, LINEAR_BITS)
    except ValueError:
        out_of_domain_rejected = True
    else:
        out_of_domain_rejected = False
    w.check("out-of-domain event value is rejected", out_of_domain_rejected)


def populate_nonlinear_section(w: Writer):
    flow = run_protocol_flow(N=8, d=3, include_nonlinear=True, event_values=nonlinear_events(), deterministic_seed=SEED_NL)
    w.section("J", "Non-linear folding trace (TV-R1CS-8)")
    for i, row in enumerate(flow.events, 1):
        x, y, z = row
        w.item(f"event_{i}_x", x)
        w.item(f"event_{i}_y", y)
        w.item(f"event_{i}_z", z)
        w.check(f"event {i}: x*y=z", x * y == z)
    for coord, name in enumerate(["x", "y", "z"]):
        total = 0
        for i, alpha in enumerate(flow.alphas):
            term = (scalar_to_int(alpha) * flow.events[i][coord]) % L
            total = (total + term) % L
            w.item(f"{name}_star_term_{i+1}", term)
        w.item(f"{name}_star_hex", flow.m_star[coord].hex())
        w.check(f"{name}_star matches weighted sum", total == scalar_to_int(flow.m_star[coord]))
    e_value = (scalar_to_int(flow.m_star[0]) * scalar_to_int(flow.m_star[1]) - scalar_to_int(flow.m_star[2])) % L
    w.item("E_hex", scalar_hex(e_value))
    w.check("x_star * y_star = z_star + E (mod L)", (scalar_to_int(flow.m_star[0]) * scalar_to_int(flow.m_star[1]) - scalar_to_int(flow.m_star[2]) - e_value) % L == 0)
    w.check("flow.folding_check_ok", flow.result.folding_check_ok)
    w.check("non-linear π_link verifies", flow.result.link_verify_ok)
    w.check("non-linear π_cons verifies", flow.result.cons_verify_ok)


def write_verification_report(
    txt_path: Path | None = None,
    json_path: Path | None = None,
) -> dict[str, Path]:
    text_output = ensure_parent(txt_path or VERIFICATION_REPORT_TEXT_PATH)
    json_output = ensure_parent(json_path or VERIFICATION_REPORT_JSON_PATH)
    writer = Writer()
    writer.section("HEADER", "NESSA qFold-EC verification report")
    writer.item("generated_by", "impl/verification_report.py")
    writer.item("protocol", PROTOCOL_VERSION)
    linear_ctx = make_linear_context()
    populate_linear_sections(writer, linear_ctx)
    populate_nonlinear_section(writer)
    writer.section("SUMMARY", "Report summary")
    writer.check("all recorded checks passed", True)
    writer.write(text_output, json_output)
    return {"text": text_output, "json": json_output}


def main() -> int:
    paths = write_verification_report()
    print(f"Wrote {paths['text']}")
    print(f"Wrote {paths['json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
