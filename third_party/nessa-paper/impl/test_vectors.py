#!/usr/bin/env python3
"""Generate complete TV-LIN-8 and TV-R1CS-8 whitepaper vectors."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_layout import TEST_VECTORS_OUTPUT_PATH, ensure_parent

from nessa_qfold import (
    L,
    PROTOCOL_VERSION,
    DeterministicScalarOracle,
    Event,
    build_tags,
    cbor_encode,
    commit_v2,
    compile_linear_policy,
    compute_alpha,
    compute_transcript_root_0,
    compute_transcript_root_i,
    compressed_linear_terms,
    derive_generators,
    fold_weight_sum,
    linear_constraint_W,
    normalize_event_values,
    run_protocol_flow,
    scalar_from_int,
    scalar_to_int,
    verify_cons_linear,
    verify_link,
)

TV_LIN_SEED = b"NESSA-EC:test-vector:TV-LIN-8:v1"
TV_R1CS_SEED = b"NESSA-EC:test-vector:TV-R1CS-8:v1"


def scalar_hex(value: int) -> str:
    return scalar_from_int(value).hex()


def build_linear_events() -> list[list[int]]:
    events = []
    for i in range(8):
        m0 = 100 * (i + 1)
        m1 = 1000 - m0
        m2 = 10 * (i + 1) + 3
        m3 = 3 * m2 - 7
        events.append([m0, m1, m2, m3])
    return events


def build_r1cs_events() -> list[list[int]]:
    events = []
    for i in range(8):
        x = 2 + i * 3
        y = 5 + i * 7
        z = x * y
        events.append([x, y, z])
    return events


def generate_tv_lin_8() -> dict:
    d = 4
    coord_bits = [32, 32, 32, 32]
    policy_rows = [[1, 1, 0, 0], [0, 0, 3, -1]]
    policy_targets = [1000, 7]
    events = build_linear_events()
    flow = run_protocol_flow(
        N=8,
        d=d,
        include_nonlinear=False,
        event_values=events,
        linear_constraint_coeffs=policy_rows[0],
        linear_constraint_target=policy_targets[0],
        linear_constraint_rows=policy_rows,
        linear_constraint_targets=policy_targets,
        coordinate_bit_lengths=coord_bits,
        deterministic_seed=TV_LIN_SEED,
        encoding_id="TV-LIN-8",
        policy_id="TV-LIN-8-policy",
    )

    gens = flow.gens
    oracle = DeterministicScalarOracle(TV_LIN_SEED)
    witnesses, rho_list = [], []
    for i, row in enumerate(events):
        vals = normalize_event_values(row, d, False, coord_bits)
        witnesses.append(Event(values=vals).encode())
        rho_list.append([oracle.scalar("rho", i, j) for j in range(d)])

    policy_compiled = compile_linear_policy(d, policy_rows, policy_targets)
    policy_hash = hashlib.sha512(policy_compiled).digest()
    transcript_seed = hashlib.sha512(TV_LIN_SEED).digest()
    tags = build_tags(
        encoding_id="TV-LIN-8",
        policy_id="TV-LIN-8-policy",
        d=d,
        policy_hash=policy_hash,
        k_rows=len(policy_rows),
        transcript_seed=transcript_seed,
    )
    tags_cbor = cbor_encode(tags)
    tags_hash = hashlib.sha512(tags_cbor).digest()

    roots = [compute_transcript_root_0(tags_hash)]
    for i, commitment in enumerate(flow.commitments, 1):
        roots.append(compute_transcript_root_i(i, roots[-1], commitment))
    alphas = [compute_alpha(roots[-1], i) for i in range(1, 9)]

    compressed_policy_hash, compressed_coeffs, compressed_target = compressed_linear_terms(
        policy_compiled,
        roots[-1],
        fold_weight_sum(alphas),
    )
    W = linear_constraint_W(flow.V_list, compressed_coeffs, compressed_target, gens["H_pol"])

    return {
        "name": "TV-LIN-8",
        "suite_id": PROTOCOL_VERSION,
        "d": d,
        "k_rows": len(policy_rows),
        "N": 8,
        "deterministic_seed_hex": TV_LIN_SEED.hex(),
        "tags_hex": tags_cbor.hex(),
        "tags_hash_hex": tags_hash.hex(),
        "policy_rows": policy_rows,
        "policy_targets": policy_targets,
        "policy_compiled_hex": policy_compiled.hex(),
        "policy_hash_hex": policy_hash.hex(),
        "compressed_policy_hash_hex": compressed_policy_hash.hex(),
        "compressed_coeffs_hex": [scalar_hex(v) for v in compressed_coeffs],
        "compressed_target_hex": scalar_hex(compressed_target),
        "generators": {
            "Br": [point.hex() for point in gens["Br"]],
            "Bm": [point.hex() for point in gens["Bm"]],
            "G_pol": gens["G_pol"].hex(),
            "H_pol": gens["H_pol"].hex(),
        },
        "events": [
            {
                "index": i + 1,
                "values": row,
                "m_hex": [value.hex() for value in witnesses[i]],
                "rho_hex": [value.hex() for value in rho_list[i]],
                "commitment_hex": flow.commitments[i].hex(),
            }
            for i, row in enumerate(events)
        ],
        "transcript": {
            "R_hex": [root.hex() for root in roots],
            "R_final_hex": roots[-1].hex(),
            "alphas_hex_le": [alpha.hex() for alpha in alphas],
        },
        "folded": {
            "C_star_hex": flow.C_star.hex(),
            "m_star_hex": [value.hex() for value in flow.m_star],
            "rho_star_hex": [value.hex() for value in flow.rho_star],
        },
        "policy_commitments_hex": [point.hex() for point in flow.V_list],
        "pi_link": {
            "T_C_hex": flow.proof.pi_link.T_commit.hex(),
            "T_V_hex": [value.hex() for value in flow.proof.pi_link.T_policy],
            "z_r_hex": [value.hex() for value in flow.proof.pi_link.z_rho],
            "z_m_hex": [value.hex() for value in flow.proof.pi_link.z_m],
            "z_gamma_hex": [value.hex() for value in flow.proof.pi_link.z_gamma],
            "challenge_hex": flow.proof.pi_link.challenge.hex(),
        },
        "pi_cons": {
            "W_hex": W.hex(),
            "T_hex": flow.proof.pi_cons_linear.T.hex(),
            "z_hex": flow.proof.pi_cons_linear.z.hex(),
            "challenge_hex": flow.proof.pi_cons_linear.challenge.hex(),
        },
        "verification": {
            "link_verify_ok": verify_link(
                flow.proof.pi_link,
                flow.C_star,
                flow.V_list,
                gens,
                flow.tags_hash,
                flow.transcript_roots[-1],
            ),
            "cons_verify_ok": verify_cons_linear(
                flow.proof.pi_cons_linear,
                W,
                gens["G_pol"],
                flow.tags_hash,
                flow.transcript_roots[-1],
                policy_hash,
            ),
            "proof_size_bytes": flow.result.proof_size_bytes,
        },
    }


def generate_tv_r1cs_8() -> dict:
    events = build_r1cs_events()
    flow = run_protocol_flow(
        N=8,
        d=3,
        include_nonlinear=True,
        event_values=events,
        deterministic_seed=TV_R1CS_SEED,
    )
    x_star, y_star, z_star = [scalar_to_int(value) for value in flow.m_star]
    e_value = (x_star * y_star - z_star) % L

    return {
        "name": "TV-R1CS-8",
        "suite_id": PROTOCOL_VERSION,
        "d": 3,
        "N": 8,
        "deterministic_seed_hex": TV_R1CS_SEED.hex(),
        "events": [
            {
                "index": i + 1,
                "x": row[0],
                "y": row[1],
                "z": row[2],
                "z_equals_xy": row[0] * row[1] == row[2],
                "commitment_hex": flow.commitments[i].hex(),
            }
            for i, row in enumerate(events)
        ],
        "tags_hash_hex": flow.tags_hash.hex(),
        "transcript_roots_hex": [root.hex() for root in flow.transcript_roots],
        "R_final_hex": flow.transcript_roots[-1].hex(),
        "alphas_hex_le": [alpha.hex() for alpha in flow.alphas],
        "folded": {
            "C_star_hex": flow.C_star.hex(),
            "x_star": x_star,
            "y_star": y_star,
            "z_star": z_star,
            "x_star_hex": flow.m_star[0].hex(),
            "y_star_hex": flow.m_star[1].hex(),
            "z_star_hex": flow.m_star[2].hex(),
            "E": e_value,
            "E_hex": scalar_hex(e_value),
            "identity": "x_star * y_star = z_star + E (mod L)",
            "identity_holds": (x_star * y_star - z_star - e_value) % L == 0,
        },
        "generators": {
            "Br": [point.hex() for point in flow.gens["Br"]],
            "Bm": [point.hex() for point in flow.gens["Bm"]],
            "G_pol": flow.gens["G_pol"].hex(),
            "H_pol": flow.gens["H_pol"].hex(),
        },
        "verification": {
            "folding_check_ok": flow.result.folding_check_ok,
            "link_verify_ok": flow.result.link_verify_ok,
            "cons_verify_ok": flow.result.cons_verify_ok,
            "proof_size_bytes": flow.result.proof_size_bytes,
        },
    }


def write_test_vectors(output_path: Path | None = None) -> Path:
    vectors = {
        "TV-LIN-8": generate_tv_lin_8(),
        "TV-R1CS-8": generate_tv_r1cs_8(),
    }
    out_path = ensure_parent(output_path or TEST_VECTORS_OUTPUT_PATH)
    out_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    return out_path


def main() -> int:
    out_path = write_test_vectors()
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
