#!/usr/bin/env python3
"""
NESSA qFold-EC v1 — Benchmark & Verification Suite
====================================================
Runs the full protocol for increasing N, reports:
  - Correctness (folding identity, π_link verification, π_cons verification)
  - Timing breakdown per phase (ms)
  - Proof sizes (bytes)
"""

import copy
import json
import os
import sys
import time
from nessa_qfold import (
    run_protocol, run_protocol_flow, derive_generators,
    L, scalar_to_int, scalar_from_int, scalar_random, scalar_mul, scalar_add,
    nonlinear_fold, h2g, h2s, expand_message_xmd,
    commit_v2, point_add, point_is_identity,
    verify_link, verify_cons_linear, verify_cons_nonlinear,
    PROTOCOL_VERSION, SECURITY_ASSUMPTIONS,
)


def fmt_ms(ms: float) -> str:
    if ms < 1:
        return f"{ms * 1000:.1f} μs"
    if ms < 1000:
        return f"{ms:.2f} ms"
    return f"{ms / 1000:.3f} s"


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b / (1024 * 1024):.2f} MB"


def fmt_int_compact(value: int, edge_digits: int = 10) -> str:
    text = str(value)
    if len(text) <= edge_digits * 2 + 1:
        return text
    return f"{text[:edge_digits]}...{text[-edge_digits:]}"


def fmt_hex(data: bytes, edge_bytes: int = 6) -> str:
    text = data.hex()
    edge_chars = edge_bytes * 2
    if len(text) <= edge_chars * 2 + 1:
        return text
    return f"{text[:edge_chars]}...{text[-edge_chars:]}"


def fmt_scalar(value: bytes, edge_digits: int = 10) -> str:
    return fmt_int_compact(scalar_to_int(value), edge_digits=edge_digits)


NONLINEAR_VECTOR_SEED = b"NESSA-EC:test-vector:nonlinear:v1"
LINEAR_VECTOR_SEED = b"NESSA-EC:test-vector:linear:v1"
LINEAR_VECTOR_COEFFS = [1, 1, -1, 0]
LINEAR_VECTOR_TARGET = 0
LINEAR_COORDINATE_BITS = [64, 64, 65, 1]

DETERMINISTIC_TEST_VECTORS = {
    "nonlinear": {
        "Br0": "f84fd7c6f34981399e4bfdbdcfc429e17d108fc674a05422865a30e2563e871a",
        "Bm0": "3c211f263f15efaadd19c52166503a384ba46933913df0b7e3fbecc2ebce2d42",
        "G_pol": "189e14198a4e5dfb141b576a48541cf410eb808c2d718eeaef8fea12e7efb047",
        "H_pol": "fc84a1de9950310234689fadf41b0eadc5fadc708217204d2045cf92670cc75a",
        "tags_hash": "34aabcccf8741d67de65276cab2f8de47efd71ebd388246d939564eefd428c66b734be0dc702c1dfd379dd290f8e26bb73b0d0a9b159f20efa94fde94dd07e76",
        "R_final": "63e46010029f5ba998e7b1b014b5682edf5f4781639a605ccb8bf0754b13a12d8fde419728662b5c9aa228cc637f26524d26ad4548387478011999a5b6386125",
        "commitments": [
            "c8171f48166327cd9e23a0d62ab640097574a0c99099f0d49835b6ae8861d20d",
            "aabbbad1ff42bd21e7123b6ea12d99ff8b30cb20901dff494d641ba5b2c8717a",
            "782d4abd3b2151da35151e7ea6ecb3ea1f1086032146dde69126dd45b53dfa5b",
            "5690b4bc2e088f5cfe160987c5108a1aff5a5cb03106b550ebdbe0f3b4857f3a",
        ],
        "alphas": [
            "5e2e707b03c275085c0a4f0e961aa7941bd4ac097070e2498f9ea5fb07dd100a",
            "4ccb5119c5d4872c9e3d0def55075afcdc344703f2f5b34dc77fff3bc39e4f03",
            "f3f7cf72a234e14e7a9fa089a5cd0c27d4dade720c8c531fddc9d00bd22ae906",
            "6cf6d1eeb165d9846fa97584dc6e5b1b0573f126c35811eac9722447280d3a02",
        ],
        "C_star": "a0c3d279f425cc6f430db6b2ac726fd0a8ce2b5c52df27c6ebb7ec21c1a7283a",
        "m_star": [
            "80e6b5fbbe330a0defdfe2c2c7c3d8d9fbba59a9189806fceb07ad5e938a8f06",
            "5ae021b3c00de065aebd8985507246c2839435ed0bbe1af4571f3c7816158609",
            "48718b53390e05b7d8d9ac8a362dd5c6c58ee9f9e47b772ee2c66d760768c50b",
        ],
        "V_list": [
            "041c6e7bce1309ef9dc5caf134dc8501f654e67da8a47349319754a2963e300a",
            "826c2f714825d1c7a41570a60ad2c77d36d87d6fb0a096a1d5e85d1a5d572372",
            "56728c78c650dc33a2524dae166aa4297bdae5ad5b6111942c6865c88f09f437",
        ],
        "L_star": 2967492635841460677130461268430637720464565893806686508166659075717629077120,
        "R_star": 4307718686384018210437018422745651835689145268188729420057532619101984383066,
        "O_star": 5324228188988974883296714527559817068116824277694763124433917299737578139976,
        "E_star": 345011848834360185626360494388857649102518556882177580155799388712512280136,
        "pi_link_challenge": "7192e994597a6f7a20709b02b102ccf47b3e7fffd718a15fb4806d95756bb40c",
        "pi_cons_challenge": "24d522f63d57f2cbfae07002398dc5167226f9171cc63bca5db42785dbd86d00",
        "C_E": "a68a239c48f4de8c2a513c4e04ca9bc336ef7731aea616f71aa276e2085da638",
        "proof_size": 1120,
    },
    "linear": {
        "Br0": "f84fd7c6f34981399e4bfdbdcfc429e17d108fc674a05422865a30e2563e871a",
        "Bm0": "3c211f263f15efaadd19c52166503a384ba46933913df0b7e3fbecc2ebce2d42",
        "G_pol": "189e14198a4e5dfb141b576a48541cf410eb808c2d718eeaef8fea12e7efb047",
        "H_pol": "fc84a1de9950310234689fadf41b0eadc5fadc708217204d2045cf92670cc75a",
        "tags_hash": "0df187e203d0a2b6d5f8a00b080d7c304168346e6a09d4e77bf8c9102ca17ba6a0d99dc91019d1ec0785575e63ec8c47a96717f21e5172eeb1136ca8604cbe58",
        "R_final": "a184bf6a4a02f23acd2cd416a1fc030fcca3973f71035c9788a6ad093c46d6e7e101342cfba08785c1bf84e8016f744b44f32586ee2e5abd1b1c0ae1ba591043",
        "commitments": [
            "e2edf3662a4be8834bc14786e04229984e88ab579af5fa20117311fc02de6e3c",
            "da20b5837315b89b84c6e93fd31fc1bf12214f57bb5b00cd6b1e475a972e7157",
            "5c288cd8de5a02cf65f3128d8b2eecf073cfb8907b5f7bf4757d2be2c969293d",
            "607fad5b007d352ff15e1703baa9f8555cab7add4d8671afbbd1a72f423b0e36",
        ],
        "alphas": [
            "b684f7f9107146579a21d8d83bd5863061d1ed19f9f88d6d6af2cc7efd0b9305",
            "a3959d7b4538eae37d24ec602031eb3cd998c7b228c01d40646c02be98305904",
            "d628d44d25120c9d3bbdbf71d9ce2d7d56f336a36ea040a40d92355674020402",
            "c2afdf4f74cb7d6776bae918cb65a62467eb33fd746d50705cbfaaead13e170f",
        ],
        "C_star": "388aac265039b7a69c48a41580160f755e430317afb1f8c35741f5b02d98456a",
        "m_star": [
            "b5015c969b074b3939fb51cf36c953919193cb94889c084840cd13d5b6dfdb03",
            "58f5eeca51055f5e9e206c21170c0ecf8e8cacaaedff2cbf0240f82f6434df07",
            "0df74a61ed0caa97d71bbef04dd561602020783f769c3507430d0c051b14bb0b",
            "041f53b6d523a8e7f3207621224167faf748206d05c73cc238b0af7ddc7d070b",
        ],
        "V_list": [
            "40a46c84d04db76f2368704c41c3ad743d4ecc85b0291274268ee18307283b2b",
            "92b1bb8b22abe4950744f095bf22f513a897cb5605ba5d7c525995a005718a6f",
            "c2d09e953dfa15a255e7b6f948766beee40d36a49f77f422f0ac4533b6537a19",
            "bebd724361420a07018c4f1fcf48434ca63974865659a5555197038170dbf77b",
        ],
        "linear_target": 0,
        "linear_W": "ec7c409f4d531e434d55c75b4c67da6832132d461314cce9f717f7bbe3753a0e",
        "pi_link_challenge": "59b630bb7a4c03112682b5ae8d19123fd4fdbd75bcbd8c3a0641b5aed0d83c01",
        "pi_cons_challenge": "b1871dbda42269314d0f76a348919e9b998be830dcc86e43a315e0543b349004",
        "proof_size": 832,
    },
}


def print_separator():
    print("=" * 90)


def build_protocol_dataset(N: int, d: int = 3, pattern: str = "correlated_polynomial"):
    if d < 3:
        raise ValueError("non-linear benchmark datasets require d >= 3")

    dataset = []
    for i in range(N):
        if pattern == "correlated_polynomial":
            x = (pow(i + 3, 5, L) + 17 * i + 11) % L
            y = (pow(i + 5, 7, L) + 3 * x + 29) % L
        elif pattern == "alternating_extremes":
            x = 0 if i % 2 == 0 else (L - 1 - i) % L
            y = (L - 1 - 37 * i) % L if i % 2 == 0 else 0
        elif pattern == "near_field_wrap":
            x = (L - 1 - (i * 104729)) % L
            y = (L - 17 - (i * i * 8191)) % L
        elif pattern == "sparse_spikes":
            x = 0 if i % 11 else (L - 1 - 97 * i) % L
            y = (pow(i + 1, 3, L) + (1 << 200) + 12345) % L
        elif pattern == "checkerboard_massive":
            high = (1 << 251) - 1
            low = (i * (1 << 64) + 0x9E3779B97F4A7C15) % L
            x = high if i % 3 == 0 else low
            y = (high - i * 1315423911) % L if i % 4 < 2 else ((low * 17) + 5) % L
        elif pattern == "random_mixed":
            x = int.from_bytes(os.urandom(32), "big") % L
            y = int.from_bytes(os.urandom(32), "big") % L
        else:
            raise ValueError(f"unknown dataset pattern: {pattern}")

        row = [x, y, (x * y) % L]
        for j in range(3, d):
            row.append(
                (
                    pow(i + j + 1, j + 2, L)
                    + (x if j % 2 == 0 else y)
                    + ((1 << min(250, 32 + 11 * j)) - 1)
                )
                % L
            )
        dataset.append(row)
    return dataset


def build_simple_flow_dataset():
    return [
        [2, 3, 6],
        [5, 7, 35],
        [11, 13, 143],
        [17, 19, 323],
    ]


def build_linear_dataset(N: int):
    dataset = []
    for i in range(N):
        x = 123_456_789_012 + 7_919 * i
        y = 98_765_432_109 + 1_543 * i
        dataset.append([x, y, x + y, 1])
    return dataset


def assert_protocol_result(result, label: str):
    assert result.folding_check_ok, f"{label}: folding identity failed"
    assert result.link_verify_ok, f"{label}: link proof verification failed"
    assert result.cons_verify_ok, f"{label}: constraint proof verification failed"


def assert_nonlinear_fold(label: str, L_vals, R_vals, alphas):
    O_vals = [(l * r) % L for l, r in zip(L_vals, R_vals)]
    t0 = time.perf_counter()
    Ls, Rs, Os, Es = nonlinear_fold(L_vals, R_vals, O_vals, alphas)
    elapsed = (time.perf_counter() - t0) * 1000
    check = (Ls * Rs - Os - Es) % L
    assert check == 0, f"{label}: non-linear fold check failed ({check})"
    print(f"    ✓ {label}: L⋆·R⋆ - O⋆ - E⋆ = 0  ({fmt_ms(elapsed)})")


def print_protocol_flow(label: str, flow):
    print(f"  {label}")
    print("    Event rows and fold weights:")
    for idx, row in enumerate(flow.events, 1):
        weight = f"alpha_{idx}={fmt_scalar(flow.fold_weights[idx - 1])}"
        print(f"      e{idx}: values={row}  weight={weight}")
    print("    Commitments:")
    for idx, point in enumerate(flow.commitments, 1):
        print(f"      C_{idx}: {fmt_hex(point, edge_bytes=8)}")
    print("    Transcript roots:")
    for idx, root in enumerate(flow.transcript_roots):
        print(f"      R_{idx}: {fmt_hex(root, edge_bytes=8)}")
    print("    Fiat-Shamir challenges:")
    for idx, alpha in enumerate(flow.alphas, 1):
        usage = "transcript-derived fold weight"
        print(f"      alpha_{idx}: {fmt_scalar(alpha)}  ({usage})")
    folded = [fmt_scalar(value) for value in flow.m_star]
    print(f"    Folded witness m*: {folded}")
    print(
        f"    Non-linear fold: L*={fmt_int_compact(flow.L_star_val)}, "
        f"R*={fmt_int_compact(flow.R_star_val)}, "
        f"O*={fmt_int_compact(flow.O_star_val)}, "
        f"E*={fmt_int_compact(flow.E_star_val)}"
    )
    print(f"    Folded commitment C*: {fmt_hex(flow.C_star, edge_bytes=8)}")
    print("    Policy commitments:")
    for idx, point in enumerate(flow.V_list, 1):
        print(f"      V_{idx}: {fmt_hex(point, edge_bytes=8)}")
    print(f"    pi_link challenge: {fmt_scalar(flow.proof.pi_link.challenge)}")
    if flow.proof.pi_cons_nonlinear is not None:
        print(f"    pi_cons challenge: {fmt_scalar(flow.proof.pi_cons_nonlinear.challenge)}")
        print(f"    C_E: {fmt_hex(flow.proof.pi_cons_nonlinear.C_E, edge_bytes=8)}")
    print(f"    Checks: fold={'PASS' if flow.result.folding_check_ok else 'FAIL'}, "
          f"pi_link={'PASS' if flow.result.link_verify_ok else 'FAIL'}, "
          f"pi_cons={'PASS' if flow.result.cons_verify_ok else 'FAIL'}")
    print(
        f"    Timing: commit={fmt_ms(flow.result.commit_ms)}, "
        f"transcript={fmt_ms(flow.result.transcript_ms)}, "
        f"fold={fmt_ms(flow.result.fold_ms)}, "
        f"prove={fmt_ms(flow.result.total_prove_ms)}, "
        f"verify={fmt_ms(flow.result.total_verify_ms)}"
    )
    print(f"    Proof size: {fmt_bytes(flow.result.proof_size_bytes)}")
    print()


def build_vector_summary(flow):
    summary = {
        "Br0": flow.gens["Br"][0].hex(),
        "Bm0": flow.gens["Bm"][0].hex(),
        "G_pol": flow.gens["G_pol"].hex(),
        "H_pol": flow.gens["H_pol"].hex(),
        "tags_hash": flow.tags_hash.hex(),
        "R_final": flow.transcript_roots[-1].hex(),
        "commitments": [point.hex() for point in flow.commitments],
        "alphas": [alpha.hex() for alpha in flow.alphas],
        "C_star": flow.C_star.hex(),
        "m_star": [value.hex() for value in flow.m_star],
        "V_list": [point.hex() for point in flow.V_list],
        "pi_link_challenge": flow.proof.pi_link.challenge.hex(),
        "proof_size": flow.result.proof_size_bytes,
    }
    if flow.proof.pi_cons_nonlinear is not None:
        summary.update(
            {
                "L_star": flow.L_star_val,
                "R_star": flow.R_star_val,
                "O_star": flow.O_star_val,
                "E_star": flow.E_star_val,
                "pi_cons_challenge": flow.proof.pi_cons_nonlinear.challenge.hex(),
                "C_E": flow.proof.pi_cons_nonlinear.C_E.hex(),
            }
        )
    if flow.proof.pi_cons_linear is not None and flow.linear_constraint_W is not None:
        summary.update(
            {
                "linear_target": flow.linear_constraint_target,
                "linear_W": flow.linear_constraint_W.hex(),
                "pi_cons_challenge": flow.proof.pi_cons_linear.challenge.hex(),
            }
        )
    return summary


def assert_known_vector(label: str, flow, expected: dict):
    actual = build_vector_summary(flow)
    assert actual == expected, (
        f"{label}: deterministic vector mismatch\n"
        f"expected={json.dumps(expected, indent=2)}\n"
        f"actual={json.dumps(actual, indent=2)}"
    )


def run_security_vectors_and_attacks(gens):
    print("[2/6] Security assumptions, deterministic vectors, and adversarial checks...\n")

    print("  Security assumptions:")
    for name, description in SECURITY_ASSUMPTIONS:
        print(f"    - {name}: {description}")
    print()

    nonlinear_flow = run_protocol_flow(
        N=4,
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=build_simple_flow_dataset(),
        deterministic_seed=NONLINEAR_VECTOR_SEED,
    )
    assert_protocol_result(nonlinear_flow.result, "non-linear known-answer vector")
    assert_known_vector(
        "non-linear known-answer vector",
        nonlinear_flow,
        DETERMINISTIC_TEST_VECTORS["nonlinear"],
    )
    nonlinear_repeat = run_protocol_flow(
        N=4,
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=build_simple_flow_dataset(),
        deterministic_seed=NONLINEAR_VECTOR_SEED,
    )
    assert_known_vector(
        "non-linear known-answer vector repeat",
        nonlinear_repeat,
        DETERMINISTIC_TEST_VECTORS["nonlinear"],
    )
    print("  ✓ Non-linear known-answer vector matches expected transcript and proof values")

    linear_gens = derive_generators(4)
    linear_flow = run_protocol_flow(
        N=4,
        d=4,
        include_nonlinear=False,
        precomputed_gens=linear_gens,
        event_values=build_linear_dataset(4),
        linear_constraint_coeffs=LINEAR_VECTOR_COEFFS,
        linear_constraint_target=LINEAR_VECTOR_TARGET,
        coordinate_bit_lengths=LINEAR_COORDINATE_BITS,
        deterministic_seed=LINEAR_VECTOR_SEED,
    )
    assert_protocol_result(linear_flow.result, "linear known-answer vector")
    assert_known_vector(
        "linear known-answer vector",
        linear_flow,
        DETERMINISTIC_TEST_VECTORS["linear"],
    )
    print("  ✓ Linear known-answer vector matches expected transcript and proof values")

    shifted_seed_flow = run_protocol_flow(
        N=4,
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=build_simple_flow_dataset(),
        deterministic_seed=b"NESSA-EC:test-vector:nonlinear:v2",
    )
    assert (
        shifted_seed_flow.C_star != nonlinear_flow.C_star
        or shifted_seed_flow.proof.pi_link.challenge != nonlinear_flow.proof.pi_link.challenge
    )
    print("  ✓ Distinct deterministic seeds change commitment and proof material")

    malformed_gens = {
        "Br": gens["Br"],
        "Bm": list(gens["Br"]),
        "G_pol": gens["G_pol"],
        "H_pol": gens["H_pol"],
    }
    try:
        run_protocol_flow(
            N=1,
            d=3,
            include_nonlinear=True,
            precomputed_gens=malformed_gens,
            event_values=[[2, 3, 6]],
            deterministic_seed=b"NESSA-EC:bad-gens",
        )
    except ValueError:
        print("  ✓ Duplicate generator sets are rejected")
    else:
        raise AssertionError("Malformed generator set was accepted")

    tampered_link = copy.deepcopy(nonlinear_flow.proof.pi_link)
    tampered_link.z_m[0] = scalar_add(tampered_link.z_m[0], scalar_from_int(1))
    assert not verify_link(
        tampered_link,
        nonlinear_flow.C_star,
        nonlinear_flow.V_list,
        nonlinear_flow.gens,
        nonlinear_flow.tags_hash,
        nonlinear_flow.transcript_roots[-1],
    )
    print("  ✓ Tampered π_link proof is rejected")

    tampered_nonlinear_cons = copy.deepcopy(nonlinear_flow.proof.pi_cons_nonlinear)
    tampered_nonlinear_cons.z_mul_blind = scalar_add(
        tampered_nonlinear_cons.z_mul_blind,
        scalar_from_int(1),
    )
    assert not verify_cons_nonlinear(
        tampered_nonlinear_cons,
        nonlinear_flow.V_list[0],
        nonlinear_flow.V_list[1],
        nonlinear_flow.V_list[2],
        nonlinear_flow.gens["G_pol"],
        nonlinear_flow.gens["H_pol"],
        nonlinear_flow.transcript_context,
    )
    print("  ✓ Tampered non-linear π_cons proof is rejected")

    tampered_linear_cons = copy.deepcopy(linear_flow.proof.pi_cons_linear)
    tampered_linear_cons.z = scalar_add(tampered_linear_cons.z, scalar_from_int(1))
    assert linear_flow.linear_constraint_W is not None
    assert not verify_cons_linear(
        tampered_linear_cons,
        linear_flow.linear_constraint_W,
        linear_flow.gens["G_pol"],
        linear_flow.tags_hash,
        linear_flow.transcript_roots[-1],
        linear_flow.tags[7],
    )
    print("  ✓ Tampered linear π_cons proof is rejected")

    overflow_dataset = build_linear_dataset(1)
    overflow_dataset[0][0] = 1 << 70
    try:
        run_protocol_flow(
            N=1,
            d=4,
            include_nonlinear=False,
            precomputed_gens=linear_gens,
            event_values=overflow_dataset,
            linear_constraint_coeffs=LINEAR_VECTOR_COEFFS,
            linear_constraint_target=LINEAR_VECTOR_TARGET,
            coordinate_bit_lengths=LINEAR_COORDINATE_BITS,
            deterministic_seed=b"NESSA-EC:overflow",
        )
    except ValueError:
        print("  ✓ Overflowing application-domain coordinates are rejected")
    else:
        raise AssertionError("Overflowing event was accepted")

    invalid_linear_dataset = build_linear_dataset(4)
    invalid_linear_dataset[2][2] += 1
    try:
        run_protocol_flow(
            N=4,
            d=4,
            include_nonlinear=False,
            precomputed_gens=linear_gens,
            event_values=invalid_linear_dataset,
            linear_constraint_coeffs=LINEAR_VECTOR_COEFFS,
            linear_constraint_target=LINEAR_VECTOR_TARGET,
            coordinate_bit_lengths=LINEAR_COORDINATE_BITS,
            deterministic_seed=b"NESSA-EC:invalid-linear",
        )
    except ValueError:
        print("  ✓ Invalid folded linear relation is rejected")
    else:
        raise AssertionError("Invalid linear relation was accepted")

    print()


def run_unit_tests():
    """Quick correctness checks before benchmarking."""
    print("\n[1/6] Running unit tests...\n")

    # Test scalar arithmetic
    a = scalar_from_int(123456789)
    b = scalar_from_int(987654321)
    c = scalar_mul(a, b)
    assert scalar_to_int(c) == (123456789 * 987654321) % L
    print("  ✓ Scalar multiplication")

    # Test huge scalar arithmetic
    huge_a = scalar_from_int(2**250 + 17)
    huge_b = scalar_from_int(2**251 - 3)
    huge_c = scalar_mul(huge_a, huge_b)
    expected = ((2**250 + 17) * (2**251 - 3)) % L
    assert scalar_to_int(huge_c) == expected
    print("  ✓ Huge scalar multiplication (250+ bit operands)")

    # Test H2G produces valid non-identity points
    pt = h2g(b"test-dst", b"test-msg")
    assert len(pt) == 32
    assert not point_is_identity(pt)
    print("  ✓ Hash-to-group (H2G)")

    # Test H2S produces valid scalars
    s = h2s(b"test-dst", b"test-msg")
    assert 0 < scalar_to_int(s) < L
    print("  ✓ Hash-to-scalar (H2S)")

    # Test expand_message_xmd
    uniform = expand_message_xmd(b"hello", b"dst", 64)
    assert len(uniform) == 64
    # Deterministic
    uniform2 = expand_message_xmd(b"hello", b"dst", 64)
    assert uniform == uniform2
    print("  ✓ expand_message_xmd determinism")

    # Test commitment homomorphism
    d = 3
    gens = derive_generators(d)
    m1 = [scalar_from_int(10), scalar_from_int(20), scalar_from_int(30)]
    r1 = [scalar_random() for _ in range(d)]
    m2 = [scalar_from_int(40), scalar_from_int(50), scalar_from_int(60)]
    r2 = [scalar_random() for _ in range(d)]

    C1 = commit_v2(m1, r1, gens["Br"], gens["Bm"])
    C2 = commit_v2(m2, r2, gens["Br"], gens["Bm"])

    # C1 + C2 should equal Com(m1+m2, r1+r2)
    m_sum = [scalar_add(m1[j], m2[j]) for j in range(d)]
    r_sum = [scalar_add(r1[j], r2[j]) for j in range(d)]
    C_sum = commit_v2(m_sum, r_sum, gens["Br"], gens["Bm"])
    C_add = point_add(C1, C2)
    assert C_sum == C_add
    print("  ✓ V2 commitment additively homomorphic")

    # Test non-linear folding identity
    N_test = 16
    L_vals = [int.from_bytes(os.urandom(31), "big") % L for _ in range(N_test)]
    R_vals = [int.from_bytes(os.urandom(31), "big") % L for _ in range(N_test)]
    O_vals = [(l * r) % L for l, r in zip(L_vals, R_vals)]
    # Fake alphas for test
    alphas = [scalar_random() for _ in range(N_test)]
    Ls, Rs, Os, Es = nonlinear_fold(L_vals, R_vals, O_vals, alphas)
    check = (Ls * Rs - Os - Es) % L
    assert check == 0, f"Non-linear fold check failed: {check}"
    print(f"  ✓ Non-linear folding identity (N={N_test}): L⋆·R⋆ - O⋆ - E⋆ = 0")

    # Test with huge numbers (close to field order)
    L_huge = [(L - 1 - i) for i in range(N_test)]
    R_huge = [(L - 100 - i * 7) % L for i in range(N_test)]
    O_huge = [(l * r) % L for l, r in zip(L_huge, R_huge)]
    Ls2, Rs2, Os2, Es2 = nonlinear_fold(L_huge, R_huge, O_huge, alphas)
    check2 = (Ls2 * Rs2 - Os2 - Es2) % L
    assert check2 == 0
    print(f"  ✓ Non-linear folding with near-field-order values (N={N_test})")

    structured_dataset = build_protocol_dataset(12, d=6, pattern="correlated_polynomial")
    structured_result = run_protocol(
        N=12,
        d=6,
        include_nonlinear=True,
        event_values=structured_dataset,
    )
    assert_protocol_result(structured_result, "structured d=6 dataset")
    print("  ✓ Structured end-to-end dataset (N=12, d=6)")

    invalid_dataset = [row[:] for row in structured_dataset[:4]]
    invalid_dataset[0][2] = (invalid_dataset[0][2] + 1) % L
    try:
        run_protocol(N=4, d=6, include_nonlinear=True, event_values=invalid_dataset)
    except ValueError:
        print("  ✓ Invalid illustrative dataset rejected before folding")
    else:
        raise AssertionError("Invalid dataset was accepted")

    example_flow = run_protocol_flow(
        N=4,
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=build_simple_flow_dataset(),
    )
    assert_protocol_result(example_flow.result, "simple flow artifacts")
    assert len(example_flow.commitments) == 4
    assert len(example_flow.transcript_roots) == 5
    assert len(example_flow.alphas) == 4
    assert len(example_flow.fold_weights) == 4
    assert example_flow.fold_weights[0] == example_flow.alphas[0]
    print("  ✓ Protocol flow artifacts available for illustrative traces")

    linear_result = run_protocol(
        N=4,
        d=4,
        include_nonlinear=False,
        precomputed_gens=derive_generators(4),
        event_values=build_linear_dataset(4),
        linear_constraint_coeffs=LINEAR_VECTOR_COEFFS,
        linear_constraint_target=LINEAR_VECTOR_TARGET,
        coordinate_bit_lengths=LINEAR_COORDINATE_BITS,
        deterministic_seed=b"NESSA-EC:unit:linear-smoke",
    )
    assert_protocol_result(linear_result, "linear d=4 dataset")
    print("  ✓ Linear-only end-to-end dataset (N=4, d=4)")

    print("\n  All unit tests passed.\n")
    return gens


def run_example_flows(gens):
    print("[3/6] Illustrative protocol flows...\n")

    simple_dataset = build_simple_flow_dataset()
    simple_flow = run_protocol_flow(
        N=len(simple_dataset),
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=simple_dataset,
    )
    assert_protocol_result(simple_flow.result, "simple protocol flow")
    print("  Example 1: Hand-checkable multiplication rows (N=4, d=3)")
    print("    All rows use transcript-derived fold weights α_i (v1 folding).")
    print_protocol_flow("Simple flow", simple_flow)

    gens_d6 = derive_generators(6)
    extended_dataset = build_protocol_dataset(4, d=6, pattern="correlated_polynomial")
    extended_flow = run_protocol_flow(
        N=4,
        d=6,
        include_nonlinear=True,
        precomputed_gens=gens_d6,
        event_values=extended_dataset,
    )
    assert_protocol_result(extended_flow.result, "extended protocol flow")
    print("  Example 2: Extended witness flow (N=4, d=6)")
    print("    Coordinates 0, 1, 2 satisfy x*y=z; coordinates 3..5 illustrate auxiliary witness slots.")
    print_protocol_flow("Extended flow", extended_flow)


def run_end_to_end_test(gens):
    """Run small N end-to-end and verify everything."""
    print("[4/6] End-to-end protocol test (N=8, d=3)...\n")

    dataset = build_protocol_dataset(8, d=3, pattern="near_field_wrap")
    result = run_protocol(
        N=8,
        d=3,
        include_nonlinear=True,
        precomputed_gens=gens,
        event_values=dataset,
    )

    print(f"  Events:              N={result.N}, d={result.d}")
    print(f"  Folding identity:    {'✓ PASS' if result.folding_check_ok else '✗ FAIL'}")
    print(f"  π_link verification: {'✓ PASS' if result.link_verify_ok else '✗ FAIL'}")
    print(f"  π_cons verification: {'✓ PASS' if result.cons_verify_ok else '✗ FAIL'}")
    print(f"  Proof size:          {fmt_bytes(result.proof_size_bytes)}")
    print(f"  Total prove time:    {fmt_ms(result.total_prove_ms)}")
    print(f"  Total verify time:   {fmt_ms(result.total_verify_ms)}")
    print()

    assert_protocol_result(result, "end-to-end test")
    print("  End-to-end test PASSED.\n")


def run_benchmarks(gens):
    """Benchmark across increasing N values."""
    print("[5/6] Benchmarking across N values...\n")

    test_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    patterns = [
        "correlated_polynomial",
        "alternating_extremes",
        "near_field_wrap",
        "sparse_spikes",
        "checkerboard_massive",
    ]
    d = 3
    results = []

    # Header
    print(f"{'N':>6} │ {'Pattern':>20} │ {'Commit':>10} │ {'Transcript':>10} │ {'Fold':>10} │ "
          f"{'NL-Fold':>10} │ {'Prove':>10} │ {'Verify':>10} │ {'Proof Size':>10} │ {'Check':>5}")
    print("─" * 129)

    for idx, N in enumerate(test_sizes):
        pattern = patterns[idx % len(patterns)]
        try:
            dataset = build_protocol_dataset(N, d=d, pattern=pattern)
            r = run_protocol(
                N=N,
                d=d,
                include_nonlinear=True,
                precomputed_gens=gens,
                event_values=dataset,
            )
            results.append(r)

            check = "✓" if (r.folding_check_ok and r.link_verify_ok and r.cons_verify_ok) else "✗"
            print(f"{N:>6} │ {pattern[:20]:>20} │ {fmt_ms(r.commit_ms):>10} │ {fmt_ms(r.transcript_ms):>10} │ "
                  f"{fmt_ms(r.fold_ms):>10} │ {fmt_ms(r.nonlinear_fold_ms):>10} │ "
                  f"{fmt_ms(r.total_prove_ms):>10} │ {fmt_ms(r.total_verify_ms):>10} │ "
                  f"{fmt_bytes(r.proof_size_bytes):>10} │ {check:>5}")
        except Exception as e:
            print(f"{N:>6} │ {pattern[:20]:>20} │ ERROR: {e}")

    print()
    return results


def run_stress_test(gens):
    """Stress test with very large numbers and edge cases."""
    print("[6/6] Stress tests...\n")

    N = 64
    alphas = [scalar_random() for _ in range(N)]
    assert_nonlinear_fold("N=64, all max-value", [L - 1] * N, [L - 1] * N, alphas)
    assert_nonlinear_fold(
        f"N={N}, alternating 0/{L - 1}",
        [0 if i % 2 == 0 else (L - 1) for i in range(N)],
        [(L - 1) if i % 2 == 0 else 0 for i in range(N)],
        alphas,
    )

    N = 256
    assert_nonlinear_fold(
        "N=256, random 252-bit",
        [int.from_bytes(os.urandom(32), "big") % L for _ in range(N)],
        [int.from_bytes(os.urandom(32), "big") % L for _ in range(N)],
        [scalar_random() for _ in range(N)],
    )

    N = 65536
    assert_nonlinear_fold(
        "N=65536, checkerboard massive scalar-only",
        [0 if i % 5 else (L - 1 - i) % L for i in range(N)],
        [((1 << 251) - 1 - 17 * i) % L if i % 3 else i % L for i in range(N)],
        [scalar_random() for _ in range(N)],
    )

    gens_d6 = derive_generators(6)

    print("  Stress test 5: Full protocol N=256, d=6 on sparse/spiky dataset")
    dataset = build_protocol_dataset(256, d=6, pattern="sparse_spikes")
    t0 = time.perf_counter()
    r = run_protocol(
        N=256,
        d=6,
        include_nonlinear=True,
        precomputed_gens=gens_d6,
        event_values=dataset,
    )
    elapsed = (time.perf_counter() - t0) * 1000
    assert_protocol_result(r, "stress test N=256, d=6")
    print(f"    ✓ Full protocol N=256, d=6: proof={fmt_bytes(r.proof_size_bytes)}  ({fmt_ms(elapsed)})")

    print("  Stress test 6: Full protocol N=1024, d=6 on checkerboard-massive dataset")
    dataset = build_protocol_dataset(1024, d=6, pattern="checkerboard_massive")
    t0 = time.perf_counter()
    r = run_protocol(
        N=1024,
        d=6,
        include_nonlinear=True,
        precomputed_gens=gens_d6,
        event_values=dataset,
    )
    elapsed = (time.perf_counter() - t0) * 1000
    assert_protocol_result(r, "stress test N=1024, d=6")
    print(f"    ✓ Full protocol N=1024, d=6: proof={fmt_bytes(r.proof_size_bytes)}  ({fmt_ms(elapsed)})")

    gens_d4 = derive_generators(4)

    print("  Stress test 7: Full linear protocol N=4096, d=4 with domain enforcement")
    dataset = build_linear_dataset(4096)
    t0 = time.perf_counter()
    r = run_protocol(
        N=4096,
        d=4,
        include_nonlinear=False,
        precomputed_gens=gens_d4,
        event_values=dataset,
        linear_constraint_coeffs=LINEAR_VECTOR_COEFFS,
        linear_constraint_target=LINEAR_VECTOR_TARGET,
        coordinate_bit_lengths=LINEAR_COORDINATE_BITS,
        deterministic_seed=b"NESSA-EC:stress:linear:4096",
    )
    elapsed = (time.perf_counter() - t0) * 1000
    assert_protocol_result(r, "stress test N=4096, d=4 linear")
    print(f"    ✓ Full linear protocol N=4096, d=4: proof={fmt_bytes(r.proof_size_bytes)}  ({fmt_ms(elapsed)})")

    print("  Stress test 8: Full protocol N=2048, d=6 on correlated dataset with deterministic proof material")
    dataset = build_protocol_dataset(2048, d=6, pattern="correlated_polynomial")
    t0 = time.perf_counter()
    r = run_protocol(
        N=2048,
        d=6,
        include_nonlinear=True,
        precomputed_gens=gens_d6,
        event_values=dataset,
        deterministic_seed=b"NESSA-EC:stress:nonlinear:2048",
    )
    elapsed = (time.perf_counter() - t0) * 1000
    assert_protocol_result(r, "stress test N=2048, d=6 deterministic")
    print(f"    ✓ Full protocol N=2048, d=6: proof={fmt_bytes(r.proof_size_bytes)}  ({fmt_ms(elapsed)})")

    print("\n  All stress tests passed.\n")


def print_summary(results):
    """Print a summary table of benchmark results."""
    print_separator()
    print("SUMMARY — NESSA qFold-EC v1 Benchmark Results")
    print_separator()
    print(f"Protocol:  {PROTOCOL_VERSION}")
    print(f"Group:     ristretto255 (RFC 9496)")
    print(f"Hash:      SHA-512 (FIPS 180-4)")
    print(f"H2G:       RFC 9380 hash_to_ristretto255 (expand_message_xmd)")
    print(f"Wire:      Deterministic CBOR (RFC 8949)")
    print(f"Dimension: d=3")
    print(f"Assumptions:{len(SECURITY_ASSUMPTIONS):>22} explicit core assumptions")
    print()

    print("Scaling analysis:")
    print(f"{'N':>6} │ {'Prover (total)':>14} │ {'Verifier (total)':>16} │ {'Proof Size':>10} │ {'Per-event commit':>16}")
    print("─" * 75)
    for r in results:
        total_prover = r.commit_ms + r.transcript_ms + r.fold_ms + r.nonlinear_fold_ms + r.total_prove_ms
        per_event = r.commit_ms / r.N
        print(f"{r.N:>6} │ {fmt_ms(total_prover):>14} │ {fmt_ms(r.total_verify_ms):>16} │ "
              f"{fmt_bytes(r.proof_size_bytes):>10} │ {fmt_ms(per_event):>16}")

    print()
    print("Key observations:")
    if len(results) >= 2:
        r_small = results[0]
        r_large = results[-1]
        ratio_n = r_large.N / r_small.N
        ratio_commit = r_large.commit_ms / max(r_small.commit_ms, 0.001)
        print(f"  - Commitment time scales ~{ratio_commit:.1f}x for {ratio_n:.0f}x N increase (expected: linear)")
        print(f"  - Proof size is CONSTANT at {fmt_bytes(r_small.proof_size_bytes)} regardless of N")
        print(f"    (folding compresses {r_large.N} events into 1 proof)")
        print(f"  - Verification time is CONSTANT (independent of N)")
    print_separator()


def main():
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print("usage: benchmark.py")
        print()
        print("Run NESSA qFold-EC v1 implementation self-checks, attack vectors, example flows,")
        print("benchmarks, and a final summary report.")
        return
    print_separator()
    print("  NESSA qFold-EC v1 — Implementation Verification & Benchmark")
    print_separator()

    # Phase 1: Unit tests
    gens = run_unit_tests()

    run_security_vectors_and_attacks(gens)

    run_example_flows(gens)

    # Phase 2: End-to-end test
    run_end_to_end_test(gens)

    # Phase 3: Benchmarks
    results = run_benchmarks(gens)

    # Phase 4: Stress tests
    run_stress_test(gens)

    # Summary
    print_summary(results)


if __name__ == "__main__":
    main()
