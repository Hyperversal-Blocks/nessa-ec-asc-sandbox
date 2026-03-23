# NESSA qFold-EC — Core Protocol Formulas

Reference-quality formula sheet for the NESSA qFold-EC v1 proof system. All formulas map directly to `impl/nessa_qfold.py`.

---

## 1. Constants & Groups

| Symbol | Value | Source |
|--------|-------|--------|
| **G** | ristretto255 base point (RFC 9496) | `point_base_mul(scalar_one)` |
| **L** | `2^252 + 27742317777372353535851937790883648493` | `nessa_qfold.py:34` |
| **0̃** | 32-byte all-zeros identity point | `IDENTITY` at `nessa_qfold.py:89` |
| **H2G** | `hash_to_ristretto255` via `expand_message_xmd(SHA-512)` per RFC 9380 | `h2g()` at `nessa_qfold.py:304` |
| **H2S** | `hash_to_field` over F_L via `expand_message_xmd(SHA-512)` | `h2s()` at `nessa_qfold.py:311` |
| **EncCBOR** | Deterministic CBOR encoding (RFC 8949, canonical map key order) | `cbor_encode()` at `nessa_qfold.py:366` |

---

## 2. Generator Derivation

For dimension **d**, four generator families are derived via hash-to-group:

```
Br_j = H2G(DST_BASE_BR, EncCBOR(["base", "Br", j, PROTOCOL_VERSION]))    for j ∈ [0, d)
Bm_j = H2G(DST_BASE_BM, EncCBOR(["base", "Bm", j, PROTOCOL_VERSION]))    for j ∈ [0, d)
G_pol = H2G(DST_BASE_GPOL, EncCBOR(["base", "Gpol", 0, PROTOCOL_VERSION]))
H_pol = H2G(DST_BASE_HPOL, EncCBOR(["base", "Hpol", 0, PROTOCOL_VERSION]))
```

**Uniqueness constraint:** All `2d + 2` generators must be distinct and non-identity.

- **Source:** `derive_generators()` at `nessa_qfold.py:571-597`

---

## 3. Commitment Profile V2

Each event row `m⃗_i = (m_{i,0}, ..., m_{i,d-1})` is committed with blinding `ρ⃗_i`:

```
C_i = Com_V2(m⃗_i; ρ⃗_i) = Σ_{j=0}^{d-1} (ρ_{i,j} · Br_j + m_{i,j} · Bm_j)
```

- **Source:** `commit_v2()` at `nessa_qfold.py:636-652`
- **Property:** Additively homomorphic — `Com(a⃗; r⃗) + Com(b⃗; s⃗) = Com(a⃗+b⃗; r⃗+s⃗)`

---

## 4. Transcript Root Chain

Binding tags and commitments into a deterministic hash chain:

```
tags = {
  0: protocol_version_number,
  1: protocol_version,
  2: rfc9380_h2g_id,
  3: encoding_id,
  4: encoding_hash,
  5: d,
  6: policy_id,
  7: policy_hash,
  8: k_rows,
  9: transcript_seed?   // optional
}
tags_hash = SHA-512(EncCBOR(tags))
R_0 = SHA-512(EncCBOR(["NESSA-EC:v1:R0", tags_hash]))
R_i = SHA-512(EncCBOR(["NESSA-EC:v1:Ri", i, R_{i-1}, C_i]))    for i ∈ [1, N]
```

- **Source:** `build_transcript()` at `nessa_qfold.py:776-793`

---

## 5. Fold Weights (Fiat-Shamir Challenges)

Derived from the final transcript root `R_N`:

```
α_i = H2S(DST_ALPHA, EncCBOR(["alpha", R_N, i]))    for i ∈ [1, N]
```

- **Source:** `compute_alpha()` at `nessa_qfold.py:762`

---

## 6. Commitment Folding

Aggregate N commitments into one:

```
C★ = Σ_{i=1}^{N} α_i · C_i
```

Folded witness and blinding:

```
m★_j = Σ_{i=1}^{N} α_i · m_{i,j}    (mod L)    for each coordinate j
ρ★_j = Σ_{i=1}^{N} α_i · ρ_{i,j}    (mod L)    for each coordinate j
```

**Consistency check:** `C★ = Com_V2(m★; ρ★)` must hold.

- **Source:** `fold_commitments()` at `nessa_qfold.py:796`, `fold_witnesses()` at `nessa_qfold.py:809`

---

## 7. Policy Commitments

For each folded coordinate, commit under the policy generators:

```
V_j = γ_j · G_pol + m★_j · H_pol    for j ∈ [0, d)
```

where `γ_j` are fresh blinding scalars.

- **Source:** `policy_commit()` at `nessa_qfold.py:656`

---

## 8. Proof Context

Binds the proof to application semantics:

```
proof_context = EncCBOR(["proof_context", tags_hash, R_N, N, d, context_label])
```

- **Source:** `build_proof_context()` at `nessa_qfold.py:524`

---

## 9. π_link — Linkage Proof (Multi-relation Schnorr NIZK)

**Statement:** Prover knows `(m★, ρ★, γ⃗)` such that:

```
C★ = Com_V2(m★; ρ★)
V_j = γ_j · G_pol + m★_j · H_pol    ∀j
```

**Protocol:**

```
1. Nonces:    k_m_j, k_ρ_j, k_γ_j sampled uniformly from F_L
2. T_commit = Com_V2(k_m; k_ρ)
3. T_j = k_γ_j · G_pol + k_m_j · H_pol
4. c = H2S(DST_LINK, EncCBOR(["link", tags_hash, R_N, C★, V_list, T_commit, T_policy]))
5. z_m_j = k_m_j + c · m★_j
   z_ρ_j = k_ρ_j + c · ρ★_j
   z_γ_j = k_γ_j + c · γ_j
```

**Verification checks:**

```
c' = H2S(DST_LINK, EncCBOR(["link", tags_hash, R_N, C★, V_list, T_commit, T_policy]))
Com_V2(z_m; z_ρ) == T_commit + c · C★
z_γ_j · G_pol + z_m_j · H_pol == T_j + c · V_j    ∀j
```

- **Prove:** `prove_link()` at `nessa_qfold.py:1015-1063`
- **Verify:** `verify_link()` at `nessa_qfold.py:1066-1099`
- **Proof size:** `d` points + `3d` scalars + 1 scalar (challenge)

---

## 10. π_cons_linear — Linear Constraint Proof

**Statement:** Prover knows `γ_res` such that:

```
Σ_{j=0}^{d-1} a_j · m★_j = t    (mod L)
W = γ_res · G_pol    (since the H_pol coefficient is 0 when the constraint holds)
```

**Protocol:**

```
1. k sampled uniformly from F_L
2. T = k · G_pol
3. c = H2S(DST_CONS, EncCBOR(["cons", tags_hash, R_N, policy_hash, W, T]))
4. z = k + c · γ_res
```

**Verification:**

```
z · G_pol == T + c · W
```

where `W = Σ a_j · V_j − t · H_pol`.

- **Prove:** `prove_cons_linear()` at `nessa_qfold.py:1114-1141`
- **Verify:** `verify_cons_linear()` at `nessa_qfold.py:1144-1152`
- **Proof size:** 1 point + 2 scalars

---

## 11. π_cons_nonlinear — Multiplicative Constraint Proof

**Statement:** Given committed values `(L★, R★, O★)` in `V_L, V_R, V_O`, prove:

```
L★ · R★ = O★ + E★    (mod L)
```

where `E★` is the nonlinear folding cross-term error accumulated by recurrence:

```
Initialize with row 0 and weight w_0 = alpha_0:
L_acc = w_0 * L_0
R_acc = w_0 * R_0
O_acc = w_0 * O_0
E_acc = (w_0^2 - w_0) * O_0

For each i = 1..N-1 with weight w_i = alpha_i:
T_i = L_acc * R_i + L_i * R_acc
E_acc = E_acc + w_i * T_i + (w_i^2 - w_i) * O_i
L_acc = L_acc + w_i * L_i
R_acc = R_acc + w_i * R_i
O_acc = O_acc + w_i * O_i
```

All operations are modulo `L`, and `E★ = E_acc` at termination. Also `C_E = r_E · G_pol + E★ · H_pol`.

**Protocol:**

```
1. Nonces: k_L, k_R, k_O, k_E, k_γ_L, k_γ_R, k_γ_O, k_rE, k_base, k_cross
2. T_L = k_γ_L · G_pol + k_L · H_pol
   T_R = k_γ_R · G_pol + k_R · H_pol
   T_O = k_γ_O · G_pol + k_O · H_pol
   T_E = k_rE  · G_pol + k_E · H_pol
   T_mul_base  = k_base  · G_pol + (k_L · k_R) · H_pol
   T_mul_cross = k_cross · G_pol + (k_L · R★ + k_R · L★) · H_pol
3. c = Schnorr_FS([T_L, T_R, T_O, T_E, T_base, T_cross], [V_L, V_R, V_O, C_E])
4. Responses: z_L = k_L + c·L★, z_R = k_R + c·R★, z_O, z_E, z_γ_L, z_γ_R, z_γ_O, z_rE
   z_mul_blind = k_base + c·k_cross + c²·(γ_O + r_E)
```

**Verification:**

```
Recompute c from [T_list, P_list]
z_γ_j · G_pol + z_j · H_pol == T_j + c · V_j    for j ∈ {L, R, O}
z_rE · G_pol + z_E · H_pol == T_E + c · C_E
z_mul_blind · G_pol + (z_L · z_R) · H_pol == T_base + c · T_cross + c² · (V_O + C_E)
```

- **Prove:** `prove_cons_nonlinear()` at `nessa_qfold.py:1177-1272`
- **Verify:** `verify_cons_nonlinear()` at `nessa_qfold.py:1275-1314`
- **Proof size:** 7 points + 9 scalars + 1 scalar (challenge)

---

## 12. Complete Proof Object

```
π = (π_link, π_cons)

π_link = (T_commit, T_policy[], z_m[], z_ρ[], z_γ[], c)
π_cons_linear = (T, z, c)                                   — OR —
π_cons_nonlinear = (C_E, T_L, T_R, T_O, T_E, T_base, T_cross,
                    z_L, z_R, z_O, z_E, z_γ_L, z_γ_R, z_γ_O, z_rE, z_mul_blind, c)
```

**Proof size (linear, d=9):** `9·32 + 3·9·32 + 32 + 32 + 2·32 = 1632 bytes`

- **Source:** `NessaProof.byte_size()` at `nessa_qfold.py:1334-1352`

---

## 13. Security Assumptions

| Assumption | Description |
|------------|-------------|
| **DL** | Discrete logarithm in ristretto255 is hard |
| **Generator independence** | All `2d+2` generators are independently derived; no known DL relations |
| **Random oracle** | SHA-512 and H2G/H2S behave as random oracles for Fiat-Shamir |
| **CBOR canonicality** | Deterministic encoding ensures unique transcript binding |

- **Source:** `SECURITY_ASSUMPTIONS` at `nessa_qfold.py:48-67`
