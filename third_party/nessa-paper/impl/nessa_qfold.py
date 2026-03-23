"""
NESSA qFold-EC v1 — Full Implementation
========================================
Prime-order group:  ristretto255 (RFC 9496)
Hash:               SHA-512 (FIPS 180-4)
Hash-to-group:      RFC 9380 hash_to_ristretto255 via expand_message_xmd(SHA-512)
Hash-to-scalar:     RFC 9380 hash_to_field over F_l via expand_message_xmd(SHA-512)
Wire format:        Deterministic CBOR (RFC 8949)
Proof system:       π = (π_link, π_cons) — multi-relation Schnorr NIZKs
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

try:
    import cbor2
except ImportError:
    cbor2 = None

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

# ristretto255 scalar field order
L = 2**252 + 27742317777372353535851937790883648493

H2S_UNIFORM_BYTES = (L.bit_length() + 128 + 7) // 8

SCALAR_BYTES = 32
POINT_BYTES = 32
HASH_BYTES = 64  # SHA-512 output

# RFC 9380 / 9496 DST for hash_to_ristretto255
H2G_SUITE_ID = b"ristretto255_XMD:SHA-512_R255MAP_RO_"

# Protocol version tag
PROTOCOL_VERSION = "NESSA-EC-RISTRETTO255-SHA512-v1"

SECURITY_ASSUMPTIONS = (
    (
        "discrete_log_and_generator_independence",
        "Pedersen commitments and Schnorr-style proofs rely on discrete-log hardness in ristretto255 and independence of the derived generators.",
    ),
    (
        "fiat_shamir_random_oracle",
        "Non-interactive soundness relies on Fiat-Shamir challenges derived by H2S behaving as a random oracle over the transcript context.",
    ),
    (
        "sha512_hash_security",
        "Transcript binding, tag binding, and deterministic challenge derivation rely on SHA-512 collision and preimage resistance.",
    ),
    (
        "deterministic_cbor_integrity",
        "Prover and verifier must hash the same canonical CBOR encodings for transcript integrity and malleability resistance.",
    ),
    (
        "fresh_prover_randomness",
        "Live proving requires fresh unpredictable prover randomness; deterministic seeds are for fixed vectors and testing only.",
    ),
    (
        "application_domain_validation",
        "Application-specific coordinate domains must be validated before scalar-field reduction to prevent wraparound and overflow attacks.",
    ),
)

DETERMINISTIC_VECTOR_DST = b"NESSA-EC:v1:deterministic"

RFC9380_H2G_ID = "ristretto255_XMD:SHA-512_R255MAP_RO_"
PROTOCOL_VERSION_NUMBER = 1

DST_BASE_BR = b"NESSA-EC:v1:base:Br"
DST_BASE_BM = b"NESSA-EC:v1:base:Bm"
DST_BASE_GPOL = b"NESSA-EC:v1:base:Gpol"
DST_BASE_HPOL = b"NESSA-EC:v1:base:Hpol"
DST_ALPHA = b"NESSA-EC:v1:alpha"
DST_LINK = b"NESSA-EC:v1:link"
DST_BETA = b"NESSA-EC:v1:beta"
DST_CONS = b"NESSA-EC:v1:cons"

# Identity point (all zeros for ristretto255)
IDENTITY = b'\x00' * POINT_BYTES


# ──────────────────────────────────────────────────────────────
# Low-level scalar / point helpers (libsodium-backed)
# ──────────────────────────────────────────────────────────────
class _Ristretto255Backend:
    def __init__(self):
        path = _find_sodium_library()
        if not path:
            raise RuntimeError("libsodium not found")
        self.lib = ctypes.cdll.LoadLibrary(path)
        if self.lib.sodium_init() < 0:
            raise RuntimeError("libsodium initialization failed")

    @staticmethod
    def _buf(data: bytes):
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    @staticmethod
    def _out(size: int):
        return (ctypes.c_ubyte * size)()

    def from_hash(self, h: bytes) -> bytes:
        out = self._out(POINT_BYTES)
        rc = self.lib.crypto_core_ristretto255_from_hash(out, self._buf(h))
        if rc != 0:
            raise RuntimeError("crypto_core_ristretto255_from_hash failed")
        return bytes(out)

    def add(self, a: bytes, b: bytes) -> bytes:
        out = self._out(POINT_BYTES)
        rc = self.lib.crypto_core_ristretto255_add(out, self._buf(a), self._buf(b))
        if rc != 0:
            raise RuntimeError("crypto_core_ristretto255_add failed")
        return bytes(out)

    def sub(self, a: bytes, b: bytes) -> bytes:
        out = self._out(POINT_BYTES)
        rc = self.lib.crypto_core_ristretto255_sub(out, self._buf(a), self._buf(b))
        if rc != 0:
            raise RuntimeError("crypto_core_ristretto255_sub failed")
        return bytes(out)

    def mul(self, s: bytes, p: bytes) -> bytes:
        out = self._out(POINT_BYTES)
        rc = self.lib.crypto_scalarmult_ristretto255(out, self._buf(s), self._buf(p))
        if rc != 0:
            raise RuntimeError("crypto_scalarmult_ristretto255 failed")
        return bytes(out)

    def base_mul(self, s: bytes) -> bytes:
        out = self._out(POINT_BYTES)
        rc = self.lib.crypto_scalarmult_ristretto255_base(out, self._buf(s))
        if rc != 0:
            raise RuntimeError("crypto_scalarmult_ristretto255_base failed")
        return bytes(out)

def _find_sodium_library() -> str | None:
    """Locate a libsodium shared library without requiring it at import time."""
    candidates = [
        ctypes.util.find_library("sodium"),
        "libsodium.so",
        "libsodium.so.23",
        "libsodium.dylib",
        "libsodium.dll",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            ctypes.cdll.LoadLibrary(candidate)
        except OSError:
            continue
        return candidate
    return None


_RISTRETTO: _Ristretto255Backend | None = None


def _get_ristretto_backend() -> _Ristretto255Backend:
    """Initialize libsodium lazily so CLI help and imports work without it."""
    global _RISTRETTO
    if _RISTRETTO is None:
        try:
            _RISTRETTO = _Ristretto255Backend()
        except RuntimeError as exc:
            raise RuntimeError(
                "Ristretto operations require libsodium. Install libsodium and retry the proving or "
                "verification command."
            ) from exc
    return _RISTRETTO


def scalar_random() -> bytes:
    """Return a uniformly random scalar in [0, L)."""
    return scalar_from_int(secrets.randbelow(L))


def scalar_from_int(n: int) -> bytes:
    """Convert a Python int (mod L) to a 32-byte LE scalar."""
    return (n % L).to_bytes(SCALAR_BYTES, "little")


def scalar_to_int(s: bytes) -> int:
    """Convert a 32-byte LE scalar to a Python int modulo L."""
    if len(s) != SCALAR_BYTES:
        raise ValueError("invalid scalar length")
    return int.from_bytes(s, "little") % L


def scalar_add(a: bytes, b: bytes) -> bytes:
    return scalar_from_int(scalar_to_int(a) + scalar_to_int(b))


def scalar_sub(a: bytes, b: bytes) -> bytes:
    return scalar_from_int(scalar_to_int(a) - scalar_to_int(b))


def scalar_mul(a: bytes, b: bytes) -> bytes:
    """Multiply two scalars mod L."""
    return scalar_from_int(scalar_to_int(a) * scalar_to_int(b))


def scalar_neg(a: bytes) -> bytes:
    return scalar_from_int(-scalar_to_int(a))


def scalar_invert(a: bytes) -> bytes:
    ai = scalar_to_int(a)
    if ai == 0:
        raise ZeroDivisionError("cannot invert zero scalar")
    return scalar_from_int(pow(ai, -1, L))


SCALAR_ZERO = scalar_from_int(0)
SCALAR_ONE = scalar_from_int(1)


def point_base_mul(s: bytes) -> bytes:
    """s * G (base-point multiplication)."""
    if scalar_to_int(s) == 0:
        return IDENTITY
    return _get_ristretto_backend().base_mul(s)


def point_mul(s: bytes, p: bytes) -> bytes:
    """s * P (variable-base scalar multiplication)."""
    if scalar_to_int(s) == 0 or point_is_identity(p):
        return IDENTITY
    return _get_ristretto_backend().mul(s, p)


def point_add(a: bytes, b: bytes) -> bytes:
    if point_is_identity(a):
        return b
    if point_is_identity(b):
        return a
    return _get_ristretto_backend().add(a, b)


def point_sub(a: bytes, b: bytes) -> bytes:
    if point_is_identity(b):
        return a
    return _get_ristretto_backend().sub(a, b)


def point_is_identity(p: bytes) -> bool:
    return p == IDENTITY


def point_from_hash(h: bytes) -> bytes:
    """Map a 64-byte hash to a ristretto255 point (RFC 9496 element derivation)."""
    if len(h) != 64:
        raise ValueError("point_from_hash expects 64 uniform bytes")
    return _get_ristretto_backend().from_hash(h)


# ──────────────────────────────────────────────────────────────
# RFC 9380  expand_message_xmd  (SHA-512)
# ──────────────────────────────────────────────────────────────

def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380 §5.3.1 expand_message_xmd with SHA-512."""
    b_in_bytes = 64  # SHA-512 output
    r_in_bytes = 128  # SHA-512 block size
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("requested output too long")
    if len(dst) > 255:
        raise ValueError("DST too long")

    dst_prime = dst + bytes([len(dst)])
    z_pad = b'\x00' * r_in_bytes
    l_i_b_str = struct.pack(">H", len_in_bytes)
    msg_prime = z_pad + msg + l_i_b_str + b'\x00' + dst_prime

    b_0 = hashlib.sha512(msg_prime).digest()
    b_vals = [None]  # b_vals[0] unused
    b_vals.append(hashlib.sha512(b_0 + b'\x01' + dst_prime).digest())

    for i in range(2, ell + 1):
        xored = bytes(x ^ y for x, y in zip(b_0, b_vals[i - 1]))
        b_vals.append(hashlib.sha512(xored + bytes([i]) + dst_prime).digest())

    uniform = b''.join(b_vals[1:])
    return uniform[:len_in_bytes]


# ──────────────────────────────────────────────────────────────
# H2G (hash-to-group) and H2S (hash-to-scalar)
# ──────────────────────────────────────────────────────────────

def h2g(dst: bytes, msg: bytes) -> bytes:
    """Hash to ristretto255 point via RFC 9380 hash_to_ristretto255."""
    # RFC 9496 requires 64 uniform bytes → ristretto255 map
    uniform = expand_message_xmd(msg, dst, 64)
    return point_from_hash(uniform)


def h2s(dst: bytes, msg: bytes) -> bytes:
    """Hash to scalar in F_l via RFC 9380 hash_to_field."""
    uniform = expand_message_xmd(msg, dst, H2S_UNIFORM_BYTES)
    n = int.from_bytes(uniform, "big") % L
    return scalar_from_int(n)


# ──────────────────────────────────────────────────────────────
# Deterministic CBOR helpers
# ──────────────────────────────────────────────────────────────

def _cbor_head(major: int, arg: int) -> bytes:
    prefix = major << 5
    if arg < 24:
        return bytes([prefix | arg])
    if arg < 2**8:
        return bytes([prefix | 24, arg])
    if arg < 2**16:
        return bytes([prefix | 25]) + arg.to_bytes(2, "big")
    if arg < 2**32:
        return bytes([prefix | 26]) + arg.to_bytes(4, "big")
    if arg < 2**64:
        return bytes([prefix | 27]) + arg.to_bytes(8, "big")
    raise ValueError("CBOR integer too large")


def _cbor_encode_fallback(obj) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, int):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        data = obj.encode("utf-8")
        return _cbor_head(3, len(data)) + data
    if isinstance(obj, (list, tuple)):
        out = _cbor_head(4, len(obj))
        for item in obj:
            out += _cbor_encode_fallback(item)
        return out
    if isinstance(obj, dict):
        items = [(_cbor_encode_fallback(k), _cbor_encode_fallback(v)) for k, v in obj.items()]
        items.sort(key=lambda item: item[0])
        out = _cbor_head(5, len(items))
        for key, value in items:
            out += key + value
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


def cbor_encode(obj) -> bytes:
    """Deterministic CBOR encoding (canonical=True for sorted map keys)."""
    if cbor2 is not None:
        return cbor2.dumps(obj, canonical=True)
    return _cbor_encode_fallback(obj)


def cbor_decode(data: bytes):
    if cbor2 is not None:
        return cbor2.loads(data)
    value, offset = _cbor_decode_fallback(data, 0)
    if offset != len(data):
        raise ValueError("trailing CBOR data")
    return value


def _cbor_decode_fallback(data: bytes, offset: int = 0):
    if offset >= len(data):
        raise ValueError("unexpected end of CBOR data")
    initial = data[offset]
    offset += 1
    major = initial >> 5
    ai = initial & 0x1F

    def read_length(addl: int, cursor: int) -> tuple[int, int]:
        if addl < 24:
            return addl, cursor
        if addl == 24:
            if cursor + 1 > len(data):
                raise ValueError("unexpected end of CBOR data")
            return data[cursor], cursor + 1
        if addl == 25:
            if cursor + 2 > len(data):
                raise ValueError("unexpected end of CBOR data")
            return int.from_bytes(data[cursor:cursor + 2], "big"), cursor + 2
        if addl == 26:
            if cursor + 4 > len(data):
                raise ValueError("unexpected end of CBOR data")
            return int.from_bytes(data[cursor:cursor + 4], "big"), cursor + 4
        if addl == 27:
            if cursor + 8 > len(data):
                raise ValueError("unexpected end of CBOR data")
            return int.from_bytes(data[cursor:cursor + 8], "big"), cursor + 8
        raise ValueError("indefinite-length CBOR is not supported")

    if major in (0, 1):
        value, offset = read_length(ai, offset)
        return (value if major == 0 else -1 - value), offset

    if major in (2, 3):
        length, offset = read_length(ai, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("unexpected end of CBOR data")
        raw = data[offset:end]
        return (raw if major == 2 else raw.decode("utf-8")), end

    if major == 4:
        length, offset = read_length(ai, offset)
        items = []
        for _ in range(length):
            item, offset = _cbor_decode_fallback(data, offset)
            items.append(item)
        return items, offset

    if major == 5:
        length, offset = read_length(ai, offset)
        items = {}
        for _ in range(length):
            key, offset = _cbor_decode_fallback(data, offset)
            value, offset = _cbor_decode_fallback(data, offset)
            items[key] = value
        return items, offset

    if major == 7:
        if ai == 20:
            return False, offset
        if ai == 21:
            return True, offset
        if ai == 22:
            return None, offset
    raise ValueError(f"unsupported CBOR major type/additional info: major={major}, ai={ai}")


def normalize_context_binding(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("proof context label must be bytes, str, or None")


def canonical_scalar_bytes(value: int) -> bytes:
    value_mod = value % L
    if value_mod >= L:
        raise ValueError("scalar must be in canonical range")
    return value_mod.to_bytes(SCALAR_BYTES, "little")


def compile_linear_policy(d: int, coeff_rows: list[list[int]], target_rows: list[int]) -> bytes:
    if len(coeff_rows) == 0:
        raise ValueError("at least one policy row is required")
    if len(coeff_rows) != len(target_rows):
        raise ValueError("policy row count mismatch")
    for row in coeff_rows:
        if len(row) != d:
            raise ValueError("policy row width does not match d")
    policy_compiled = {
        0: 1,
        1: d,
        2: len(coeff_rows),
        3: [[canonical_scalar_bytes(entry) for entry in row] for row in coeff_rows],
        4: [canonical_scalar_bytes(target) for target in target_rows],
    }
    return cbor_encode(policy_compiled)


def build_tags(
    *,
    encoding_id: str,
    policy_id: str,
    d: int,
    policy_hash: bytes,
    k_rows: int,
    encoding_hash: bytes | None = None,
    transcript_seed: bytes | None = None,
) -> dict[int, object]:
    if not encoding_id:
        raise ValueError("encoding_id must be non-empty")
    if not policy_id:
        raise ValueError("policy_id must be non-empty")
    if len(policy_hash) != HASH_BYTES:
        raise ValueError("policy_hash must be 64 bytes")
    if encoding_hash is None:
        encoding_hash = hashlib.sha512(cbor_encode(["encoding_schema", encoding_id, d])).digest()
    if len(encoding_hash) != HASH_BYTES:
        raise ValueError("encoding_hash must be 64 bytes")
    if transcript_seed is not None and len(transcript_seed) != HASH_BYTES:
        raise ValueError("transcript_seed must be 64 bytes when present")

    tags: dict[int, object] = {
        0: PROTOCOL_VERSION_NUMBER,
        1: PROTOCOL_VERSION,
        2: RFC9380_H2G_ID,
        3: encoding_id,
        4: encoding_hash,
        5: d,
        6: policy_id,
        7: policy_hash,
        8: k_rows,
    }
    if transcript_seed is not None:
        tags[9] = transcript_seed
    return tags


def build_proof_context(tags_hash: bytes, final_root: bytes,
                        N: int, d: int,
                        proof_context_label: bytes | str | None = None) -> bytes:
    return cbor_encode([
        "proof_context",
        tags_hash,
        final_root,
        N,
        d,
        normalize_context_binding(proof_context_label),
    ])


class DeterministicScalarOracle:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) == 0:
            raise ValueError("deterministic seed must be non-empty bytes")
        self.seed = bytes(seed)
        self.counter = 0

    def scalar(self, label: str, *parts) -> bytes:
        self.counter += 1
        msg = cbor_encode(["det_scalar", self.seed, self.counter, label, *parts])
        return h2s(DETERMINISTIC_VECTOR_DST, msg)


# ──────────────────────────────────────────────────────────────
# Generator derivation (§ Commitments)
# ──────────────────────────────────────────────────────────────

def derive_generator(family_dst: bytes, label: str, index: int,
                     existing: set[bytes] | None = None) -> bytes:
    """
    Derive a ristretto255 generator deterministically.
    Retries with incrementing counter if identity or duplicate.
    """
    if existing is None:
        existing = set()
    counter = 0
    while True:
        msg = cbor_encode(["base", label, index, PROTOCOL_VERSION] if counter == 0 else ["base", label, index, PROTOCOL_VERSION, counter])
        pt = h2g(family_dst, msg)
        if not point_is_identity(pt) and pt not in existing:
            return pt
        counter += 1


def derive_generators(d: int) -> dict:
    """
    Derive full generator set for message dimension d.
    Returns dict with keys: Br (list[d]), Bm (list[d]), G_pol, H_pol.
    """
    existing: set[bytes] = set()
    Br = []
    Bm = []

    for j in range(d):
        pt = derive_generator(DST_BASE_BR, "Br", j + 1, existing)
        Br.append(pt)
        existing.add(pt)

    for j in range(d):
        pt = derive_generator(DST_BASE_BM, "Bm", j + 1, existing)
        Bm.append(pt)
        existing.add(pt)

    # Policy generators
    msg_gpol = cbor_encode(["base", "Gpol", 0, PROTOCOL_VERSION])
    G_pol = h2g(DST_BASE_GPOL, msg_gpol)
    while point_is_identity(G_pol) or G_pol in existing:
        msg_gpol = cbor_encode(["base", "Gpol", 0, PROTOCOL_VERSION, len(existing)])
        G_pol = h2g(DST_BASE_GPOL, msg_gpol)
    existing.add(G_pol)

    msg_hpol = cbor_encode(["base", "Hpol", 0, PROTOCOL_VERSION])
    H_pol = h2g(DST_BASE_HPOL, msg_hpol)
    while point_is_identity(H_pol) or H_pol in existing:
        msg_hpol = cbor_encode(["base", "Hpol", 0, PROTOCOL_VERSION, len(existing)])
        H_pol = h2g(DST_BASE_HPOL, msg_hpol)
    existing.add(H_pol)

    gens = {"Br": Br, "Bm": Bm, "G_pol": G_pol, "H_pol": H_pol}
    validate_generator_set(gens, d)
    return gens


def validate_generator_set(gens: dict, d: int) -> None:
    missing = [key for key in ("Br", "Bm", "G_pol", "H_pol") if key not in gens]
    if missing:
        raise ValueError(f"missing generator entries: {missing}")

    Br = gens["Br"]
    Bm = gens["Bm"]
    if len(Br) != d or len(Bm) != d:
        raise ValueError("generator vector lengths do not match d")

    seen: set[bytes] = set()
    for point in [*Br, *Bm, gens["G_pol"], gens["H_pol"]]:
        point_bytes = bytes(point)
        if len(point_bytes) != POINT_BYTES:
            raise ValueError("invalid generator point length")
        if point_is_identity(point_bytes):
            raise ValueError("generator set contains identity point")
        if point_bytes in seen:
            raise ValueError("generator set contains duplicate points")
        seen.add(point_bytes)


# ──────────────────────────────────────────────────────────────
# V2 Commitment scheme
# ──────────────────────────────────────────────────────────────

def commit_v2(m_vec: list[bytes], rho_vec: list[bytes],
              Br: list[bytes], Bm: list[bytes]) -> bytes:
    """
    Com_V2(m; ρ) = Σ_{j} ρ_j·B^r_j + m_j·B^m_j
    """
    d = len(m_vec)
    if d == 0:
        raise ValueError("empty commitment vectors are not supported")
    if len(rho_vec) != d or len(Br) != d or len(Bm) != d:
        raise ValueError("commit_v2 input lengths do not match")

    # Start with identity
    result = point_mul(rho_vec[0], Br[0])
    result = point_add(result, point_mul(m_vec[0], Bm[0]))

    for j in range(1, d):
        term_r = point_mul(rho_vec[j], Br[j])
        term_m = point_mul(m_vec[j], Bm[j])
        result = point_add(result, term_r)
        result = point_add(result, term_m)

    return result


# ──────────────────────────────────────────────────────────────
# Event encoding
# ──────────────────────────────────────────────────────────────

@dataclass
class Event:
    """A single execution event with d field values."""
    values: list[int]  # each in domain before mod-l reduction

    def encode(self) -> list[bytes]:
        """Encode event values to scalar field elements."""
        return [scalar_from_int(v) for v in self.values]


def normalize_event_values(values: list[int], d: int,
                           include_nonlinear: bool,
                           coordinate_bit_lengths: list[int] | None = None) -> list[int]:
    """Normalize and validate event coordinates for the protocol."""
    if len(values) != d:
        raise ValueError(f"expected {d} event coordinates, got {len(values)}")

    if coordinate_bit_lengths is not None and len(coordinate_bit_lengths) != d:
        raise ValueError(f"expected {d} coordinate bit lengths, got {len(coordinate_bit_lengths)}")

    for idx, value in enumerate(values):
        if value < 0:
            raise ValueError(f"event coordinate {idx} must be non-negative")
        if coordinate_bit_lengths is not None:
            bit_length = coordinate_bit_lengths[idx]
            if bit_length < 0:
                raise ValueError("coordinate bit lengths must be non-negative")
            if value >= (1 << bit_length):
                raise ValueError(
                    f"event coordinate {idx} exceeds configured {bit_length}-bit domain"
                )

    normalized = [v % L for v in values]
    if include_nonlinear:
        if d < 3:
            raise ValueError("non-linear mode requires d >= 3")
        expected_output = (normalized[0] * normalized[1]) % L
        if normalized[2] != expected_output:
            raise ValueError(
                "event coordinate 2 must equal coordinate 0 * coordinate 1 mod L"
            )
    return normalized


def random_event_values(d: int, include_nonlinear: bool) -> list[int]:
    """Generate a random protocol event with a valid multiplication witness."""
    if include_nonlinear:
        if d < 3:
            raise ValueError("non-linear mode requires d >= 3")
        lhs = int.from_bytes(os.urandom(32), "big") % L
        rhs = int.from_bytes(os.urandom(32), "big") % L
        values = [lhs, rhs, (lhs * rhs) % L]
        values.extend(int.from_bytes(os.urandom(32), "big") % L for _ in range(d - 3))
        return values
    return [int.from_bytes(os.urandom(32), "big") % L for _ in range(d)]


# ──────────────────────────────────────────────────────────────
# Transcript binding & Fiat–Shamir challenges
# ──────────────────────────────────────────────────────────────

@dataclass
class TranscriptState:
    tags: dict[int, object] = field(default_factory=dict)
    tags_hash: bytes = b''
    roots: list[bytes] = field(default_factory=list)
    alphas: list[bytes] = field(default_factory=list)


def compute_tags_hash(
    *,
    encoding_id: str = "default",
    policy_id: str = "default",
    d: int = 3,
    policy_hash: bytes | None = None,
    k_rows: int = 1,
    encoding_hash: bytes | None = None,
    transcript_seed: bytes | None = None,
) -> bytes:
    """Compute tags_hash = SHA-512(EncCBOR(tags))."""
    if policy_hash is None:
        policy_hash = hashlib.sha512(compile_linear_policy(d, [[1] * d], [0])).digest()
    tags = build_tags(
        encoding_id=encoding_id,
        policy_id=policy_id,
        d=d,
        policy_hash=policy_hash,
        k_rows=k_rows,
        encoding_hash=encoding_hash,
        transcript_seed=transcript_seed,
    )
    return hashlib.sha512(cbor_encode(tags)).digest()


def compute_transcript_root_0(tags_hash: bytes) -> bytes:
    """R_0 = SHA-512(EncCBOR(["NESSA-EC:v1:R0", tags_hash]))."""
    return hashlib.sha512(cbor_encode(["NESSA-EC:v1:R0", tags_hash])).digest()


def compute_transcript_root_i(i: int, r_prev: bytes, c_i: bytes) -> bytes:
    """R_i = SHA-512(EncCBOR(["NESSA-EC:v1:Ri", i, R_{i-1}, Enc(C_i)]))"""
    return hashlib.sha512(
        cbor_encode(["NESSA-EC:v1:Ri", i, r_prev, c_i])
    ).digest()


def compute_alpha(final_root: bytes, i: int) -> bytes:
    """α_i = H2S(DST_ALPHA, EncCBOR(["alpha", R, i]))."""
    msg = cbor_encode(["alpha", final_root, i])
    return h2s(DST_ALPHA, msg)


def build_transcript(tags: dict[int, object], commitments: list[bytes]) -> TranscriptState:
    """Build full transcript chain and derive all α_i challenges."""
    ts = TranscriptState(tags=dict(tags), tags_hash=hashlib.sha512(cbor_encode(tags)).digest())
    r_0 = compute_transcript_root_0(ts.tags_hash)
    ts.roots.append(r_0)

    for i in range(1, len(commitments) + 1):
        r_i = compute_transcript_root_i(i, ts.roots[-1], commitments[i - 1])
        ts.roots.append(r_i)
    final_root = ts.roots[-1]
    for i in range(1, len(commitments) + 1):
        ts.alphas.append(compute_alpha(final_root, i))

    return ts


# ──────────────────────────────────────────────────────────────
# Folding — Linear combination of events
# ──────────────────────────────────────────────────────────────

def fold_commitments(commitments: list[bytes], alphas: list[bytes]) -> bytes:
    """C⋆ = Σ_i α_i·C_i."""
    if len(commitments) == 0:
        raise ValueError("expected at least one commitment")
    if len(alphas) != len(commitments):
        raise ValueError("fold_commitments requires one challenge per commitment")
    c_star = IDENTITY
    for alpha_i, commitment in zip(alphas, commitments):
        c_star = point_add(c_star, point_mul(alpha_i, commitment))
    return c_star


def fold_witnesses(witnesses: list[list[bytes]], alphas: list[bytes]) -> list[bytes]:
    """
    m⋆_j = Σ_i α_i · m_{i,j}
    Returns folded witness vector.
    """
    if len(witnesses) == 0:
        raise ValueError("expected at least one witness vector")
    if len(alphas) != len(witnesses):
        raise ValueError("fold_witnesses requires one challenge per witness vector")
    d = len(witnesses[0])
    if d == 0:
        raise ValueError("empty witness vectors are not supported")
    for witness in witnesses:
        if len(witness) != d:
            raise ValueError("witness vector lengths do not match")
    m_star = [SCALAR_ZERO for _ in range(d)]
    for i in range(len(witnesses)):
        for j in range(d):
            m_star[j] = scalar_add(m_star[j], scalar_mul(alphas[i], witnesses[i][j]))
    return m_star


def fold_randomness(rho_list: list[list[bytes]], alphas: list[bytes]) -> list[bytes]:
    """Same structure as fold_witnesses but for randomness vectors."""
    return fold_witnesses(rho_list, alphas)


def fold_weight_sum(alphas: list[bytes]) -> int:
    if len(alphas) == 0:
        raise ValueError("expected at least one folding challenge")
    total = 0
    for alpha in alphas:
        total = (total + scalar_to_int(alpha)) % L
    return total


# ──────────────────────────────────────────────────────────────
# Non-linear folding with cross-term error E
# ──────────────────────────────────────────────────────────────

def nonlinear_fold(L_vals: list[int], R_vals: list[int], O_vals: list[int],
                   alphas: list[bytes]) -> Tuple[int, int, int, int]:
    """
    Non-linear folding with explicit cross-term error recurrence.

    For each event: L_i·R_i = O_i  (multiplication gate)
    Weights: w_i=α_i for every row.

    Returns (L_star, R_star, O_star, E_star) as Python ints mod L.
    Verifier checks: L_star·R_star - O_star - E_star = 0 (mod L).
    """
    N = len(L_vals)
    if N == 0:
        raise ValueError("expected at least one multiplication row")
    if N != len(R_vals) or N != len(O_vals) or N != len(alphas):
        raise ValueError("nonlinear_fold inputs must have matching lengths")

    # Initialize with the first transcript-derived weight.
    w_0 = scalar_to_int(alphas[0])
    L0 = L_vals[0] % L
    R0 = R_vals[0] % L
    O0 = O_vals[0] % L
    L_acc = (w_0 * L0) % L
    R_acc = (w_0 * R0) % L
    O_acc = (w_0 * O0) % L
    E_acc = ((w_0 * w_0 - w_0) * O0) % L

    for i in range(1, N):
        w_i = scalar_to_int(alphas[i])

        # Cross terms
        T_i = (L_acc * R_vals[i] + L_vals[i] * R_acc) % L
        E_acc = (E_acc + w_i * T_i + (w_i * w_i - w_i) * O_vals[i]) % L

        L_acc = (L_acc + w_i * L_vals[i]) % L
        R_acc = (R_acc + w_i * R_vals[i]) % L
        O_acc = (O_acc + w_i * O_vals[i]) % L

    return L_acc, R_acc, O_acc, E_acc


# ──────────────────────────────────────────────────────────────
# Policy commitments (Pedersen on G_pol, H_pol)
# ──────────────────────────────────────────────────────────────

def pedersen_commit(blinding: bytes, value: bytes,
                    G_pol: bytes, H_pol: bytes) -> bytes:
    return point_add(point_mul(blinding, G_pol), point_mul(value, H_pol))

def policy_commit(gamma_j: bytes, m_star_j: bytes,
                  G_pol: bytes, H_pol: bytes) -> bytes:
    """V_j = γ_j·G_pol + m⋆_j·H_pol"""
    return pedersen_commit(gamma_j, m_star_j, G_pol, H_pol)


def linear_constraint_residual(m_star: list[bytes], coeffs: list[int], target: int) -> int:
    if len(m_star) != len(coeffs):
        raise ValueError("linear constraint dimensions do not match")
    residual = 0
    for coeff, value in zip(coeffs, m_star):
        residual = (residual + (coeff % L) * scalar_to_int(value)) % L
    return (residual - target) % L


def linear_constraint_gamma_residual(gamma_vec: list[bytes], coeffs: list[int]) -> bytes:
    if len(gamma_vec) != len(coeffs):
        raise ValueError("linear gamma dimensions do not match")
    acc = 0
    for coeff, gamma in zip(coeffs, gamma_vec):
        acc = (acc + (coeff % L) * scalar_to_int(gamma)) % L
    return scalar_from_int(acc)


def linear_constraint_W(V_list: list[bytes], coeffs: list[int], target: int,
                        H_pol: bytes) -> bytes:
    if len(V_list) != len(coeffs):
        raise ValueError("linear public commitment dimensions do not match")
    W = IDENTITY
    for coeff, V_j in zip(coeffs, V_list):
        coeff_mod = coeff % L
        if coeff_mod != 0:
            W = point_add(W, point_mul(scalar_from_int(coeff_mod), V_j))
    target_mod = target % L
    if target_mod != 0:
        W = point_sub(W, point_mul(scalar_from_int(target_mod), H_pol))
    return W


def parse_scalar_le_bytes(data: bytes) -> int:
    if len(data) != SCALAR_BYTES:
        raise ValueError("expected 32-byte scalar encoding")
    value = int.from_bytes(data, "little")
    if value >= L:
        raise ValueError("non-canonical scalar encoding")
    return value


def decode_compiled_policy(policy_compiled: bytes) -> tuple[int, list[list[int]], list[int]]:
    policy = cbor_decode(policy_compiled)
    if policy[0] != 1:
        raise ValueError("unsupported policy format version")
    d = policy[1]
    k_rows = policy[2]
    rows = [[parse_scalar_le_bytes(entry) for entry in row] for row in policy[3]]
    targets = [parse_scalar_le_bytes(entry) for entry in policy[4]]
    if len(rows) != k_rows or len(targets) != k_rows:
        raise ValueError("policy row count mismatch")
    for row in rows:
        if len(row) != d:
            raise ValueError("policy width mismatch")
    return d, rows, targets


def compressed_linear_terms(policy_compiled: bytes, final_root: bytes, weight_sum: int) -> tuple[bytes, list[int], int]:
    policy_hash = hashlib.sha512(policy_compiled).digest()
    d, rows, targets = decode_compiled_policy(policy_compiled)
    betas = [scalar_to_int(beta_challenge(final_root, policy_hash, row_index)) for row_index in range(1, len(rows) + 1)]
    compressed_coeffs = [0] * d
    compressed_target = 0
    for beta, row, target in zip(betas, rows, targets):
        for j, entry in enumerate(row):
            compressed_coeffs[j] = (compressed_coeffs[j] + beta * entry) % L
        compressed_target = (compressed_target + beta * ((weight_sum % L) * target % L)) % L
    return policy_hash, compressed_coeffs, compressed_target


# ──────────────────────────────────────────────────────────────
# Schnorr NIZK proof primitives (Fiat–Shamir via CBOR)
# ──────────────────────────────────────────────────────────────

def link_challenge(tags_hash: bytes, final_root: bytes, c_star: bytes, v_list: list[bytes],
                   t_commit: bytes, t_policy: list[bytes]) -> bytes:
    msg = cbor_encode(["link", tags_hash, final_root, c_star, *v_list, t_commit, *t_policy])
    return h2s(DST_LINK, msg)


def beta_challenge(final_root: bytes, policy_hash: bytes, row_index: int) -> bytes:
    msg = cbor_encode(["beta", final_root, policy_hash, row_index])
    return h2s(DST_BETA, msg)


def cons_challenge(tags_hash: bytes, final_root: bytes, policy_hash: bytes, w_point: bytes, nonce_t: bytes) -> bytes:
    msg = cbor_encode(["cons", tags_hash, final_root, policy_hash, w_point, nonce_t])
    return h2s(DST_CONS, msg)


def schnorr_fs_challenge(context: bytes, commitments_T: list[bytes],
                         public_points: list[bytes]) -> bytes:
    msg = cbor_encode(["NESSA-EC:v1:schnorr", context, commitments_T, public_points])
    return h2s(DST_CONS, msg)


# ──────────────────────────────────────────────────────────────
# π_link: Linkage proof
# ──────────────────────────────────────────────────────────────

@dataclass
class ProofLink:
    """π_link: proves knowledge of (m⋆, ρ⋆, γ⃗) binding C⋆ and V_j."""
    T_commit: bytes        # commitment nonce for C⋆ relation
    T_policy: list[bytes]  # commitment nonces for V_j relations
    z_m: list[bytes]       # response for m⋆ coordinates
    z_rho: list[bytes]     # response for ρ⋆ coordinates
    z_gamma: list[bytes]   # response for γ_j blinding factors
    challenge: bytes       # Fiat–Shamir challenge


def prove_link(m_star: list[bytes], rho_star: list[bytes],
               gamma_vec: list[bytes], C_star: bytes, V_list: list[bytes],
               gens: dict, tags_hash: bytes, final_root: bytes,
               scalar_draw: Callable[..., bytes] | None = None) -> ProofLink:
    """
    Generate π_link: multi-relation Schnorr NIZK.

    Proves:
      C⋆ = Com_V2(m⋆; ρ⋆)
      ∀j: V_j = γ_j·G_pol + m⋆_j·H_pol
    """
    d = len(m_star)
    Br, Bm = gens["Br"], gens["Bm"]
    G_pol, H_pol = gens["G_pol"], gens["H_pol"]

    if scalar_draw is None:
        def draw_scalar(_label: str, *_parts) -> bytes:
            return scalar_random()
    else:
        draw_scalar = scalar_draw

    # Nonces
    k_m = [draw_scalar("link:k_m", j) for j in range(d)]
    k_rho = [draw_scalar("link:k_rho", j) for j in range(d)]
    k_gamma = [draw_scalar("link:k_gamma", j) for j in range(d)]

    # T for C⋆ equation: T_commit = Com_V2(k_m; k_rho)
    T_commit = commit_v2(k_m, k_rho, Br, Bm)

    # T for each V_j equation: T_j = k_gamma_j·G_pol + k_m_j·H_pol
    T_policy = []
    for j in range(d):
        T_j = point_add(point_mul(k_gamma[j], G_pol), point_mul(k_m[j], H_pol))
        T_policy.append(T_j)

    # Fiat–Shamir challenge
    all_T = [T_commit] + T_policy
    all_P = [C_star] + V_list
    c = link_challenge(tags_hash, final_root, C_star, V_list, T_commit, T_policy)

    # Responses: z = k + c·witness
    z_m = [scalar_add(k_m[j], scalar_mul(c, m_star[j])) for j in range(d)]
    z_rho = [scalar_add(k_rho[j], scalar_mul(c, rho_star[j])) for j in range(d)]
    z_gamma = [scalar_add(k_gamma[j], scalar_mul(c, gamma_vec[j])) for j in range(d)]

    return ProofLink(
        T_commit=T_commit, T_policy=T_policy,
        z_m=z_m, z_rho=z_rho, z_gamma=z_gamma, challenge=c
    )


def verify_link(proof: ProofLink, C_star: bytes, V_list: list[bytes],
                gens: dict, tags_hash: bytes, final_root: bytes) -> bool:
    """
    Verify π_link.

    Check:
      Com_V2(z_m; z_rho) == T_commit + c·C⋆
      ∀j: z_gamma_j·G_pol + z_m_j·H_pol == T_j + c·V_j
    """
    d = len(proof.z_m)
    Br, Bm = gens["Br"], gens["Bm"]
    G_pol, H_pol = gens["G_pol"], gens["H_pol"]
    c = proof.challenge

    # Recompute challenge
    c_check = link_challenge(tags_hash, final_root, C_star, V_list, proof.T_commit, proof.T_policy)
    if c != c_check:
        return False

    # Check C⋆ relation: Com_V2(z_m; z_rho) == T_commit + c·C⋆
    lhs = commit_v2(proof.z_m, proof.z_rho, Br, Bm)
    rhs = point_add(proof.T_commit, point_mul(c, C_star))
    if lhs != rhs:
        return False

    # Check each V_j relation
    for j in range(d):
        lhs_j = point_add(point_mul(proof.z_gamma[j], G_pol),
                          point_mul(proof.z_m[j], H_pol))
        rhs_j = point_add(proof.T_policy[j], point_mul(c, V_list[j]))
        if lhs_j != rhs_j:
            return False

    return True


# ──────────────────────────────────────────────────────────────
# π_cons: Constraint proof (linear and non-linear)
# ──────────────────────────────────────────────────────────────

@dataclass
class ProofConsLinear:
    """π_cons for linear-only policy: Schnorr proof that constraint residual = 0."""
    T: bytes       # nonce commitment
    z: bytes       # response
    challenge: bytes


def prove_cons_linear(m_star: list[bytes], gamma_residual: bytes,
                      coeffs: list[int], target: int,
                      G_pol: bytes, H_pol: bytes,
                      tags_hash: bytes, final_root: bytes, policy_hash: bytes,
                      scalar_draw: Callable[..., bytes] | None = None) -> ProofConsLinear:
    """
    Prove linear constraint: Σ coeffs_j · m⋆_j = target (mod L).

    W = gamma_residual·G_pol + (Σ coeffs_j·m⋆_j - target)·H_pol
    Since the constraint holds, the H_pol coefficient is 0, so W = gamma_residual·G_pol.
    Prove knowledge of gamma_residual for W.
    """
    # Compute W (should be gamma_residual·G_pol if constraint holds)
    residual = linear_constraint_residual(m_star, coeffs, target)
    W = point_add(point_mul(gamma_residual, G_pol),
                  point_mul(scalar_from_int(residual), H_pol))

    # Schnorr proof of knowledge of discrete log of W w.r.t. G_pol
    if scalar_draw is None:
        k = scalar_random()
    else:
        k = scalar_draw("cons_linear:k")
    T = point_mul(k, G_pol)

    c_fs = cons_challenge(tags_hash, final_root, policy_hash, W, T)
    z = scalar_add(k, scalar_mul(c_fs, gamma_residual))

    return ProofConsLinear(T=T, z=z, challenge=c_fs)


def verify_cons_linear(proof: ProofConsLinear, W: bytes,
                       G_pol: bytes, tags_hash: bytes, final_root: bytes, policy_hash: bytes) -> bool:
    """Verify: z·G_pol == T + c·W."""
    c_check = cons_challenge(tags_hash, final_root, policy_hash, W, proof.T)
    if proof.challenge != c_check:
        return False
    lhs = point_mul(proof.z, G_pol)
    rhs = point_add(proof.T, point_mul(proof.challenge, W))
    return lhs == rhs


@dataclass
class ProofConsNonlinear:
    """π_cons for non-linear policy bound to folded witness commitments."""
    C_E: bytes
    T_L: bytes
    T_R: bytes
    T_O: bytes
    T_E: bytes
    T_mul_base: bytes
    T_mul_cross: bytes
    z_L: bytes
    z_R: bytes
    z_O: bytes
    z_E: bytes
    z_gamma_L: bytes
    z_gamma_R: bytes
    z_gamma_O: bytes
    z_rE: bytes
    z_mul_blind: bytes
    challenge: bytes


def prove_cons_nonlinear(L_star: int, R_star: int, O_star: int, E_star: int,
                         gamma_L: bytes, gamma_R: bytes, gamma_O: bytes,
                         V_L: bytes, V_R: bytes, V_O: bytes,
                         G_pol: bytes, H_pol: bytes,
                         transcript_context: bytes,
                         scalar_draw: Callable[..., bytes] | None = None) -> ProofConsNonlinear:
    """
    Prove the folded multiplicative relation using the same commitments bound by π_link.

    Public commitments V_L, V_R, V_O are the policy commitments for the folded
    witness coordinates. The proof adds only a commitment to E⋆ and proves that
    the committed values satisfy L⋆·R⋆ = O⋆ + E⋆.
    """
    Ls = scalar_from_int(L_star)
    Rs = scalar_from_int(R_star)
    Os = scalar_from_int(O_star)
    Es = scalar_from_int(E_star)

    if V_L != pedersen_commit(gamma_L, Ls, G_pol, H_pol):
        raise ValueError("V_L does not match the supplied folded L witness")
    if V_R != pedersen_commit(gamma_R, Rs, G_pol, H_pol):
        raise ValueError("V_R does not match the supplied folded R witness")
    if V_O != pedersen_commit(gamma_O, Os, G_pol, H_pol):
        raise ValueError("V_O does not match the supplied folded O witness")

    if scalar_draw is None:
        def draw_scalar(_label: str, *_parts) -> bytes:
            return scalar_random()
    else:
        draw_scalar = scalar_draw

    r_E = draw_scalar("cons_nonlinear:r_E")
    C_E = pedersen_commit(r_E, Es, G_pol, H_pol)

    k_L = draw_scalar("cons_nonlinear:k_L")
    k_R = draw_scalar("cons_nonlinear:k_R")
    k_O = draw_scalar("cons_nonlinear:k_O")
    k_E = draw_scalar("cons_nonlinear:k_E")
    k_gamma_L = draw_scalar("cons_nonlinear:k_gamma_L")
    k_gamma_R = draw_scalar("cons_nonlinear:k_gamma_R")
    k_gamma_O = draw_scalar("cons_nonlinear:k_gamma_O")
    k_rE = draw_scalar("cons_nonlinear:k_rE")
    k_mul_base = draw_scalar("cons_nonlinear:k_mul_base")
    k_mul_cross = draw_scalar("cons_nonlinear:k_mul_cross")

    T_L = pedersen_commit(k_gamma_L, k_L, G_pol, H_pol)
    T_R = pedersen_commit(k_gamma_R, k_R, G_pol, H_pol)
    T_O = pedersen_commit(k_gamma_O, k_O, G_pol, H_pol)
    T_E = pedersen_commit(k_rE, k_E, G_pol, H_pol)

    T_mul_base = pedersen_commit(k_mul_base, scalar_mul(k_L, k_R), G_pol, H_pol)
    cross_term = scalar_add(scalar_mul(k_L, Rs), scalar_mul(k_R, Ls))
    T_mul_cross = pedersen_commit(k_mul_cross, cross_term, G_pol, H_pol)

    all_T = [T_L, T_R, T_O, T_E, T_mul_base, T_mul_cross]
    all_P = [V_L, V_R, V_O, C_E]
    c_fs = schnorr_fs_challenge(transcript_context, all_T, all_P)
    c_sq = scalar_mul(c_fs, c_fs)

    z_L = scalar_add(k_L, scalar_mul(c_fs, Ls))
    z_R = scalar_add(k_R, scalar_mul(c_fs, Rs))
    z_O = scalar_add(k_O, scalar_mul(c_fs, Os))
    z_E = scalar_add(k_E, scalar_mul(c_fs, Es))
    z_gamma_L = scalar_add(k_gamma_L, scalar_mul(c_fs, gamma_L))
    z_gamma_R = scalar_add(k_gamma_R, scalar_mul(c_fs, gamma_R))
    z_gamma_O = scalar_add(k_gamma_O, scalar_mul(c_fs, gamma_O))
    z_rE = scalar_add(k_rE, scalar_mul(c_fs, r_E))

    committed_output_blind = scalar_add(gamma_O, r_E)
    z_mul_blind = scalar_add(
        k_mul_base,
        scalar_add(
            scalar_mul(c_fs, k_mul_cross),
            scalar_mul(c_sq, committed_output_blind),
        ),
    )

    return ProofConsNonlinear(
        C_E=C_E,
        T_L=T_L,
        T_R=T_R,
        T_O=T_O,
        T_E=T_E,
        T_mul_base=T_mul_base,
        T_mul_cross=T_mul_cross,
        z_L=z_L,
        z_R=z_R,
        z_O=z_O,
        z_E=z_E,
        z_gamma_L=z_gamma_L,
        z_gamma_R=z_gamma_R,
        z_gamma_O=z_gamma_O,
        z_rE=z_rE,
        z_mul_blind=z_mul_blind,
        challenge=c_fs,
    )


def verify_cons_nonlinear(proof: ProofConsNonlinear,
                          V_L: bytes, V_R: bytes, V_O: bytes,
                          G_pol: bytes, H_pol: bytes,
                          transcript_context: bytes) -> bool:
    """Verify the bound non-linear folded multiplication proof."""
    all_T = [proof.T_L, proof.T_R, proof.T_O, proof.T_E,
             proof.T_mul_base, proof.T_mul_cross]
    all_P = [V_L, V_R, V_O, proof.C_E]
    c_check = schnorr_fs_challenge(transcript_context, all_T, all_P)
    if proof.challenge != c_check:
        return False

    c_sq = scalar_mul(proof.challenge, proof.challenge)

    if pedersen_commit(proof.z_gamma_L, proof.z_L, G_pol, H_pol) != point_add(
        proof.T_L, point_mul(proof.challenge, V_L)
    ):
        return False
    if pedersen_commit(proof.z_gamma_R, proof.z_R, G_pol, H_pol) != point_add(
        proof.T_R, point_mul(proof.challenge, V_R)
    ):
        return False
    if pedersen_commit(proof.z_gamma_O, proof.z_O, G_pol, H_pol) != point_add(
        proof.T_O, point_mul(proof.challenge, V_O)
    ):
        return False
    if pedersen_commit(proof.z_rE, proof.z_E, G_pol, H_pol) != point_add(
        proof.T_E, point_mul(proof.challenge, proof.C_E)
    ):
        return False

    lhs_mul = pedersen_commit(
        proof.z_mul_blind,
        scalar_mul(proof.z_L, proof.z_R),
        G_pol,
        H_pol,
    )
    rhs_mul = point_add(proof.T_mul_base, point_mul(proof.challenge, proof.T_mul_cross))
    rhs_mul = point_add(rhs_mul, point_mul(c_sq, point_add(V_O, proof.C_E)))
    return lhs_mul == rhs_mul

# ──────────────────────────────────────────────────────────────
# Complete proof protocol
# ──────────────────────────────────────────────────────────────

@dataclass
class NessaProof:
    """Complete NESSA qFold-EC proof."""
    # Public data
    C_star: bytes               # folded commitment
    V_list: list[bytes]         # policy commitments
    # Proof components
    pi_link: ProofLink          # linkage proof
    pi_cons_linear: Optional[ProofConsLinear] = None
    pi_cons_nonlinear: Optional[ProofConsNonlinear] = None
    # Metadata
    N: int = 0                  # number of events
    d: int = 0                  # message dimension

    def byte_size(self) -> int:
        """Compute total proof size in bytes."""
        size = POINT_BYTES  # C_star
        size += len(self.V_list) * POINT_BYTES
        # pi_link
        size += POINT_BYTES  # T_commit
        size += len(self.pi_link.T_policy) * POINT_BYTES
        size += len(self.pi_link.z_m) * SCALAR_BYTES
        size += len(self.pi_link.z_rho) * SCALAR_BYTES
        size += len(self.pi_link.z_gamma) * SCALAR_BYTES
        size += SCALAR_BYTES  # challenge
        # pi_cons
        if self.pi_cons_nonlinear:
            size += 7 * POINT_BYTES  # C_E and six nonce commitments
            size += 9 * SCALAR_BYTES  # all z responses
            size += SCALAR_BYTES  # challenge
        if self.pi_cons_linear:
            size += POINT_BYTES + 2 * SCALAR_BYTES
        return size


# ──────────────────────────────────────────────────────────────
# End-to-end protocol runner
# ──────────────────────────────────────────────────────────────

@dataclass
class BenchmarkResult:
    N: int
    d: int
    gen_derive_ms: float
    commit_ms: float
    transcript_ms: float
    fold_ms: float
    nonlinear_fold_ms: float
    prove_link_ms: float
    prove_cons_ms: float
    verify_link_ms: float
    verify_cons_ms: float
    total_prove_ms: float
    total_verify_ms: float
    proof_size_bytes: int
    folding_check_ok: bool
    link_verify_ok: bool
    cons_verify_ok: bool


@dataclass
class ProtocolFlow:
    result: BenchmarkResult
    gens: dict
    events: list[list[int]]
    commitments: list[bytes]
    tags: dict[int, object]
    tags_hash: bytes
    policy_compiled: bytes
    transcript_roots: list[bytes]
    alphas: list[bytes]
    fold_weights: list[bytes]
    C_star: bytes
    m_star: list[bytes]
    rho_star: list[bytes]
    V_list: list[bytes]
    transcript_context: bytes
    proof: NessaProof
    encoding_id: str = "default"
    policy_id: str = "default"
    linear_constraint_coeffs: Optional[list[int]] = None
    linear_constraint_target: Optional[int] = None
    linear_constraint_W: Optional[bytes] = None
    proof_context_label: bytes = b""
    L_star_val: int = 0
    R_star_val: int = 0
    O_star_val: int = 0
    E_star_val: int = 0


def run_protocol_flow(N: int, d: int = 3,
                      include_nonlinear: bool = True,
                      precomputed_gens: dict | None = None,
                      event_values: list[list[int]] | None = None,
                      linear_constraint_coeffs: list[int] | None = None,
                      linear_constraint_target: int = 0,
                      linear_constraint_rows: list[list[int]] | None = None,
                      linear_constraint_targets: list[int] | None = None,
                      coordinate_bit_lengths: list[int] | None = None,
                      deterministic_seed: bytes | None = None,
                      encoding_id: str = "default",
                      policy_id: str = "default",
                      proof_context_label: bytes | str | None = None) -> ProtocolFlow:
    if N < 1:
        raise ValueError("N must be >= 1")
    if include_nonlinear and d < 3:
        raise ValueError("non-linear mode requires d >= 3")
    if event_values is not None and len(event_values) != N:
        raise ValueError(f"expected {N} events, got {len(event_values)}")
    if coordinate_bit_lengths is not None and len(coordinate_bit_lengths) != d:
        raise ValueError(f"expected {d} coordinate bit lengths, got {len(coordinate_bit_lengths)}")
    if coordinate_bit_lengths is not None and event_values is None:
        raise ValueError("coordinate bit lengths require explicit event values")
    if include_nonlinear and linear_constraint_coeffs is not None:
        raise ValueError("linear constraints are only supported in linear mode")
    if include_nonlinear and linear_constraint_rows is not None:
        raise ValueError("linear policy rows are only supported in linear mode")
    if not include_nonlinear and linear_constraint_coeffs is None and linear_constraint_rows is None:
        raise ValueError("linear mode requires linear policy coefficients or rows")
    if not encoding_id:
        raise ValueError("encoding_id must be non-empty")
    if not policy_id:
        raise ValueError("policy_id must be non-empty")

    normalized_linear_coeffs = None
    normalized_linear_rows = None
    normalized_linear_targets = None
    if linear_constraint_coeffs is not None:
        if len(linear_constraint_coeffs) != d:
            raise ValueError(f"expected {d} linear coefficients, got {len(linear_constraint_coeffs)}")
        normalized_linear_coeffs = [c % L for c in linear_constraint_coeffs]
    if linear_constraint_rows is not None:
        if len(linear_constraint_rows) == 0:
            raise ValueError("linear policy requires at least one row")
        if linear_constraint_targets is None or len(linear_constraint_targets) != len(linear_constraint_rows):
            raise ValueError("linear policy row/target count mismatch")
        normalized_linear_rows = []
        for row in linear_constraint_rows:
            if len(row) != d:
                raise ValueError(f"expected linear policy rows of width {d}")
            normalized_linear_rows.append([entry % L for entry in row])
        normalized_linear_targets = [target % L for target in linear_constraint_targets]
        if normalized_linear_coeffs is None:
            normalized_linear_coeffs = list(normalized_linear_rows[0])
            linear_constraint_target = normalized_linear_targets[0]

    scalar_oracle = DeterministicScalarOracle(deterministic_seed) if deterministic_seed is not None else None

    def draw_scalar(label: str, *parts) -> bytes:
        if scalar_oracle is None:
            return scalar_random()
        return scalar_oracle.scalar(label, *parts)

    # ── Step 1: Generator derivation ──
    t0 = time.perf_counter()
    if precomputed_gens is not None:
        gens = precomputed_gens
    else:
        gens = derive_generators(d)
    validate_generator_set(gens, d)
    gen_derive_ms = (time.perf_counter() - t0) * 1000

    Br, Bm = gens["Br"], gens["Bm"]
    G_pol, H_pol = gens["G_pol"], gens["H_pol"]

    # ── Step 2: Generate random events and commitments ──
    t0 = time.perf_counter()
    events = []
    witnesses = []
    rho_list = []
    commitments = []

    for i in range(N):
        if event_values is None:
            vals = random_event_values(d, include_nonlinear)
        else:
            vals = normalize_event_values(
                event_values[i],
                d,
                include_nonlinear,
                coordinate_bit_lengths,
            )
        event = Event(values=vals)
        events.append(event)

        m_vec = event.encode()
        witnesses.append(m_vec)

        rho_vec = [draw_scalar("rho", i, j) for j in range(d)]
        rho_list.append(rho_vec)

        C_i = commit_v2(m_vec, rho_vec, Br, Bm)
        commitments.append(C_i)
    commit_ms = (time.perf_counter() - t0) * 1000

    # ── Step 3: Transcript binding ──
    t0 = time.perf_counter()
    policy_compiled = b""
    policy_hash = hashlib.sha512(compile_linear_policy(d, [[1] * d], [0])).digest()
    k_rows = 1
    if normalized_linear_rows is not None:
        policy_compiled = compile_linear_policy(d, normalized_linear_rows, normalized_linear_targets)
        policy_hash = hashlib.sha512(policy_compiled).digest()
        k_rows = len(normalized_linear_rows)
    elif normalized_linear_coeffs is not None:
        policy_compiled = compile_linear_policy(d, [normalized_linear_coeffs], [linear_constraint_target])
        policy_hash = hashlib.sha512(policy_compiled).digest()
        k_rows = 1
    transcript_seed = hashlib.sha512(deterministic_seed).digest() if deterministic_seed is not None else None
    tags = build_tags(
        encoding_id=encoding_id,
        policy_id=policy_id,
        d=d,
        policy_hash=policy_hash,
        k_rows=k_rows,
        transcript_seed=transcript_seed,
    )
    ts = build_transcript(tags, commitments)
    proof_context_label_bytes = normalize_context_binding(proof_context_label)
    transcript_ms = (time.perf_counter() - t0) * 1000

    # ── Step 4: Folding ──
    t0 = time.perf_counter()
    C_star = fold_commitments(commitments, ts.alphas)
    m_star = fold_witnesses(witnesses, ts.alphas)
    rho_star = fold_randomness(rho_list, ts.alphas)
    fold_ms = (time.perf_counter() - t0) * 1000

    # Verify: C_star == Com_V2(m_star, rho_star)
    C_star_check = commit_v2(m_star, rho_star, Br, Bm)
    assert C_star == C_star_check, "Folded commitment mismatch!"

    # ── Step 5: Non-linear folding (if requested) ──
    nonlinear_fold_ms = 0.0
    folding_check_ok = True
    L_star_val = R_star_val = O_star_val = E_star_val = 0

    if include_nonlinear:
        t0 = time.perf_counter()
        L_vals = [e.values[0] % L for e in events]
        R_vals = [e.values[1] % L for e in events]
        O_vals = [e.values[2] % L for e in events]

        L_star_val, R_star_val, O_star_val, E_star_val = nonlinear_fold(
            L_vals, R_vals, O_vals, ts.alphas
        )
        nonlinear_fold_ms = (time.perf_counter() - t0) * 1000

        if scalar_to_int(m_star[0]) != L_star_val:
            raise AssertionError("folded L witness does not match transcript folding")
        if scalar_to_int(m_star[1]) != R_star_val:
            raise AssertionError("folded R witness does not match transcript folding")
        if scalar_to_int(m_star[2]) != O_star_val:
            raise AssertionError("folded O witness does not match transcript folding")

        # Verify folding identity: L⋆·R⋆ - O⋆ - E⋆ = 0 (mod L)
        check = (L_star_val * R_star_val - O_star_val - E_star_val) % L
        folding_check_ok = (check == 0)

    # ── Step 6: Policy commitments ──
    gamma_vec = [draw_scalar("gamma", j) for j in range(d)]
    V_list = [policy_commit(gamma_vec[j], m_star[j], G_pol, H_pol)
              for j in range(d)]
    transcript_context = build_proof_context(ts.tags_hash, ts.roots[-1], N, d, proof_context_label_bytes)

    # ── Step 7: Prove π_link ──
    t0 = time.perf_counter()
    pi_link = prove_link(m_star, rho_star, gamma_vec, C_star, V_list,
                         gens, ts.tags_hash, ts.roots[-1], scalar_draw=draw_scalar)
    prove_link_ms = (time.perf_counter() - t0) * 1000

    # ── Step 8: Prove π_cons ──
    t0 = time.perf_counter()
    pi_cons_nl = None
    pi_cons_lin = None
    linear_W = None
    folded_linear_target = None
    if include_nonlinear:
        pi_cons_nl = prove_cons_nonlinear(
            L_star_val, R_star_val, O_star_val, E_star_val,
            gamma_vec[0], gamma_vec[1], gamma_vec[2],
            V_list[0], V_list[1], V_list[2],
            G_pol, H_pol, transcript_context,
            scalar_draw=draw_scalar,
        )
    else:
        if not policy_compiled:
            policy_compiled = compile_linear_policy(d, [normalized_linear_coeffs], [linear_constraint_target])
        policy_hash, compressed_coeffs, folded_linear_target = compressed_linear_terms(
            policy_compiled,
            ts.roots[-1],
            fold_weight_sum(ts.alphas),
        )
        linear_residual = linear_constraint_residual(
            m_star,
            compressed_coeffs,
            folded_linear_target,
        )
        if linear_residual != 0:
            raise ValueError("folded linear constraint is not satisfied")
        gamma_residual = linear_constraint_gamma_residual(gamma_vec, compressed_coeffs)
        linear_W = linear_constraint_W(V_list, compressed_coeffs, folded_linear_target, H_pol)
        pi_cons_lin = prove_cons_linear(
            m_star,
            gamma_residual,
            compressed_coeffs,
            folded_linear_target,
            G_pol,
            H_pol,
            ts.tags_hash,
            ts.roots[-1],
            policy_hash,
            scalar_draw=draw_scalar,
        )
    prove_cons_ms = (time.perf_counter() - t0) * 1000

    # ── Step 9: Verify π_link ──
    t0 = time.perf_counter()
    link_ok = verify_link(pi_link, C_star, V_list, gens, ts.tags_hash, ts.roots[-1])
    verify_link_ms = (time.perf_counter() - t0) * 1000

    # ── Step 10: Verify π_cons ──
    t0 = time.perf_counter()
    cons_ok = True
    if pi_cons_nl:
        cons_ok = verify_cons_nonlinear(pi_cons_nl,
                                        V_list[0], V_list[1], V_list[2],
                                        G_pol, H_pol,
                                        build_proof_context(ts.tags_hash, ts.roots[-1], N, d, proof_context_label_bytes))
    elif pi_cons_lin and linear_W is not None:
        cons_ok = verify_cons_linear(pi_cons_lin, linear_W, G_pol, ts.tags_hash, ts.roots[-1], policy_hash)
    verify_cons_ms = (time.perf_counter() - t0) * 1000

    # ── Build proof object for size measurement ──
    proof = NessaProof(
        C_star=C_star, V_list=V_list,
        pi_link=pi_link,
        pi_cons_linear=pi_cons_lin,
        pi_cons_nonlinear=pi_cons_nl,
        N=N, d=d
    )

    result = BenchmarkResult(
        N=N, d=d,
        gen_derive_ms=gen_derive_ms,
        commit_ms=commit_ms,
        transcript_ms=transcript_ms,
        fold_ms=fold_ms,
        nonlinear_fold_ms=nonlinear_fold_ms,
        prove_link_ms=prove_link_ms,
        prove_cons_ms=prove_cons_ms,
        verify_link_ms=verify_link_ms,
        verify_cons_ms=verify_cons_ms,
        total_prove_ms=prove_link_ms + prove_cons_ms,
        total_verify_ms=verify_link_ms + verify_cons_ms,
        proof_size_bytes=proof.byte_size(),
        folding_check_ok=folding_check_ok,
        link_verify_ok=link_ok,
        cons_verify_ok=cons_ok,
    )

    return ProtocolFlow(
        result=result,
        gens=gens,
        events=[event.values[:] for event in events],
        commitments=list(commitments),
        tags=dict(tags),
        encoding_id=encoding_id,
        policy_id=policy_id,
        tags_hash=ts.tags_hash,
        policy_compiled=policy_compiled,
        transcript_roots=list(ts.roots),
        alphas=list(ts.alphas),
        fold_weights=list(ts.alphas),
        C_star=C_star,
        m_star=list(m_star),
        rho_star=list(rho_star),
        V_list=list(V_list),
        transcript_context=build_proof_context(ts.tags_hash, ts.roots[-1], N, d, proof_context_label_bytes),
        proof=proof,
        linear_constraint_coeffs=list(normalized_linear_coeffs) if normalized_linear_coeffs is not None else None,
        linear_constraint_target=folded_linear_target,
        linear_constraint_W=linear_W,
        proof_context_label=proof_context_label_bytes,
        L_star_val=L_star_val,
        R_star_val=R_star_val,
        O_star_val=O_star_val,
        E_star_val=E_star_val,
    )


def run_protocol(N: int, d: int = 3,
                 include_nonlinear: bool = True,
                 precomputed_gens: dict | None = None,
                 event_values: list[list[int]] | None = None,
                 linear_constraint_coeffs: list[int] | None = None,
                 linear_constraint_target: int = 0,
                 coordinate_bit_lengths: list[int] | None = None,
                 deterministic_seed: bytes | None = None,
                 encoding_id: str = "default",
                 policy_id: str = "default",
                 proof_context_label: bytes | str | None = None) -> BenchmarkResult:
    """
    Run the full NESSA qFold-EC protocol for N events with dimension d.
    Returns timing and verification results.
    """
    return run_protocol_flow(
        N=N,
        d=d,
        include_nonlinear=include_nonlinear,
        precomputed_gens=precomputed_gens,
        event_values=event_values,
        linear_constraint_coeffs=linear_constraint_coeffs,
        linear_constraint_target=linear_constraint_target,
        coordinate_bit_lengths=coordinate_bit_lengths,
        deterministic_seed=deterministic_seed,
        encoding_id=encoding_id,
        policy_id=policy_id,
        proof_context_label=proof_context_label,
    ).result
