#!/usr/bin/env python3
"""
Intuitive qFold-EC application examples (user / product side).

These demos map the flows described in NESSA-qfold-applications-intuition.md onto the
implemented v1 stack: Commitment Profile V2, transcript folding, and per-scenario
binding / packing policies built from a shared checksum relation.
They do not implement lattice Pedersen, quaternion rotors, or 4-ary dimension halving;
see the intuition doc for that PQ mental model.

Encoding discipline matches implementation logic: fixed per-coordinate bit domains before
reduction mod L (nessa_qfold.normalize_event_values).

User-facing layer
-----------------
* **Material** dataclasses: what the *integrator* supplies (labels, epochs, handles).
* **UsecaseResult**: cryptographic `flow` plus a **UserProofStory** (plain-language steps)
  and **integrator_metadata** for logging or API responses.
* **validate_* ** functions: fail fast before proving when inputs violate demo contracts.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field, fields
from enum import Enum
from pathlib import Path
from typing import Any, Union

from nessa_qfold import (
    ProtocolFlow,
    build_transcript,
    cbor_encode,
    compute_tags_hash,
    derive_generators,
    fold_commitments,
    run_protocol_flow,
    verify_cons_linear,
    verify_link,
)

# Shared row shape: eight 32-bit payload limbs plus one 64-bit checksum limb.
# Most demos below use this as a binding / packing relation only:
# sum(payload_i) - checksum = 0 (integer identity, checked mod L after fold).
D_USECASE = 9
COORD_BITS_USECASE = [32] * 8 + [64]
CHECKSUM_LINEAR_COEFFS = [1, 1, 1, 1, 1, 1, 1, 1, -1]
LINEAR_TARGET_ZERO = 0

# Demo limits (integrators raise real limits in production schemas).
_MAX_LABEL_LEN = 512
_MAX_UINT32 = (1 << 32) - 1


class UsecaseScenario(str, Enum):
    login = "login"
    delegation = "delegation"
    credential = "credential"
    revocation = "revocation"
    attestation = "attestation"
    handshake = "handshake"
    ivc = "ivc"


@dataclass(frozen=True)
class UserProofStory:
    """
    Plain-language narrative for product, support, or audit readers.
    Not a security guarantee; the cryptographic checks are in the verifier.
    """

    scenario: UsecaseScenario
    template_status: str
    title: str
    one_line: str
    steps_for_end_user: tuple[str, ...]
    steps_for_integrator: tuple[str, ...]
    committed_public_semantics: tuple[str, ...]
    prover_side_secret: tuple[str, ...]
    verifier_receives: tuple[str, ...]
    verifier_checks: tuple[str, ...]
    out_of_scope_v1: tuple[str, ...]

    def as_markdown(self) -> str:
        lines = [
            f"### {self.title}",
            "",
            f"**Status:** {self.template_status}",
            "",
            self.one_line,
            "",
            "**If you are the person using the app**",
            "",
        ]
        lines.extend(f"- {s}" for s in self.steps_for_end_user)
        lines.extend(["", "**If you are integrating NESSA into a product**", ""])
        lines.extend(f"- {s}" for s in self.steps_for_integrator)
        lines.extend(["", "**What the math is effectively committing to (via hashes)**", ""])
        lines.extend(f"- {s}" for s in self.committed_public_semantics)
        lines.extend(["", "**What stays on the prover device (not sent raw)**", ""])
        lines.extend(f"- {s}" for s in self.prover_side_secret)
        lines.extend(["", "**What the verifier sees on the wire**", ""])
        lines.extend(f"- {s}" for s in self.verifier_receives)
        lines.extend(["", "**What the qFold-EC v1 verifier checks**", ""])
        lines.extend(f"- {s}" for s in self.verifier_checks)
        lines.extend(["", "**What this stack does *not* claim (read before shipping)**", ""])
        lines.extend(f"- {s}" for s in self.out_of_scope_v1)
        return "\n".join(lines)


def _story_login() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.login,
        template_status="Mechanics demo only — verifier must recompute request context and enforce login semantics externally.",
        title="Login binding / packing demo (session)",
        one_line="Bind a proof to this RP, this session key label, this epoch, and these policy flags; the demo proves row integrity plus transcript binding, not full login semantics.",
        steps_for_end_user=(
            "Complete sign-in so the app knows your session key (or its fingerprint).",
            "Approve the access request when the app shows who is asking (RP / app id).",
            "The app may show a short “session proof ready” message; you do not handle raw proof bytes.",
        ),
        steps_for_integrator=(
            "Collect `session_pk_label` (hash or stable id of the session public key), `rp_id`, `epoch`, `policy_flags`.",
            "Call `prove_login_session` (or `UsecaseClient.login(...)`) after domain validation.",
            "Send `UsecaseResult.to_wallet_bundle()` to your verifier service or peer.",
        ),
        committed_public_semantics=(
            "Explicit semantic slots: session-key handle, RP handle, epoch, and policy flags packed into 32-bit coordinates.",
            "A 64-bit checksum limb that proves row integrity for those packed coordinates.",
        ),
        prover_side_secret=(
            "Blinding vectors ρ used in Commitment Profile V2 for each event.",
            "Policy blinding γ_j and Schnorr nonces inside π_link / π_cons.",
            "Any long-term private keys—you only pass labels or hashes into this demo API.",
        ),
        verifier_receives=(
            "Ordered event commitments {C_i}, folded C⋆, policy commitments {V_j}, and π = (π_link, π_cons).",
            "`proof_context_label`: SHA-512 over a CBOR blob that includes your RP id, epoch, and flags.",
            "`encoding_id` nessa_uc_login_v1 so parsers pick the right field layout.",
        ),
        verifier_checks=(
            "Recomputes transcript roots and folding challenges α_i from embedded commitments.",
            "Checks π_link binds C⋆ to {V_j} for the folded witness.",
            "Checks π_cons for the row-integrity checksum policy on the folded coordinates.",
        ),
        out_of_scope_v1=(
            "The proof does not verify that the session key is currently authenticated to the RP; the application verifies that externally.",
            "No in-circuit Schnorr / PoP verification; bind key material as hashes only unless you add another proof system.",
            "No lattice residual e or rotor R; no range proofs for clock slack.",
            "N and commitment order are visible to the verifier (same as core qFold-EC v1).",
        ),
    )


def _story_delegation() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.delegation,
        template_status="Mechanics demo only — application must enforce delegation signatures, scope semantics, and validity windows externally.",
        title="Delegation binding / packing demo (parent → child)",
        one_line="Record child-key, scope, and validity labels in a binding proof; the demo proves packing integrity, not delegation validity.",
        steps_for_end_user=(
            "Parent approves creating or rotating a child key in the delegated app.",
            "Child device enrolls; user sees scope and validity dates the parent allowed.",
        ),
        steps_for_integrator=(
            "Fill `DelegationMaterial` with child key label, capability bits, validity window, parent digest.",
            "Optionally require an out-of-band parent signature before calling prove.",
        ),
        committed_public_semantics=("Explicit slots for child-key handle, scope bits, validity window, and parent-authority handle plus checksum limb.",),
        prover_side_secret=("Blinding and proof randomness; not the raw parent signature bytes in this demo.",),
        verifier_receives=("Same proof bundle shape as login; encoding_id nessa_uc_delegation_v1.",),
        verifier_checks=("Transcript binding + row-integrity checksum on folded witness.",),
        out_of_scope_v1=(
            "The proof does not verify that the parent actually delegated the child key for the stated scope/window; the application verifies that externally.",
            "Parent signature verification inside π is not part of v1; prove verification elsewhere or extend the proof relation.",
        ),
    )


def _story_credential() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.credential,
        template_status="Mechanics demo only — application must enforce credential predicates externally.",
        title="Selective credential binding / packing demo",
        one_line="Commit attribute bands and a predicate selector plus a credential root label; the demo proves binding to packed labels, not credential predicates.",
        steps_for_end_user=(
            "Issuer has already given you a credential; the app asks only for the checks it needs (e.g. age band).",
            "You approve releasing a proof tied to that credential root, not necessarily every field.",
        ),
        steps_for_integrator=(
            "Map attributes to small integers (`age_band`, `region_code`, `role_flags`) and a `predicate_selector`.",
            "Put issuer root or Merkle label in `credential_root_label`.",
        ),
        committed_public_semantics=("Explicit slots for age band, region code, role flags, predicate selector, and credential-root handle plus checksum.",),
        prover_side_secret=("Full credential payload if you keep it local; only derived limbs go into the commitment in this demo.",),
        verifier_receives=("encoding_id nessa_uc_credential_v1.",),
        verifier_checks=("Row-integrity checksum after fold; no arbitrary predicates (age ≥ 18) inside v1 π_cons.",),
        out_of_scope_v1=(
            "The proof does not verify that any credential predicate holds; the application verifies predicate meaning externally.",
            "Predicate satisfaction (comparisons, set membership) needs a future constraint system or external ZK.",
        ),
    )


def _story_revocation() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.revocation,
        template_status="Mechanics demo only — application must enforce non-revocation, freshness, and counter policy externally.",
        title="Revocation binding / packing demo",
        one_line="Anchor nullifier-seed, counter, epoch, and accumulator-handle labels in a binding proof; the demo does not itself prove revocation state.",
        steps_for_end_user=(
            "Use a credential or pass until the app says the usage budget changed.",
            "If revoked, the app refuses before building a new proof.",
        ),
        steps_for_integrator=(
            "Track `use_counter` and `epoch` in your state machine; pass stable string labels for seeds and accumulator handles.",
        ),
        committed_public_semantics=("Explicit slots for nullifier handle, usage counter, epoch, and accumulator handle plus checksum.",),
        prover_side_secret=("The full secret behind the nullifier if you separate label from sk in your app.",),
        verifier_receives=("encoding_id nessa_uc_revocation_v1.",),
        verifier_checks=("Row-integrity checksum only in this demo; your service must interpret counter semantics.",),
        out_of_scope_v1=(
            "The proof does not verify non-revocation, accumulator membership, or counter freshness; the application verifies those externally.",
            "No accumulator membership proof inside v1; pass digest handles and verify revocation out-of-band.",
        ),
    )


def _story_attestation() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.attestation,
        template_status="Mechanics demo only — application must validate attestation evidence and posture policy externally.",
        title="Device attestation binding / packing demo",
        one_line="Bind proof to measurement labels, firmware, app binary, and channel transcript label; the demo proves binding, not device trustworthiness.",
        steps_for_end_user=(
            "Device posture check completes; you may see “device verified” without raw PCR dumps.",
        ),
        steps_for_integrator=(
            "Feed stable string labels or hashes of measurements; keep verbose logs off the proof wire.",
        ),
        committed_public_semantics=("Explicit slots for measurement, firmware, app-measurement, and channel handles plus checksum.",),
        prover_side_secret=("Measurement secrets if any; proof hides witness under Pedersen commitments.",),
        verifier_receives=("encoding_id nessa_uc_attest_v1; proof_context binds channel transcript label.",),
        verifier_checks=("Standard qFold-EC v1 linkage + row-integrity checksum policy.",),
        out_of_scope_v1=(
            "The proof does not verify TPM quotes, PCR semantics, or enterprise posture policy; the application verifies those externally.",
            "No literal quaternion rotor; transcript binding plays the “context lock” role on the EC stack.",
        ),
    )


def _story_handshake() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.handshake,
        template_status="Mechanics demo only — application must validate TLS/OAuth semantics externally.",
        title="TLS / OAuth handshake binding demo",
        one_line="Tie a proof to a handshake transcript label, server id, ephemeral key label, and client binding tag; the demo proves binding, not server authentication.",
        steps_for_end_user=(
            "Complete OAuth or TLS as usual; the wallet proves it used the same handshake context the server expects.",
        ),
        steps_for_integrator=(
            "After handshake, compute stable labels (e.g. hash of ClientHello..ServerFinished) and pass them in `HandshakeBindingMaterial`.",
        ),
        committed_public_semantics=("Explicit slots for transcript, server, ephemeral-key, and client-binding handles plus checksum.",),
        prover_side_secret=("TLS key material; only labels agreed with the RP enter this API.",),
        verifier_receives=("encoding_id nessa_uc_tls_v1.",),
        verifier_checks=("π binds to proof_context_label derived from the same strings plus the row-integrity checksum relation.",),
        out_of_scope_v1=(
            "The proof does not verify server identity, certificate validity, or handshake transcript correctness; the application verifies those externally.",
            "This demo does not terminate TLS; it only commits labels you provide.",
        ),
    )


def _story_ivc() -> UserProofStory:
    return UserProofStory(
        scenario=UsecaseScenario.ivc,
        template_status="Mechanics demo only — this is multi-event folding, not recursive proof verification.",
        title="IVC-style step-chain binding demo",
        one_line="Multiple events (one per step root label) fold into one C⋆ under a per-row checksum relation; the demo proves row integrity plus transcript binding, not recursive step semantics.",
        steps_for_end_user=(
            "You may see several “steps” aggregated (e.g. batch approvals) as one verifier check.",
        ),
        steps_for_integrator=(
            "Provide ordered `step_roots` and a `cycle_tag`; each step becomes one event row.",
        ),
        committed_public_semantics=("Per step: explicit slots for index, cycle handle, and step-root handle plus checksum.",),
        prover_side_secret=("Per-event blinding; folding combines steps with transcript-derived α_i.",),
        verifier_receives=("N > 1 commitments; encoding_id nessa_uc_ivc_v1.",),
        verifier_checks=(
            "Same row-integrity checksum applied to the folded witness coordinates (weights absorb α_i).",
        ),
        out_of_scope_v1=(
            "The proof does not verify transition validity between steps; the application verifies step semantics externally.",
            "This is not a full IVC recursion gadget; it is multi-event folding on the existing v1 transcript schedule.",
        ),
    )


_STORIES: dict[UsecaseScenario, UserProofStory] = {
    UsecaseScenario.login: _story_login(),
    UsecaseScenario.delegation: _story_delegation(),
    UsecaseScenario.credential: _story_credential(),
    UsecaseScenario.revocation: _story_revocation(),
    UsecaseScenario.attestation: _story_attestation(),
    UsecaseScenario.handshake: _story_handshake(),
    UsecaseScenario.ivc: _story_ivc(),
}


_POLICY_BY_ENCODING_ID: dict[str, dict[str, Any]] = {
    "nessa_uc_login_v1": {
        "name": "nessa_uc_login_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for login-labeled material.",
    },
    "nessa_uc_delegation_v1": {
        "name": "nessa_uc_delegation_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for delegation-labeled material.",
    },
    "nessa_uc_credential_v1": {
        "name": "nessa_uc_credential_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for credential-labeled material.",
    },
    "nessa_uc_revocation_v1": {
        "name": "nessa_uc_revocation_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for revocation-labeled material.",
    },
    "nessa_uc_attest_v1": {
        "name": "nessa_uc_attestation_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for attestation-labeled material.",
    },
    "nessa_uc_tls_v1": {
        "name": "nessa_uc_handshake_binding_checksum_v1",
        "summary": "Binding demo only: row integrity checksum plus transcript binding for handshake-labeled material.",
    },
    "nessa_uc_ivc_v1": {
        "name": "nessa_uc_ivc_binding_checksum_v1",
        "summary": "Binding demo only: per-row integrity checksum plus transcript binding for folded step labels.",
    },
}


def _app_policy_for_usecase(encoding_id: str) -> dict[str, Any]:
    policy = _POLICY_BY_ENCODING_ID.get(encoding_id)
    if policy is None:
        raise ValueError(f"unknown usecase encoding_id: {encoding_id}")
    return {
        "name": policy["name"],
        "encoding_id": encoding_id,
        "linear_constraint_coeffs": CHECKSUM_LINEAR_COEFFS,
        "linear_constraint_target": LINEAR_TARGET_ZERO,
        "verifier_semantics": policy["summary"],
    }


def context_digest(dst_label: str, *parts: Any) -> bytes:
    # Application-level binding; fed to proof_context_label like app.request_context_digest.
    return hashlib.sha512(cbor_encode([dst_label, *parts])).digest()


def label_to_u32(domain: str, value: str) -> int:
    """Stable 32-bit handle for labels used by the mechanics demos."""
    digest = hashlib.sha256(cbor_encode([domain, value])).digest()
    return int.from_bytes(digest[:4], "big")


def row_with_checksum(payload_u32s: list[int]) -> list[int]:
    if len(payload_u32s) != 8:
        raise ValueError("expected exactly eight 32-bit payload words")
    for i, w in enumerate(payload_u32s):
        if w < 0 or w >= (1 << 32):
            raise ValueError(f"payload word {i} out of uint32 range")
    checksum = sum(payload_u32s)
    if checksum < 0 or checksum >= (1 << 64):
        raise ValueError("checksum overflow for 64-bit limb (should not happen)")
    return payload_u32s + [checksum]


def pad_semantic_words(*words: int) -> list[int]:
    """
    Fill the eight checksum-demo payload coordinates with explicit semantic slots.

    This keeps the examples inside the linear checksum relation while avoiding the
    misleading "hash the whole application object into one opaque payload" pattern.
    """
    if len(words) > 8:
        raise ValueError("at most eight semantic words are supported")
    payload = list(words) + [0] * (8 - len(words))
    for i, w in enumerate(payload):
        if w < 0 or w >= (1 << 32):
            raise ValueError(f"semantic word {i} out of uint32 range")
    return payload


# ── Material dataclasses (must precede validate_* for clear reading order) ────


@dataclass
class LoginSessionMaterial:
    """Session proof-of-control inputs. Use stable string labels, not raw private keys."""

    session_pk_label: str = field(metadata={"user_help": "Fingerprint or label of the session public key (hash recommended)."})
    rp_id: str = field(metadata={"user_help": "Relying party / app id the user sees at login."})
    epoch: int = field(metadata={"user_help": "Unix time or counter slot; must fit in 32 bits for this encoding."})
    policy_flags: int = field(metadata={"user_help": "Small bitfield for MFA tier, step-up, etc. (32-bit)."})


@dataclass
class DelegationMaterial:
    child_pk_label: str = field(metadata={"user_help": "Child public key fingerprint or label."})
    scope_bits: int = field(metadata={"user_help": "Capability bitmask (32-bit)."})
    valid_from: int = field(metadata={"user_help": "Start of validity window (32-bit slot)."})
    valid_until: int = field(metadata={"user_help": "End of validity window (32-bit slot)."})
    parent_digest_label: str = field(metadata={"user_help": "Digest or label anchoring the parent authority."})


@dataclass
class CredentialMaterial:
    age_band: int = field(metadata={"user_help": "Encoded age bucket (not necessarily years)."})
    region_code: int = field(metadata={"user_help": "Region or jurisdiction code as agreed with issuer."})
    role_flags: int = field(metadata={"user_help": "Bitmask of roles."})
    predicate_selector: int = field(metadata={"user_help": "Which disclosure policy branch applies."})
    credential_root_label: str = field(metadata={"user_help": "Issuer credential Merkle root or stable id."})


@dataclass
class RevocationMaterial:
    nullifier_seed_label: str = field(metadata={"user_help": "Label derived from holder secret material (not raw sk on wire)."})
    use_counter: int = field(metadata={"user_help": "Monotonic or capped usage count."})
    epoch: int = field(metadata={"user_help": "Revocation / epoch window."})
    accumulator_handle_label: str = field(metadata={"user_help": "Digest of accumulator state or CRS handle."})


@dataclass
class AttestationMaterial:
    measurement_label: str = field(metadata={"user_help": "Device measurement or PCR-pack label."})
    firmware_id: str = field(metadata={"user_help": "Firmware or build id string."})
    app_measurement_label: str = field(metadata={"user_help": "App binary or version measurement label."})
    channel_transcript_label: str = field(metadata={"user_help": "Channel / session transcript binding label."})


@dataclass
class HandshakeBindingMaterial:
    transcript_label: str = field(metadata={"user_help": "Handshake transcript hash label (how you name the digest)."})
    sni_or_server_id: str = field(metadata={"user_help": "Server identity the user expects."})
    ephemeral_key_label: str = field(metadata={"user_help": "Ephemeral key fingerprint for this session."})
    client_binding_tag: str = field(metadata={"user_help": "OAuth state, DCAPI binding, or similar tag."})


def field_helps(cls: type) -> dict[str, str]:
    """Return {field_name: user_help} from dataclass metadata."""
    out: dict[str, str] = {}
    for f in fields(cls):
        h = f.metadata.get("user_help")
        if isinstance(h, str):
            out[f.name] = h
    return out


def material_schema_for_docs() -> dict[str, dict[str, str]]:
    """Per-flow material fields and short UX-oriented help (for docs or in-app tooltips)."""
    return {
        "LoginSessionMaterial": field_helps(LoginSessionMaterial),
        "DelegationMaterial": field_helps(DelegationMaterial),
        "CredentialMaterial": field_helps(CredentialMaterial),
        "RevocationMaterial": field_helps(RevocationMaterial),
        "AttestationMaterial": field_helps(AttestationMaterial),
        "HandshakeBindingMaterial": field_helps(HandshakeBindingMaterial),
        "IVC": {"step_roots": "Ordered Merkle roots or step labels, one event per entry.", "cycle_tag": "Batch or epoch name binding every step in the chain."},
    }


def _check_label(name: str, value: str) -> list[str]:
    err: list[str] = []
    if not value or not value.strip():
        err.append(f"{name} must be a non-empty string")
    elif len(value) > _MAX_LABEL_LEN:
        err.append(f"{name} exceeds max length {_MAX_LABEL_LEN}")
    return err


def _check_u32(name: str, value: int) -> list[str]:
    if value < 0 or value > _MAX_UINT32:
        return [f"{name} must fit in 32 bits (0..{_MAX_UINT32})"]
    return []


def validate_login_material(m: LoginSessionMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_label("session_pk_label", m.session_pk_label))
    e.extend(_check_label("rp_id", m.rp_id))
    e.extend(_check_u32("epoch", m.epoch))
    e.extend(_check_u32("policy_flags", m.policy_flags))
    return e


def validate_delegation_material(m: DelegationMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_label("child_pk_label", m.child_pk_label))
    e.extend(_check_u32("scope_bits", m.scope_bits))
    e.extend(_check_u32("valid_from", m.valid_from))
    e.extend(_check_u32("valid_until", m.valid_until))
    if m.valid_until < m.valid_from:
        e.append("valid_until must be >= valid_from")
    e.extend(_check_label("parent_digest_label", m.parent_digest_label))
    return e


def validate_credential_material(m: CredentialMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_u32("age_band", m.age_band))
    e.extend(_check_u32("region_code", m.region_code))
    e.extend(_check_u32("role_flags", m.role_flags))
    e.extend(_check_u32("predicate_selector", m.predicate_selector))
    e.extend(_check_label("credential_root_label", m.credential_root_label))
    return e


def validate_revocation_material(m: RevocationMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_label("nullifier_seed_label", m.nullifier_seed_label))
    e.extend(_check_u32("use_counter", m.use_counter))
    e.extend(_check_u32("epoch", m.epoch))
    e.extend(_check_label("accumulator_handle_label", m.accumulator_handle_label))
    return e


def validate_attestation_material(m: AttestationMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_label("measurement_label", m.measurement_label))
    e.extend(_check_label("firmware_id", m.firmware_id))
    e.extend(_check_label("app_measurement_label", m.app_measurement_label))
    e.extend(_check_label("channel_transcript_label", m.channel_transcript_label))
    return e


def validate_handshake_material(m: HandshakeBindingMaterial) -> list[str]:
    e: list[str] = []
    e.extend(_check_label("transcript_label", m.transcript_label))
    e.extend(_check_label("sni_or_server_id", m.sni_or_server_id))
    e.extend(_check_label("ephemeral_key_label", m.ephemeral_key_label))
    e.extend(_check_label("client_binding_tag", m.client_binding_tag))
    return e


def validate_ivc_inputs(step_roots: list[str], cycle_tag: str) -> list[str]:
    e: list[str] = []
    if not step_roots:
        e.append("step_roots must contain at least one label")
    for i, r in enumerate(step_roots):
        e.extend(_check_label(f"step_roots[{i}]", r))
    e.extend(_check_label("cycle_tag", cycle_tag))
    return e


@dataclass
class UsecaseResult:
    """Single use-case proof: cryptography + human-readable story + API metadata."""

    flow: ProtocolFlow
    story: UserProofStory
    integrator_metadata: dict[str, Any]

    def to_wallet_bundle(self) -> dict[str, Any]:
        return flow_to_wallet_bundle(self)

    def summary_json(self) -> dict[str, Any]:
        policy = _app_policy_for_usecase(self.flow.encoding_id)
        return {
            "scenario": self.story.scenario.value,
            "template_status": self.story.template_status,
            "title": self.story.title,
            "one_line": self.story.one_line,
            "encoding_id": self.flow.encoding_id,
            "policy_id": policy["name"],
            "N": self.flow.result.N,
            "d": self.flow.result.d,
            "proof_size_bytes": self.flow.result.proof_size_bytes,
            "link_ok": self.flow.result.link_verify_ok,
            "cons_ok": self.flow.result.cons_verify_ok,
            "integrator_metadata": self.integrator_metadata,
        }

    def summary_text(self) -> str:
        m = self.integrator_metadata
        lines = [
            f"[{self.story.scenario.value}] {self.story.title}",
            f"status={self.story.template_status}",
            self.story.one_line,
            "",
            f"encoding_id={self.flow.encoding_id}  N={self.flow.result.N}  "
            f"proof_bytes={self.flow.result.proof_size_bytes}",
        ]
        if m.get("user_visible_hints"):
            lines.append("")
            lines.append("Hints for UX copy:")
            for h in m["user_visible_hints"]:
                lines.append(f"  • {h}")
        return "\n".join(lines)


def _finalize_result(
    *,
    scenario: UsecaseScenario,
    flow: ProtocolFlow,
    integrator_metadata: dict[str, Any],
) -> UsecaseResult:
    policy = _app_policy_for_usecase(flow.encoding_id)
    meta = {
        **integrator_metadata,
        "coordinate_bit_lengths": COORD_BITS_USECASE,
        "policy_id": policy["name"],
        "verifier_semantics": policy["verifier_semantics"],
        "linear_policy": "row-integrity only: sum(first_eight_u32) == ninth_u64_checksum",
    }
    return UsecaseResult(flow=flow, story=_STORIES[scenario], integrator_metadata=meta)


def prove_usecase_flow(
    *,
    scenario: UsecaseScenario,
    encoding_id: str,
    proof_context_label: bytes,
    event_rows: list[list[int]],
    deterministic_seed: bytes | None = None,
    integrator_metadata: dict[str, Any] | None = None,
) -> UsecaseResult:
    if not encoding_id:
        raise ValueError("encoding_id required")
    policy = _app_policy_for_usecase(encoding_id)
    n = len(event_rows)
    for row in event_rows:
        if len(row) != D_USECASE:
            raise ValueError(f"each event row must have length {D_USECASE}")
    flow = run_protocol_flow(
        N=n,
        d=D_USECASE,
        include_nonlinear=False,
        event_values=event_rows,
        linear_constraint_coeffs=CHECKSUM_LINEAR_COEFFS,
        linear_constraint_target=LINEAR_TARGET_ZERO,
        coordinate_bit_lengths=COORD_BITS_USECASE,
        deterministic_seed=deterministic_seed,
        encoding_id=encoding_id,
        policy_id=policy["name"],
        proof_context_label=proof_context_label,
    )
    return _finalize_result(
        scenario=scenario,
        flow=flow,
        integrator_metadata=integrator_metadata or {},
    )


# ── 1) Login / proof-of-control ─────────────────────────────────────────────


def prove_login_session(
    m: LoginSessionMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_login_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid LoginSessionMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        label_to_u32("login:session_pk_label", m.session_pk_label),
        label_to_u32("login:rp_id", m.rp_id),
        m.epoch,
        m.policy_flags,
    )
    bind = context_digest(
        "NESSA-UC:v1:login",
        m.session_pk_label,
        m.rp_id,
        m.epoch,
        m.policy_flags,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.login,
        encoding_id="nessa_uc_login_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {
                "rp_id": m.rp_id,
                "epoch": m.epoch,
                "session_pk_label": m.session_pk_label[:48] + ("…" if len(m.session_pk_label) > 48 else ""),
            },
            "user_visible_hints": (
                f"Proof binds to “{m.rp_id}”, the current session label, and the transcript context you supplied.",
                "This demo does not prove the session is authenticated to the RP; your application must verify that externally.",
            ),
        },
    )


# ── 2) Delegation ────────────────────────────────────────────────────────────


def prove_delegation(
    m: DelegationMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_delegation_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid DelegationMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        label_to_u32("delegation:child_pk_label", m.child_pk_label),
        m.scope_bits,
        m.valid_from,
        m.valid_until,
        label_to_u32("delegation:parent_digest_label", m.parent_digest_label),
    )
    bind = context_digest(
        "NESSA-UC:v1:delegation",
        m.child_pk_label,
        m.scope_bits,
        m.valid_from,
        m.valid_until,
        m.parent_digest_label,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.delegation,
        encoding_id="nessa_uc_delegation_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {
                "child_pk_label": m.child_pk_label[:48],
                "valid_from": m.valid_from,
                "valid_until": m.valid_until,
            },
            "user_visible_hints": (
                "This demo binds the child label, scope bits, and validity window into the proof transcript.",
                "It does not prove the delegation is valid; your application must verify parent authorization externally.",
            ),
        },
    )


# ── 3) Credential ─────────────────────────────────────────────────────────────


def prove_selective_credential(
    m: CredentialMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_credential_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid CredentialMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        m.age_band,
        m.region_code,
        m.role_flags,
        m.predicate_selector,
        label_to_u32("credential:root_label", m.credential_root_label),
    )
    bind = context_digest(
        "NESSA-UC:v1:credential",
        m.age_band,
        m.region_code,
        m.role_flags,
        m.predicate_selector,
        m.credential_root_label,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.credential,
        encoding_id="nessa_uc_credential_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {
                "predicate_selector": m.predicate_selector,
                "credential_root_label": m.credential_root_label[:48],
            },
            "user_visible_hints": (
                "The verifier only gets a binding proof over packed attribute labels; raw attributes may stay off the wire if you use bands.",
                "This demo does not prove credential predicates such as “age ≥ 18”; your application must verify predicate meaning externally.",
            ),
        },
    )


# ── 4) Revocation ───────────────────────────────────────────────────────────


def prove_revocation_usage(
    m: RevocationMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_revocation_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid RevocationMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        label_to_u32("revocation:nullifier_seed_label", m.nullifier_seed_label),
        m.use_counter,
        m.epoch,
        label_to_u32("revocation:accumulator_handle_label", m.accumulator_handle_label),
    )
    bind = context_digest(
        "NESSA-UC:v1:revocation",
        m.nullifier_seed_label,
        m.use_counter,
        m.epoch,
        m.accumulator_handle_label,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.revocation,
        encoding_id="nessa_uc_revocation_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {
                "use_counter": m.use_counter,
                "epoch": m.epoch,
            },
            "user_visible_hints": (
                "Show remaining uses or epoch window in the UI only if your revocation service already checked them externally.",
                "This demo binds revocation-related labels but does not itself prove non-revocation or counter freshness.",
            ),
        },
    )


# ── 5) Attestation ────────────────────────────────────────────────────────────


def prove_device_attestation(
    m: AttestationMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_attestation_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid AttestationMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        label_to_u32("attestation:measurement_label", m.measurement_label),
        label_to_u32("attestation:firmware_id", m.firmware_id),
        label_to_u32("attestation:app_measurement_label", m.app_measurement_label),
        label_to_u32("attestation:channel_transcript_label", m.channel_transcript_label),
    )
    bind = context_digest(
        "NESSA-UC:v1:attest",
        m.measurement_label,
        m.firmware_id,
        m.app_measurement_label,
        m.channel_transcript_label,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.attestation,
        encoding_id="nessa_uc_attest_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {
                "firmware_id": m.firmware_id[:48],
                "channel_transcript_label": m.channel_transcript_label[:48],
            },
            "user_visible_hints": (
                "This demo binds measurement labels and channel context into the proof transcript.",
                "Do not claim the proof established device trustworthiness unless your attestation service verified it externally.",
            ),
        },
    )


# ── 6) Handshake binding ─────────────────────────────────────────────────────


def prove_handshake_binding(
    m: HandshakeBindingMaterial,
    *,
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_handshake_material(m) if strict_validate else []
    if errs:
        raise ValueError("invalid HandshakeBindingMaterial: " + "; ".join(errs))
    words = pad_semantic_words(
        label_to_u32("handshake:transcript_label", m.transcript_label),
        label_to_u32("handshake:server_id", m.sni_or_server_id),
        label_to_u32("handshake:ephemeral_key_label", m.ephemeral_key_label),
        label_to_u32("handshake:client_binding_tag", m.client_binding_tag),
    )
    bind = context_digest(
        "NESSA-UC:v1:tls",
        m.transcript_label,
        m.sni_or_server_id,
        m.ephemeral_key_label,
        m.client_binding_tag,
    )
    return prove_usecase_flow(
        scenario=UsecaseScenario.handshake,
        encoding_id="nessa_uc_tls_v1",
        proof_context_label=bind,
        event_rows=[row_with_checksum(words)],
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {"server": m.sni_or_server_id[:64]},
            "user_visible_hints": (
                f"Proof is bound to server label “{m.sni_or_server_id}” and your OAuth/TLS context labels.",
                "This demo does not prove server identity or certificate validity; your application must verify those externally.",
            ),
        },
    )


# ── 7) IVC chain ──────────────────────────────────────────────────────────────


def prove_ivc_step_chain(
    step_roots: list[str],
    *,
    cycle_tag: str = "default",
    deterministic_seed: bytes | None = None,
    strict_validate: bool = True,
) -> UsecaseResult:
    errs = validate_ivc_inputs(step_roots, cycle_tag) if strict_validate else []
    if errs:
        raise ValueError("invalid IVC inputs: " + "; ".join(errs))
    rows: list[list[int]] = []
    for idx, root in enumerate(step_roots):
        words = pad_semantic_words(
            idx,
            label_to_u32("ivc:cycle_tag", cycle_tag),
            label_to_u32("ivc:step_root", root),
        )
        rows.append(row_with_checksum(words))
    bind = context_digest("NESSA-UC:v1:ivc", cycle_tag, *step_roots)
    return prove_usecase_flow(
        scenario=UsecaseScenario.ivc,
        encoding_id="nessa_uc_ivc_v1",
        proof_context_label=bind,
        event_rows=rows,
        deterministic_seed=deterministic_seed,
        integrator_metadata={
            "material_preview": {"steps": len(step_roots), "cycle_tag": cycle_tag},
            "user_visible_hints": (
                f"This bundle folds {len(step_roots)} packed step labels into one verifier check.",
                "This demo does not prove the steps form a valid recursive computation; your application must verify step semantics externally.",
            ),
        },
    )


# ── User-facing facade (optional naming for app layers) ──────────────────────


class UsecaseClient:
    """
    Thin namespaced API for application code: same functions, reads like product copy.
    """

    login = staticmethod(prove_login_session)
    delegation = staticmethod(prove_delegation)
    credential = staticmethod(prove_selective_credential)
    revocation = staticmethod(prove_revocation_usage)
    attestation = staticmethod(prove_device_attestation)
    tls_handshake = staticmethod(prove_handshake_binding)
    ivc_chain = staticmethod(prove_ivc_step_chain)


# ── Verification helpers (mirror app.VerifyFolded wiring) ────────────────────


def _encode_tags_for_wire(tags: dict[int, object]) -> dict[str, object]:
    encoded: dict[str, object] = {}
    for key, value in tags.items():
        if isinstance(value, bytes):
            encoded[str(key)] = value.hex()
        else:
            encoded[str(key)] = value
    return encoded


def flow_folded_object(flow: ProtocolFlow) -> dict[str, Any]:
    return {
        "N": flow.result.N,
        "d": flow.result.d,
        "tags": _encode_tags_for_wire(flow.tags),
        "policy_compiled": flow.policy_compiled.hex(),
        "commitments": [p.hex() for p in flow.commitments],
        "tags_hash": flow.tags_hash.hex(),
        "final_root": flow.transcript_roots[-1].hex(),
        "C_star": flow.C_star.hex(),
        "V_list": [p.hex() for p in flow.V_list],
        "proof_context_label": flow.proof_context_label.hex(),
        "proof_size_bytes": flow.result.proof_size_bytes,
    }


def flow_proof_payload(flow: ProtocolFlow) -> dict[str, Any]:
    proof = flow.proof
    if proof.pi_cons_linear is None:
        raise ValueError("expected linear proof")
    return {
        "N": proof.N,
        "d": proof.d,
        "pi_link": {
            "T_commit": proof.pi_link.T_commit.hex(),
            "T_policy": [x.hex() for x in proof.pi_link.T_policy],
            "z_m": [x.hex() for x in proof.pi_link.z_m],
            "z_rho": [x.hex() for x in proof.pi_link.z_rho],
            "z_gamma": [x.hex() for x in proof.pi_link.z_gamma],
            "challenge": proof.pi_link.challenge.hex(),
        },
        "pi_cons_linear": {
            "T": proof.pi_cons_linear.T.hex(),
            "z": proof.pi_cons_linear.z.hex(),
            "challenge": proof.pi_cons_linear.challenge.hex(),
        },
    }


def verify_flow_locally(flow: ProtocolFlow) -> bool:
    return flow.result.link_verify_ok and flow.result.cons_verify_ok


def flow_to_wallet_bundle(flow: Union[ProtocolFlow, UsecaseResult]) -> dict[str, Any]:
    """
    Shape compatible with app.VerifyFolded(policy, folded_object, proof_payload).
    Accepts ProtocolFlow or UsecaseResult.
    """
    f = flow.flow if isinstance(flow, UsecaseResult) else flow
    return {
        "version": "nessa-usecase-demos-v1",
        "engine": "qFold-EC",
        "allowed": True,
        "reason_codes": [],
        "policy": _app_policy_for_usecase(f.encoding_id),
        "folded_object": flow_folded_object(f),
        "proof": flow_proof_payload(f),
        "user_summary": (flow.summary_json() if isinstance(flow, UsecaseResult) else None),
    }


def verify_flow_like_app(encoding_id: str, flow: ProtocolFlow) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    policy = _app_policy_for_usecase(encoding_id)
    d = flow.result.d
    tags_hash = compute_tags_hash(
        encoding_id=policy["encoding_id"],
        policy_id=policy["name"],
        d=d,
        policy_hash=flow.tags[7],
        k_rows=flow.tags[8],
        transcript_seed=flow.tags.get(9),
    )
    ts = build_transcript(flow.tags, flow.commitments)
    c_star = fold_commitments(flow.commitments, ts.alphas)
    if tags_hash != flow.tags_hash:
        reasons.append("tags_hash_mismatch")
    if ts.roots[-1] != flow.transcript_roots[-1]:
        reasons.append("transcript_root_mismatch")
    if c_star != flow.C_star:
        reasons.append("folded_commitment_mismatch")
    gens = derive_generators(d)
    link_ok = verify_link(
        flow.proof.pi_link,
        flow.C_star,
        flow.V_list,
        gens,
        flow.tags_hash,
        flow.transcript_roots[-1],
    )
    if not link_ok:
        reasons.append("pi_link_invalid")
    if flow.linear_constraint_W is None or flow.proof.pi_cons_linear is None:
        reasons.append("missing_linear_artifacts")
    else:
        cons_ok = verify_cons_linear(
            flow.proof.pi_cons_linear,
            flow.linear_constraint_W,
            gens["G_pol"],
            flow.tags_hash,
            flow.transcript_roots[-1],
            flow.tags[7],
        )
        if not cons_ok:
            reasons.append("pi_cons_linear_invalid")
    return not reasons, reasons


def deterministic_seed_for_demo(flow_name: str, deterministic: bool) -> bytes | None:
    if not deterministic:
        return None
    return hashlib.sha512(cbor_encode(["NESSA-UC:demo-seed:v1", flow_name])).digest()


def story_deterministic_seed(run_counter: int, step_key: str, prover_actor: str) -> bytes | None:
    """
    Per-step seed for multi-actor story runs so the same (run_counter, step, actor)
    tuple reproduces the same proof bytes (when other inputs match).
    """
    return hashlib.sha512(
        cbor_encode(["NESSA-UC:story-seed:v1", run_counter, step_key, prover_actor])
    ).digest()


def _story_interactive_pause(
    interactive: bool,
    print_func: Any,
    input_func: Any,
    *,
    at_keyboard: str,
    headline: str,
    detail: str = "",
) -> None:
    if not interactive:
        return
    print_func("")
    print_func("=" * 60)
    print_func(f">> [{at_keyboard}] {headline}")
    if detail:
        print_func(f"   {detail}")
    input_func("   [Enter] to continue… ")


def run_multi_user_story(
    cache_path: str | Path | None = None,
    *,
    deterministic: bool = True,
    interactive: bool = False,
    input_func: Any = input,
    print_func: Any = print,
) -> dict[str, Any]:
    """
    Execute a fixed multi-actor narrative using ``usecase_actor_cache`` (JSON on disk).

    Actors (defaults in cache file): alice (holder), bob (verifier), charlie (delegatee),
    dana (issuer), eve (TLS peer). Each run increments ``run_counter`` and appends to
    ``history`` in the JSON cache.

    With ``interactive=True``, prompts each role for fields (empty line keeps cache), then
    pauses before each proof so different people can drive the terminal in turn.

    Returns a report dict suitable for JSON logging; mutates and saves the cache file.
    """
    from usecase_actor_cache import (
        _actor,
        _rp_consistent,
        cache_path_from_arg,
        load_actor_cache,
        prompt_actor_cache_interactive,
        save_actor_cache,
    )

    path = cache_path_from_arg(cache_path)
    doc = load_actor_cache(path)

    if interactive:
        prompt_actor_cache_interactive(doc, path, input_func=input_func, print_func=print_func)

    doc["run_counter"] = int(doc.get("run_counter", 0)) + 1
    rc = doc["run_counter"]
    rp_ok = _rp_consistent(doc)

    alice = _actor(doc, "alice")
    bob = _actor(doc, "bob")
    charlie = _actor(doc, "charlie")
    dana = _actor(doc, "dana")
    eve = _actor(doc, "eve")

    def seed(step_key: str, prover: str) -> bytes | None:
        if not deterministic:
            return None
        return story_deterministic_seed(rc, step_key, prover)

    steps_out: list[dict[str, Any]] = []
    narrative: list[str] = [
        f"— Story run #{rc} (cache: {path}) —",
        f"{alice.get('display_name', 'alice')}: holder; {bob.get('display_name', 'bob')}: expects RP {bob.get('verifies_rp')}.",
        f"RP alignment check: {'ok' if rp_ok else 'MISMATCH — fix alice.rp_id vs bob.verifies_rp in cache'}.",
    ]
    if interactive:
        for line in narrative:
            print_func(line)
        _story_interactive_pause(
            True,
            print_func,
            input_func,
            at_keyboard="Everyone",
            headline="Cryptographic story steps",
            detail="Next: Alice (holder) will generate the login proof.",
        )

    epoch_login = 1_700_000_000 + (rc % 100_000)
    m_login = LoginSessionMaterial(
        str(alice["session_pk_label"]),
        str(alice["rp_id"]),
        epoch_login,
        int(alice.get("policy_flags", 0)),
    )
    _story_interactive_pause(
        interactive,
        print_func,
        input_func,
        at_keyboard=alice.get("display_name", "alice"),
        headline="Prove session login",
        detail=f"rp_id={alice['rp_id']!r}, epoch_slot={epoch_login}",
    )
    r_login = prove_login_session(m_login, deterministic_seed=seed("login", "alice"))
    ok_a, reasons_a = verify_flow_like_app(r_login.flow.encoding_id, r_login.flow)
    steps_out.append(
        {
            "step": "login",
            "prover": "alice",
            "verifier": "bob",
            "scenario": "session_proof",
            "encoding_id": r_login.flow.encoding_id,
            "epoch_used": epoch_login,
            "local_ok": verify_flow_locally(r_login.flow),
            "app_style_ok": ok_a,
            "reasons": reasons_a,
        }
    )
    narrative.append(
        f"[1] Alice proves login to {alice['rp_id']} (epoch slot {epoch_login}); "
        f"Bob can verify with the exported bundle. crypto_ok={ok_a}."
    )
    if interactive:
        print_func(narrative[-1])

    parent_digest = f"parent:{alice['session_pk_label']}:run-{rc}"
    _story_interactive_pause(
        interactive,
        print_func,
        input_func,
        at_keyboard=charlie.get("display_name", "charlie"),
        headline="Prove delegation from Alice’s line",
        detail=f"parent_digest suffix run-{rc}",
    )
    dm = DelegationMaterial(
        str(charlie["child_pk_label"]),
        int(charlie["scope_bits"]),
        int(charlie["valid_from"]),
        int(charlie["valid_until"]),
        parent_digest,
    )
    r_del = prove_delegation(dm, deterministic_seed=seed("delegation", "charlie"))
    ok_d, reasons_d = verify_flow_like_app(r_del.flow.encoding_id, r_del.flow)
    steps_out.append(
        {
            "step": "delegation",
            "prover": "charlie",
            "verifier": "bob",
            "scenario": "parent_to_child",
            "encoding_id": r_del.flow.encoding_id,
            "parent_digest_in_proof": parent_digest,
            "local_ok": verify_flow_locally(r_del.flow),
            "app_style_ok": ok_d,
            "reasons": reasons_d,
        }
    )
    narrative.append(
        f"[2] Charlie’s device is delegated under digest {parent_digest[:48]}…; crypto_ok={ok_d}."
    )
    if interactive:
        print_func(narrative[-1])

    _story_interactive_pause(
        interactive,
        print_func,
        input_func,
        at_keyboard=dana.get("display_name", "dana"),
        headline="Prove credential snapshot (issuer)",
        detail=f"root={dana.get('credential_root_label', '')[:40]}…",
    )
    cm = CredentialMaterial(
        int(dana["age_band"]),
        int(dana["region_code"]),
        int(dana["role_flags"]),
        int(dana["predicate_selector"]),
        str(dana["credential_root_label"]),
    )
    r_cred = prove_selective_credential(cm, deterministic_seed=seed("credential", "dana"))
    ok_c, reasons_c = verify_flow_like_app(r_cred.flow.encoding_id, r_cred.flow)
    steps_out.append(
        {
            "step": "credential",
            "prover": "dana",
            "verifier": "bob",
            "scenario": "selective_disclosure",
            "encoding_id": r_cred.flow.encoding_id,
            "local_ok": verify_flow_locally(r_cred.flow),
            "app_style_ok": ok_c,
            "reasons": reasons_c,
        }
    )
    narrative.append(
        f"[3] Dana’s issuer root anchors a credential snapshot for the verifier; crypto_ok={ok_c}."
    )
    if interactive:
        print_func(narrative[-1])

    _story_interactive_pause(
        interactive,
        print_func,
        input_func,
        at_keyboard=eve.get("display_name", "eve"),
        headline="Prove TLS / OAuth handshake binding",
        detail=f"SNI {eve.get('sni_or_server_id', '')!r}",
    )
    hm = HandshakeBindingMaterial(
        str(eve["transcript_label"]),
        str(eve["sni_or_server_id"]),
        str(eve["ephemeral_key_label"]),
        str(eve["client_binding_tag"]),
    )
    r_tls = prove_handshake_binding(hm, deterministic_seed=seed("tls", "eve"))
    ok_t, reasons_t = verify_flow_like_app(r_tls.flow.encoding_id, r_tls.flow)
    steps_out.append(
        {
            "step": "handshake",
            "prover": "eve",
            "verifier": "bob",
            "scenario": "tls_oauth_binding",
            "encoding_id": r_tls.flow.encoding_id,
            "local_ok": verify_flow_locally(r_tls.flow),
            "app_style_ok": ok_t,
            "reasons": reasons_t,
        }
    )
    narrative.append(
        f"[4] Eve’s handshake labels bind OAuth/TLS context to {eve['sni_or_server_id']}; crypto_ok={ok_t}."
    )
    if interactive:
        print_func(narrative[-1])

    _story_interactive_pause(
        interactive,
        print_func,
        input_func,
        at_keyboard=f"{alice.get('display_name', 'alice')} + {charlie.get('display_name', 'charlie')}",
        headline="Fold IVC chain (3 anchors)",
        detail="Combines session + delegate + run id.",
    )
    step_roots = [
        f"alice:{alice['session_pk_label']}",
        f"charlie:{charlie['child_pk_label']}",
        f"run:{rc}",
    ]
    r_ivc = prove_ivc_step_chain(
        step_roots,
        cycle_tag=f"story-batch-{rc}",
        deterministic_seed=seed("ivc", "alice-charlie"),
    )
    ok_i, reasons_i = verify_flow_like_app(r_ivc.flow.encoding_id, r_ivc.flow)
    steps_out.append(
        {
            "step": "ivc_chain",
            "prover": "alice+charlie",
            "verifier": "bob",
            "scenario": "folded_steps",
            "encoding_id": r_ivc.flow.encoding_id,
            "N": r_ivc.flow.result.N,
            "local_ok": verify_flow_locally(r_ivc.flow),
            "app_style_ok": ok_i,
            "reasons": reasons_i,
        }
    )
    narrative.append(
        f"[5] IVC-style fold over {len(step_roots)} anchors (N={r_ivc.flow.result.N}); crypto_ok={ok_i}."
    )
    if interactive:
        print_func(narrative[-1])

    all_ok = all(s["app_style_ok"] for s in steps_out) and rp_ok
    history_entry = {
        "run_id": rc,
        "rp_aligned": rp_ok,
        "all_crypto_ok": all_ok,
        "steps": steps_out,
    }
    hist = doc.setdefault("history", [])
    hist.append(history_entry)
    if len(hist) > 64:
        del hist[:-64]
    save_actor_cache(path, doc)

    return {
        "cache_path": str(path.resolve()),
        "run_id": rc,
        "rp_aligned": rp_ok,
        "all_crypto_ok": all_ok,
        "interactive": interactive,
        "narrative": narrative,
        "steps": steps_out,
        "proof_size_bytes": {
            "login": r_login.flow.result.proof_size_bytes,
            "delegation": r_del.flow.result.proof_size_bytes,
            "credential": r_cred.flow.result.proof_size_bytes,
            "handshake": r_tls.flow.result.proof_size_bytes,
            "ivc": r_ivc.flow.result.proof_size_bytes,
        },
    }


def integrator_checklist(result: UsecaseResult) -> list[tuple[str, str]]:
    """
    Ordered (phase, action) pairs for onboarding docs or wizard UI.
    """
    return [
        ("validate", "Reject empty labels and out-of-range 32-bit fields before proving."),
        ("commit", f"User approved scenario “{result.story.title}”; material preview in integrator_metadata."),
        ("prove", f"Produced π with N={result.flow.result.N}, d={result.flow.result.d}, encoding_id={result.flow.encoding_id}."),
        ("serialize", "Call to_wallet_bundle() and transmit folded_object + proof + policy to verifier."),
        ("verify", "Verifier runs the same transcript recompute and checks π_link, π_cons (see app.VerifyFolded)."),
        ("disclose", "Only show user_visible_hints in UI; do not paste raw commitments unless debugging."),
    ]


# ── CLI ─────────────────────────────────────────────────────────────────────


def run_all_demos(*, deterministic: bool = False) -> list[tuple[str, UsecaseResult]]:
    flows: list[tuple[str, UsecaseResult]] = []

    flows.append(
        (
            "login",
            prove_login_session(
                LoginSessionMaterial("pk:demo-session", "rp://payments", 1700000000, 0x10),
                deterministic_seed=deterministic_seed_for_demo("login", deterministic),
            ),
        )
    )
    flows.append(
        (
            "delegation",
            prove_delegation(
                DelegationMaterial("pk:child-42", 0x0F, 1, 2_000_000_000, "parent:alpha"),
                deterministic_seed=deterministic_seed_for_demo("delegation", deterministic),
            ),
        )
    )
    flows.append(
        (
            "credential",
            prove_selective_credential(
                CredentialMaterial(21, 404, 0x03, 1, "cred-root:issuer-9"),
                deterministic_seed=deterministic_seed_for_demo("credential", deterministic),
            ),
        )
    )
    flows.append(
        (
            "revocation",
            prove_revocation_usage(
                RevocationMaterial("null-seed:x", 2, 99, "acc:handle-1"),
                deterministic_seed=deterministic_seed_for_demo("revocation", deterministic),
            ),
        )
    )
    flows.append(
        (
            "attestation",
            prove_device_attestation(
                AttestationMaterial(
                    "tpm:pcr-pack",
                    "fw:build-77",
                    "app:binary-abc",
                    "ch:transcript-xyz",
                ),
                deterministic_seed=deterministic_seed_for_demo("attestation", deterministic),
            ),
        )
    )
    flows.append(
        (
            "handshake",
            prove_handshake_binding(
                HandshakeBindingMaterial(
                    "tls:hs:sha256-label",
                    "svc.example.com",
                    "ek:client-eph",
                    "bind:oauth-state",
                ),
                deterministic_seed=deterministic_seed_for_demo("handshake", deterministic),
            ),
        )
    )
    flows.append(
        (
            "ivc",
            prove_ivc_step_chain(
                ["stepA-root", "stepB-root", "stepC-root"],
                cycle_tag="batch-1",
                deterministic_seed=deterministic_seed_for_demo("ivc", deterministic),
            ),
        )
    )
    return flows


def _argv_get_path(args: list[str], flag: str) -> Path | None:
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 >= len(args) or args[i + 1].startswith("-"):
        raise SystemExit(f"{flag} requires a path argument")
    return Path(args[i + 1])


def main(argv: list[str] | None = None) -> int:
    # When embedded (e.g. app.py), pass only the flags: ["--deterministic", "-v"].
    args = list(argv) if argv is not None else sys.argv[1:]
    if "--help" in args or "-h" in args:
        print("usage: usecase_flows.py [--deterministic] [--verbose|-v] [--json-summary] [--story]")
        print("                        [--init-actor-cache [--actor-cache PATH] [--force]]")
        print("                        [--multi-user-story [--actor-cache PATH] [--deterministic]")
        print("                         [--json-summary] [--interactive|-i]]")
        print()
        print("Run the NESSA qFold-EC demo flows and print summaries, stories, or actor-cache narratives.")
        print("Default actor cache path: docs/generated/usecase_flows/actor_cache/nessa_usecase_actors.json")
        return 0
    deterministic = "--deterministic" in args
    verbose = "--verbose" in args or "-v" in args
    json_summary = "--json-summary" in args
    first_story_only = "--story" in args
    init_cache = "--init-actor-cache" in args
    multi_story = "--multi-user-story" in args
    cache_path_arg = _argv_get_path(args, "--actor-cache")

    if init_cache:
        from usecase_actor_cache import cache_path_from_arg, init_actor_cache

        p = cache_path_from_arg(cache_path_arg)
        overwrite = "--force" in args
        init_actor_cache(p, overwrite=overwrite)
        print(f"Wrote default actor cache to {p.resolve()}")
        print("Edit JSON to change actors; re-run with --multi-user-story.")
        return 0

    if multi_story:
        from usecase_actor_cache import cache_path_from_arg, init_actor_cache

        interactive = "--interactive" in args or "-i" in args
        p = cache_path_from_arg(cache_path_arg)
        if not p.is_file():
            if interactive:
                print(f"No cache at {p}; writing defaults for interactive session.")
                init_actor_cache(p, overwrite=False)
            else:
                print(f"Cache missing: {p}\nRun:  python usecase_flows.py --init-actor-cache [--actor-cache PATH]")
                return 1
        report = run_multi_user_story(
            p,
            deterministic=deterministic,
            interactive=interactive,
        )
        if not interactive:
            for line in report["narrative"]:
                print(line)
            print()
        if json_summary:
            out = {k: v for k, v in report.items() if k != "narrative"}
            print(json.dumps(out, indent=2))
        else:
            print(
                f"run_id={report['run_id']}  all_crypto_ok={report['all_crypto_ok']}  "
                f"rp_aligned={report['rp_aligned']}"
            )
            print(f"proof_size_bytes: {report['proof_size_bytes']}")
            print(f"cache updated: {report['cache_path']}")
            if interactive:
                print("(interactive) Each role was prompted for fields; proofs ran after per-step [Enter].")
        return 0

    print("NESSA qFold-EC use-case demos (binding / packing checksum demos, d=9)")
    print("See NESSA-qfold-applications-intuition.md for PQ vs EC scope.")
    print(
        "Flags: --deterministic  --verbose|-v  --json-summary  --story  "
        "--init-actor-cache [--actor-cache PATH] [--force]  "
        "--multi-user-story [--actor-cache PATH] [--deterministic] [--json-summary] "
        "[--interactive|-i]\n"
    )

    if first_story_only:
        _, first = run_all_demos(deterministic=deterministic)[0]
        print(first.story.as_markdown())
        return 0

    summaries: list[dict[str, Any]] = []
    for name, result in run_all_demos(deterministic=deterministic):
        flow = result.flow
        enc = flow.encoding_id
        ok_local = verify_flow_locally(flow)
        ok_app, reasons = verify_flow_like_app(enc, flow)
        summaries.append(result.summary_json() | {"flow_key": name, "app_style_ok": ok_app, "reasons": reasons})
        if json_summary:
            continue
        print(
            f"{name:12}  N={flow.result.N}  proof_bytes={flow.result.proof_size_bytes}  "
            f"local_ok={ok_local}  app_style_ok={ok_app}"
        )
        if not ok_app:
            print(f"              reasons: {reasons}")
        if verbose:
            print(result.summary_text())
            print("  Integrator checklist:")
            for phase, action in integrator_checklist(result):
                print(f"    [{phase}] {action}")
            print()

    if json_summary:
        print(json.dumps(summaries, indent=2))

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
