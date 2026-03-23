#!/usr/bin/env python3
"""
ASC-inspired privacy-preserving ad metadata demo for NESSA qFold-EC.

This module provides a prover flow (user-centric wallet) and verifier flow
(ad/data feed harvester) with weighted metadata proofs, nullifier-based Sybil
resistance checks, deterministic benchmarking, and report generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL_DIR = ROOT / "impl"
if str(IMPL_DIR) not in sys.path:
    sys.path.insert(0, str(IMPL_DIR))

sys.path.insert(0, str(ROOT))
from artifact_layout import ASC_AD_AUDIT_DIR, ASC_AD_REPORTS_DIR
from app import VerifyFolded
from nessa_qfold import cbor_encode, run_protocol_flow
from usecase_flows import (
    CHECKSUM_LINEAR_COEFFS,
    COORD_BITS_USECASE,
    D_USECASE,
    LINEAR_TARGET_ZERO,
    flow_folded_object,
    flow_proof_payload,
    row_with_checksum,
)

ASC_DEMO_VERSION = "nessa-asc-ad-demo-v1"
ASC_ENGINE = "qFold-EC"
ASC_ENCODING_ID = "nessa_asc_ad_v1"

MAX_UINT32 = (1 << 32) - 1

ATTRIBUTE_FIELDS = (
    "age_band",
    "interest_code",
    "location_tier",
    "device_class",
    "browsing_segment",
    "income_bracket",
    "engagement_level",
    "consent_flags",
)

WEIGHT_PROFILES: dict[str, tuple[int, int, int, int, int, int, int, int]] = {
    "luxury_targeting": (1, 1, 1, 1, 1, 4, 3, 1),
    "local_business": (1, 3, 4, 1, 1, 1, 1, 1),
    "broad_reach": (2, 2, 2, 2, 2, 2, 2, 2),
    "behavioral_retarget": (1, 1, 1, 1, 4, 1, 4, 1),
    "consent_gated": (1, 1, 1, 1, 1, 1, 1, 5),
}

SCALE_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]

REASON_POLICY_CONTEXT_MISMATCH = "campaign_policy_mismatch"
REASON_REQUEST_CONTEXT_MISMATCH = "request_context_mismatch"
REASON_REQUEST_CONTEXT_INVALID = "request_context_invalid"
REASON_PROOF_CONTEXT_MISSING = "proof_context_missing"
REASON_PROOF_CONTEXT_INVALID = "proof_context_invalid"
REASON_ASC_META_MISSING = "asc_meta_missing"
REASON_ASC_META_MALFORMED = "asc_meta_malformed"

PROVER_POLICY_DENIAL_REASONS = {
    "metadata_missing",
    "consent_mask_missing",
    "age_band_below_minimum",
}

PSEUDONYM_SCOPE_VERIFIER = "per_verifier"
PSEUDONYM_SCOPE_CAMPAIGN_WINDOW = "per_campaign_window"

DEFAULT_PSEUDONYM_SCOPE = PSEUDONYM_SCOPE_VERIFIER

ROOT_ARTIFACT_FILENAMES = {
    "artifact_manifest": "asc_ad_artifact_manifest.json",
    "dataset_users": "asc_ad_dataset_users.json",
    "campaigns": "asc_ad_campaigns.json",
    "focused_proofs": "asc_ad_focused_proofs.json",
    "focused_verifications": "asc_ad_focused_verifications.json",
    "focused_matrix": "asc_ad_focused_matrix.json",
    "generated_content": "asc_ad_generated_content.json",
    "test_metadata": "asc_ad_test_metadata.json",
    "privacy_audit": "asc_ad_privacy_audit.json",
    "business_summary": "asc_ad_business_summary.json",
    "reach_summary": "asc_ad_reach_summary.json",
    "benchmark_rows": "asc_ad_benchmark_rows.json",
    "benchmark_validity": "asc_ad_benchmark_validity.json",
    "asc_ad_report": "asc_ad_report.json",
}


@dataclass(frozen=True)
class AdMetadataProfile:
    age_band: int
    interest_code: int
    location_tier: int
    device_class: int
    browsing_segment: int
    income_bracket: int
    engagement_level: int
    consent_flags: int

    def payload_words(self) -> list[int]:
        return [
            self.age_band,
            self.interest_code,
            self.location_tier,
            self.device_class,
            self.browsing_segment,
            self.income_bracket,
            self.engagement_level,
            self.consent_flags,
        ]


@dataclass(frozen=True)
class AdCampaign:
    campaign_id: str
    verifier_id: str
    campaign_window: str
    weight_profile: str
    required_consent_mask: int = 0
    min_age_band: int = 0
    pseudonym_scope: str = DEFAULT_PSEUDONYM_SCOPE

    def weight_vector(self) -> tuple[int, int, int, int, int, int, int, int]:
        if self.weight_profile not in WEIGHT_PROFILES:
            raise ValueError(f"unknown weight profile: {self.weight_profile}")
        return WEIGHT_PROFILES[self.weight_profile]

    def policy_id(self) -> str:
        return f"nessa_asc_ad_{self.weight_profile}_checksum_v1"

    def policy_name_for_context(self, context_digest: bytes | str | None = None) -> str:
        if context_digest is None:
            return self.policy_id()
        digest_bytes = context_digest if isinstance(context_digest, bytes) else bytes.fromhex(context_digest)
        anchor = hashlib.sha256(digest_bytes).hexdigest()
        return f"{self.policy_id()}:ctx:{anchor}"

    def policy_payload(self, *, context_digest: bytes | str | None = None) -> dict[str, Any]:
        return {
            "name": self.policy_name_for_context(context_digest),
            "encoding_id": ASC_ENCODING_ID,
            "linear_constraint_coeffs": list(CHECKSUM_LINEAR_COEFFS),
            "linear_constraint_target": LINEAR_TARGET_ZERO,
            "campaign_id": self.campaign_id,
            "weight_profile": self.weight_profile,
            "pseudonym_scope": self.pseudonym_scope,
            "verifier_semantics": "ad metadata binding checksum demo (row integrity + transcript binding)",
        }


@dataclass
class AdVerificationReceipt:
    campaign_id: str
    accepted: bool
    reason_codes: list[str]
    verify_ms: float
    proof_size_bytes: int
    pseudonym: str
    nullifier: str
    proof_valid: bool
    eligibility_valid: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SyntheticUser:
    user_label: str
    segment: str
    metadata: AdMetadataProfile


def _stable_u32(*parts: Any) -> int:
    digest = hashlib.sha256(cbor_encode(list(parts))).digest()
    return int.from_bytes(digest[:4], "big")


def _stable_digest(*parts: Any) -> bytes:
    return hashlib.sha512(cbor_encode(list(parts))).digest()


def _is_hex(text: str, length: int | None = None) -> bool:
    if not isinstance(text, str):
        return False
    if length is not None and len(text) != length:
        return False
    try:
        bytes.fromhex(text)
        return True
    except ValueError:
        return False


def _context_digest_for_bundle(
    campaign: AdCampaign,
    *,
    pseudonym: str,
    nullifier: str,
    row_count: int,
) -> bytes:
    return _stable_digest(
        "NESSA-ASC:context",
        campaign.campaign_id,
        campaign.verifier_id,
        campaign.campaign_window,
        campaign.weight_profile,
        campaign.pseudonym_scope,
        pseudonym,
        nullifier,
        row_count,
    )


def validate_metadata_profile(profile: AdMetadataProfile) -> list[str]:
    errors: list[str] = []
    values = profile.payload_words()
    for name, value in zip(ATTRIBUTE_FIELDS, values):
        if not isinstance(value, int):
            errors.append(f"{name} must be an integer")
            continue
        if value < 0 or value > MAX_UINT32:
            errors.append(f"{name} must fit in uint32")

    if not (0 <= profile.age_band <= 15):
        errors.append("age_band must be in [0, 15]")
    if not (0 <= profile.location_tier <= 7):
        errors.append("location_tier must be in [0, 7]")
    if not (0 <= profile.device_class <= 7):
        errors.append("device_class must be in [0, 7]")
    if not (0 <= profile.income_bracket <= 15):
        errors.append("income_bracket must be in [0, 15]")
    if not (0 <= profile.engagement_level <= 100):
        errors.append("engagement_level must be in [0, 100]")
    if profile.consent_flags > 0xFFFF:
        errors.append("consent_flags must fit in 16 bits")
    return errors


def validate_profile_for_campaign(profile: AdMetadataProfile, campaign: AdCampaign) -> list[str]:
    errors = validate_metadata_profile(profile)
    if campaign.required_consent_mask:
        if (profile.consent_flags & campaign.required_consent_mask) != campaign.required_consent_mask:
            errors.append("consent_mask_missing")
    if campaign.min_age_band and profile.age_band < campaign.min_age_band:
        errors.append("age_band_below_minimum")
    return errors


def build_weighted_event_rows(
    profile: AdMetadataProfile,
    campaign: AdCampaign,
    *,
    target_rows: int | None = None,
) -> list[list[int]]:
    payload = profile.payload_words()
    weights = campaign.weight_vector()

    def _focus_rows(row_count: int) -> list[list[int]]:
        rows: list[list[int]] = []
        for idx, repeats in enumerate(weights):
            for rep in range(int(repeats)):
                words = payload[:]
                value = payload[idx]
                if repeats > 1 and value > 0:
                    focused = (value * (rep + 1) + repeats - 1) // repeats
                    words[idx] = min(MAX_UINT32, focused)
                rows.append(row_with_checksum(words))
        if len(rows) == row_count:
            return rows
        if len(rows) > row_count:
            return rows[:row_count]
        out = rows[:]
        while len(out) < row_count:
            needed = row_count - len(out)
            out.extend(rows[:needed])
        return out

    if target_rows is None:
        return _focus_rows(sum(weights))

    if target_rows < 1:
        raise ValueError("target_rows must be >= 1")

    # Benchmark path: fixed row-count requested by caller.
    # Keep full-profile rows to preserve business semantics while scaling N.
    return [row_with_checksum(payload[:]) for _ in range(target_rows)]


REDACTED_FIELDS = {
    "prover_identity",
    "raw_profile",
    "user_secret_digest",
}


class AdPrivacyRedactor:
    def __init__(self, extra_fields: set[str] | None = None):
        self.strip_fields = REDACTED_FIELDS | (extra_fields or set())

    def redact(self, bundle: dict[str, Any]) -> dict[str, Any]:
        redacted = json.loads(json.dumps(bundle))
        for key in list(redacted.keys()):
            if key in self.strip_fields:
                del redacted[key]

        summary = redacted.get("user_summary")
        if isinstance(summary, dict):
            meta = summary.get("integrator_metadata")
            if isinstance(meta, dict):
                meta.pop("raw_profile", None)
                meta.pop("prover_identity", None)
                meta.pop("user_label", None)
                meta.pop("device_label", None)

        folded_object = redacted.get("folded_object")
        if isinstance(folded_object, dict):
            folded_object.pop("material_preview", None)
            folded_object.pop("selected_row_count", None)

        return redacted

    def audit_report(self, original: dict[str, Any], redacted: dict[str, Any]) -> list[str]:
        report: list[str] = []
        for field in sorted(self.strip_fields):
            if field in original and field not in redacted:
                report.append(f"redacted {field}")

        orig_meta = (
            original.get("user_summary", {})
            .get("integrator_metadata", {})
            if isinstance(original.get("user_summary"), dict)
            else {}
        )
        red_meta = (
            redacted.get("user_summary", {})
            .get("integrator_metadata", {})
            if isinstance(redacted.get("user_summary"), dict)
            else {}
        )
        for field in ("raw_profile", "prover_identity", "user_label", "device_label"):
            if field in orig_meta and field not in red_meta:
                report.append(f"redacted user_summary.integrator_metadata.{field}")
        return report


class AdProverWallet:
    def __init__(
        self,
        user_label: str,
        device_label: str,
        user_secret: bytes,
        *,
        redactor: AdPrivacyRedactor | None = None,
    ):
        self.user_label = user_label
        self.device_label = device_label
        self.user_secret = user_secret
        self.redactor = redactor or AdPrivacyRedactor()
        self.metadata: AdMetadataProfile | None = None

    @classmethod
    def create(
        cls,
        user_label: str,
        device_label: str,
        *,
        deterministic_secret: bool = False,
    ) -> "AdProverWallet":
        if deterministic_secret:
            user_secret = _stable_digest("NESSA-ASC:wallet-secret", user_label, device_label)
        else:
            user_secret = secrets.token_bytes(32)
        return cls(user_label, device_label, user_secret)

    def set_metadata(self, profile: AdMetadataProfile) -> None:
        errors = validate_metadata_profile(profile)
        if errors:
            raise ValueError("invalid AdMetadataProfile: " + "; ".join(errors))
        self.metadata = profile

    def generate_pseudonym(
        self,
        verifier_id: str,
        *,
        campaign_window: str | None = None,
        scope: str = DEFAULT_PSEUDONYM_SCOPE,
    ) -> str:
        scope_part = verifier_id
        if scope == PSEUDONYM_SCOPE_CAMPAIGN_WINDOW:
            scope_part = f"{verifier_id}|{campaign_window or ''}"
        return hashlib.sha256(
            cbor_encode(["NESSA-ASC:pseudonym", self.user_secret.hex(), scope_part, scope])
        ).hexdigest()

    def generate_nullifier(self, campaign_id: str, verifier_id: str, campaign_window: str) -> str:
        return hashlib.sha256(
            cbor_encode(
                [
                    "NESSA-ASC:nullifier",
                    self.user_secret.hex(),
                    campaign_id,
                    verifier_id,
                    campaign_window,
                ]
            )
        ).hexdigest()

    def _context_digest(self, campaign: AdCampaign, pseudonym: str, nullifier: str, row_count: int) -> bytes:
        return _context_digest_for_bundle(
            campaign,
            pseudonym=pseudonym,
            nullifier=nullifier,
            row_count=row_count,
        )

    def _deterministic_seed(
        self,
        campaign: AdCampaign,
        *,
        deterministic: bool,
        deterministic_seed: bytes | None,
        row_count: int,
    ) -> bytes | None:
        if not deterministic:
            return None
        if deterministic_seed is not None:
            return deterministic_seed
        return _stable_digest(
            "NESSA-ASC:det-seed",
            self.user_label,
            self.device_label,
            campaign.campaign_id,
            campaign.campaign_window,
            campaign.weight_profile,
            row_count,
        )

    def _denied_bundle(
        self,
        campaign: AdCampaign,
        *,
        reasons: list[str],
        pseudonym: str,
        nullifier: str,
    ) -> dict[str, Any]:
        return {
            "version": ASC_DEMO_VERSION,
            "engine": ASC_ENGINE,
            "allowed": False,
            "reason_codes": reasons,
            "policy": campaign.policy_payload(),
            "request": {
                "campaign_id": campaign.campaign_id,
                "verifier": campaign.verifier_id,
                "context_digest": "",
            },
            "asc_meta": {
                "campaign_id": campaign.campaign_id,
                "verifier_id": campaign.verifier_id,
                "campaign_window": campaign.campaign_window,
                "weight_profile": campaign.weight_profile,
                "pseudonym_scope": campaign.pseudonym_scope,
                "pseudonym": pseudonym,
                "nullifier": nullifier,
                "row_count": 0,
            },
        }

    def prove_targeting(
        self,
        campaign: AdCampaign,
        *,
        deterministic: bool = False,
        deterministic_seed: bytes | None = None,
        target_rows: int | None = None,
    ) -> dict[str, Any]:
        pseudonym = self.generate_pseudonym(
            campaign.verifier_id,
            campaign_window=campaign.campaign_window,
            scope=campaign.pseudonym_scope,
        )
        nullifier = self.generate_nullifier(
            campaign.campaign_id,
            campaign.verifier_id,
            campaign.campaign_window,
        )

        if self.metadata is None:
            return self._denied_bundle(
                campaign,
                reasons=["metadata_missing"],
                pseudonym=pseudonym,
                nullifier=nullifier,
            )

        validation_errors = validate_profile_for_campaign(self.metadata, campaign)
        if validation_errors:
            return self._denied_bundle(
                campaign,
                reasons=validation_errors,
                pseudonym=pseudonym,
                nullifier=nullifier,
            )

        rows = build_weighted_event_rows(self.metadata, campaign, target_rows=target_rows)
        context_digest = self._context_digest(campaign, pseudonym, nullifier, len(rows))
        policy_payload = campaign.policy_payload(context_digest=context_digest)
        seed = self._deterministic_seed(
            campaign,
            deterministic=deterministic,
            deterministic_seed=deterministic_seed,
            row_count=len(rows),
        )

        t0 = time.perf_counter()
        flow = run_protocol_flow(
            N=len(rows),
            d=D_USECASE,
            include_nonlinear=False,
            event_values=rows,
            linear_constraint_coeffs=list(CHECKSUM_LINEAR_COEFFS),
            linear_constraint_target=LINEAR_TARGET_ZERO,
            coordinate_bit_lengths=list(COORD_BITS_USECASE),
            deterministic_seed=seed,
            encoding_id=ASC_ENCODING_ID,
            policy_id=policy_payload["name"],
            proof_context_label=context_digest,
        )
        prove_ms = (time.perf_counter() - t0) * 1000

        folded = flow_folded_object(flow)
        folded["weight_profile"] = campaign.weight_profile
        folded["selected_row_count"] = len(rows)
        folded["material_preview"] = {
            "age_band": self.metadata.age_band,
            "location_tier": self.metadata.location_tier,
            "engagement_level": self.metadata.engagement_level,
            "consent_flags": self.metadata.consent_flags,
        }

        bundle = {
            "version": ASC_DEMO_VERSION,
            "engine": ASC_ENGINE,
            "allowed": True,
            "reason_codes": [],
            "policy": policy_payload,
            "request": {
                "campaign_id": campaign.campaign_id,
                "verifier": campaign.verifier_id,
                "context_digest": context_digest.hex(),
            },
            "folded_object": folded,
            "proof": flow_proof_payload(flow),
            "asc_meta": {
                "campaign_id": campaign.campaign_id,
                "verifier_id": campaign.verifier_id,
                "campaign_window": campaign.campaign_window,
                "weight_profile": campaign.weight_profile,
                "pseudonym_scope": campaign.pseudonym_scope,
                "pseudonym": pseudonym,
                "nullifier": nullifier,
                "row_count": len(rows),
                "timings": {
                    "commit_ms": flow.result.commit_ms,
                    "transcript_ms": flow.result.transcript_ms,
                    "fold_ms": flow.result.fold_ms,
                    "prove_core_ms": flow.result.total_prove_ms,
                    "verify_core_ms": flow.result.total_verify_ms,
                    "prove_end_to_end_ms": prove_ms,
                },
            },
            "user_summary": {
                "title": "ASC ad metadata targeting proof",
                "one_line": "User proves campaign-bound metadata integrity without revealing identity.",
                "integrator_metadata": {
                    "campaign_id": campaign.campaign_id,
                    "weight_profile": campaign.weight_profile,
                    "row_count": len(rows),
                    "raw_profile": asdict(self.metadata),
                    "prover_identity": {
                        "user_label": self.user_label,
                        "device_label": self.device_label,
                    },
                },
            },
            "prover_identity": {
                "user_label": self.user_label,
                "device_label": self.device_label,
            },
            "raw_profile": asdict(self.metadata),
            "user_secret_digest": hashlib.sha256(self.user_secret).hexdigest(),
        }
        return bundle

    def redact_for_wire(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return self.redactor.redact(bundle)


class AdVerifier:
    def __init__(self, campaigns: list[AdCampaign] | None = None):
        self.campaigns: dict[str, AdCampaign] = {}
        self.seen_nullifiers: set[str] = set()
        self.impression_counts: dict[str, int] = {}
        self.receipts: list[AdVerificationReceipt] = []
        self.reason_counts: dict[str, int] = {}
        if campaigns:
            for campaign in campaigns:
                self.register_campaign(campaign)

    def register_campaign(self, campaign: AdCampaign) -> None:
        self.campaigns[campaign.campaign_id] = campaign

    def _validate_allowed_envelope(
        self,
        bundle: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        reasons: list[str] = []
        asc_meta_raw = bundle.get("asc_meta")
        if not isinstance(asc_meta_raw, dict):
            return None, [REASON_ASC_META_MISSING]

        required_fields: dict[str, type] = {
            "campaign_id": str,
            "verifier_id": str,
            "campaign_window": str,
            "weight_profile": str,
            "pseudonym_scope": str,
            "pseudonym": str,
            "nullifier": str,
            "row_count": int,
        }
        for key, expected_type in required_fields.items():
            if key not in asc_meta_raw:
                reasons.append(f"{REASON_ASC_META_MALFORMED}:{key}_missing")
                continue
            if not isinstance(asc_meta_raw[key], expected_type):
                reasons.append(f"{REASON_ASC_META_MALFORMED}:{key}_type")
                continue
            if key == "row_count" and isinstance(asc_meta_raw[key], bool):
                reasons.append(f"{REASON_ASC_META_MALFORMED}:{key}_type")

        if reasons:
            return None, reasons

        asc_meta = dict(asc_meta_raw)
        if not _is_hex(asc_meta["pseudonym"], 64):
            reasons.append(f"{REASON_ASC_META_MALFORMED}:pseudonym_hex")
        if not _is_hex(asc_meta["nullifier"], 64):
            reasons.append(f"{REASON_ASC_META_MALFORMED}:nullifier_hex")
        if asc_meta["row_count"] < 1:
            reasons.append(f"{REASON_ASC_META_MALFORMED}:row_count")

        req = bundle.get("request")
        if not isinstance(req, dict):
            reasons.append(REASON_REQUEST_CONTEXT_INVALID)
        else:
            context_hex = req.get("context_digest")
            if not isinstance(context_hex, str) or not _is_hex(context_hex, 128):
                reasons.append(REASON_REQUEST_CONTEXT_INVALID)

        folded = bundle.get("folded_object")
        if not isinstance(folded, dict):
            reasons.append(REASON_PROOF_CONTEXT_MISSING)
        else:
            proof_context = folded.get("proof_context_label")
            if not isinstance(proof_context, str) or not _is_hex(proof_context, 128):
                reasons.append(REASON_PROOF_CONTEXT_INVALID)

        if reasons:
            return None, reasons
        return asc_meta, reasons

    def check_nullifier(self, nullifier: str) -> bool:
        return nullifier not in self.seen_nullifiers

    def record_impression(self, campaign_id: str, pseudonym: str) -> None:
        key = f"{campaign_id}:{pseudonym}"
        self.impression_counts[key] = self.impression_counts.get(key, 0) + 1

    def _record_receipt(self, receipt: AdVerificationReceipt) -> None:
        self.receipts.append(receipt)
        for reason in receipt.reason_codes:
            self.reason_counts[reason] = self.reason_counts.get(reason, 0) + 1

    def verify_targeting(self, bundle: dict[str, Any], campaign_id: str) -> AdVerificationReceipt:
        started = time.perf_counter()
        reasons: list[str] = []
        details: dict[str, Any] = {}
        proof_valid = False
        eligibility_valid = False

        campaign = self.campaigns.get(campaign_id)
        if campaign is None:
            receipt = AdVerificationReceipt(
                campaign_id=campaign_id,
                accepted=False,
                reason_codes=["unknown_campaign"],
                verify_ms=(time.perf_counter() - started) * 1000,
                proof_size_bytes=0,
                pseudonym="",
                nullifier="",
                proof_valid=False,
                eligibility_valid=False,
            )
            self._record_receipt(receipt)
            return receipt

        asc_meta = bundle.get("asc_meta", {}) if isinstance(bundle.get("asc_meta"), dict) else {}
        pseudonym = str(asc_meta.get("pseudonym", ""))
        nullifier = str(asc_meta.get("nullifier", ""))
        proof_size = int(bundle.get("folded_object", {}).get("proof_size_bytes", 0)) if isinstance(bundle.get("folded_object"), dict) else 0

        if not bundle.get("allowed", False):
            raw_reasons = bundle.get("reason_codes", [])
            if isinstance(raw_reasons, list) and raw_reasons:
                reasons.extend(str(x) for x in raw_reasons)
            else:
                reasons.append("prover_denied")
            eligibility_valid = False
            proof_valid = False
        else:
            validated_meta, envelope_reasons = self._validate_allowed_envelope(bundle)
            if envelope_reasons:
                reasons.extend(envelope_reasons)
                validated_meta = None

            if validated_meta is not None:
                asc_meta = validated_meta
                pseudonym = asc_meta["pseudonym"]
                nullifier = asc_meta["nullifier"]

            if asc_meta.get("campaign_id") != campaign_id:
                reasons.append("campaign_id_mismatch")
            if asc_meta.get("verifier_id") != campaign.verifier_id:
                reasons.append("verifier_id_mismatch")
            if asc_meta.get("campaign_window") != campaign.campaign_window:
                reasons.append("campaign_window_mismatch")
            if asc_meta.get("weight_profile") != campaign.weight_profile:
                reasons.append("weight_profile_mismatch")
            if asc_meta.get("pseudonym_scope") != campaign.pseudonym_scope:
                reasons.append("pseudonym_scope_mismatch")
            if not nullifier:
                reasons.append("nullifier_missing")
            elif not self.check_nullifier(nullifier):
                reasons.append("duplicate_nullifier")

            expected_context: bytes | None = None
            expected_policy: dict[str, Any] | None = None
            if validated_meta is not None:
                expected_context = _context_digest_for_bundle(
                    campaign,
                    pseudonym=pseudonym,
                    nullifier=nullifier,
                    row_count=asc_meta["row_count"],
                )

                request_payload = bundle.get("request", {}) if isinstance(bundle.get("request"), dict) else {}
                request_context = request_payload.get("context_digest") if isinstance(request_payload.get("context_digest"), str) else ""
                if request_context != expected_context.hex():
                    reasons.append(REASON_REQUEST_CONTEXT_MISMATCH)

                folded_payload = bundle.get("folded_object", {}) if isinstance(bundle.get("folded_object"), dict) else {}
                proof_context = folded_payload.get("proof_context_label") if isinstance(folded_payload.get("proof_context_label"), str) else ""
                if proof_context != expected_context.hex():
                    reasons.append(REASON_REQUEST_CONTEXT_MISMATCH)

                expected_policy = campaign.policy_payload(context_digest=expected_context)
                bundle_policy_name = ""
                if isinstance(bundle.get("policy"), dict):
                    bundle_policy_name = str(bundle["policy"].get("name", ""))
                if bundle_policy_name and bundle_policy_name != expected_policy["name"]:
                    reasons.append(REASON_POLICY_CONTEXT_MISMATCH)

            if not any(
                reason.startswith(REASON_ASC_META_MALFORMED)
                or reason in {
                    REASON_ASC_META_MISSING,
                    REASON_REQUEST_CONTEXT_INVALID,
                    REASON_PROOF_CONTEXT_MISSING,
                    REASON_PROOF_CONTEXT_INVALID,
                    REASON_POLICY_CONTEXT_MISMATCH,
                    REASON_REQUEST_CONTEXT_MISMATCH,
                    "campaign_id_mismatch",
                    "verifier_id_mismatch",
                    "campaign_window_mismatch",
                    "weight_profile_mismatch",
                    "pseudonym_scope_mismatch",
                }
                for reason in reasons
            ) and expected_context is not None and expected_policy is not None:
                try:
                    outcome = VerifyFolded(
                        expected_policy,
                        bundle["folded_object"],
                        bundle["proof"],
                        expected_request={"context_digest": expected_context.hex()},
                    )
                    details.update(outcome.details)
                    proof_valid = outcome.allowed
                    if not outcome.allowed:
                        reasons.extend(outcome.reason_codes)
                except Exception as exc:
                    reasons.append(f"verification_error:{exc.__class__.__name__}")
            eligibility_valid = bool(bundle.get("allowed", False))

        reasons = list(dict.fromkeys(reasons))
        accepted = len(reasons) == 0
        if accepted and nullifier:
            self.seen_nullifiers.add(nullifier)
            self.record_impression(campaign_id, pseudonym)
        if accepted:
            proof_valid = True
            eligibility_valid = True

        receipt = AdVerificationReceipt(
            campaign_id=campaign_id,
            accepted=accepted,
            reason_codes=reasons,
            verify_ms=(time.perf_counter() - started) * 1000,
            proof_size_bytes=proof_size,
            pseudonym=pseudonym,
            nullifier=nullifier,
            proof_valid=proof_valid,
            eligibility_valid=eligibility_valid,
            details=details,
        )
        self._record_receipt(receipt)
        return receipt

    def batch_verify(self, bundles: list[dict[str, Any]], campaign_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        receipts = [self.verify_targeting(bundle, campaign_id) for bundle in bundles]
        elapsed_ms = (time.perf_counter() - started) * 1000
        accepted_count = sum(1 for receipt in receipts if receipt.accepted)
        throughput_per_sec = accepted_count / (elapsed_ms / 1000) if elapsed_ms > 0 else 0.0
        return {
            "batch_size": len(bundles),
            "accepted_count": accepted_count,
            "rejected_count": len(bundles) - accepted_count,
            "elapsed_ms": elapsed_ms,
            "throughput_per_sec": throughput_per_sec,
            "all_valid": accepted_count == len(bundles),
            "receipts": [asdict(r) for r in receipts],
        }

    def harvest_report(self) -> dict[str, Any]:
        accepted = sum(1 for receipt in self.receipts if receipt.accepted)
        rejected = len(self.receipts) - accepted
        return {
            "registered_campaigns": len(self.campaigns),
            "total_verifications": len(self.receipts),
            "accepted": accepted,
            "rejected": rejected,
            "seen_nullifiers": len(self.seen_nullifiers),
            "impression_keys": len(self.impression_counts),
            "reason_counts": dict(sorted(self.reason_counts.items())),
        }


def build_default_campaigns(
    *,
    verifier_id: str = "verifier://ads-harvester",
    campaign_window: str = "window:2026-q1",
) -> list[AdCampaign]:
    return [
        AdCampaign(
            campaign_id="campaign://luxury-targeting",
            verifier_id=verifier_id,
            campaign_window=campaign_window,
            weight_profile="luxury_targeting",
            min_age_band=2,
        ),
        AdCampaign(
            campaign_id="campaign://local-business",
            verifier_id=verifier_id,
            campaign_window=campaign_window,
            weight_profile="local_business",
        ),
        AdCampaign(
            campaign_id="campaign://broad-reach",
            verifier_id=verifier_id,
            campaign_window=campaign_window,
            weight_profile="broad_reach",
        ),
        AdCampaign(
            campaign_id="campaign://behavioral-retarget",
            verifier_id=verifier_id,
            campaign_window=campaign_window,
            weight_profile="behavioral_retarget",
        ),
        AdCampaign(
            campaign_id="campaign://consent-gated",
            verifier_id=verifier_id,
            campaign_window=campaign_window,
            weight_profile="consent_gated",
            required_consent_mask=0b0001,
            min_age_band=3,
        ),
    ]


def _segment_profile(segment: str, index: int) -> AdMetadataProfile:
    if segment == "premium":
        return AdMetadataProfile(
            age_band=8 + (index % 4),
            interest_code=_stable_u32("premium", "interest", index),
            location_tier=2 + (index % 2),
            device_class=index % 4,
            browsing_segment=_stable_u32("premium", "browse", index),
            income_bracket=10 + (index % 4),
            engagement_level=80 + (index % 20),
            consent_flags=0b1111,
        )
    if segment == "local":
        return AdMetadataProfile(
            age_band=4 + (index % 6),
            interest_code=_stable_u32("local", "interest", index),
            location_tier=5 + (index % 2),
            device_class=index % 3,
            browsing_segment=_stable_u32("local", "browse", index),
            income_bracket=5 + (index % 3),
            engagement_level=50 + (index % 30),
            consent_flags=0b0111,
        )
    if segment == "broad":
        return AdMetadataProfile(
            age_band=3 + (index % 8),
            interest_code=_stable_u32("broad", "interest", index),
            location_tier=2 + (index % 4),
            device_class=index % 5,
            browsing_segment=_stable_u32("broad", "browse", index),
            income_bracket=4 + (index % 6),
            engagement_level=30 + (index % 40),
            consent_flags=0b0011,
        )
    if segment == "restricted":
        return AdMetadataProfile(
            age_band=1 + (index % 4),
            interest_code=_stable_u32("restricted", "interest", index),
            location_tier=1 + (index % 3),
            device_class=index % 3,
            browsing_segment=_stable_u32("restricted", "browse", index),
            income_bracket=2 + (index % 3),
            engagement_level=15 + (index % 30),
            consent_flags=0 if index % 2 == 0 else 0b0001,
        )
    raise ValueError(f"unknown segment: {segment}")


def build_focused_dataset() -> list[SyntheticUser]:
    dataset: list[SyntheticUser] = []
    for segment in ("premium", "local", "broad", "restricted"):
        for index in range(5):
            dataset.append(
                SyntheticUser(
                    user_label=f"user://{segment}-{index}",
                    segment=segment,
                    metadata=_segment_profile(segment, index),
                )
            )
    return dataset


def _synthetic_user_record(user: SyntheticUser) -> dict[str, Any]:
    return {
        "user_label": user.user_label,
        "segment": user.segment,
        "metadata": asdict(user.metadata),
    }


def _campaign_record(campaign: AdCampaign) -> dict[str, Any]:
    return {
        **asdict(campaign),
        "weight_vector": list(campaign.weight_vector()),
        "policy_id": campaign.policy_id(),
    }


def _content_record(
    user: SyntheticUser,
    campaign: AdCampaign,
    bundle: dict[str, Any],
    receipt: AdVerificationReceipt,
) -> dict[str, Any]:
    user_summary = bundle.get("user_summary", {}) if isinstance(bundle.get("user_summary"), dict) else {}
    integrator_metadata = (
        user_summary.get("integrator_metadata", {})
        if isinstance(user_summary.get("integrator_metadata"), dict)
        else {}
    )
    title = user_summary.get("title") if isinstance(user_summary.get("title"), str) else "ASC ad metadata targeting proof"
    one_line = user_summary.get("one_line") if isinstance(user_summary.get("one_line"), str) else ""
    if not one_line:
        one_line = (
            "User proves campaign-bound metadata integrity without revealing identity."
            if bundle.get("allowed", False)
            else "Eligibility denied before proof issuance."
        )
    return {
        "user": user.user_label,
        "segment": user.segment,
        "campaign": campaign.campaign_id,
        "weight_profile": campaign.weight_profile,
        "allowed": bool(bundle.get("allowed", False)),
        "accepted": receipt.accepted,
        "reason_codes": [str(x) for x in bundle.get("reason_codes", [])]
        if isinstance(bundle.get("reason_codes"), list)
        else [],
        "title": title,
        "one_line": one_line,
        "integrator_metadata": integrator_metadata,
    }


def _wire_bundle_is_redacted(bundle: dict[str, Any]) -> bool:
    if any(field in bundle for field in REDACTED_FIELDS):
        return False
    summary = bundle.get("user_summary", {}) if isinstance(bundle.get("user_summary"), dict) else {}
    meta = summary.get("integrator_metadata", {}) if isinstance(summary.get("integrator_metadata"), dict) else {}
    return all(
        field not in meta
        for field in ("raw_profile", "prover_identity", "user_label", "device_label")
    )


def run_focused_correctness_demo(
    *,
    deterministic: bool = False,
    verbose: bool = True,
    include_records: bool = False,
) -> dict[str, Any]:
    campaigns = build_default_campaigns()
    verifier = AdVerifier(campaigns)
    dataset = build_focused_dataset()

    matrix: list[dict[str, Any]] = []
    redaction_audit: list[str] = []
    proof_records: list[dict[str, Any]] = []
    verification_records: list[dict[str, Any]] = []
    generated_content_records: list[dict[str, Any]] = []

    for user in dataset:
        wallet = AdProverWallet.create(
            user.user_label,
            f"device://{user.segment}",
            deterministic_secret=deterministic,
        )
        wallet.set_metadata(user.metadata)

        for campaign in campaigns:
            raw_bundle = wallet.prove_targeting(campaign, deterministic=deterministic)
            wire_bundle = wallet.redact_for_wire(raw_bundle)
            if not redaction_audit and raw_bundle.get("allowed"):
                redaction_audit = wallet.redactor.audit_report(raw_bundle, wire_bundle)

            receipt = verifier.verify_targeting(wire_bundle, campaign.campaign_id)
            if include_records:
                proof_records.append(
                    {
                        "user": user.user_label,
                        "segment": user.segment,
                        "campaign": campaign.campaign_id,
                        "weight_profile": campaign.weight_profile,
                        "bundle": json.loads(json.dumps(wire_bundle)),
                    }
                )
                verification_records.append(
                    {
                        "user": user.user_label,
                        "segment": user.segment,
                        "campaign": campaign.campaign_id,
                        "weight_profile": campaign.weight_profile,
                        "receipt": asdict(receipt),
                    }
                )
                generated_content_records.append(_content_record(user, campaign, wire_bundle, receipt))
            matrix.append(
                {
                    "user": user.user_label,
                    "segment": user.segment,
                    "campaign": campaign.campaign_id,
                    "weight_profile": campaign.weight_profile,
                    "row_count": int(wire_bundle.get("asc_meta", {}).get("row_count", 0)),
                    "accepted": receipt.accepted,
                    "proof_valid": receipt.proof_valid,
                    "eligibility_valid": receipt.eligibility_valid,
                    "reason_codes": receipt.reason_codes,
                    "expected_denial": (
                        (not receipt.accepted)
                        and bool(receipt.reason_codes)
                        and set(receipt.reason_codes).issubset(PROVER_POLICY_DENIAL_REASONS)
                    ),
                    "proof_size_bytes": receipt.proof_size_bytes,
                    "verify_ms": receipt.verify_ms,
                }
            )

    accepted = sum(1 for row in matrix if row["accepted"])
    rejected = len(matrix) - accepted
    expected_denials = sum(1 for row in matrix if row["expected_denial"])
    unexpected_rejections = sum(
        1 for row in matrix if (not row["accepted"] and not row["expected_denial"])
    )

    by_segment: dict[str, dict[str, int]] = {}
    for row in matrix:
        segment = row["segment"]
        by_segment.setdefault(segment, {"accepted": 0, "rejected": 0})
        key = "accepted" if row["accepted"] else "rejected"
        by_segment[segment][key] += 1

    by_campaign: dict[str, dict[str, int]] = {}
    for row in matrix:
        campaign = row["campaign"]
        by_campaign.setdefault(campaign, {"accepted": 0, "rejected": 0})
        key = "accepted" if row["accepted"] else "rejected"
        by_campaign[campaign][key] += 1

    sample_user = dataset[0]
    sample_wallet = AdProverWallet.create(
        "user://cross-campaign",
        "device://cross-check",
        deterministic_secret=deterministic,
    )
    sample_wallet.set_metadata(sample_user.metadata)
    campaign_a = campaigns[0]
    campaign_b = campaigns[1]
    mismatch_bundle = sample_wallet.redact_for_wire(
        sample_wallet.prove_targeting(campaign_a, deterministic=deterministic)
    )
    mismatch_receipt = AdVerifier(campaigns).verify_targeting(mismatch_bundle, campaign_b.campaign_id)

    known_vector: dict[str, Any] | None = None
    if deterministic:
        seed = _stable_digest("NESSA-ASC:known-vector", sample_user.user_label, campaign_a.campaign_id)
        known_bundle = sample_wallet.prove_targeting(
            campaign_a,
            deterministic=True,
            deterministic_seed=seed,
        )
        if known_bundle.get("allowed"):
            known_vector = {
                "campaign_id": campaign_a.campaign_id,
                "pseudonym": known_bundle["asc_meta"]["pseudonym"],
                "nullifier": known_bundle["asc_meta"]["nullifier"],
                "tags_hash": known_bundle["folded_object"]["tags_hash"],
                "final_root": known_bundle["folded_object"]["final_root"],
                "C_star": known_bundle["folded_object"]["C_star"],
                "pi_link_challenge": known_bundle["proof"]["pi_link"]["challenge"],
                "pi_cons_challenge": known_bundle["proof"]["pi_cons_linear"]["challenge"],
            }

    summary = {
        "total_checks": len(matrix),
        "accepted": accepted,
        "rejected": rejected,
        "expected_denials": expected_denials,
        "unexpected_rejections": unexpected_rejections,
        "segments": by_segment,
        "campaigns": by_campaign,
        "cross_campaign_rejection": {
            "accepted": mismatch_receipt.accepted,
            "reason_codes": mismatch_receipt.reason_codes,
        },
        "redaction_audit": redaction_audit,
        "known_answer_vector": known_vector,
        "harvester_report": verifier.harvest_report(),
        "matrix": matrix,
    }
    if include_records:
        summary["dataset_users"] = [_synthetic_user_record(user) for user in dataset]
        summary["campaign_definitions"] = [_campaign_record(campaign) for campaign in campaigns]
        summary["proof_records"] = proof_records
        summary["verification_records"] = verification_records
        summary["generated_content_records"] = generated_content_records

    if verbose:
        print("[ASC] Focused correctness demo")
        print(f"  checks={len(matrix)} accepted={accepted} rejected={rejected}")
        print(
            f"  expected_denials={expected_denials} "
            f"unexpected_rejections={unexpected_rejections}"
        )
        print(
            "  cross-campaign check="
            f"{'REJECTED' if not mismatch_receipt.accepted else 'UNEXPECTED PASS'}"
        )

    return summary


def _benchmark_profile(index: int) -> AdMetadataProfile:
    return AdMetadataProfile(
        age_band=5 + (index % 6),
        interest_code=_stable_u32("bench", "interest", index),
        location_tier=2 + (index % 4),
        device_class=index % 5,
        browsing_segment=_stable_u32("bench", "browse", index),
        income_bracket=6 + (index % 6),
        engagement_level=55 + (index % 35),
        consent_flags=0b1111,
    )


def run_scaling_benchmark(*, deterministic: bool = False, verbose: bool = True) -> dict[str, Any]:
    campaign = AdCampaign(
        campaign_id="campaign://scaling-broad-reach",
        verifier_id="verifier://ads-benchmark",
        campaign_window="window:scaling",
        weight_profile="broad_reach",
    )

    rows: list[dict[str, Any]] = []

    if verbose:
        print("[ASC] Scaling benchmark")

    for n_rows in SCALE_SIZES:
        wallet = AdProverWallet.create(
            f"bench://single-{n_rows}",
            "device://bench",
            deterministic_secret=deterministic,
        )
        wallet.set_metadata(_benchmark_profile(n_rows))
        raw_bundle = wallet.prove_targeting(
            campaign,
            deterministic=deterministic,
            target_rows=n_rows,
        )
        wire_bundle = wallet.redact_for_wire(raw_bundle)

        verifier = AdVerifier([campaign])
        receipt = verifier.verify_targeting(wire_bundle, campaign.campaign_id)

        batch_size = 4 if n_rows <= 128 else 2 if n_rows <= 1024 else 1
        batch_bundles: list[dict[str, Any]] = []
        for i in range(batch_size):
            b_wallet = AdProverWallet.create(
                f"bench://batch-{n_rows}-{i}",
                "device://bench",
                deterministic_secret=deterministic,
            )
            b_wallet.set_metadata(_benchmark_profile(n_rows + i + 17))
            b_raw = b_wallet.prove_targeting(
                campaign,
                deterministic=deterministic,
                target_rows=n_rows,
            )
            batch_bundles.append(b_wallet.redact_for_wire(b_raw))
        batch_verifier = AdVerifier([campaign])
        batch_summary = batch_verifier.batch_verify(batch_bundles, campaign.campaign_id)

        timings = wire_bundle.get("asc_meta", {}).get("timings", {})
        row = {
            "N": n_rows,
            "proof_size_bytes": receipt.proof_size_bytes,
            "prove_ms": float(timings.get("prove_end_to_end_ms", 0.0)),
            "verify_ms": receipt.verify_ms,
            "commit_ms": float(timings.get("commit_ms", 0.0)),
            "transcript_ms": float(timings.get("transcript_ms", 0.0)),
            "fold_ms": float(timings.get("fold_ms", 0.0)),
            "accepted": receipt.accepted,
            "proof_valid": receipt.proof_valid,
            "eligibility_valid": receipt.eligibility_valid,
            "reason_codes": receipt.reason_codes,
            "batch_size": batch_size,
            "batch_elapsed_ms": float(batch_summary["elapsed_ms"]),
            "batch_throughput_per_sec": float(batch_summary["throughput_per_sec"]),
            "batch_accepted": int(batch_summary["accepted_count"]),
            "batch_all_valid": bool(batch_summary["all_valid"]),
        }
        rows.append(row)

        if verbose:
            print(
                f"  N={n_rows:>4}  prove={row['prove_ms']:.2f}ms  "
                f"verify={row['verify_ms']:.2f}ms  proof={row['proof_size_bytes']}B  "
                f"batch={row['batch_size']}"
            )

    proof_sizes = {row["proof_size_bytes"] for row in rows}
    validity_matrix = [
        {
            "N": row["N"],
            "single_ok": row["accepted"],
            "single_proof_valid": row["proof_valid"],
            "single_eligibility_valid": row["eligibility_valid"],
            "batch_ok": row["batch_all_valid"],
        }
        for row in rows
    ]
    validity_counts = {
        "single_pass": sum(1 for row in rows if row["accepted"]),
        "single_fail": sum(1 for row in rows if not row["accepted"]),
        "batch_pass": sum(1 for row in rows if row["batch_all_valid"]),
        "batch_fail": sum(1 for row in rows if not row["batch_all_valid"]),
    }
    observations = {
        "constant_proof_size": len(proof_sizes) == 1,
        "proof_sizes": sorted(proof_sizes),
        "all_single_verify_passed": all(row["accepted"] for row in rows),
        "all_batch_passed": all(row["batch_all_valid"] for row in rows),
    }

    return {
        "sizes": SCALE_SIZES,
        "rows": rows,
        "validity_matrix": validity_matrix,
        "validity_counts": validity_counts,
        "observations": observations,
    }


def _fmt_ms(value: float) -> str:
    if value < 1:
        return f"{value * 1000:.1f}us"
    if value < 1000:
        return f"{value:.2f}ms"
    return f"{value / 1000:.3f}s"


def _format_user_campaign_matrix(focused: dict[str, Any]) -> list[str]:
    matrix = focused.get("matrix", [])
    campaigns = sorted({row["campaign"] for row in matrix})
    users = sorted({row["user"] for row in matrix})

    by_key: dict[tuple[str, str], bool] = {}
    for row in matrix:
        by_key[(row["user"], row["campaign"])] = bool(row["accepted"])

    lines = ["User x Campaign correctness matrix (OK/NO):"]
    lines.append("  " + " | ".join(["user"] + [c.replace("campaign://", "") for c in campaigns]))
    for user in users:
        cells = ["OK" if by_key.get((user, campaign), False) else "NO" for campaign in campaigns]
        lines.append("  " + " | ".join([user.replace("user://", ""), *cells]))
    return lines


def render_text_report(report: dict[str, Any]) -> str:
    lines = [
        "ASC Ad Metadata Demo Report",
        "===========================",
        f"version={report.get('version')}",
        f"deterministic={report.get('deterministic')}",
        f"benchmark_enabled={report.get('benchmark_enabled')}",
        "",
    ]

    focused = report["focused_correctness"]
    lines.append("Focused Correctness")
    lines.append("-------------------")
    lines.append(
        "checks={total_checks} accepted={accepted} rejected={rejected}".format(
            total_checks=focused["total_checks"],
            accepted=focused["accepted"],
            rejected=focused["rejected"],
        )
    )
    lines.append(
        "expected_denials={expected_denials} unexpected_rejections={unexpected_rejections}".format(
            expected_denials=focused.get("expected_denials", 0),
            unexpected_rejections=focused.get("unexpected_rejections", 0),
        )
    )
    lines.append(
        "cross_campaign_rejection="
        + ("PASS" if not focused["cross_campaign_rejection"]["accepted"] else "FAIL")
        + f" reasons={focused['cross_campaign_rejection']['reason_codes']}"
    )
    lines.append("segment_summary=" + json.dumps(focused["segments"], sort_keys=True))
    lines.append("campaign_summary=" + json.dumps(focused["campaigns"], sort_keys=True))
    if focused.get("redaction_audit"):
        lines.append("redaction_audit=" + ", ".join(focused["redaction_audit"]))
    if focused.get("known_answer_vector"):
        lines.append("known_answer_vector=" + json.dumps(focused["known_answer_vector"], sort_keys=True))
    lines.append("")
    lines.extend(_format_user_campaign_matrix(focused))

    benchmark = report.get("benchmark")
    if isinstance(benchmark, dict):
        lines.extend(["", "Scaling Benchmark", "-----------------"])
        validity_counts = benchmark.get("validity_counts", {})
        if isinstance(validity_counts, dict):
            lines.append("validity_counts=" + json.dumps(validity_counts, sort_keys=True))
        lines.append(
            "  N | proof_size | prove | verify | batch_size | batch_elapsed | batch_thr/s | single_ok | batch_ok"
        )
        for row in benchmark.get("rows", []):
            lines.append(
                f"  {row['N']:>4} | {row['proof_size_bytes']:>10} | "
                f"{_fmt_ms(row['prove_ms']):>8} | {_fmt_ms(row['verify_ms']):>8} | "
                f"{row['batch_size']:>10} | {_fmt_ms(row['batch_elapsed_ms']):>12} | "
                f"{row['batch_throughput_per_sec']:>11.2f} | "
                f"{str(row['accepted']):>9} | {str(row['batch_all_valid']):>8}"
            )
        lines.append("validity_matrix=")
        for item in benchmark.get("validity_matrix", []):
            lines.append(
                "  N={N:>4} single_ok={single_ok} batch_ok={batch_ok} "
                "single_proof_valid={single_proof_valid} single_eligibility_valid={single_eligibility_valid}".format(
                    **item
                )
            )
        lines.append("observations=" + json.dumps(benchmark.get("observations", {}), sort_keys=True))

    lines.extend(
        [
            "",
            "Notes",
            "-----",
            "- This demo proves metadata binding and transcript integrity, not full ad-policy predicates or issuer-backed truth of self-asserted metadata.",
            "- Nullifier checks are application-layer Sybil controls scoped to (user, verifier, campaign window).",
            "- Default pseudonym scope is per-verifier (supports capping/analytics but allows intra-verifier campaign linkability).",
            "- Use per-campaign-window pseudonyms for stronger unlinkability at the cost of weaker longitudinal analytics.",
        ]
    )
    return "\n".join(lines) + "\n"


def _compact_report_for_output(report: dict[str, Any]) -> dict[str, Any]:
    compact = json.loads(json.dumps(report))
    focused = compact.get("focused_correctness")
    if isinstance(focused, dict):
        for key in (
            "dataset_users",
            "campaign_definitions",
            "proof_records",
            "verification_records",
            "generated_content_records",
        ):
            focused.pop(key, None)
    compact.pop("report_files", None)
    compact.pop("root_artifact_files", None)
    return compact


def _build_business_summary(focused: dict[str, Any]) -> dict[str, Any]:
    total_checks = int(focused.get("total_checks", 0))
    accepted = int(focused.get("accepted", 0))
    rejected = int(focused.get("rejected", 0))
    return {
        "total_checks": total_checks,
        "accepted": accepted,
        "rejected": rejected,
        "acceptance_rate": (accepted / total_checks) if total_checks else 0.0,
        "expected_denials": int(focused.get("expected_denials", 0)),
        "unexpected_rejections": int(focused.get("unexpected_rejections", 0)),
        "segment_summary": focused.get("segments", {}),
        "campaign_summary": focused.get("campaigns", {}),
        "reason_counts": focused.get("harvester_report", {}).get("reason_counts", {}),
        "cross_campaign_rejection": focused.get("cross_campaign_rejection", {}),
    }


def _build_reach_summary(
    dataset_users: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    matrix: list[dict[str, Any]],
    harvester_report: dict[str, Any],
) -> dict[str, Any]:
    accepted_rows = [row for row in matrix if row.get("accepted")]
    accepted_users_any = sorted({str(row["user"]) for row in accepted_rows})
    accepted_users_by_segment: dict[str, int] = {}
    accepted_users_by_campaign: dict[str, int] = {}
    for segment in sorted({str(row["segment"]) for row in accepted_rows}):
        accepted_users_by_segment[segment] = len(
            {str(row["user"]) for row in accepted_rows if str(row["segment"]) == segment}
        )
    for campaign_id in sorted({str(row["campaign"]) for row in accepted_rows}):
        accepted_users_by_campaign[campaign_id] = len(
            {str(row["user"]) for row in accepted_rows if str(row["campaign"]) == campaign_id}
        )

    accepted_impressions_by_segment: dict[str, int] = {}
    accepted_impressions_by_campaign: dict[str, int] = {}
    for row in accepted_rows:
        segment = str(row["segment"])
        campaign_id = str(row["campaign"])
        accepted_impressions_by_segment[segment] = accepted_impressions_by_segment.get(segment, 0) + 1
        accepted_impressions_by_campaign[campaign_id] = accepted_impressions_by_campaign.get(campaign_id, 0) + 1

    total_users = len({str(item["user_label"]) for item in dataset_users})
    return {
        "total_users": total_users,
        "total_campaigns": len(campaigns),
        "total_checks": len(matrix),
        "accepted_impressions": len(accepted_rows),
        "accepted_users_any_campaign": len(accepted_users_any),
        "accepted_users_by_segment": dict(sorted(accepted_users_by_segment.items())),
        "accepted_users_by_campaign": dict(sorted(accepted_users_by_campaign.items())),
        "accepted_impressions_by_segment": dict(sorted(accepted_impressions_by_segment.items())),
        "accepted_impressions_by_campaign": dict(sorted(accepted_impressions_by_campaign.items())),
        "impression_keys": int(harvester_report.get("impression_keys", 0)),
    }


def build_root_artifact_payloads(report: dict[str, Any]) -> dict[str, Any]:
    focused = report.get("focused_correctness", {})
    benchmark = report.get("benchmark", {}) if isinstance(report.get("benchmark"), dict) else {}

    dataset_users = focused.get("dataset_users", []) if isinstance(focused.get("dataset_users"), list) else []
    campaigns = (
        focused.get("campaign_definitions", [])
        if isinstance(focused.get("campaign_definitions"), list)
        else []
    )
    proof_records = focused.get("proof_records", []) if isinstance(focused.get("proof_records"), list) else []
    verification_records = (
        focused.get("verification_records", [])
        if isinstance(focused.get("verification_records"), list)
        else []
    )
    generated_content = (
        focused.get("generated_content_records", [])
        if isinstance(focused.get("generated_content_records"), list)
        else []
    )
    matrix = focused.get("matrix", []) if isinstance(focused.get("matrix"), list) else []
    benchmark_rows = benchmark.get("rows", []) if isinstance(benchmark.get("rows"), list) else []
    benchmark_validity = {
        "sizes": benchmark.get("sizes", []) if isinstance(benchmark.get("sizes"), list) else [],
        "validity_matrix": benchmark.get("validity_matrix", [])
        if isinstance(benchmark.get("validity_matrix"), list)
        else [],
        "validity_counts": benchmark.get("validity_counts", {})
        if isinstance(benchmark.get("validity_counts"), dict)
        else {},
        "observations": benchmark.get("observations", {})
        if isinstance(benchmark.get("observations"), dict)
        else {},
    }
    privacy_audit = {
        "redacted_fields": sorted(REDACTED_FIELDS),
        "audit_entries": list(focused.get("redaction_audit", []))
        if isinstance(focused.get("redaction_audit"), list)
        else [],
        "proof_records_total": len(proof_records),
        "all_proofs_redacted": all(
            _wire_bundle_is_redacted(record["bundle"])
            for record in proof_records
            if isinstance(record, dict) and isinstance(record.get("bundle"), dict)
        ),
    }
    business_summary = _build_business_summary(focused)
    reach_summary = _build_reach_summary(
        dataset_users,
        campaigns,
        matrix,
        focused.get("harvester_report", {}) if isinstance(focused.get("harvester_report"), dict) else {},
    )
    test_metadata = {
        "schema_version": "nessa_asc_root_artifacts_v1",
        "version": report.get("version", ASC_DEMO_VERSION),
        "engine": ASC_ENGINE,
        "encoding_id": ASC_ENCODING_ID,
        "deterministic": bool(report.get("deterministic", False)),
        "benchmark_enabled": bool(report.get("benchmark_enabled", False)),
        "attribute_fields": list(ATTRIBUTE_FIELDS),
        "weight_profiles": {key: list(value) for key, value in WEIGHT_PROFILES.items()},
        "scale_sizes": list(SCALE_SIZES),
        "focused_dataset_size": len(dataset_users),
        "focused_campaign_count": len(campaigns),
    }
    compact_report = _compact_report_for_output(report)

    record_counts = {
        "dataset_users": len(dataset_users),
        "campaigns": len(campaigns),
        "focused_proofs": len(proof_records),
        "focused_verifications": len(verification_records),
        "focused_matrix": len(matrix),
        "generated_content": len(generated_content),
        "benchmark_rows": len(benchmark_rows),
        "benchmark_validity": len(benchmark_validity.get("validity_matrix", [])),
    }
    artifact_manifest = {
        "schema_version": "nessa_asc_root_artifacts_v1",
        "version": report.get("version", ASC_DEMO_VERSION),
        "deterministic": bool(report.get("deterministic", False)),
        "benchmark_enabled": bool(report.get("benchmark_enabled", False)),
        "artifact_filenames": dict(ROOT_ARTIFACT_FILENAMES),
        "files_generated": list(ROOT_ARTIFACT_FILENAMES.values()),
        "record_counts": record_counts,
        "totals": {
            "total_checks": int(focused.get("total_checks", 0)),
            "accepted": int(focused.get("accepted", 0)),
            "rejected": int(focused.get("rejected", 0)),
            "expected_denials": int(focused.get("expected_denials", 0)),
            "unexpected_rejections": int(focused.get("unexpected_rejections", 0)),
        },
    }

    return {
        "artifact_manifest": artifact_manifest,
        "dataset_users": dataset_users,
        "campaigns": campaigns,
        "focused_proofs": proof_records,
        "focused_verifications": verification_records,
        "focused_matrix": matrix,
        "generated_content": generated_content,
        "test_metadata": test_metadata,
        "privacy_audit": privacy_audit,
        "business_summary": business_summary,
        "reach_summary": reach_summary,
        "benchmark_rows": benchmark_rows,
        "benchmark_validity": benchmark_validity,
        "asc_ad_report": compact_report,
    }


def write_report_files(report: dict[str, Any], output_path: Path) -> dict[str, str]:
    if output_path.suffix:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        json_path = output_path.with_suffix(".json")
        txt_path = output_path.with_suffix(".txt")
    else:
        output_path.mkdir(parents=True, exist_ok=True)
        json_path = output_path / "asc_ad_benchmark_report.json"
        txt_path = output_path / "asc_ad_benchmark_report.txt"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    txt_path.write_text(render_text_report(report), encoding="utf-8")
    return {
        "json": str(json_path),
        "text": str(txt_path),
    }


def write_root_artifact_files(report: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads = build_root_artifact_payloads(report)
    written: dict[str, str] = {}
    for key, filename in ROOT_ARTIFACT_FILENAMES.items():
        path = output_dir / filename
        path.write_text(json.dumps(payloads[key], indent=2, sort_keys=True), encoding="utf-8")
        written[key] = str(path)
    return written


def run_asc_ad_demo(
    *,
    deterministic: bool = False,
    include_benchmark: bool = False,
    verbose: bool = True,
    report_path: Path | None = None,
    root_artifacts_dir: Path | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "version": ASC_DEMO_VERSION,
        "deterministic": deterministic,
        "benchmark_enabled": include_benchmark,
        "focused_correctness": run_focused_correctness_demo(
            deterministic=deterministic,
            verbose=verbose,
            include_records=root_artifacts_dir is not None,
        ),
    }

    if include_benchmark:
        report["benchmark"] = run_scaling_benchmark(
            deterministic=deterministic,
            verbose=verbose,
        )

    output_report = _compact_report_for_output(report)

    if report_path is not None:
        output_report["report_files"] = write_report_files(output_report, report_path)
        if verbose:
            print("[ASC] wrote reports:")
            print(f"  json: {output_report['report_files']['json']}")
            print(f"  text: {output_report['report_files']['text']}")

    if root_artifacts_dir is not None:
        output_report["root_artifact_files"] = write_root_artifact_files(report, root_artifacts_dir)
        if verbose:
            print("[ASC] wrote audit artifacts:")
            print(f"  manifest: {output_report['root_artifact_files']['artifact_manifest']}")
            print(f"  files: {len(output_report['root_artifact_files'])}")

    return output_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asc-ad-demo")
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Directory for ASC audit JSON artifacts (default: docs/generated/asc_ad_demo/audit)",
    )
    parser.add_argument(
        "--root-artifacts",
        action="store_true",
        help="Write the full ASC audit JSON artifact set to the default docs tree",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Directory or file prefix for report outputs (default: docs/generated/asc_ad_demo/reports when artifact mode is enabled)",
    )
    args = parser.parse_args(argv)
    artifact_output_dir = args.artifacts_dir
    if artifact_output_dir is None and args.root_artifacts:
        artifact_output_dir = ASC_AD_AUDIT_DIR
    report_output_path = args.report
    if report_output_path is None and artifact_output_dir is not None:
        report_output_path = ASC_AD_REPORTS_DIR

    result = run_asc_ad_demo(
        deterministic=args.deterministic,
        include_benchmark=args.benchmark,
        verbose=not args.json,
        report_path=report_output_path,
        root_artifacts_dir=artifact_output_dir,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        focused = result["focused_correctness"]
        print("\nASC ad metadata demo complete")
        print(
            f"  focused checks={focused['total_checks']} "
            f"accepted={focused['accepted']} rejected={focused['rejected']}"
        )
        if args.benchmark and "benchmark" in result:
            rows = result["benchmark"]["rows"]
            print(
                "  benchmark sizes="
                f"{len(rows)} minN={rows[0]['N']} maxN={rows[-1]['N']}"
            )
        if "report_files" in result:
            print(f"  report json={result['report_files']['json']}")
            print(f"  report text={result['report_files']['text']}")
        if "root_artifact_files" in result:
            print(f"  audit artifact manifest={result['root_artifact_files']['artifact_manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
