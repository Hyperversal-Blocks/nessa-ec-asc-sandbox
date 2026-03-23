from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
GENERATED_DOCS_DIR = DOCS_DIR / "generated"
ARTIFACTS_DIR = GENERATED_DOCS_DIR

PROTOCOL_ARTIFACTS_DIR = ARTIFACTS_DIR / "protocol"
PROTOCOL_TEST_VECTORS_DIR = PROTOCOL_ARTIFACTS_DIR / "test_vectors"
PROTOCOL_VERIFICATION_DIR = PROTOCOL_ARTIFACTS_DIR / "verification"

ASC_AD_ARTIFACTS_DIR = ARTIFACTS_DIR / "asc_ad_demo"
ASC_AD_AUDIT_DIR = ASC_AD_ARTIFACTS_DIR / "audit"
ASC_AD_REPORTS_DIR = ASC_AD_ARTIFACTS_DIR / "reports"

USECASE_ARTIFACTS_DIR = ARTIFACTS_DIR / "usecase_flows"
USECASE_ACTOR_CACHE_DIR = USECASE_ARTIFACTS_DIR / "actor_cache"
USECASE_ACTOR_CACHE_PATH = USECASE_ACTOR_CACHE_DIR / "nessa_usecase_actors.json"
USECASE_METADATA_DIR = USECASE_ARTIFACTS_DIR / "metadata"
USECASE_MATERIAL_SCHEMA_PATH = USECASE_METADATA_DIR / "material_schema.json"
USECASE_FLOW_SUMMARIES_PATH = USECASE_METADATA_DIR / "flow_summaries.json"

TEST_VECTORS_OUTPUT_PATH = PROTOCOL_TEST_VECTORS_DIR / "test_vectors_output.json"
VERIFICATION_REPORT_TEXT_PATH = PROTOCOL_VERIFICATION_DIR / "verification_report.txt"
VERIFICATION_REPORT_JSON_PATH = PROTOCOL_VERIFICATION_DIR / "verification_report.json"
DOCS_BUNDLE_README_PATH = DOCS_DIR / "README.md"
DOCS_BUNDLE_MANIFEST_PATH = GENERATED_DOCS_DIR / "docs_bundle_manifest.json"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
