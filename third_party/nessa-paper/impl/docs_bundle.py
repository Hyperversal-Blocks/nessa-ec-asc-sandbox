#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL_DIR = ROOT / "impl"
if str(IMPL_DIR) not in sys.path:
    sys.path.insert(0, str(IMPL_DIR))

from artifact_layout import (
    DOCS_DIR,
    ensure_parent,
)
from asc_ad_demo import run_asc_ad_demo
from test_vectors import write_test_vectors
from usecase_actor_cache import default_cache_document, save_actor_cache
from usecase_flows import material_schema_for_docs, run_all_demos, verify_flow_like_app, verify_flow_locally
from verification_report import write_verification_report


def _bundle_paths(output_root: Path | None = None) -> dict[str, Path]:
    docs_root = output_root or DOCS_DIR
    generated_root = docs_root / "generated"
    return {
        "docs_root": docs_root,
        "generated_root": generated_root,
        "docs_readme": docs_root / "README.md",
        "docs_manifest": generated_root / "docs_bundle_manifest.json",
        "test_vectors": generated_root / "protocol" / "test_vectors" / "test_vectors_output.json",
        "verification_text": generated_root / "protocol" / "verification" / "verification_report.txt",
        "verification_json": generated_root / "protocol" / "verification" / "verification_report.json",
        "asc_audit_dir": generated_root / "asc_ad_demo" / "audit",
        "asc_reports_dir": generated_root / "asc_ad_demo" / "reports",
        "actor_cache": generated_root / "usecase_flows" / "actor_cache" / "nessa_usecase_actors.json",
        "material_schema": generated_root / "usecase_flows" / "metadata" / "material_schema.json",
        "flow_summaries": generated_root / "usecase_flows" / "metadata" / "flow_summaries.json",
    }


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _usecase_flow_summaries(*, deterministic: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for flow_key, result in run_all_demos(deterministic=deterministic):
        flow = result.flow
        app_ok, reasons = verify_flow_like_app(flow.encoding_id, flow)
        rows.append(
            result.summary_json()
            | {
                "flow_key": flow_key,
                "local_ok": verify_flow_locally(flow),
                "app_style_ok": app_ok,
                "reasons": reasons,
            }
        )
    return rows


def _render_docs_readme(manifest: dict[str, Any]) -> str:
    asc_summary = manifest.get("asc_summary", {})
    counts = asc_summary.get("record_counts", {}) if isinstance(asc_summary, dict) else {}
    totals = asc_summary.get("totals", {}) if isinstance(asc_summary, dict) else {}
    lines = [
        "# NESSA Documentation Bundle",
        "",
        "This directory contains the generated documentation package for the NESSA qFold-EC repository.",
        "It groups machine-readable artifacts, human-readable reports, reproducible inputs, and audit metadata under a single docs-oriented layout.",
        "",
        "## Generate everything",
        "",
        "```bash",
        "python app.py docs-bundle --deterministic --benchmark",
        "```",
        "",
        "This one command generates:",
        "",
        "- protocol test vectors",
        "- protocol verification report JSON/TXT",
        "- ASC ad demo audit JSON set",
        "- ASC ad demo report JSON/TXT",
        "- use-case actor cache input JSON",
        "- use-case material schema metadata",
        "- use-case flow summaries metadata",
        "- bundle manifest metadata",
        "- this comprehensive docs README",
        "",
        "## Directory layout",
        "",
        "```text",
        "docs/",
        "├── README.md",
        "└── generated/",
        "    ├── asc_ad_demo/",
        "    │   ├── audit/",
        "    │   └── reports/",
        "    ├── protocol/",
        "    │   ├── test_vectors/",
        "    │   └── verification/",
        "    ├── usecase_flows/",
        "    │   ├── actor_cache/",
        "    │   └── metadata/",
        "    └── docs_bundle_manifest.json",
        "```",
        "",
        "## Key outputs",
        "",
        f"- protocol test vectors: `{manifest['outputs']['protocol']['test_vectors']}`",
        f"- protocol verification report JSON: `{manifest['outputs']['protocol']['verification_json']}`",
        f"- protocol verification report TXT: `{manifest['outputs']['protocol']['verification_text']}`",
        f"- ASC audit manifest: `{manifest['outputs']['asc_ad_demo']['audit_manifest']}`",
        f"- ASC report JSON: `{manifest['outputs']['asc_ad_demo']['report_json']}`",
        f"- ASC report TXT: `{manifest['outputs']['asc_ad_demo']['report_text']}`",
        f"- use-case actor cache: `{manifest['outputs']['usecase_flows']['actor_cache']}`",
        f"- use-case material schema: `{manifest['outputs']['usecase_flows']['material_schema']}`",
        f"- use-case flow summaries: `{manifest['outputs']['usecase_flows']['flow_summaries']}`",
        f"- bundle manifest: `{manifest['outputs']['bundle']['manifest']}`",
        "",
        "## ASC audit summary",
        "",
        f"- total checks: `{totals.get('total_checks', 0)}`",
        f"- accepted: `{totals.get('accepted', 0)}`",
        f"- rejected: `{totals.get('rejected', 0)}`",
        f"- expected denials: `{totals.get('expected_denials', 0)}`",
        f"- focused proofs: `{counts.get('focused_proofs', 0)}`",
        f"- benchmark rows: `{counts.get('benchmark_rows', 0)}`",
        "",
        "## Use-case metadata",
        "",
        "- `actor_cache/nessa_usecase_actors.json` is a reusable input template for multi-actor stories.",
        "- `metadata/material_schema.json` documents UX-oriented fields for each use-case material dataclass.",
        "- `metadata/flow_summaries.json` captures deterministic summaries of the built-in use-case demo flows.",
        "",
        "## Guarantee boundary for the ASC ad demo",
        "",
        "- The proof verifies **binding + transcript integrity** of committed metadata material for a campaign context.",
        "- The verifier enforces application-layer controls (nullifier replay checks, context/policy consistency checks).",
        "- This v1 demo does **not** by itself prove issuer-backed truth of self-asserted metadata or full ad-policy predicates.",
        "",
        "## Determinism",
        "",
        f"- deterministic mode: `{manifest.get('deterministic', False)}`",
        f"- benchmark enabled: `{manifest.get('benchmark_enabled', False)}`",
        "- Re-run the one-command bundle generator to refresh every generated file in this docs tree.",
        "",
    ]
    return "\n".join(lines)


def generate_docs_bundle(
    *,
    deterministic: bool = False,
    include_benchmark: bool = False,
    output_root: Path | None = None,
) -> dict[str, Any]:
    paths = _bundle_paths(output_root)

    test_vectors_path = write_test_vectors(paths["test_vectors"])
    verification_paths = write_verification_report(
        txt_path=paths["verification_text"],
        json_path=paths["verification_json"],
    )
    asc_result = run_asc_ad_demo(
        deterministic=deterministic,
        include_benchmark=include_benchmark,
        verbose=False,
        report_path=paths["asc_reports_dir"],
        root_artifacts_dir=paths["asc_audit_dir"],
    )

    actor_cache_doc = default_cache_document()
    actor_cache_path = ensure_parent(paths["actor_cache"])
    save_actor_cache(actor_cache_path, actor_cache_doc)

    material_schema_path = ensure_parent(paths["material_schema"])
    material_schema = material_schema_for_docs()
    material_schema_path.write_text(json.dumps(material_schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    flow_summaries_path = ensure_parent(paths["flow_summaries"])
    flow_summaries = _usecase_flow_summaries(deterministic=deterministic)
    flow_summaries_path.write_text(json.dumps(flow_summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    asc_manifest_path = Path(asc_result["root_artifact_files"]["artifact_manifest"])
    asc_manifest = json.loads(asc_manifest_path.read_text(encoding="utf-8"))

    manifest = {
        "bundle": "nessa_docs_bundle_v1",
        "deterministic": deterministic,
        "benchmark_enabled": include_benchmark,
        "docs_root": _display_path(paths["docs_root"]),
        "generated_root": _display_path(paths["generated_root"]),
        "outputs": {
            "bundle": {
                "readme": _display_path(paths["docs_readme"]),
                "manifest": _display_path(paths["docs_manifest"]),
            },
            "protocol": {
                "test_vectors": _display_path(test_vectors_path),
                "verification_text": _display_path(verification_paths["text"]),
                "verification_json": _display_path(verification_paths["json"]),
            },
            "asc_ad_demo": {
                "audit_dir": _display_path(paths["asc_audit_dir"]),
                "reports_dir": _display_path(paths["asc_reports_dir"]),
                "audit_manifest": _display_path(asc_manifest_path),
                "report_json": _display_path(Path(asc_result["report_files"]["json"])),
                "report_text": _display_path(Path(asc_result["report_files"]["text"])),
            },
            "usecase_flows": {
                "actor_cache": _display_path(actor_cache_path),
                "material_schema": _display_path(material_schema_path),
                "flow_summaries": _display_path(flow_summaries_path),
            },
        },
        "counts": {
            "usecase_flow_summaries": len(flow_summaries),
            "usecase_material_schema_sections": len(material_schema),
            "actor_cache_actors": len(actor_cache_doc.get("actors", {})),
        },
        "asc_summary": asc_manifest,
    }

    docs_readme_path = ensure_parent(paths["docs_readme"])
    docs_readme_path.write_text(_render_docs_readme(manifest), encoding="utf-8")

    docs_manifest_path = ensure_parent(paths["docs_manifest"])
    docs_manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docs-bundle")
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit bundle manifest as JSON")
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=None,
        help="Target docs directory to populate (default: docs)",
    )
    args = parser.parse_args(argv)

    manifest = generate_docs_bundle(
        deterministic=args.deterministic,
        include_benchmark=args.benchmark,
        output_root=args.docs_dir,
    )
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"docs readme={manifest['outputs']['bundle']['readme']}")
        print(f"docs manifest={manifest['outputs']['bundle']['manifest']}")
        print(f"asc audit manifest={manifest['outputs']['asc_ad_demo']['audit_manifest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
