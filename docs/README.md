# NESSA Documentation Bundle

This directory contains the generated documentation package for the NESSA qFold-EC repository.
It groups machine-readable artifacts, human-readable reports, reproducible inputs, and audit metadata under a single docs-oriented layout.

## Generate everything

```bash
python app.py docs-bundle --deterministic --benchmark
```

This one command generates:

- protocol test vectors
- protocol verification report JSON/TXT
- ASC ad demo audit JSON set
- ASC ad demo report JSON/TXT
- use-case actor cache input JSON
- use-case material schema metadata
- use-case flow summaries metadata
- bundle manifest metadata
- this comprehensive docs README

## Directory layout

```text
docs/
├── README.md
└── generated/
    ├── asc_ad_demo/
    │   ├── audit/
    │   └── reports/
    ├── protocol/
    │   ├── test_vectors/
    │   └── verification/
    ├── usecase_flows/
    │   ├── actor_cache/
    │   └── metadata/
    └── docs_bundle_manifest.json
```

## Key outputs

- protocol test vectors: `docs/generated/protocol/test_vectors/test_vectors_output.json`
- protocol verification report JSON: `docs/generated/protocol/verification/verification_report.json`
- protocol verification report TXT: `docs/generated/protocol/verification/verification_report.txt`
- ASC audit manifest: `docs/generated/asc_ad_demo/audit/asc_ad_artifact_manifest.json`
- ASC report JSON: `docs/generated/asc_ad_demo/reports/asc_ad_benchmark_report.json`
- ASC report TXT: `docs/generated/asc_ad_demo/reports/asc_ad_benchmark_report.txt`
- use-case actor cache: `docs/generated/usecase_flows/actor_cache/nessa_usecase_actors.json`
- use-case material schema: `docs/generated/usecase_flows/metadata/material_schema.json`
- use-case flow summaries: `docs/generated/usecase_flows/metadata/flow_summaries.json`
- bundle manifest: `docs/generated/docs_bundle_manifest.json`

## ASC audit summary

- total checks: `100`
- accepted: `94`
- rejected: `6`
- expected denials: `6`
- focused proofs: `100`
- benchmark rows: `13`

## Use-case metadata

- `actor_cache/nessa_usecase_actors.json` is a reusable input template for multi-actor stories.
- `metadata/material_schema.json` documents UX-oriented fields for each use-case material dataclass.
- `metadata/flow_summaries.json` captures deterministic summaries of the built-in use-case demo flows.

## Guarantee boundary for the ASC ad demo

- The proof verifies **binding + transcript integrity** of committed metadata material for a campaign context.
- The verifier enforces application-layer controls (nullifier replay checks, context/policy consistency checks).
- This v1 demo does **not** by itself prove issuer-backed truth of self-asserted metadata or full ad-policy predicates.

## Determinism

- deterministic mode: `True`
- benchmark enabled: `True`
- Re-run the one-command bundle generator to refresh every generated file in this docs tree.
