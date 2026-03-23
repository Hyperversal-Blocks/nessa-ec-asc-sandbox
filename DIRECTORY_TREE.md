# NESSA qFold-EC — Repository Directory Tree

Annotated directory structure. Generated outputs under `docs/generated/` are excluded (regenerate with `python app.py docs-bundle --deterministic --benchmark`).

---

```text
nessa-paper/
├── app.py                                    # CLI entry + NessaAccessWallet + VerifyFolded (734 lines)
├── AnonymousSelfCredentials.pdf              # Reference PDF for ASC dataset
├── README.md                                 # Top-level project README
├── .gitignore
│
├── impl/                                     # All implementation modules
│   ├── nessa_qfold.py                        # Core protocol: ristretto255, commitments, transcript,
│   │                                         #   folding, π_link, π_cons, run_protocol_flow (1739 lines)
│   ├── asc_ad_demo.py                        # ASC ad targeting demo: AdProverWallet, AdVerifier,
│   │                                         #   weighted metadata, nullifier Sybil resistance (1762 lines)
│   ├── usecase_flows.py                      # 7 use-case demos: login, delegation, credential,
│   │                                         #   revocation, attestation, handshake, IVC (1630 lines)
│   ├── integration_gateway.py                # API gateway demo: GatewayProver, GatewayVerifier,
│   │                                         #   PrivacyRedactor, replay/rate/budget (619 lines)
│   ├── docs_bundle.py                        # One-command docs generator: generate_docs_bundle() (269 lines)
│   ├── verification_report.py                # Step-by-step cryptographic audit trace (498 lines)
│   ├── test_vectors.py                       # TV-LIN-8 and TV-R1CS-8 whitepaper vectors (279 lines)
│   ├── benchmark.py                          # Deterministic known-answer vectors + security checks (894 lines)
│   ├── nessa_cli.py                          # Interactive ANSI CLI: menus, inspectors, sessions (570 lines)
│   ├── usecase_actor_cache.py                # Multi-actor JSON cache for use-case stories (204 lines)
│   └── artifact_layout.py                    # Shared output path constants for docs/ layout (39 lines)
│
├── tests/                                    # Test suite (823 lines total)
│   ├── test_asc_ad_demo.py                   # 18 ASC demo tests (392 lines)
│   ├── test_gateway_integration.py           # 8 gateway tests (292 lines)
│   ├── test_docs_bundle.py                   # 1 docs bundle integration test (75 lines)
│   └── test_cli_imports.py                   # Import smoke tests (64 lines)
│
├── docs/                                     # Documentation package
│   ├── README.md                             # Auto-generated comprehensive docs README
│   ├── CODEMAP.md                            # Enriched 7-trace architecture codemap (49 locations)
│   ├── MERMAID_FLOWS.md                      # Colored Mermaid diagrams for all 7 traces
│   ├── PROTOCOL_FORMULAS.md                  # Core protocol formula reference
│   ├── INTEGRITY.md                          # SHA-256 checksums for all source files
│   ├── CHANGELOG.md                          # Project changelog
│   ├── DIRECTORY_TREE.md                     # This file
│   ├── GO_REWRITE_PLAN.md                    # Go rewrite implementation plan
│   └── generated/                            # Machine-generated artifacts (gitignored)
│       ├── docs_bundle_manifest.json         # Bundle manifest with all output paths
│       ├── protocol/
│       │   ├── test_vectors/
│       │   │   └── test_vectors_output.json  # TV-LIN-8 + TV-R1CS-8
│       │   └── verification/
│       │       ├── verification_report.json  # Cryptographic audit trace (JSON)
│       │       └── verification_report.txt   # Cryptographic audit trace (text)
│       ├── asc_ad_demo/
│       │   ├── audit/                        # 14 ASC audit JSON artifacts
│       │   │   ├── asc_ad_artifact_manifest.json
│       │   │   ├── asc_ad_dataset_users.json
│       │   │   ├── asc_ad_campaigns.json
│       │   │   ├── asc_ad_focused_proofs.json
│       │   │   ├── asc_ad_focused_verifications.json
│       │   │   ├── asc_ad_focused_matrix.json
│       │   │   ├── asc_ad_generated_content.json
│       │   │   ├── asc_ad_test_metadata.json
│       │   │   ├── asc_ad_privacy_audit.json
│       │   │   ├── asc_ad_business_summary.json
│       │   │   ├── asc_ad_reach_summary.json
│       │   │   ├── asc_ad_benchmark_rows.json
│       │   │   ├── asc_ad_benchmark_validity.json
│       │   │   └── asc_ad_report.json
│       │   └── reports/
│       │       ├── asc_ad_benchmark_report.json
│       │       └── asc_ad_benchmark_report.txt
│       └── usecase_flows/
│           ├── actor_cache/
│           │   └── nessa_usecase_actors.json  # Multi-actor input template
│           └── metadata/
│               ├── material_schema.json       # UX field documentation per use-case
│               └── flow_summaries.json        # Deterministic flow summary + verification status
│
├── knowledge base/                           # Reference RFCs and papers
│   ├── refs-25__rfc9496__ristretto255.pdf
│   ├── refs-4-...__rfc9380__Hashing-to-Elliptic-Curves.pdf
│   ├── refs-3-...__rfc8949__CBOR.pdf
│   ├── refs-2-...__rfc8235__Schnorr-NIZK.pdf
│   ├── refs-1-...__Bulletproofs.pdf
│   └── ... (11 files)
│
├── latest-whitepaper-docs/                   # Whitepaper package
│   ├── NESSA qFold-EC Revised Whitepaper Package.pdf
│   └── deep-research-report (14).md
│
├── latest-whitepaper.md                      # Full whitepaper markdown (67,815 bytes)
├── implementation logic.md                   # Implementation notes
│
├── older audits/                             # Historical audit files (4 items)
├── older iterations/                         # Historical implementation iterations (21 items)
└── prompts/                                  # AI prompt templates (1 item)
```

---

## Line Count Summary

| Category | Files | Lines |
|----------|------:|------:|
| Core protocol | 1 | 1,739 |
| Application layer | 1 | 734 |
| Demo modules | 4 | 4,280 |
| Documentation generators | 3 | 1,046 |
| Tooling & config | 3 | 1,438 |
| **Source total** | **12** | **9,237** |
| Tests | 4 | 823 |
| **Grand total** | **16** | **10,060** |
