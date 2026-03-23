# NESSA qFold-EC Go rewrite (nessa-go)

This module is intended to be a byte‑for‑byte compatible Go implementation of the
reference Python protocol implementation in this repository.  It introduces a
dedicated Go module under `nessa-go` and provides deterministic CBOR encoding,
hash‑to‑curve expand via XMD using SHA‑512, group/scalar derivations, and
golden‑vector tests aligned to the audit artefacts in `docs/generated/`.

## Usage

Run the tests to verify that the Go implementation matches the published
verification report:

```bash
cd nessa-go
go test ./...
```

At this early stage the `cmd/nessa` CLI simply prints a placeholder message.
Additional protocol subcommands will be added once the parity layers have been
validated.