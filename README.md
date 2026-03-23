# NESSA qFold-EC Go integration (nessa-go)

This module now provides a Go-native CLI that integrates the existing Python
protocol core directly for ASC end-to-end execution, without rewriting the core
cryptographic flow. It also includes foundational Go parity primitives (CBOR,
H2C/H2S, and vector checks).

The integration uses established OSS building blocks instead of custom cache
plumbing:

- `github.com/hashicorp/golang-lru/v2` for in-memory LRU result caching
- standard `flag` + `os/exec` for explicit, auditable CLI/process orchestration

## Usage

Run tests:

```bash
go test ./...
```

Run ASC end-to-end via the Python core from Go:

```bash
go run ./cmd/nessa asc-e2e \
  --deterministic \
  --python-root /home/haseeb/code/nessa-paper \
  --python-bin /home/haseeb/code/nessa-paper/impl/.venv/bin/python
```

Optional flags:

- `--benchmark`
- `--artifacts-dir <dir>`
- `--root-artifacts`
- `--report <path>`

Run a user-centric single-wallet / single-campaign prove+verify flow:

```bash
go run ./cmd/nessa asc-user \
  --user-label user://alice \
  --device-label device://phone \
  --campaign-id campaign://luxury-targeting \
  --deterministic \
  --python-root /home/haseeb/code/nessa-paper \
  --python-bin /home/haseeb/code/nessa-paper/impl/.venv/bin/python
```

Useful `asc-user` flags:

- `--json` for full machine-readable output
- `--repeat <n>` to run multiple times in one process and observe cache hits
- `--no-cache` to disable in-memory cache
- metadata flags (`--age-band`, `--interest-code`, `--consent-flags`, etc.)
- campaign controls (`--weight-profile`, `--required-consent-mask`, `--min-age-band`)

Environment variables (if flags are omitted):

- `NESSA_PY_ROOT` (path to `nessa-paper` containing `app.py`)
- `NESSA_PYTHON_BIN` (python executable)