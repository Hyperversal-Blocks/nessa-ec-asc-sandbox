# NESSA qFold-EC Go integration (nessa-go)

This module now provides a Go-native CLI that integrates the existing Python
protocol core directly for ASC end-to-end execution, without rewriting the core
cryptographic flow. It also includes foundational Go parity primitives (CBOR,
H2C/H2S, and vector checks).

The Python source is vendored into this app at:

- `third_party/nessa-paper/app.py`
- `third_party/nessa-paper/impl/*.py`

So `asc-e2e`, `asc-user`, and `asc-api` can run without requiring access to the
private repo path. Explicit `--python-root` still overrides this default.

The integration uses established OSS building blocks instead of custom cache
plumbing:

- `github.com/go-chi/chi/v5` for HTTP API routing/middleware
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

Run the ASC API server (`chi`) for verifier-centric and user-centric multi-party flows:

```bash
go run ./cmd/nessa asc-api \
  --addr :8090 \
  --python-root /home/haseeb/code/nessa-paper \
  --python-bin /home/haseeb/code/nessa-paper/impl/.venv/bin/python
```

The API writes flow artifacts under:

- default: `/home/haseeb/code/nessa-paper/docs/generated/asc_api_demo`
- override via `--artifacts-dir`

Key API endpoints:

- `POST /api/v1/wallets` create wallet (private key + public key)
- `PUT /api/v1/wallets/{walletID}/metadata` set wallet metadata (cached in-memory)
- `POST /api/v1/flows/verifier-centric` multi-user prove+verify for one verifier/campaign
- `POST /api/v1/flows/user-centric` single-user prove+verify across many verifiers
- `POST /api/v1/benchmarks` benchmark runner
- `POST /api/v1/stress` stress/concurrency runner
- `GET /api/v1/references/go-migration` reputed Go library references for Python decoupling roadmap

Environment variables (if flags are omitted):

- `NESSA_PY_ROOT` (path to `nessa-paper` containing `app.py`)
- `NESSA_PYTHON_BIN` (python executable)