# Void

Coverage-guided web API fuzzer — the Go runtime of the UpsideFuzz platform.

---

## Environment Variables (required)

The fuzzer reads target URL and auth from environment, **not** from flags:

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_HOST` | Base URL of the instrumented API | `http://localhost:8080` |
| `SHM_HOST` | URL of the SHM/coverage endpoint (usually same as TARGET_HOST) | `http://localhost:8080` |
| `AUTH_TOKEN` | Raw JWT only — **do not** include the `Bearer ` prefix; Void sends `Authorization: Bearer <value>` | `eyJhbGci...` |
| `AUTH_HEADERS_JSON` | JSON object of header → value (use full `Bearer …` inside `Authorization` if you set it here) | `{"Authorization":"Bearer eyJ..."}` |
| `AUTH_COOKIE` | Optional `Cookie` header for session auth | `sessionid=abc` |
| `AUTH_URL` / `AUTH_METHOD` / `AUTH_BODY` / … | Login flow to obtain a token when `AUTH_TOKEN` is unset | See `auth.go` |
| `AUTH_IDENTITIES_JSON` | Multi-identity weighted fuzzing | See below |

Full table and edge cases: **[`INSTRUCTIONS.md`](../INSTRUCTIONS.md#authentication-jwt-custom-headers-and-cookies)**.

---

## Minimal Run Commands

### Host mode (HTTP coverage — no Docker required)

```bash
export TARGET_HOST="http://localhost:8080"
export SHM_HOST="http://localhost:8080"
export AUTH_TOKEN="<jwt>"

./void -time-budget 60
```

That's it. All bug-finding features are **on by default**: crash triage, repro, minimization, race detection, anti-forgery, source-aware priority, adaptive concurrency, multi-identity.

### Docker sidecar mode (direct SHM — faster coverage, recommended)

```bash
cd <instrumented-project-dir>
export AUTH_TOKEN="<jwt>"

docker compose --profile fuzz-go run --rm void \
  -direct-shm \
  -time-budget 60
```

Only `-direct-shm` needs to be added — this switches from HTTP polling to file-backed mmap for ~10× lower coverage overhead. The SHM path defaults to `/coverage_shm/bitmap` which matches the container volume mount.

---

## When to Override Defaults

Only specify flags when you need **non-default** behaviour:

| Situation | Flag(s) |
|-----------|---------|
| High-throughput / throughput profiling | `-concurrency 64 -coverage-interval 6 -request-timeout 2.5` |
| Noisy target with many expected 500s | `-skip-endpoint-on-500` |
| Strict dedup (same path + mutation = unique) | `-crash-signature-mutation` |
| Disable slow repro on fast runs | `-repro-runs 0 -minimize-crash=false -crash-triage=false` |
| Run without the live terminal UI | `-no-ui` |
| Force UI in non-TTY (CI logs) | `-plain-ui` |

### Typical "fast scan" profile (maximise throughput in CI)

```bash
docker compose --profile fuzz-go run --rm void \
  -direct-shm \
  -time-budget 20 \
  -concurrency 64 -max-concurrency 128 \
  -request-timeout 2.5 -coverage-interval 6 \
  -repro-runs 0 -minimize-crash=false -crash-triage=false \
  -crash-replay-count 0 -crash-boost-requests 0 \
  -no-ui
```

### Typical "deep scan" profile (maximize bug finding, default is already close)

```bash
docker compose --profile fuzz-go run --rm void \
  -direct-shm \
  -time-budget 120 \
  -sequence-prob 0.5 -sequence-max-depth 5 -sequence-fanout 8
```

---

## Full CLI Reference

### Target / Grammar

| Flag | Default | Description |
|------|---------|-------------|
| `-grammar` | `.` | Directory with `grammar.py` and `dict.json` |
| `-dict` | _(from grammar dir)_ | Custom JSON dictionary path |
| `-templates-json` | `<grammar>/templates.export.json` | Pre-exported template JSON (skip re-export) |
| `-exporter` | `./export-templates.py` | Path to grammar exporter script |
| `-refresh-templates` | `false` | Force re-export even if JSON exists |
| `-src` | _(empty)_ | Source tree path for source-aware prioritization |
| `-time-budget` | `10` | Run duration in minutes |

### Concurrency

| Flag | Default | Description |
|------|---------|-------------|
| `-concurrency` | `10` | Starting parallel request count |
| `-adaptive-concurrency` | **true** | Auto-scale concurrency based on latency |
| `-min-concurrency` | `1` | Adaptive lower bound |
| `-max-concurrency` | `64` | Adaptive upper bound |
| `-request-timeout` | `5.0` | Per-request timeout (seconds) |
| `-max-response-bytes` | `262144` | Max bytes read from response body |

### Coverage

| Flag | Default | Description |
|------|---------|-------------|
| `-direct-shm` | `false` | Read coverage bitmap from SHM file (faster than HTTP) |
| `-shm-path` | `/coverage_shm/bitmap` | Path to the mmap bitmap file |
| `-shm-read-mode` | `file` | SHM read mode: `file` \| `mmap` \| `auto` |
| `-coverage-interval` | `1` | Read coverage every N completed requests |
| `-coverage-bitmap-size` | `262144` | SHM bitmap size in bytes |

### Sequences (stateful multi-step chains)

| Flag | Default | Description |
|------|---------|-------------|
| `-sequence-prob` | `0.30` | Probability of scheduling a sequence step |
| `-sequence-max-depth` | `3` | Max chain length (create → read → update → delete) |
| `-sequence-fanout` | `6` | Max follow-up requests per successful step |
| `-sequential-baseline` | `false` | Run baseline epoch sequentially instead of concurrent |

### Crash Analysis (all ON by default)

| Flag | Default | Description |
|------|---------|-------------|
| `-crash-triage` | **true** | Score crashes: noise / needs_review / likely_vuln |
| `-crash-signature-mode` | `balanced` | Dedup mode: `coarse` \| `balanced` \| `strict` |
| `-crash-signature-mutation` | `false` | Include mutation label in signature (more unique crashes) |
| `-crash-signature-query-values` | `false` | Include query values in signature |
| `-repro-runs` | `5` | Repro probe count per unique crash (0 = disable) |
| `-repro-target` | `80.0` | Stability % required to confirm crash |
| `-repro-timeout` | `5.0` | Timeout per repro probe (seconds) |
| `-minimize-crash` | **true** | Delta-reduce payload/path/query for minimal PoC |
| `-minimize-max-probes` | `24` | Max requests for minimization |

### Crash Replay & Boost

| Flag | Default | Description |
|------|---------|-------------|
| `-crash-replay-count` | `4` | Replay requests after a unique crash |
| `-crash-replay-prob` | `0.35` | Probability of draining replay queue per step |
| `-crash-replay-queue-max` | `96` | Max queued replay requests |
| `-crash-replay-per-endpoint` | `24` | Max replay requests per endpoint |
| `-crash-boost-requests` | `80` | Burst N requests to crashing endpoint (0 = off) |
| `-crash-boost-max-per-endpoint` | `2` | Max boost activations per endpoint |
| `-crash-boost-weight` | `8.0` | Template weight during boost |

### Race Detection (ON by default)

| Flag | Default | Description |
|------|---------|-------------|
| `-race-mode` | **true** | Send concurrent conflicting requests to write endpoints |
| `-race-prob` | `0.10` | Probability of race burst after successful write |
| `-race-burst` | `4` | Number of concurrent conflicting requests per burst |

### Endpoint Throttling

| Flag | Default | Description |
|------|---------|-------------|
| `-skip-endpoint-on-500` | `false` | Stop hitting endpoint after first 500 |
| `-skip-on-crash` | `false` | Remove endpoint from active set after any 5xx |
| `-endpoint-stall-reqs` | `220` | Down-weight after N requests with no new edges |
| `-endpoint-zero-edge-reqs` | `120` | Down-weight when total reqs exceed N but no edges |
| `-endpoint-req-share-cap-pct` | `2.0` | Soft share cap (%) when no new edges |
| `-endpoint-crash-rate-threshold` | `50.0` | 5xx% threshold for crash-rate throttling |
| `-endpoint-crash-rate-min-crashes` | `50` | Min 5xx count before throttling applies |

### Auth / Identity

| Flag | Default | Description |
|------|---------|-------------|
| `-multi-identity` | **true** | Rotate identities from `AUTH_IDENTITIES_JSON` |
| `-identity-mode` | `weighted` | Scheduling: `weighted` \| `round-robin` \| `random` |
| `-auto-antiforgery` | **true** | Auto-harvest CSRF tokens from HTML responses |
| `-antiforgery-sample-rate` | `0.10` | Fraction of HTML responses to scan for CSRF tokens |
| `-antiforgery-max-tokens` | `2048` | Max CSRF tokens in pool |
| `-antiforgery-token-ttl` | `300` | Token TTL seconds |
| `-antiforgery-cooldown` | `10` | Seconds between harvest attempts per endpoint |

### Output Files

| Flag | Default | Description |
|------|---------|-------------|
| `-crash-file` | `crashes/crashes-<ts>.jsonl` | All crashes (every 5xx) |
| `-unique-crash-file` | `crashes/unique-crashes-<ts>.jsonl` | Deduplicated crashes |
| `-summary-file` | `summaries/summary-<ts>.json` | Run statistics |
| `-report-file` | _(derived from summary)_ | Structured bug report JSON |
| `-poc-dir` | `crashes/pocs` | Reproducer shell scripts |
| `-timeline-dir` | `crashes/timelines` | Mermaid exploit flow diagrams |

### UI

| Flag | Default | Description |
|------|---------|-------------|
| `-no-ui` | `false` | Disable dashboard (plain stdout) |
| `-plain-ui` | `false` | Simple line-by-line output |
| `-ascii-ui` | `false` | ASCII borders (no Unicode box drawing) |
| `-force-ui` | `false` | Force dashboard even when stdout is not a TTY |
| `-ui-no-clear` | `false` | Don't clear screen between refreshes |
| `-ui-width` | `0` (auto) | Fixed dashboard width (80–200) |
| `-ui-interval` | `1.0` | Dashboard refresh interval (seconds) |
| `-ui-endpoint-sort` | `hot` | Sort: `hot` \| `recent` \| `req` \| `edges` \| `alpha` |
| `-ui-endpoint-rotate` | **true** | Auto-rotate endpoint pages |

---

## Architecture & Code Structure (`void/go/`)

The fuzzer engine has been designed around distinct, cohesive files for maintainability and clear onboarding:

- **`types.go`**: Core data structures (`Config`, `WorkItem`, `SendResult`, `Fuzzer` interfaces).
- **`mutations.go`**: MOpt-style payload dictionaries and adaptive mutation category selection algorithms.
- **`store.go`**: Runtime knowledge extraction, global value deduplication, and dynamic `DictStore` lookup.
- **`coverage.go`**: Handlers for Shared Memory (SHM) direct byte reads and HTTP `/coverage` polling.
- **`fuzzer.go`**: Main fuzzer struct and high-level lifecycle hooks (`Run`, `Close`, scheduling steps).
- **`auth.go`**: Identity rotation (JWT, session cookies) and Anti-forgery (CSRF) token harvesting/injection.
- **`template.go`**: Parsing of `templates.export.json` and rendering API request structures into raw HTTP bytes.
- **`worker.go`**: Core fuzzing loop, concurrency management, and worker thread synchronization (`sync.WaitGroup`).
- **`sequence.go`**: Stateful multi-step chains (e.g., CREATE $\rightarrow$ READ $\rightarrow$ UPDATE $\rightarrow$ DELETE), matching producer/consumer followup endpoints.
- **`crash.go`**: Unique crash detection, fingerprinting, deduplication, triage severity scoring, and reproduction queues.
- **`mutation_engine.go`**: Context-aware injection algorithms (JSON payload flipping, path traversal injection, query dropping, etc.).
- **`ui.go`**: Rich terminal dashboard rendering, ASCII progress bars, and run reporting.
- **`utils.go`**: General string manipulation, byte arrays, path parsers, and generic mathematical helpers.
- **`main.go`**: CLI flags parsing, configuration validation, and application bootstrap entry point.

---

## Build for Any Platform

The Go binary is fully self-contained. Cross-compilation requires only Go 1.22+ installed locally (no CGO, no external deps).

### Prerequisites

```bash
# macOS (Homebrew)
brew install go

# Ubuntu / Debian
sudo apt-get install -y golang-1.22

# Verify
go version  # should print go1.22 or newer
```

### Native build (current OS + arch)

```bash
cd void/go
go build -o void .
```

### Cross-compilation table

```bash
cd void/go

# macOS Apple Silicon (M1/M2/M3)
GOOS=darwin  GOARCH=arm64 go build -o ../void-darwin-arm64 .

# macOS Intel
GOOS=darwin  GOARCH=amd64 go build -o ../void-darwin-amd64 .

# Linux aarch64 (ARM64 — Docker on M1, AWS Graviton, RPi)
GOOS=linux   GOARCH=arm64 go build -o ../void-linux-arm64 .

# Linux amd64 (most servers, Docker on Intel/AMD)
GOOS=linux   GOARCH=amd64 go build -o ../void-linux-amd64 .

# Windows 64-bit
GOOS=windows GOARCH=amd64 go build -o ../void-windows-amd64.exe .
```

### Build via Docker (no local Go needed)

```bash
cd void

# Linux amd64 (for use inside Docker compose)
docker run --rm -v "$(pwd)/go:/src" -w /src golang:1.22-alpine \
  go build -o /src/void-linux-amd64 .

# macOS arm64 cross-compiled inside Docker
docker run --rm -v "$(pwd)/go:/src" -w /src golang:1.22-alpine \
  sh -c "GOOS=darwin GOARCH=arm64 go build -o /src/void-darwin-arm64 ."
```

### Build optimized release binary (smaller, no debug symbols)

```bash
cd void/go
GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o ../void-linux-amd64 .
```

> `-s -w` strips the symbol table and DWARF debug info, reducing binary size from ~8MB to ~5MB.

### Dockerfile.go (update for multi-arch publish)

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go/ .
RUN go build -ldflags="-s -w" -o /void .

FROM alpine:3.19
COPY --from=builder /void /void
COPY export-templates.py /export-templates.py
ENTRYPOINT ["/void"]
```

Build for multiple platforms via `docker buildx`:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f void/Dockerfile.go \
  -t void:latest \
  void/
```

---

## Mutation Categories

MOpt-style weighted selection — categories that find more edges get higher probability:

`boundary` · `overflow` · `sqli` · `xss` · `cmdi` · `path_traversal` · `ssrf` · `ssti` · `open_redirect` · `crlf` · `log4shell` · `nosqli` · `ldap` · `xxe` · `unicode`

---

## Epoch Schedule

| Epoch | Budget | Strategy |
|-------|--------|----------|
| Baseline | 5% | Unmutated — build seed corpus |
| Deterministic | 30% | One mutation per field |
| Havoc | 50% | 1–4 stacked mutations, escalates on coverage stall |
| Splicing | 15% | Cross-seed mutations |

---

## Crash Output (JSONL)

```json
{
  "ts": "2026-03-01T10:15:00Z",
  "signature": "7ecd321e718f5a26",
  "status_code": 500,
  "method": "PUT",
  "path": "/v1/helpdesk/channels/0",
  "mutation": "sqli",
  "payload": "'{\"name\":\"' OR 1=1--\"}",
  "response_body": "An error occurred while processing your request.",
  "triage": {"classification": "needs_review", "severity_score": 5},
  "repro": {"stable_reproducible": true, "stability_pct": "100.0"},
  "minimized": {"path": "/v1/helpdesk/channels/0", "payload": ""},
  "poc_file": "./crashes/pocs/poc-7ecd321e718f5a26.sh",
  "timeline_file": "./crashes/timelines/timeline-7ecd321e718f5a26.md"
}
```
