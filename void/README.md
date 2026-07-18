# Void

Coverage-guided web API fuzzer — the Go runtime of the UpsideFuzz platform.

---

## Target And Authentication

The fuzzer reads target URLs from environment variables. Authentication can come from the recommended `-auth-file` / `AUTH_FILE` identity file or from legacy single-identity environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_HOST` | Base URL of the instrumented API | `http://localhost:8080` |
| `SHM_HOST` | URL of the SHM/coverage endpoint (usually same as TARGET_HOST) | `http://localhost:8080` |
| `AUTH_FILE` | Path to a documented multi-identity auth file | `./auth.identities.json` |
| `AUTH_TOKEN` | Raw JWT recommended; Void sends `Authorization: Bearer <value>` and strips a pasted `Bearer ` prefix | `eyJhbGci...` |
| `AUTH_HEADERS_JSON` | JSON object of header → value (use full `Bearer …` inside `Authorization` if you set it here) | `{"Authorization":"Bearer eyJ..."}` |
| `AUTH_HEADER` | Legacy single `Header-Name: value` shortcut | `Authorization: Bearer eyJ...` |
| `AUTH_COOKIE` | Optional `Cookie` header for session auth | `sessionid=abc` |
| `AUTH_URL` / `AUTH_METHOD` / `AUTH_BODY` / … | Login flow to obtain a token when `AUTH_TOKEN` is unset | See `auth.go` |
| `AUTH_IDENTITIES_JSON` | Legacy inline multi-identity JSON | Prefer `AUTH_FILE` / `-auth-file` |

Canonical auth file schema and access-control guidance: **[`docs/FUZZER_AUTHENTICATION.md`](../docs/FUZZER_AUTHENTICATION.md)**.
Security-focused flag interactions and recommended profiles: **[`INSTRUCTIONS.md`](../INSTRUCTIONS.md#security-campaign-profiles)**.

---

## Minimal Run Commands

### Host mode (HTTP coverage — no Docker required)

```bash
export TARGET_HOST="http://localhost:8080"
export SHM_HOST="http://localhost:8080"
export AUTH_TOKEN="<jwt>"

./void -time-budget 60
```

For access-control fuzzing with multiple roles:

```bash
./void \
  -auth-file ../docs/auth.identities.example.json \
  -identity-mode weighted \
  -time-budget 60
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

## Profiles (fastest way to start)

Instead of memorizing the 90 flags, pass a `-profile`. It sets a curated bundle of knobs; **any individual flag you also pass still overrides the profile.**

| Profile | Optimizes for | Sets (unless you override) |
|---------|---------------|----------------------------|
| `-profile fast` | CI smoke / max throughput | `repro-runs 0`, `minimize-crash=false`, oracles off, `race-mode=false`, `sequence-prob 0.1` |
| `-profile deep` | Thorough scan | `time-budget 60`, `repro-runs 5`, `minimize-crash`, `sequence-prob 0.5`, oracles on, `race-mode` |
| `-profile security` | Vulnerability hunting | multi-identity + guest on, `access-probe` (prob 0.75), injection oracle, source-aware priority, `sequence-prob 0.5`, `race-mode` |

```bash
./void -profile security -auth-file auth.json -time-budget 90
```

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

## Startup Output Explained

At startup Void prints the effective campaign configuration. This is the fastest way to sanity-check that the run is using the intended auth, dictionary, coverage mode, and security features.

| Line | What it means | Why it matters |
|------|---------------|----------------|
| `Loaded dictionary: ...` | The active mutation dictionary path. | For security campaigns this should point to your security/domain dictionary, not only the default RESTler dictionary. |
| `Time budget: ... minutes` | Wall-clock fuzzing budget. | Confirms long runs were not accidentally started with a short smoke-test value. |
| `Concurrency: N (adaptive=... min=... max=...)` | Initial worker count and adaptive bounds. | Too high can destabilize slow targets; too low wastes fast targets. |
| `Output files: crash=... unique=... summary=... report=...` | Where artifacts will be written. | Use these paths for later triage and to confirm Docker volumes are mounted correctly. |
| `Content-Type adaptation: true` | Void can switch JSON/form content types based on endpoint feedback. | Helps reach MVC/form endpoints instead of repeatedly sending the wrong body type. |
| `Anti-forgery auto-harvest: ...` | CSRF token discovery/injection settings. | Important for ASP.NET MVC apps with form anti-forgery validation. |
| `Coverage bitmap target size: ...` | Expected SHM bitmap size. | Must match the instrumented API side; mismatches reduce or break coverage feedback. |
| `Endpoint stall throttle: ...` | Per-endpoint down-weighting thresholds. | Prevents the scheduler from wasting the campaign on endpoints that stop yielding new coverage. |
| `Advanced: triage=... repro_runs=... minimize=... race=... source_priority=... multi_identity=...` | Summary of major bug-finding features. | This should stay enabled for security reporting unless you are intentionally benchmarking throughput. |
| `Crash dedup: mode=...` | Unique crash signature strategy. | `balanced` is the default; stricter modes produce more unique findings. |
| `Crash replay: ...` | Whether Void schedules follow-up requests near crashy areas. | Disable with `-crash-replay-count 0` for strict breadth scans that should not revisit crash sites. |
| `Crash boost: ...` | Whether crashy endpoints receive temporary scheduler weight. | Useful for variant discovery; disable for noisy targets when one endpoint dominates. |
| `Template policy: remove crashing template...` | Printed when `-skip-on-crash` is enabled. | Confirms only the crashing template is removed, not the whole endpoint. |
| `Endpoint policy: stop fuzzing endpoint...` | Printed when `-skip-endpoint-on-500` is enabled. | Confirms the stronger endpoint-level skip policy is active. |
| `Identities loaded: N (mode=... guest=... auth_file=...)` | Number of auth identities and scheduling mode. | For access-control fuzzing, confirm this is more than one and `auth_file=true`. |
| `Direct SHM read mode: requested=... active=...` | Whether coverage is read from shared memory. | `active=file` or `active=mmap` means the fast Docker sidecar path is working. |
| `Coverage after reset: ... edges` | Edges visible immediately after bitmap reset. | A small non-zero value can be normal if the API is active; a huge stale value suggests reset/mount problems. |
| `Dependency graph: producers=... consumers=...` | Number of producer/consumer links found for sequences. | Higher numbers mean Void can build more stateful request chains. |
| `Source-aware priority: boosted templates=...` | Templates boosted from source/route heuristics. | Confirms `-src` and `-source-aware-priority` are actually helping the scheduler. |
| `Templates loaded: ...` | Number of request templates from `templates.export.json`. | If this is unexpectedly low, grammar export or mount paths are wrong. |
| `Baseline corpus seeded: ...` | Initial corpus entries created from templates. | Should usually match the template count at startup. |

With `-no-ui`, Docker logs are intentionally quiet during the run: Void prints startup lines, writes JSONL/PoC/workflow artifacts continuously, and prints the final summary at shutdown. For live progress in container logs, use `-plain-ui` or omit `-no-ui` when running in an interactive terminal.

The final block starts with `Fuzzing complete.` and summarizes:

| Final field | Meaning |
|-------------|---------|
| `Requests done/sent` | Completed requests vs scheduled/sent requests and their rates. |
| `Coverage` | Final edge count, baseline ceiling, and mutation coverage above baseline. |
| `Latency avg`, `errors`, `crashes`, `uniq` | Health and finding counters for the campaign. |
| `Top endpoints` | Hot or high-signal endpoints with request/status/edge counts. |
| `Endpoints with logged 500` | Endpoints that produced crash records. |
| `Top triaged findings` | Highest-scored findings after triage/repro/minimization. |

Generated PoC scripts and structured reports redact sensitive auth headers. If a finding required bearer auth, the PoC uses `${AUTH_TOKEN:?set AUTH_TOKEN}`; set that environment variable before replaying it manually. Crash records still keep non-secret auth metadata in `auth_context`: identity name, sensitive header name, auth scheme, JWT marker when applicable, token length, cookie names, and short SHA-256 fingerprints. This lets you compare which credential triggered a finding without writing live tokens to disk.

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
| `-source-aware-priority` | **true** | Prioritize sensitive endpoints using source and route heuristics |
| `-bootstrap-max` | `20` | Max GET requests during runtime bootstrap value harvest |
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
| `-adaptive-content-type` | **true** | Adapt request `Content-Type` per endpoint using response feedback |

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
| `-crash-triage` | **true** | Classify crashes: `noise` / `needs_review` / `confirmed_unhandled_exception` / `likely_vuln[_high]` / `target_misconfiguration` |
| `-crash-signature-mode` | `balanced` | Dedup mode: `coarse` \| `balanced` \| `strict` |
| `-crash-signature-mutation` | `false` | Include mutation label in signature (more unique crashes) |
| `-crash-signature-query-values` | `false` | Include query values in signature |
| `-repro-runs` | `5` | Repro probe count per unique crash (0 = disable) |
| `-repro-target` | `80.0` | Stability % required to confirm crash |
| `-repro-timeout` | `5.0` | Timeout per repro probe (seconds) |
| `-minimize-crash` | **true** | Delta-reduce payload/path/query for minimal PoC |
| `-minimize-max-probes` | `24` | Max requests for minimization |

### Vulnerability Oracles (ON by default)

Signals that go beyond "HTTP 500 = bug". Access-control probes are most valuable with a multi-identity `-auth-file`.

| Flag | Default | Description |
|------|---------|-------------|
| `-access-probe` | **true** | Master toggle for all three access-control probes below |
| `-probe-bola` | **true** | Cross-identity BOLA/IDOR replay under every other identity |
| `-probe-auth-bypass` | **true** | No-credential replay. **Precondition:** only fires on endpoints already observed rejecting unauthenticated access with 401/403 — a truly public endpoint never triggers it, so no public-endpoint false positives. Confidence is `likely_vuln_high` when the endpoint was seen rejecting an *unauthenticated* request, else `likely_vuln` + `needs_manual_verification`. |
| `-probe-mass-assign` | **true** | Re-send successful writes with privileged fields over-posted |
| `-access-probe-prob` | `0.5` | Probability of firing access-control probes after a successful resource-scoped request |
| `-access-probe-max-per-endpoint` | `6` | Max access-control probes queued per endpoint per run |
| `-access-probe-queue-max` | `256` | Global cap on queued access-control probes |
| `-injection-oracle` | **true** | Positive injection detection: time-based SQLi, evaluated SSTI (`{{1337*1337}}`→`1787569`), reflected XSS |
| `-sqli-time-threshold` | `1.5` | Absolute latency (s) — also requires ≥3× baseline — that flags a sleep/benchmark SQLi payload |

A cross-identity or no-credential 2xx to another principal's resource is reported as `likely_vuln_high` (identical body) or `likely_vuln` (needs manual verification), with an `access_control: true` field recording `origin_identity` → `shadow_identity`. **Mass-assignment**: after a successful write, the body is re-sent with privileged fields over-posted (`isAdmin`, `role:"SuperAdmin"`, `permissions:["*"]`, …); if the server echoes an injected privileged field back, it's reported as `likely_vuln` (`mass_assignment_privileged_field_accepted`). The run report exposes `access_control_findings` and `distinct_root_causes` counters.

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
| `-skip-on-crash` | `false` | Remove only the crashing template after any 5xx |
| `-endpoint-stall-reqs` | `220` | Down-weight after N requests with no new edges |
| `-endpoint-zero-edge-reqs` | `120` | Down-weight when total reqs exceed N but no edges |
| `-endpoint-req-share-cap-pct` | `2.0` | Soft share cap (%) when no new edges |
| `-endpoint-req-cap-min-reqs` | `500` | Min endpoint requests before share cap applies |
| `-endpoint-no-edge-cap-weight` | `0.01` | Weight when endpoint exceeds share cap without new edges |
| `-endpoint-crash-rate-threshold` | `50.0` | 5xx% threshold for crash-rate throttling |
| `-endpoint-crash-rate-min-crashes` | `50` | Min 5xx count before throttling applies |
| `-endpoint-crash-rate-weight` | `0.02` | Weight for high crash-rate endpoints |

`-skip-on-crash` and `-skip-endpoint-on-500` are intentionally different. The first removes one crashing template; the second removes the whole endpoint. If crash replay or crash boost is still enabled, the fuzzer may deliberately revisit nearby crash areas to find variants. For a strict breadth scan on noisy targets, combine `-skip-on-crash -skip-endpoint-on-500 -crash-replay-count 0 -crash-boost-requests 0`.

### Auth / Identity

| Flag | Default | Description |
|------|---------|-------------|
| `-auth-file` | empty | Path to documented JWT/API-key/cookie identity file |
| `-multi-identity` | **true** | Rotate identities from `-auth-file`, `AUTH_FILE`, or `AUTH_IDENTITIES_JSON` |
| `-identity-mode` | `weighted` | Scheduling: `weighted` \| `round-robin` \| `random` |
| `-identity-include-guest` | **true** | Add anonymous guest traffic when no `guest` identity is present |
| `-auto-antiforgery` | **true** | Auto-harvest CSRF tokens from HTML responses |
| `-antiforgery-field` | `__RequestVerificationToken` | Form field name used for CSRF token injection |
| `-antiforgery-header` | `RequestVerificationToken` | Request header name used for CSRF token injection |
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
| `-poc-dir` | `crashes/pocs` | Reproducer shell scripts with sensitive auth headers redacted |
| `-timeline-dir` | `crashes/timelines` | Mermaid exploit flow diagrams |

### UI

| Flag | Default | Description |
|------|---------|-------------|
| `-no-ui` | `false` | Disable dashboard (plain stdout) |
| `-web-ui` | `false` | Enable the rich web UI dashboard server |
| `-web-ui-port` | `13377` | Port for the web UI dashboard |
| `-plain-ui` | `false` | Simple line-by-line output |
| `-ascii-ui` | `false` | ASCII borders (no Unicode box drawing) |
| `-force-ui` | `false` | Force dashboard even when stdout is not a TTY |
| `-ui-no-clear` | `false` | Don't clear screen between refreshes |
| `-ui-width` | `0` (auto) | Fixed dashboard width (80–200) |
| `-ui-interval` | `1.0` | Dashboard refresh interval (seconds) |
| `-ui-endpoint-sort` | `hot` | Sort: `hot` \| `recent` \| `req` \| `edges` \| `alpha` |
| `-ui-endpoint-rotate` | **true** | Auto-rotate endpoint pages |
| `-ui-endpoint-rotate-sec` | `1.0` | Seconds between endpoint page rotations |

---

## Architecture & Code Structure (`void/go/`)

The fuzzer engine has been designed around distinct, cohesive files for maintainability and clear onboarding:

- **`types.go`**: Core data structures (`Config`, `WorkItem`, `SendResult`, `Fuzzer` interfaces).
- **`mutations.go`**: MOpt-style payload dictionaries and adaptive mutation category selection algorithms.
- **`store.go`**: Runtime knowledge extraction, global value deduplication, and dynamic `DictStore` lookup.
- **`coverage.go`**: Handlers for Shared Memory (SHM) direct byte reads and HTTP `/coverage` polling.
- **`fuzzer.go`**: Main fuzzer struct and high-level lifecycle hooks (`Run`, `Close`, scheduling steps).
- **`auth.go`**: JWT/header/cookie authentication state, login fallback, and Anti-forgery (CSRF) token harvesting/injection.
- **`template.go`**: Parsing of `templates.export.json` and rendering API request structures into raw HTTP bytes.
- **`worker.go`**: Core fuzzing loop, concurrency management, and worker thread synchronization (`sync.WaitGroup`).
- **`sequence.go`**: Stateful multi-step chains (e.g., CREATE $\rightarrow$ READ $\rightarrow$ UPDATE $\rightarrow$ DELETE), matching producer/consumer followup endpoints.
- **`triage.go`**: Source-aware priority and routing of crash severity scores.
- **`cluster.go`**: Root-cause clustering — collapses many per-payload crash signatures into distinct bugs via normalized exception message + top application stack frame.
- **`oracle.go`**: Vulnerability oracles beyond HTTP 500 — BOLA/IDOR and broken-auth via cross-identity/no-credential replay, plus positive injection detection (time-based SQLi, evaluated SSTI, reflected XSS).
- **`poc.go`**: Generation of `curl` reproducer shell scripts and Markdown exploit timelines.
- **`report.go`**: Assembly of the final JSON crash report and vulnerability findings.
- **`minimize.go`**: Delta-debugging logic to binary-search and strip away unnecessary JSON fields from a crashing payload.
- **`identity.go`**: Auth identity files, weighted identity scheduling, trace decoration, and race condition probes.
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
  /usr/local/go/bin/go build -o /src/void-linux-amd64 .

# macOS arm64 cross-compiled inside Docker
docker run --rm -v "$(pwd)/go:/src" -w /src golang:1.22-alpine \
  sh -c "GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o /src/void-darwin-arm64 ."
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
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download
COPY go/ ./go/
RUN cd go && go build -ldflags="-s -w" -o /out/void .

FROM alpine:3.19
RUN apk add --no-cache python3
WORKDIR /fuzzer
COPY export-templates.py .
COPY --from=builder /out/void /usr/local/bin/void
ENTRYPOINT ["/usr/local/bin/void"]
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
  "path": "/api/example-resource/0",
  "identity": "org-a-admin",
  "auth_context": {
    "identity": "org-a-admin",
    "redacted": true,
    "credential_count": 1,
    "credentials": [
      {
        "header": "Authorization",
        "scheme": "Bearer",
        "token_format": "jwt",
        "token_len": 1089,
        "token_fingerprint": "sha256:2d8b6a2a9f7d0c31",
        "masked": "Bearer ${AUTH_TOKEN:?set AUTH_TOKEN}"
      }
    ]
  },
  "mutation": "sqli",
  "payload": "'{\"name\":\"' OR 1=1--\"}",
  "response_body": "An error occurred while processing your request.",
  "triage": {"classification": "needs_review", "severity_score": 5, "crash_layer": "model_binding"},
  "repro": {"stable_reproducible": true, "stability_pct": "100.0"},
  "minimized": {"path": "/api/example-resource/0", "payload": ""},
  "poc_file": "./crashes/pocs/poc-7ecd321e718f5a26.sh",
  "timeline_file": "./crashes/timelines/timeline-7ecd321e718f5a26.md"
}
```
