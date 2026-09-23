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

Canonical auth file schema and access-control guidance: **[`docs/guides/authentication.md`](../../../../docs/guides/authentication.md)**.
Security-focused flag interactions and recommended profiles: **[`INSTRUCTIONS.md`](../../../../docs/getting-started/quickstart.md#security-campaign-profiles)**.

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
  -auth-file ../../../../docs/guides/auth.identities.example.json \
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
| `-profile fast` | CI smoke / max throughput | `repro-runs 0`, `minimize-crash=false`, oracles off, `race-mode=false`, `sequence-prob 0.1`, **`typed-body-mutation=false`** |
| `-profile deep` | Thorough scan | `time-budget 60`, `repro-runs 5`, `minimize-crash`, `sequence-prob 0.5`, oracles on, `race-mode`, **`typed-body-mutation=true`, `adversarial-body-rate 0.5`** |
| `-profile security` | Vulnerability hunting | multi-identity + guest on, `access-probe` (prob 0.75), injection oracle, source-aware priority, `sequence-prob 0.5`, `race-mode`, **`typed-body-mutation=true`, `adversarial-body-rate 0.75`** |

Why `fast` turns typed body mutation off rather than just leaving it at its own default: it
measurably costs throughput (schema-correct bodies clear validation and reach real business
logic instead of failing fast on malformed JSON — see the measured comparison in
[`docs/guides/typed-structural-mutation.md`](../../../../docs/guides/typed-structural-mutation.md)),
the wrong trade for a throughput-first CI smoke profile.

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
| Run started fails with `coverage instrumentation degraded` | Fix the instrumentation first (rebuild via `fuzz-prep-multi.py`, check `verify-hook.sh`) — don't just pass `-allow-degraded-coverage`, that run will find nothing since the coverage feedback loop is broken |

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
| `Loaded dictionary: ...` | The active mutation dictionary path. | For security campaigns this should point to your security/domain dictionary, not only the auto-generated default one. |
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
| `Coverage health: shm_bound=... app_assemblies=...` | Facts fetched from `/shm/health` before the fail-closed warm-up probe runs. | `shm_bound=false` or an empty `app_assemblies` list is an early warning sign. |
| `Coverage health OK: warm-up probe (...) produced N new edge(s)` | The engine sent a few real unmutated requests and confirmed the shared coverage bitmap actually moved. | If this line is missing, the run exited instead — see `-allow-degraded-coverage` below. |
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
| `-grammar` | `.` | Directory with `templates.export.json` and `dict.json` (written directly by `compile-grammar.sh` — see [ARCHITECTURE.md §6](../../../../docs/architecture/overview.md)) |
| `-dict` | _(from grammar dir)_ | Custom JSON dictionary path |
| `-templates-json` | `<grammar>/templates.export.json` | Path to the compiled template JSON |
| `-exporter` | `./export-templates.py` | **Legacy fallback only**: path to the old `grammar.py`→JSON exporter, auto-invoked *only* if `templates.export.json` is missing but a pre-migration `grammar.py` is present in `-grammar`'s directory. Grammars generated by the current `compile-grammar.sh` never need this. |
| `-refresh-templates` | `false` | Force re-export from `grammar.py` via the legacy exporter above, even if JSON already exists (has no effect on grammars that never had a `grammar.py`) |
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
| `-direct-shm` | `false` | Read coverage bitmap from SHM file (faster than HTTP — but only if `-shm-read-mode mmap` is also set; see warning directly below) |
| `-shm-path` | `/coverage_shm/bitmap` | Path to the mmap bitmap file |
| `-shm-read-mode` | `file` | SHM read mode: `file` \| `mmap` \| `auto`. **⚠️ Always pass `mmap` explicitly when running `void` as a Linux container against a shared volume — this is the normal `-direct-shm` deployment shape (a Docker sidecar) and `mmap` only activates on Linux.** The `file` default re-reads *and re-scans the entire bitmap* via a fresh syscall on every single `GetEdges()` call (called ~2x per request) — measured on a real Bitwarden run, `-shm-read-mode file` was **slower overall (229 req/s) than plain HTTP-mode coverage polling (266–302 req/s)**, because HTTP mode fetches one pre-computed integer from the target while `file` mode re-reads and re-scans a multi-MB bitmap from scratch on every call. `mmap` gives a persistent zero-copy view instead — no re-read, no re-scan setup cost — and is dramatically faster once the container is actually Linux (which it always is for the Docker-sidecar deployment). `file` stays the *default* only because it is the sole mode guaranteed correct on every OS/filesystem this flag might run from (e.g. it is NOT safe to assume for non-container or non-Linux hosts) — it is not a recommendation to use it when you control the environment. |
| `-coverage-interval` | `1` | Read coverage every N completed requests |
| `-coverage-bitmap-size` | `262144` | SHM bitmap size hint in bytes. Diagnostic only in `-direct-shm` mode (Top-20 #17): the engine now trusts the real on-disk SHM file size (which the .NET side auto-sizes from the real instrumented-type count, ~64KB–8MB) rather than truncating to this value — a mismatch just logs a note instead of silently dropping coverage |
| `-allow-degraded-coverage` | `false` | Continue even if the fail-closed startup health check (Top-20 #4) reports degraded instrumentation. Off by default — the engine refuses to start a run whose coverage bitmap doesn't move under real warm-up traffic, since that run would otherwise burn its whole time budget finding nothing. See "Self-verifying, fail-closed instrumentation" below. |

### CmpLog / Constant Extraction

| Flag | Default | Description |
|------|---------|-------------|
| `-cmplog` | **true** | Poll `/shm/cmplog` for comparison operands harvested straight out of the target's own IL (the literal right-hand side of `String.Equals`/`StartsWith`/`Contains`/`==` and integer-compare checks) and blend recovered "magic values" into string/int mutation. No-op against a target built without `--cmplog` at instrument time, or in `--inject-mode source` |
| `-cmplog-interval` | `3.0` | Seconds between `/shm/cmplog` polls |

Constant/string dictionary extraction (`constants.go`) is a separate, always-on, read-only pass — it needs no flag; it fetches `/shm/constants` once at startup.

### Sequences (stateful multi-step chains)

| Flag | Default | Description |
|------|---------|-------------|
| `-sequence-prob` | `0.30` | Probability of scheduling a sequence step |
| `-sequence-max-depth` | `3` | Max chain length (create → read → update → delete) |
| `-sequence-fanout` | `6` | Max follow-up requests per successful step (widened by 1 for a step that just reached a never-seen workflow shape — Top-20 #12) |
| `-sequential-baseline` | `false` | Run baseline epoch sequentially instead of concurrent |
| `-pagination-chaining` | **true** | A GET list response carrying a recognized cursor/next-page field or `Link: rel="next"` header gets a follow-up request continuing the same endpoint's next page — a shape the general producer/consumer follow-up logic can't produce on its own |

**State-reward search (Top-20 #12):** a sequence step reaching a workflow *shape* (ordered method+normpath+status-class, concrete IDs collapsed) never seen this run earns a state-novelty energy bonus and one extra fanout branch — rewarding new *states*, not just new coverage edges. `printFinalReport` shows `Sequence engine: new_states_found=N unique_workflows_persisted=M`; the latter also dedups the on-disk workflow reports (`workflows/*.json`+`.sh`) by final shape so equivalent workflows aren't all dumped to disk.

**Typed resource state graph** (see `docs/research/design-notes/resource-state-graph-plan.md`):

| Flag | Default | Description |
|------|---------|-------------|
| `-resource-graph` | **true** | Typed resource-lifecycle tracking + generalized (HAL/JSON:API/header/shape) extraction + coverage-directed consumer scheduling. `false` reproduces the exact prior name-based extraction and static verb-affinity fanout ordering |
| `-resource-graph-max-per-type` | `500` | Max tracked resource instances per resource type (oldest/lowest-confidence evicted first) |
| `-resource-graph-max-aliases` | `16` | Max alternative identities tracked per resource instance |
| `-resource-graph-max-transitions` | `5000` | Max lifecycle transitions retained (ring-bounded) |
| `-resource-graph-explore-rate` | `0.10` | Probability of promoting a lower-scored sequence consumer ahead of the coverage-directed ranking, so it's never permanently starved |
| `-resource-graph-min-confidence` | `0.30` | Minimum extraction confidence for a candidate to be recorded in the graph |
| `-resource-graph-unreached-weight` | `40.0` | Scoring bonus for a consumer never yet reached |
| `-resource-graph-yield-weight` | `2.0` | Scoring weight per historical new-edge discovered at a consumer's endpoint |
| `-resource-graph-failure-penalty` | `5.0` | Scoring penalty per consecutive failed attempt at a consumer |
| `-resource-graph-stale-explore-prob` | `0.15` | Probability of deliberately binding a follow-up to a DELETED/INVALIDATED resource, to exercise stale-read/update-after-delete workflows rather than only valid ones |
| `-resource-graph-value-bias-weight` | `3` | Extra weighted copies of a resource-graph-known, still-alive value added to a body/query field's candidate pool before random selection (`0` disables the bias). See "Chain-quality improvements" below |
| `-resource-graph-success-prob-weight` | `15.0` | Valid-workflow planner term: scoring weight for a consumer's own historical 2xx rate (`0` disables it) |
| `-resource-graph-availability-weight` | `20.0` | Valid-workflow planner term: scoring bonus when a resource instance of the consumer's expected type is actually available right now (`0` disables it) |

Lifecycle states (`Unknown`/`Discovered`/`Created`/`Readable`/`Modified`/`Deleted`/`Invalidated`/`FailedCreation`/`FailedModification`/`FailedDeletion`/`Stale`) are derived from method+status+prior-state, never method alone — e.g. a `GET` returning 200 against a resource this run already deleted is `Stale`/`invalid`, not `Readable`. Persisted workflow JSON (`workflows/*.json`) gains optional `resources`/`transitions` fields with the graph's own snapshot for that sequence.

#### Chain-quality improvements

Five targeted fixes, measured against a real Bitwarden fuzzing run and documented in full (including the measurements that justified them) in [`docs/research/design-notes/resource-state-graph-report.md`](../../../../docs/research/design-notes/resource-state-graph-report.md):

1. **Value substitution now prefers resource-graph values.** Previously, a sequence follow-up's path placeholder was *always* filled from the old id-name-centric extraction (`entityIDs[0]`), even when the resource graph had a real, freshly-extracted GUID on hand for that exact consumer's resource type — the graph only ever influenced *which* consumer template got scheduled next, never *which concrete value* was plugged into it. `pickFollowupPathValue` (`sequence.go`) now checks `findCompatibleResources` first; body/query fields get the same treatment via `-resource-graph-value-bias-weight` (weighted extra candidates, not a replacement — generic/boundary values like `fuzzstring`/`sample`/`true`/`false` remain in the pool). Follow-ups that used a graph value carry a `+graph_id` tag in their mutation label.
2. **Dedup upgrades to real-ID provenance.** The on-disk workflow exemplar kept per shape signature is no longer strictly "whichever sequence arrived first" — if a later occurrence of the same shape shows a genuine producer(response)→consumer(request) real-ID chain and the current exemplar doesn't, the later one replaces it on disk (still exactly one file per shape).
3. **Persistence bar lowered for genuine real-ID chains.** A sequence normally needs to reach the full configured depth (`-sequence-max-depth`) before `maybePersistSequence` will write it to disk. A shallower sequence (as few as 2 steps) that already shows a genuine real-ID chain bypasses that gate — the single most useful signal this feature can produce was previously invisible below full depth regardless of quality.
4. **Crashes now link back to their originating sequence.** `CrashRecord` gained a `sequence_id` field, and `sequence_event.jsonl`'s `produced_bug_id` (previously always empty, an explicitly-flagged gap) is now populated from the root-cause cluster(s) recorded against that sequence.
5. **Counters for why a sequence stopped extending.** `seq_stop_max_depth` / `seq_stop_failed_step` / `seq_stop_no_produced_value` / `seq_stop_no_followup_candidate` / `seq_stop_render_failed` (printed at run end and in the summary JSON) replace what used to require ad hoc log analysis to answer "why don't more chains reach full depth."

Measured impact (10-minute validation run, see the report for full numbers): before these fixes, only 3/59 dedup-rejected sequences in a comparable run carried real-ID provenance — these fixes target the value-substitution step that was the actual root cause of that low rate, not just its downstream symptom.

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
| `-minimize-chain` | **true** | For a crash reached through a multi-step sequence chain, also try dropping non-essential earlier *steps* entirely (not just shrinking the final request's own fields — requires `-minimize-crash`) |
| `-minimize-max-probes` | `24` | Max requests for minimization (shared budget for both field- and chain-level minimization) |

### Vulnerability Oracles (ON by default)

Signals that go beyond "HTTP 500 = bug". Access-control probes are most valuable with a multi-identity `-auth-file`.

| Flag | Default | Description |
|------|---------|-------------|
| `-access-probe` | **true** | Master toggle for all four access-control probes below |
| `-probe-bola` | **true** | Cross-identity BOLA/IDOR replay under every other identity |
| `-probe-auth-bypass` | **true** | No-credential replay. **Precondition:** only fires on endpoints already observed rejecting unauthenticated access with 401/403 — a truly public endpoint never triggers it, so no public-endpoint false positives. Confidence is `likely_vuln_high` when the endpoint was seen rejecting an *unauthenticated* request, else `likely_vuln` + `needs_manual_verification`. |
| `-probe-mass-assign` | **true** | Re-send successful writes with privileged fields over-posted |
| `-probe-differential` | **true** | (Top-20 #18) Verb (GET→HEAD)/content-type (JSON→text/plain)/route-case/param-location confusion, replayed with no credentials. **Precondition:** only fires on endpoints with *strong* auth evidence (a plain unauthenticated request was already rejected) — a hit means the confusion technique itself, not general laxness, bypassed the check. `likely_vuln_high`, tagged `differential_auth_bypass:<technique>` |
| `-access-probe-prob` | `0.5` | Probability of firing access-control probes after a successful resource-scoped request |
| `-access-probe-max-per-endpoint` | `6` | Max access-control probes queued per endpoint per run |
| `-access-probe-queue-max` | `256` | Global cap on queued access-control probes |
| `-injection-oracle` | **true** | Positive injection detection: time-based SQLi, evaluated SSTI (`{{1337*1337}}`→`1787569`), reflected XSS |
| `-schema-conformance` | **true** | (Top-20+ #23) Validate 2xx response bodies against the declared OpenAPI response schema. Undeclared fields are tagged `schema_undeclared_field` (`needs_review`) or, when the field name looks sensitive (password/secret/token/hash/...), `schema_undeclared_sensitive_field` (`likely_vuln`); declared-vs-observed type drift is `schema_type_mismatch` (`needs_review`, low confidence). Silent on endpoints whose grammar declares no response schema — no ground truth, no finding |
| `-sqli-time-threshold` | `1.5` | Absolute latency (s) — also requires ≥3× baseline — that flags a sleep/benchmark SQLi payload |

A cross-identity or no-credential 2xx to another principal's resource is reported as `likely_vuln_high` (identical body) or `likely_vuln` (needs manual verification), with an `access_control: true` field recording `origin_identity` → `shadow_identity`. **Mass-assignment**: after a successful write, the body is re-sent with privileged fields over-posted (`isAdmin`, `role:"SuperAdmin"`, `permissions:["*"]`, …); if the server echoes an injected privileged field back, it's reported as `likely_vuln` (`mass_assignment_privileged_field_accepted`). The run report exposes `access_control_findings` and `distinct_root_causes` counters.

#### Stateful oracles (require `-resource-graph`, see below)

These reuse the typed resource-lifecycle graph rather than a stateless replay — each catches a bug class the plain access-control probes above structurally can't see, since it depends on *prior request history*, not just "does another identity get in":

| Flag | Default | Description |
|------|---------|-------------|
| `-probe-stale-object` | **true** | Flags a mutating operation that unexpectedly succeeds against a resource this run already observed as deleted (stale read = `likely_vuln`; write-after-delete = `likely_vuln_high`, severity 8) |
| `-probe-stale-etag` | **true** | Replays a write with a deliberately wrong `If-Match` against a resource with a known real ETag; acceptance (instead of 409/412/428) flags optimistic-locking not enforced |
| `-probe-workflow-bypass` | **true** | Flags an action endpoint (`x-state-transition` declared in the grammar) that succeeded against a resource whose known state doesn't satisfy the declared predecessor state (e.g. `pay()` succeeding on an invoice that was never `sent`). Narrow by construction — real-world OpenAPI specs rarely declare `x-state-transition`, so this rarely fires without one |
| `-probe-idempotency` | **true** | Verbatim-replays a just-succeeded create-shaped POST (same body/headers, including any client idempotency key); a second, *different* created resource id flags non-idempotent processing — most severe on payment/refund/redeem/withdraw/transfer-shaped endpoints, where it means a double charge or payout |

Findings from this group carry `"oracle": "stale_object" | "stale_etag" | "workflow_bypass" | "idempotency_replay"` in `triage` and are counted separately from `access_control_findings`. See [`docs/architecture/stateful-fuzzing.md` §2.5](../../../../docs/architecture/stateful-fuzzing.md) for the full security-scenario-family mapping.

### Typed Structural Body Mutation (ON by default, requires a grammar compiled with a current `grammarc`)

| Flag | Default | Description |
|------|---------|-------------|
| `-typed-body-mutation` | **true** | Schema-aware object/array/`oneOf`+discriminator-aware mutation for templates whose grammar carries a `body_schema` (compiled by the current `tools/grammar/grammarc/`). `false` always uses the legacy flat-segment/`mutateJSONBody` path — additive/no-op for grammars predating this feature either way |
| `-adversarial-body-rate` | `0.5` | Probability (during `mutate`/`havoc` epochs only) of applying exactly one deliberate structural violation to a typed body instead of a schema-correct "valid" instance |

Ten operators (add/remove field, required-field omission, array resize, `oneOf`/discriminator
switch, type substitution, null injection, undeclared-property insertion, duplicate object
key, nesting-depth stress, constraint boundary), each targeting a real object/array/`oneOf`
tree instead of a flattened JSON string. Full design, the operator-by-operator bug-class
table, concrete example commands for "which command finds which kind of bug," and a real
measured A/B comparison against the legacy flat mutator (65% more coverage, ~2.8× higher
confirmed-bug rate, on a real Bitwarden checkout):
**[`docs/guides/typed-structural-mutation.md`](../../../../docs/guides/typed-structural-mutation.md)**.

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
| `-probe-race-outcome` | **true** | Evaluate whether *more than one* of a burst's N concurrent identical requests actually succeeded (double-spend, concurrent-approve, over-redeem) — a distinct, sharper signal than "did the target crash under contention"; requires `-race-mode` |

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
| `-sarif-file` | empty (not written) | Findings as SARIF 2.1.0 — drops into GitHub code scanning / DefectDojo without a custom parser. One SARIF "rule" per distinct root-cause cluster or strong oracle signal (`sqli_time_based`, `bola_identical_cross_identity_response`, ...); `noise`/`target_misconfiguration` findings excluded |
| `-poc-dir` | `crashes/pocs` | Reproducer shell scripts with sensitive auth headers redacted |
| `-timeline-dir` | `crashes/timelines` | Mermaid exploit flow diagrams |

### Checkpoint / Resume

For a long campaign that might get interrupted (or one you want to pause and continue later without losing valid-chain state):

| Flag | Default | Description |
|------|---------|-------------|
| `-checkpoint-path` | empty | Path to periodically save a corpus + resource-graph checkpoint (single JSON file). Empty disables checkpointing entirely — opt-in, zero behavior change otherwise |
| `-checkpoint-interval-sec` | `60.0` | How often to auto-save the checkpoint while running (also saved once on graceful exit) |
| `-resume` | `false` | Load an existing `-checkpoint-path` at startup (if present) instead of starting from a fresh baseline corpus/resource graph. `false` with `-checkpoint-path` set still *writes* checkpoints, just never reads one back — "always save, resume only when I ask for it" |

### Reproducibility / Run Manifest

Every JSON report and SARIF output now carries a `run_manifest` (report.go/sarif.go, `manifest.go`) — run id, seed, target, and a **locally-verified SHA-256** of the exact `templates.export.json` this run loaded. The three flags below are pure pass-through labels for provenance void cannot verify itself (it never inspects the running container or the original OpenAPI document) — set them from your CI/orchestration layer if you want that provenance recorded:

| Flag | Default | Description |
|------|---------|-------------|
| `-target-image-digest` | empty | Container image digest of the target under test, recorded in the run manifest |
| `-openapi-spec-hash` | empty | Hash of the source OpenAPI/swagger document this run's grammar was generated from, recorded in the run manifest |
| `-campaign-config` | empty | Path to the `campaign.yaml` that drove this run, if any (see [`docs/guides/campaigns.md`](../../../../docs/guides/campaigns.md)), recorded in the run manifest |
| `-seed` | `0` (unseeded) | Seed `math/rand`'s global source for reproducible mutation/scheduling draws. Not bit-for-bit deterministic under concurrency, but removes the dominant source of run-to-run variance |
| `-run-id` | empty | Opaque run identifier stamped into every `-event-log` row (benchmark harness use; purely a label) |
| `-event-log` | empty | Path to a per-request JSONL event log (epoch, mutation category, coverage delta, sequence/corpus ancestry, identity, valid/state-change flags). Off by default — opt in for benchmark data collection; adds one JSON-encode+write per completed request when enabled |

A sequence-originated finding's own `bugs[].chain` (report.go) / `results[].properties.chain` (SARIF) additionally carries the full step-by-step request chain (already minimized, if `-minimize-chain` shrank it) and its producer-consumer value bindings — "which id genuinely came from which prior response" as a directly reportable fact.

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

## Architecture & Code Structure (`internal/engine/`)

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
- **`resource_graph.go`**: Typed, bounded resource-lifecycle state graph (identities, aliases, lifecycle transitions) layered on top of the sequence engine.
- **`resource_extraction.go`**: Generalized entity/reference extraction (HAL `_links`, JSON:API relationships, headers, route-template-typed URI segments, value-shape detection) replacing id-name-centric extraction.
- **`resource_scheduling.go`**: Lifecycle-transition derivation and coverage-directed consumer scoring/ranking, replacing the purely-static verb-affinity fanout sort.
- **`adversarial.go`**: Stale-object (deleted-resource-still-mutable) and stale-ETag (optimistic-locking) oracles, plus the shared adversarial-finding sink both they and `idempotency.go`/`webhook.go` funnel through.
- **`idempotency.go`**: Idempotency-replay oracle — verbatim-replays a just-succeeded create-shaped POST; a second, different created id flags non-idempotent (double-payment-class) processing.
- **`race.go`**: Race-burst outcome evaluation — did more than one of N concurrent identical requests succeed (double-spend/concurrent-approve), not just "did it crash under contention."
- **`async.go`**: Async-operation model (submit → poll → terminal) — recognizes a 202/Retry-After submission and a resource's own terminal-status attribute, biasing the scheduler to keep polling a still-pending job.
- **`pagination.go`** (`-pagination-chaining`): follows a paginated list response's own cursor/next-page field or `Link: rel="next"` header with a same-endpoint next-page request.
- **`multipart_chain.go`**: Multipart-upload → process → download chain modeling — tags an upload's produced resource and biases the scheduler toward a matching download/retrieval follow-up.
- **`webhook.go`**: Soft-disabled-but-still-active detection — a webhook/subscription resource turned off via `active:false`/`enabled:false` (not DELETE) that still fires on a trigger-shaped action.
- **`checkpoint.go`** (`-checkpoint-path`/`-resume`): periodic corpus + resource-graph snapshot to a single JSON file, so a long campaign can resume instead of rebuilding valid chains from scratch.
- **`manifest.go`**: Run manifest (run id, seed, target, the locally-hashed templates JSON, plus pass-through image-digest/OpenAPI-spec-hash/campaign-config labels) surfaced in the JSON report and SARIF output for reproducibility.
- **`triage.go`**: Source-aware priority and routing of crash severity scores.
- **`cluster.go`**: Root-cause clustering — collapses many per-payload crash signatures into distinct bugs via normalized exception message + top application stack frame.
- **`oracle.go`**: Vulnerability oracles beyond HTTP 500 — BOLA/IDOR and broken-auth via cross-identity/no-credential replay, mass assignment, plus positive injection detection (time-based SQLi, evaluated SSTI, reflected XSS).
- **`schema_oracle.go`**: Response-schema conformance oracle (`-schema-conformance`) — undeclared/sensitive fields and type drift vs. the declared OpenAPI response schema.
- **`cmplog.go`**: CmpLog/RedQueen IL-comparison operand harvesting — polls `/shm/cmplog` and feeds recovered string/int constants into mutation.
- **`constants.go`**: Static constant/string dictionary extraction pool — fetches `/shm/constants` once at startup.
- **`poc.go`**: Generation of `curl` reproducer shell scripts and Markdown exploit timelines.
- **`report.go`**: Assembly of the final JSON crash report and vulnerability findings, including the run manifest and (for sequence-originated findings) the full chain trace + producer-consumer bindings.
- **`sarif.go`**: SARIF 2.1.0 findings export (`-sarif-file`, opt-in) for GitHub code scanning/DefectDojo integration, including the run manifest and chain trace as result/run properties.
- **`minimize.go`**: Delta-debugging logic to binary-search and strip away unnecessary JSON fields from a crashing payload, plus whole-chain minimization (`-minimize-chain`) for crashes reached through a multi-step sequence.
- **`identity.go`**: Auth identity files, weighted identity scheduling, trace decoration, and race condition probes.
- **`jwt_expiry.go`**: Parses the unsigned `exp` claim off JWT-shaped identity tokens and warns at startup/mid-run before/when one expires.
- **`mutation_engine.go`**: Context-aware injection algorithms (JSON payload flipping, path traversal injection, query dropping, etc.).
- **`ui.go`**: Rich terminal dashboard rendering, ASCII progress bars, and run reporting.
- **`webui.go`**: Embedded live web dashboard (`-web-ui`/`-web-ui-port`) as a browser-based alternative to the terminal UI.
- **`utils.go`**: General string manipulation, byte arrays, path parsers, and generic mathematical helpers.
- **`main.go`**: CLI flags parsing, configuration validation, and application bootstrap entry point.

See [`docs/architecture/stateful-fuzzing.md`](../../../../docs/architecture/stateful-fuzzing.md) for how the resource-graph/sequence/adversarial files above fit into the broader stateful-fuzzing design (typed resource model → valid-workflow planning → adversarial branching → oracles → reproducibility), and [`docs/guides/security-scenarios.md`](../../../../docs/guides/security-scenarios.md) / [`security_scenarios.yaml`](../../../../tools/campaign/security_scenarios.yaml) for the declarative catalog of every stateful security-scenario family this engine implements, cross-checked against this exact code.

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

All commands below run from **`src/void/`** (this directory's own parent) — `go.mod` lives
there, covering both `cmd/` and `internal/` as a self-contained Go module; there is no
`go.mod`/`main.go` at the actual repo root or under `internal/engine/` directly (an older
layout some docs used to reference before the module was reorganized — if you see `cd
internal/engine/ && go build -o void .` or a repo-root `go.mod` referenced anywhere, it's
stale, file it as a bug). From the actual repo root, run `go -C src/void build -o void ./cmd/void`
instead (see `Makefile`'s `build-void` target).

### Native build (current OS + arch)

```bash
go build -o void ./cmd/void
```

### Cross-compilation table

```bash
# macOS Apple Silicon (M1/M2/M3)
GOOS=darwin  GOARCH=arm64 go build -o void-darwin-arm64 ./cmd/void

# macOS Intel
GOOS=darwin  GOARCH=amd64 go build -o void-darwin-amd64 ./cmd/void

# Linux aarch64 (ARM64 — Docker on M1, AWS Graviton, RPi)
GOOS=linux   GOARCH=arm64 go build -o void-linux-arm64 ./cmd/void

# Linux amd64 (most servers, Docker on Intel/AMD)
GOOS=linux   GOARCH=amd64 go build -o void-linux-amd64 ./cmd/void

# Windows 64-bit
GOOS=windows GOARCH=amd64 go build -o void-windows-amd64.exe ./cmd/void
```

### Build via Docker (no local Go needed)

```bash
# Linux amd64 (for use inside Docker compose)
docker run --rm -v "$(pwd):/src" -w /src golang:1.22-alpine \
  go build -o /src/void-linux-amd64 ./cmd/void

# macOS arm64 cross-compiled inside Docker
docker run --rm -v "$(pwd):/src" -w /src golang:1.22-alpine \
  sh -c "GOOS=darwin GOARCH=arm64 go build -o /src/void-darwin-arm64 ./cmd/void"
```

### Build optimized release binary (smaller, no debug symbols)

```bash
GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o void-linux-amd64 ./cmd/void
```

> `-s -w` strips the symbol table and DWARF debug info, reducing binary size from ~8MB to ~5MB.

### Multi-arch container image

The real, already-maintained Dockerfile is **[`deployments/docker/Dockerfile.void`](../../../../deployments/docker/Dockerfile.void)**
— unlike every other command on this page, this one runs from the **actual repo root**, not
`src/void/` (build context must be the repo root so the Dockerfile can `COPY src/void/...`):

```bash
docker build -t void-fuzzer -f deployments/docker/Dockerfile.void .
```

Build for multiple platforms via `docker buildx` (also from the actual repo root, same reason):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f deployments/docker/Dockerfile.void \
  -t void:latest \
  .
```

---

## Mutation Categories

MOpt-style weighted selection — categories that find more edges get higher probability:

`boundary` · `overflow` · `sqli` · `xss` · `cmdi` · `path_traversal` · `ssrf` · `ssti` · `open_redirect` · `crlf` · `log4shell` · `nosqli` · `ldap` · `xxe` · `unicode`

**Constraint-aware boundary mutation.** When a segment in `templates.export.json` carries
declared constraints (`min_length`/`max_length`/`minimum`/`maximum`/`pattern`/`enum_values`
— populated by `tools/grammar/grammarc/`/`analyzer` from the target's OpenAPI spec + real C# validation
attributes), `mutateInt`/`mutateNumber`/`mutateStringCategorized` blend exact boundary
candidates (`{min-1, min, min+1, max-1, max, max+1}`, exact min/max-length strings,
valid/near-miss-invalid enum values) into the `boundary`/`overflow` pools above — additive,
not a separate category, so it shows up under the same category labels. Segments with no
declared constraint (or grammars generated before this existed) get exactly the generic
behavior described above, unchanged.

**Typed structural body mutation** is a separate, sibling MOpt registry (`mcat_struct_*`
labels) covering request bodies specifically — object/array/`oneOf` structure, not string
bytes. See [Typed Structural Body Mutation](#typed-structural-body-mutation-on-by-default-requires-a-grammar-compiled-with-a-current-grammarc) above and [`docs/guides/typed-structural-mutation.md`](../../../../docs/guides/typed-structural-mutation.md).

**CMPLOG-lite (400-body mining).** Independent of the mutation categories above: every 4xx
response body is parsed for ASP.NET's standard validation-error shape
(`{"errors":{"Field":["msg"]}}`) and free-text enum hints (`"must be one of [...]"`).
Extracted field names/values are fed into the runtime value store automatically — no flag
needed — so `custom_payload` fields the fuzzer initially guessed wrong start getting real,
server-taught candidate values as the run progresses.

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
