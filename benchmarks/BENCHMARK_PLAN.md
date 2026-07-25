# UpsideFuzz vs RESTler — Benchmark & Evaluation Plan

**Status:** design + infrastructure. Updated 2026-07-24: the *Immediate Prerequisites* (§20) / *Top-15 tasks #1–8* (§21) are now implemented and individually verified against a live target, and a scaled-down pilot (§19 Phase 2, T0-only, C1+C3 — see scope note below) has been run. **No comparative/campaign-scale runs (Phases 3–8) have been executed** — those remain exactly what §7's core-hour estimates describe (hundreds to thousands of core-hours), a deliberate scope decision, not a limitation discovered along the way. This document remains the specification for that larger campaign.

**What's now built** (all verified working against `fixtures/planted-bug-api/`, not just written):
- `benchmarks/harness/coverage_poller.py` + `resource_sampler.py` — external, tool-agnostic (§16 P0 #1).
- `void/go`'s `-event-log` flag → `request_event.jsonl` + `epoch_event.jsonl` + `sequence_event.jsonl` (§16 P0 #6, plus epoch/sequence streams from the same table).
- `void/go`'s `-seed` flag, seeding `math/rand`'s global source (§16/§21 P0 #8) — not bit-for-bit deterministic under concurrency (documented in-code), but closes the "always unseeded" gap.
- `benchmarks/harness/reset_target.py` — compose down/up + readiness poll + coverage reset (§13, §21 P0 #2). **T0-only**: T0 has no database, so this is the full reset contract for it; T1–T3's golden-snapshot-restore + checksum gate for real databases is *not* built (flagged explicitly in the script's own docstring, not silently assumed).
- `benchmarks/manifests/planted-bug-api.json` — ground-truth manifest for T0's one seeded vuln (§8/§21 P0 #4). Explicitly self-authored (§18 implementation-bias threat applies); a second, externally-authored controlled target's manifest is still needed for headline accuracy claims.
- `benchmarks/harness/shared_judge.py` — a Python port of `cluster.go::rootCauseClusterKey`, applied uniformly to both tools' raw findings (§8/§21 P0 #3), plus a taxonomy classifier. Verified it correctly clusters the *same* real bug found independently by both tools during pilot validation into one root cause.
- `benchmarks/RESTLER_RUNBOOK.md` — RESTler (`restler_bin/`) verified to actually run in this environment (`.NET 6.0` target, needs `DOTNET_ROLL_FORWARD=Major`) and to find real bugs against the same live instrumented target UpsideFuzz fuzzes (§5/§21 P0 #5).
- `benchmarks/harness/run_cell.py` + `run_batch.py` — resumable single-cell and batch orchestration (§15/§21 P0 #7), both tool branches (RESTler and UpsideFuzz) verified end to end through the full reset→poll/sample→run→judge→artifact sequence.

**Scope note (honesty first, updated):** the *dictionary* axis (C2/C4, the `generic-sec` shared dictionary and its RESTler-format conversion) is **not built** — `benchmarks/dictionaries/` does not exist yet. The pilot actually run (see `benchmarks/raw/pilot/`) covers **C1 (RESTler, no dict) and C3 (UpsideFuzz, no dict) only**, 5 reps each, 10-minute wall-clock budget, against T0 — a deliberately reduced slice of §19 Phase 2, not the full base matrix. RQ2 (dictionary effect) and RQ3/RQ6 (epoch/feedback ablation, still needing A6–A8's new flags) remain unanswered by anything run so far. Per-run artifact volume is real and large (a 10-minute UpsideFuzz run against a 3-endpoint target produced ~35MB of `crashes.jsonl` + ~20MB of `request_event.jsonl`) — a full campaign's disk footprint needs planning before scaling past the pilot.

---

## 1. What the repository actually provides (audit)

Evidence base for every design decision below.

**Fuzzer engine (`void/go/`).**
- Epoch scheduler (`worker.go::mainLoop`): five epochs by time fraction — `Baseline` 0.05, `Harvest` 0.25, `Deterministic` 0.25, `Havoc` 0.35, `Splicing` 0.10 — with adaptive rebalancing that steals fraction from an unproductive epoch into `Havoc` (`prevReqs > 200 && edgeRate < 0.001`). Three additional *pseudo-epochs* label out-of-band work: `Sequence` (producer/consumer follow-ups), `Replay` (crash replay), and oracle/race queues drained in `buildWorkItem` (`template.go`).
- Mutation categories (`mutations.go`, MOpt-weighted, `mutation_engine.go`): `boundary, overflow, sqli, xss, cmdi, path_traversal, ssrf, ssti, open_redirect, crlf, log4shell, nosqli, ldap, xxe, unicode, json` (+ `dotnet_deser` gadgets). Weights adapt via `weight = 1 + hitRate*4` on new-edge hits.
- Coverage: AFL-bucketed SHM bitmap (`coverage.go::countClass`), three read paths — HTTP `GET /shm/coverage`, direct `mmap` (`-direct-shm`), and per-request `X-Coverage-Delta` header. Health/self-verify via `GET /shm/health` and `coverage.go::checkCoverageHealth` (fail-closed unless `-allow-degraded-coverage`).
- Sequences (`sequence.go`): entity harvesting (`extractEntityIDs`), producer/consumer dep index, per-chain state clone, coarse state-shape signature (`sequenceStateSignature`), persisted workflows (JSON + curl).
- Oracles (`oracle.go`): BOLA/IDOR, broken-auth (evidence-gated on `authRequiredEndpoints`), mass-assignment, positive injection (time-based SQLi/SSTI/reflected-XSS), parser/router-confusion differentials.
- Triage taxonomy (`triage.go`, `crash.go`, `cluster.go`): `likely_vuln_high / likely_vuln / confirmed_unhandled_exception / needs_review / target_misconfiguration / noise`; two-level identity (fine `signature` + root-cause `cluster_key`).
- Output artifacts: `crashes-<ts>.jsonl` (all 5xx), `unique-crashes-<ts>.jsonl` (dedup unique + oracle/injection findings), `summary-<ts>.json` / report JSON (aggregates), PoC shell scripts, Mermaid timelines, persisted workflows.
- Config surface (`main.go`): ~90 flags incl. `-time-budget`, `-concurrency`, `-direct-shm`, `-auth-file`, `-sequence-prob`, `-profile {fast,deep,security}`, `-access-probe` + per-oracle toggles, `-injection-oracle`, `-race-mode`, `-crash-triage`, `-repro-runs`, `-adaptive-content-type`, `-auto-antiforgery`. **No `-seed` flag exists** (RNG is `math/rand` default-seeded → runs are not reproducible).

**Grammar / prep.**
- `fuzz-prep-multi.py` (instrument, `--inject-mode hook|source`), `analyzer/` (Roslyn constraints), `grammarc/` (first-party OpenAPI→grammar; RESTler retired for *my* grammar), `compile-grammar.sh` (still wraps the RESTler compiler for the RESTler configuration), `sanitize-swagger-for-restler.sh`.
- Orchestration: `upsidefuzz.py` (subcommands), `verify-hook.sh`, `scripts/e2e-test.sh`, `.github/workflows/e2e.yml`.

**RESTler.** `restler_bin/` (compiler + engine) present; `restler_input/`, `restler_output/`. RESTler is already used to compile grammars; running it as a *fuzzer* (Test / Fuzz-lean / Fuzz modes) is the comparison baseline.

**Targets present / referenced.** `fixtures/planted-bug-api/` (controlled, seeded bugs used by the e2e gate); `esh`/`eshprep` (eShopOnWeb PublicApi, minimal-API); `simplcommerce`/`simplcommerce_prep` (modular monolith, cookie auth + anti-forgery); `btcpayserver`/`btcpayserver_prep` (API-key, complex); `bitwarden_*` (multi-service, JWT). Quickstarts exist for the four real targets.

**Recorded inconsistencies to respect during benchmarking.**
- Adapted-Dockerfile instrumentation currently uses the **namespace allowlist** (`--config namespaces.json`), not `--instrument-all-user-code` as some docs state (`fuzz-prep-multi.py`). Fix or pin per target so coverage denominators are stable.
- Coverage `%` in the report is against a **baseline ceiling proxy**, not a true edge count. Use raw edge/bucket counts for cross-tool comparison, never the percentage.
- Per-request `X-Coverage-Delta` is legitimately absent on chunked 200 responses (see `verify-hook.sh` note); the engine falls back to periodic polling. Coverage measurement for the benchmark must use the **external poll**, not the header.

---

## 2. Research questions & hypotheses

Framed so RESTler can win. Independent variable = tool configuration unless stated; runs are the unit; targets are blocked.

| RQ | Question | H₀ (null) | H₁ (alt) | Primary dependent metric | Control variables | Acceptance criterion |
|---|---|---|---|---|---|---|
| RQ1 | Does feedback-guided scheduling reduce time-to-unique-bug vs RESTler? | median TTU equal | medians differ | TTU (time to each unique confirmed robustness bug) | target, budget, auth, hardware, dict | Mann–Whitney p<0.05 **and** Cliff's δ ≥ 0.33, per target |
| RQ2 | Does a generic security dictionary help both tools, and equally? | dict effect = 0 for each; effects equal | dict effect > 0; effects differ | Δ unique bugs, Δ coverage-at-budget | tool, target, budget | per-tool paired test + tool×dict interaction test |
| RQ3 | Which epochs/mutation categories contribute most coverage and confirmed vulns? | uniform contribution | non-uniform | new-edges & first-discovery attribution by epoch/category | target, budget | descriptive + attribution model (§10) |
| RQ4 | Does my sequence exploration reach deeper valid workflows than RESTler dependency sequences? | equal max/median successful depth | mine deeper | successful sequence depth distribution | target, budget, auth | Mann–Whitney on depth per stateful target |
| RQ5 | What is the performance cost of instrumentation? | overhead = 0 | overhead > 0 | RPS & p95 latency (instrumented vs not) | target, load | report magnitude + CI; no "win" framing |
| RQ6 | Does feedback add value **beyond** dictionary mutation? | feedback-off = feedback-on given same dict | differ | coverage & unique bugs at budget | dict, target | ablation contrast (needs feedback-off flag, §18) |
| RQ7 | Which tool produces fewer duplicate/low-value findings? | equal duplicate-to-unique ratio | differ | duplicate:unique ratio, FP rate | target, oracle | report per tool; lower is better |
| RQ8 | Which tool achieves greater externally-measured coverage at equal budget? | equal | differ | edges/buckets at budget | target, instrumentation | Mann–Whitney per target |

**Capability vs. head-to-head separation (critical fairness rule).** RESTler cannot emit BOLA / mass-assignment / injection oracle findings. Therefore **RQ1/RQ7/RQ8 head-to-head comparisons are restricted to the bug classes both tools can produce** (robustness / unhandled-exception / DoS, judged by a shared external oracle). UpsideFuzz's oracle-only findings are reported **separately** as a capability delta (§9), never folded into a single "N× more bugs" claim.

---

## 3. Configurations under test

Base four (mandatory):

| ID | Tool | Dictionary | Notes |
|---|---|---|---|
| C1 | RESTler | none | Test + Fuzz-lean, zero-config |
| C2 | RESTler | generic-sec | same dictionary content as C4 (format-converted) |
| C3 | UpsideFuzz | none (built-in mutators only) | `dict.json` absent; built-in `sqli/xss/...` categories still active |
| C4 | UpsideFuzz | generic-sec | shared generic dictionary |

Ablations (only those the architecture actually supports today; each isolates one factor by flag):

| ID | Config | Flag(s) | Isolates | Feasible now? |
|---|---|---|---|---|
| A1 | No sequences | `-sequence-prob 0 -race-mode=false` | stateful exploration | ✅ |
| A2 | No access/injection oracles | `-access-probe=false -injection-oracle=false` | oracle contribution to coverage/robustness | ✅ |
| A3 | HTTP coverage vs direct-SHM | `-direct-shm=false` vs `-direct-shm` | coverage-channel overhead & fidelity | ✅ |
| A4 | Profiles | `-profile fast|deep|security` | knob-bundle effect | ✅ |
| A5 | No dictionary | omit `dict.json` (= C3) | dictionary contribution | ✅ |
| A6 | No feedback (coverage ignored for scheduling) | **needs new flag** `-no-feedback` | the core thesis (RQ6) | ❌ requires code (see §18) |
| A7 | Only-havoc / only-deterministic | **needs new flag** to pin single epoch | epoch isolation | ❌ epochs are time-fraction based; requires code |
| A8 | No entity harvesting (but sequences on) | **needs new flag** | harvesting vs chaining | ❌ harvesting feeds sequences; no independent toggle |

**Do not fake A6/A7/A8 by proxy.** They require small, clearly-scoped feature flags added *before* the ablation phase (§18). Until then, report only A1–A5. Presenting `-sequence-prob 0` as "no feedback" would be misleading — sequences ≠ coverage feedback.

**Tuning transparency.** Every result set is tagged with one of four tuning tiers and reported in separate columns, never mixed:
1. **zero-config** (defaults, spec-only),
2. **generic-dictionary** (shared dict, no per-target edits),
3. **target-specific-dictionary** (per-target values — allowed only if applied symmetrically to RESTler and UpsideFuzz),
4. **manually-tuned** (auth files, endpoint hints — symmetric or excluded).

---

## 4. Target suite & selection strategy

Selection principle: **diversity over favorability**. Include stateless and stateful, small and large, auth-light and auth-heavy, controlled and real. Minimum viable suite = T0 + T1 + T2. Full suite adds T3–T5.

### Group 1 — Controlled targets with known/seeded vulnerabilities (accuracy measurement)

| Field | T0: planted-bug-api |
|---|---|
| Location | `fixtures/planted-bug-api/` |
| Framework | ASP.NET Core (.NET 8), minimal API |
| Size / endpoints | small; enumerate from its swagger (record exact N at pilot) |
| Auth | per fixture (likely none/simple) |
| Statefulness | low–medium |
| Deployment | trivial (used by `scripts/e2e-test.sh`) |
| Why included | **ground-truth** for detection accuracy, FP rate, TTU; already CI-wired |
| Expected bug classes | seeded 500, injection, BOLA (confirm from source) |
| Known bugs | yes — build the ground-truth manifest (§8) from the fixture source |
| Coverage collectable | yes (instrumented) |
| Reset | recreate container / in-memory DB per run |
| Runtime | 10–30 min sufficient |
| Risks | too small to generalize → must not be the only target |

**Add one external controlled target** (do not rely on a single self-authored fixture — implementation bias). Candidate: **OWASP-style vulnerable .NET API** or a purpose-built second fixture authored by someone other than the tool author, with an independent manifest. Record commit + manifest author.

### Group 2 — Real-world open-source applications (practical applicability)

| Field | T1: eShopOnWeb PublicApi | T2: SimplCommerce | T3: BTCPayServer Greenfield |
|---|---|---|---|
| Location | `esh` / `eshprep` | `simplcommerce` / `_prep` | `btcpayserver` / `_prep` |
| Framework | ASP.NET Core, minimal-API/`IEndpoint` | modular monolith, MVC + Identity | ASP.NET Core, API-key |
| Size | small–medium | medium | large |
| Auth | JWT (simple) | cookie + anti-forgery | API-key / Greenfield |
| Statefulness | medium (catalog/basket/order) | high (cart→checkout) | high (invoices/stores) |
| Deployment | SQL Server; compose | SQL Server; modular load | Postgres + NBXplorer + Bitcoin |
| Why included | clean small stateful baseline; minimal-API route style | anti-forgery + dynamic module loading (coverage-linking stress) | large service graph, realistic complexity |
| Expected bugs | validation/robustness, IDOR on catalog/order | mass-assignment, auth, business-logic | robustness, auth, boundary |
| Coverage | yes | yes (verify module linking via `/shm/health`) | yes (heavier) |
| Reset | DB volume reset + reseed | DB reset + reseed | full stack reset (expensive) |
| Runtime | 30 min–4 h | 30 min–4 h | 1–8 h |
| Risks | small surface | anti-forgery may throttle RESTler unfairly (document) | slow reset, flaky external deps → CI-unfriendly |

### Group 3 — Project-specific dev targets

Bitwarden (`bitwarden_*`): multi-service, JWT, strict validation. **Optional / long-runs only** — expensive to reset, and it is a target the tool was developed against (known-vulnerability & tuning bias). If used, disclose the development history and treat coverage/bug numbers as *illustrative*, not comparative headline results.

### Group 4 — Optional stress / scalability

A synthetic high-endpoint-count API (e.g. generated 200-endpoint CRUD) for throughput/overhead and scheduler-scaling measurement only — **not** for bug-count claims.

**Target-category reporting.** Always report per-target and per-category (stateless-CRUD, stateful-workflow, auth-heavy). Aggregate only with rank-based methods that prevent a large target from dominating (§11).

---

## 5. Fairness contract

Held **identical** across all configurations for a given (target, budget) cell:

- **Target version:** pinned git commit + container digest (record both). Rebuild from the same commit for every run.
- **DB state:** identical seed dataset restored before every run (see reset, §13). Snapshot/volume restore, not "re-run migrations" (nondeterministic ordering).
- **Target config & env:** same `appsettings`, same `ASPNETCORE_ENVIRONMENT`. **Instrument the target identically for both tools** — RESTler runs against the *same instrumented image* so coverage is observed externally without feeding RESTler.
- **API spec:** the same `swagger.json` snapshot feeds both `grammarc/` and the RESTler compiler; store the exact file per target.
- **Auth identity & credentials:** identical `auth.identities.json` / RESTler auth token script; same accounts, same roles, same initial data ownership. If RESTler cannot consume a multi-identity file, restrict that cell to single-identity for both and note it.
- **Hardware & limits:** pinned host; each run in its own container with `--cpus` and `--memory` fixed and identical for tool + target across configs. Record CPU model, kernel, Docker version.
- **Network:** tool and target on the same Docker network / localhost; no external latency in the loop (except targets with unavoidable external deps — document).
- **Concurrency:** set UpsideFuzz `-concurrency` and RESTler's parallelism to the **same effective client concurrency**; if models differ, report both request-rate and concurrency (§6) rather than forcing false equivalence.
- **Request timeout & retries:** UpsideFuzz `-request-timeout`; match RESTler's timeout; disable tool-specific aggressive retry or document it.
- **Dictionary:** byte-identical generic dictionary content; a single documented format conversion per tool, checked in.
- **Bug oracle:** a **shared external judge** (§8) classifies findings from both tools with one taxonomy; do not use each tool's native classification for the comparison.
- **Seeds:** RESTler exposes limited seeding; UpsideFuzz has **none today**. Until `-seed` exists, treat every repetition as an independent random draw and compensate with more repetitions (§7). This is a genuine reproducibility limitation, stated as such.

**Explicitly not equalized (report the difference instead of hiding it):** execution models. RESTler is a grammar-driven sequence generator; UpsideFuzz is a coverage-guided mutator with oracles. They will not issue the same request mix. Report the divergence (status-code mix, valid-request rate, RPS) as data.

---

## 6. Budgets: primary and secondary

Wall-clock alone is not fair (instrumentation overhead, different RPS). Collect **all** budgets; analyze against several.

| Budget | Role | Rationale |
|---|---|---|
| **Wall-clock time** | **Primary** | what a practitioner actually spends; matches CI/engagement reality |
| Total requests | Secondary | isolates per-request efficiency from throughput differences |
| Valid requests (2xx/expected 4xx of intent) | Secondary | fairness vs tools that spray invalid requests |
| Successful state-changing requests (2xx on POST/PUT/PATCH/DELETE) | Secondary | best proxy for "reached business logic" on stateful targets |
| CPU-time | Secondary | normalizes for instrumentation CPU overhead |

Report the headline comparison at **equal wall-clock**, then a robustness check at **equal total-requests** and **equal valid-requests**. If conclusions flip between budgets, say so — that *is* the finding.

Recommended tiered durations (do **not** run all):
- **Smoke:** 10 min × few seeds — methodology/harness validation only.
- **Comparative (medium):** **1 hour** — the primary comparative budget for RQ1/7/8 across the full suite.
- **Bug-discovery (long):** **8 hours** (and 24 h on ≤2 targets) — for rare-bug discovery and coverage-plateau analysis.
- 30 min and 4 h are collected implicitly as checkpoints within longer runs (event timeline lets you truncate post-hoc), so they need no dedicated runs.

---

## 7. Repetitions, run count, and compute budget

Fuzzing is randomized; single runs are inadmissible. Because UpsideFuzz has no seed control, variance is higher → more repetitions.

| Evidence tier | Repetitions / cell | Basis |
|---|---|---|
| Engineering validation | 5 | detect gross differences, tune harness |
| Conference-quality (BSides/Arsenal/DEF CON) | **10** | standard minimum for fuzzing evaluation; enables Mann–Whitney + Cliff's δ |
| Publication-quality | **20** (≥10 absolute floor) | tighter CIs, survival curves with usable risk sets |

**Primary comparative matrix (conference tier), medium budget:**
- Targets: T0, T1, T2 (+ 1 external controlled) = 4
- Configs: C1–C4 = 4
- Reps: 10
- Budget: 1 h
- = **160 runs × 1 h ≈ 160 core-hours** for the head-to-head.

**Ablation matrix (A1–A5, UpsideFuzz only):** 3 targets × 5 ablations × 10 reps × 1 h = **150 runs / core-hours**.

**Long bug-discovery:** 3 targets × 4 configs × 5 reps × 8 h = **480 core-hours**.

**Overhead/perf micro-benchmarks (§14):** small, ~20 core-hours.

**Estimated total (conference tier): ~800–900 core-hours** plus reset/warm-up overhead (budget +25% ≈ **~1,100 core-hours**). Publication tier (20 reps) roughly doubles the head-to-head and ablation portions → **~1,800–2,000 core-hours**. Tradeoff: serialize on one pinned host for validity, or parallelize across identical isolated hosts (§15) to cut wall-time at the cost of cross-host variance (add host as a random-effect / block).

---

## 8. Bug definition, taxonomy, deduplication, and ground truth

### What counts as a bug
A **bug candidate** is any tool-reported anomaly. A **confirmed bug** is a candidate that passes the shared validation pipeline (below). **An HTTP 500 is not a bug until confirmed and deduplicated to a root cause.** DI/service-resolution failures caused by the instrumented image (`target_misconfiguration`) are **excluded** from bug counts for both tools.

### Taxonomy (shared judge assigns exactly one primary class)
`unhandled_exception`, `crash/DoS`, `resource_exhaustion`, `authn_bypass`, `authz_bypass`, `IDOR/BOLA`, `mass_assignment`, `injection_sqli`, `injection_cmdi`, `injection_ssti`, `injection_other`, `path_traversal`, `ssrf`, `unsafe_deserialization`, `validation_bypass`, `numeric_boundary`, `race_condition`, `business_logic`, `state_machine_violation`, `sensitive_data_exposure`, `integrity_violation`.

**Head-to-head classes** (both tools can produce): `unhandled_exception`, `crash/DoS`, `resource_exhaustion`, `numeric_boundary`, `validation_bypass`. **Capability-delta classes** (UpsideFuzz oracles; RESTler generally cannot): BOLA, mass_assignment, injection_*, authz/authn_bypass, differential. Reported separately (§9).

### Deduplication (applied uniformly to both tools' raw findings)
Cluster by, in order: (1) normalized backend exception message + first *application* stack frame (reuse `cluster.go::rootCauseClusterKey` logic as the shared judge, applied to RESTler's captured responses too, since both hit the same instrumented target and get the same `X-Exception-*` headers); (2) when no exception detail, `(method, route-template, status-class)`; (3) for oracle findings, `(class, method, route-template, origin→shadow identity)`. Final tie-break: manual root-cause review on the minimized reproducer. Report both `unique signatures` and `distinct root causes`; **headline counts use distinct root causes.**

### Ground-truth manifest (controlled targets)
Per seeded vuln: `vuln_id, bug_class, endpoint(s), required_preconditions, required_sequence, expected_oracle, severity, known_triggering_input`. Detection = a confirmed finding whose minimized reproducer satisfies the manifest entry. Compute **recall** (seeded vulns found) and **precision** (confirmed findings that map to a manifest entry vs spurious) per tool.

### Validation pipeline (both tools, controlled + real)
1. Automatic reproduction (N attempts) on a **clean** target replay (fresh reset).
2. Minimized reproducer (UpsideFuzz already minimizes; for RESTler, drive its reproducer/replay against clean state).
3. Repeated confirmation → `reproducibility_rate` (fraction of replays that re-trigger).
4. Evidence capture: `X-Exception-Type/Message`, stack frame, or oracle signal (cross-identity 2xx body, reflected privileged field, time-delay).
5. Label: `true_positive | false_positive | duplicate | flaky | unresolved`.

**Flaky / race / nondeterministic handling:** a finding reproducing in ≥ `repro_target` (default 80%, `-repro-target`) of replays is `confirmed`; 1–80% is `flaky` (reported separately, never in headline TP counts); 0% is `false_positive`. Race-condition candidates run a dedicated burst-replay confirmation. Environment/cascading failures (target OOM, DB down) are tagged `infra` and excluded from bug metrics but counted in run-failure reporting.

---

## 9. Metric catalogue (precise definitions)

All metrics collected per run and, where applicable, as an event timeline (elapsed_s, request_index).

**Bug discovery:** total candidates; unique signatures; distinct root causes; TP; FP; duplicates; flaky; known-vulns-found (recall); unknown-vulns-found; unique bug classes; severity distribution; per-endpoint distribution; sequence depth required per bug; minimized-reproducer size (bytes/fields); reproducibility_rate.

**Time/requests-to-discovery** (per bug, with censoring): time-to-first-candidate; time-to-first-confirmed; time-to-first-unique; **time-to-each-unique** (the survival dataset); time-to-first-high-severity; requests-to-first-bug; valid-requests-to-first-bug; CPU-time-to-first-bug. Runs finding nothing are **right-censored** at budget (never dropped).

**Coverage (external measurement):** edges (bytes>0) and **distinct (edge,bucket) classes** at fixed poll cadence; final coverage; unique-coverage-over-time series; coverage growth rate (edges/min early vs late); plateau time (first time with <X% growth over window); coverage per request; per valid request; per CPU-minute. **Same external poll for RESTler and UpsideFuzz.**

**Request quality:** total requests; RPS; valid vs invalid; status-code histogram; successful state-changing requests; unique (endpoint,method) pairs reached; unique response schemas; % rejected by validation; % reaching business logic (2xx on non-trivial endpoints); % requests producing new coverage; % mutations producing useful (new-coverage or state-changing) inputs.

**Stateful/sequence:** sequences attempted; valid sequences; successful workflows (all steps 2xx/expected); max & mean successful depth; unique sequence shapes (`sequenceStateSignature`); entities harvested; entity-reuse success rate; producer→consumer satisfaction rate; sequence mutations → new coverage; → bugs; time-to-first-successful-workflow; state-reset failures; orphaned/invalid entity references. **RESTler comparison:** map RESTler's rendered dependency sequences to the same `(method, route-template, status-class)` shape signature so depth and shape distributions are directly comparable.

**Performance/stability:** tool CPU%/RSS; target CPU%/RSS; RPS; instrumentation overhead (§14); startup+prep time; grammar-compile time; target reset time; crash-recovery time; dropped/stale coverage events; SHM errors; HTTP-fallback overhead; tool failures; target failures unrelated to fuzzing; run-completion rate.

**Epoch/mutation (UpsideFuzz):** per epoch and per mutation category — requests generated; time spent; new coverage discovered; unique bugs discovered; bug classes; first epoch to trigger each bug; requests-per-unique-coverage; requests-per-unique-bug; valid-request rate; duplicate rate; sequence depth; dictionary-token effectiveness; effectiveness-over-time (pre/post plateau). **All of this requires the event log in §16/§18 — not available today.**

---

## 10. Epoch & mutation attribution methodology

Naive attribution ("the epoch that sent the crashing request gets the credit") is misleading, because `Baseline`/`Harvest` build the corpus and harvest entities that later let `Havoc`/`Sequence` trigger the bug. Track three attribution levels per bug and per coverage edge:

1. **Direct discovery** — the epoch/category of the request that first produced the finding/edge.
2. **Enabling contribution** — the epoch that produced the seed (corpus ancestor) the discovering request mutated (`SeedIdx` → corpus entry → creating epoch), and the epoch that harvested the entity/dependency value used.
3. **Ancestor corpus contribution** — full provenance chain to the `Baseline` seed.

Report all three; headline "epoch X finds most bugs" claims must state which attribution level they use. Provide a chart of **direct vs enabling** credit so a reader sees, e.g., that `Havoc` gets direct credit but `Baseline`+`Harvest` get most enabling credit. Also measure **post-plateau usefulness**: after coverage plateaus, which epochs still produce new distinct root-cause bugs (tests whether an epoch is worth its budget late in a run).

**Prerequisite:** requires event-level logging of `epoch, mutation_category, seed_idx/corpus ancestry, sequence_id, coverage_delta, bug_candidate_id` per request (§16). Not present today.

---

## 11. Statistical analysis

- **Never means-only.** Report **median + IQR**, and distributions (per-target box/violin).
- **Two-tool contrasts:** Mann–Whitney U (unpaired across independent runs) with **Cliff's δ** effect size (report δ and its CI). Threshold |δ|≥0.33 (medium) for a claim.
- **CIs:** 95% via BCa **bootstrap** (10k resamples) for medians, rates, and coverage-at-budget.
- **Time-to-bug:** **Kaplan–Meier** survival curves per config with right-censoring at budget; log-rank test for curve differences; report **median TTU** and **P(≥1 bug within {10m,1h,8h})** and **P(specific known vuln within budget)** on controlled targets.
- **Dictionary (RQ2):** per-tool paired contrast (dict vs no-dict on same target) + a **tool×dict interaction** test (e.g., aligned-rank-transform ANOVA or bootstrap of the interaction contrast) to answer "does the dictionary help my tool *more* than RESTler."
- **Cross-target aggregation without domination:** rank tools within each target (or use per-target standardized effect sizes / win-tie-loss), then aggregate ranks (Friedman across targets + Nemenyi post-hoc, or a random-effects meta-analysis of Cliff's δ). **Do not pool raw bug counts across targets** — one large target would dominate.
- **Reporting levels:** always per-target; then per-category; then aggregate (rank-based only).
- **Missing/censored:** timeouts/no-find = censored at budget (kept in survival). Infra-failed runs excluded from metric analysis but **reported** in the run-failure table; if >10% of a cell's runs fail, flag the cell as low-confidence.
- **Multiplicity:** many RQ×target tests → control FDR (Benjamini–Hochberg) within each RQ family.

Repetition guidance restated: 5 (eng) / 10 (conference) / 20 (publication). Below 10, survival curves and δ CIs are too wide to support claims.

---

## 12. Data model (append-only, machine-readable)

Raw data is **immutable JSONL**; all tables/charts derive from it. One directory per run.

Entities (files/tables), key fields:

- **experiment.json** — experiment_id, hypothesis set, git_commit(fuzzer), analyzer/grammarc versions, plan version, created_at.
- **run.json** — run_id (uuid, immutable), experiment_id, target_id, target_commit, container_digest, tool_config_id, dict_version, oas_sha256, instrumentation_mode, budget_spec, seed (or "unseeded"), host_id, cpu_model, mem_limit, cpu_limit, start/stop ts, completion_status.
- **target.json** — target_id, name, framework, endpoint_count, auth_mode, reset_strategy, dataset_sha256.
- **tool_config.json** — tool, version, full CLI/args, profile, oracle toggles, concurrency, timeout.
- **request_event.jsonl** *(NEW — §18)* — run_id, ts, elapsed_s, request_index, epoch, mutation_category, dict_tokens_used[], corpus_seed_idx, sequence_id, seq_depth, method, endpoint_template, status, coverage_delta, identity, valid_flag, state_change_flag. *(sampled or full; see §16)*
- **coverage_event.jsonl** — run_id, ts, elapsed_s, request_index, edges, buckets, source(poll|header|mmap). External poller writes this for **both** tools.
- **epoch_event.jsonl** *(NEW)* — run_id, ts, epoch_from, epoch_to, elapsed_s, request_index, rebalance_reason.
- **sequence_event.jsonl** — run_id, sequence_id, shape_signature, depth, steps[], harvested_entities[], success_flag, new_coverage, produced_bug_id.
- **bug_candidate.jsonl** — candidate_id, run_id, ts, elapsed_s, request_index, method, endpoint, status, exception_type, signature, cluster_key, mutation_label, epoch, identity, payload, response_snippet, poc_ref.
- **confirmed_bug.json** — bug_id, cluster_key, class, severity, tp/fp/flaky, reproducibility_rate, min_reproducer_ref, manifest_vuln_id?, validated_by, notes.
- **resource_sample.jsonl** *(NEW)* — run_id, ts, target_cpu, target_rss, tool_cpu, tool_rss, rps.
- **artifact/** — raw tool logs, request traces, coverage snapshots, crashes JSONL, minimized reproducers, PoCs.
- **environment.json** — kernel, docker version, images, clock source.

**Directory layout (raw immutable, derived separate):**
```
benchmarks/
  manifests/            ground-truth per controlled target
  dictionaries/         generic-sec.json + per-tool converted forms (+sha256)
  configs/              tool_config_*.json, budgets, target pins
  raw/<experiment>/<run_id>/   run.json, *_event.jsonl, artifact/, environment.json   (READ-ONLY after run)
  processed/<experiment>/      normalized parquet/csv derived from raw
  charts/<experiment>/
  reports/<experiment>/
```
Every result traces to: fuzzer commit, target commit, container digest, tool_config, seed, dict_version, oas_sha256, instrumentation_version, host/env. Processing is a pure function of `raw/`; deleting `processed/` and re-running must reproduce identical outputs.

---

## 13. Target reset & warm-up contract

- **Reset (before every run):** restore a **DB snapshot/volume** to a fixed seed dataset (not re-migration). For compose targets: `docker compose down -v` → restore named volume from a golden snapshot → `up`. Verify a dataset checksum/known row count post-restore; abort run on mismatch (prevents contamination).
- **Seed data:** identical initial entities and, for BOLA/ownership tests, known objects owned by each identity (records feed the ground-truth manifest).
- **Warm-up:** poll `GET /shm/health` (hook mode) or a readiness endpoint until `shm_bound=true` and `linked_assemblies>0`, plus a readiness probe for the app itself (avoid the fixed `sleep 45` that failed in `verify-hook.sh`). Warm-up requests (health/readiness) are **excluded** from budgets and metrics.
- **Coverage reset:** `POST /shm/reset` immediately before the measured window so `edges` start at 0 for both tools.
- **Reset failures** are logged (`state_reset_failures`) and the run is discarded + retried, not silently continued.

---

## 14. Instrumentation-overhead sub-benchmark

Isolate the coverage layer; four target builds:
1. uninstrumented,
2. instrumented + coverage runtime disabled (hook present, `-no-op`),
3. instrumented + SHM coverage (direct),
4. instrumented + HTTP-fallback coverage.

Drive each with a **fixed non-fuzzing load generator** (constant request mix) and measure RPS, p50/p95/p99 latency, target CPU/RSS. Also: startup overhead, coverage-collection overhead, SHM vs HTTP overhead, coverage accuracy/determinism (repeat identical request N× → coverage delta variance; quantifies concurrency smearing residual), and bitmap collision estimate (distinct edges vs 256KB capacity per target). **Fairness link:** since RESTler runs against the instrumented image too, both tools pay the same instrumentation tax — report the absolute tax so readers can judge external validity, and confirm it does not differentially advantage either tool.

---

## 15. Harness design (specification, not implementation)

Capabilities: provision clean target → seed data → start instrumentation → start resource monitor → run one config → collect event-level data → stop at budget → preserve artifacts → reset → validate → emit normalized results → resume interrupted batches.

- **Execution:** Docker Compose per target (Kubernetes unnecessary at this scale). One run = one isolated compose project (`-p run_<id>`), unique network + **dynamically allocated ports** (avoid collisions), fixed `--cpus/--memory` on tool and target.
- **Serialize vs parallelize:** **serialize on a single pinned host for the headline comparative matrix** (eliminates noisy-neighbor confounding). Parallelize *only* across dedicated identical hosts, with `host_id` recorded and modeled as a block/random effect. Never co-locate two runs on one host for measured cells.
- **Budget enforcement:** wall-clock timer as primary stop; also stop-and-record at request/valid-request checkpoints via the event stream (post-hoc truncation for secondary budgets).
- **Failure handling:** health-check gates each stage; failed startup → retry ≤3 → mark `infra_fail`; timeouts kill the run cleanly; every run gets a unique immutable dir; batch runner is idempotent/resumable (skip completed run_ids).
- **Secrets:** credentials injected via env/secret files, never committed; auth token acquisition scripted per target identically for both tools.
- **Determinism:** pass seeds where supported (RESTler); record "unseeded" for UpsideFuzz until §18 lands.

---

## 16. Instrumentation & logging gap analysis

**Legend:** ✅ available · ◑ partial · ❌ missing. "Source" = where it exists or should hook in. Updated 2026-07-24 — items below marked **✅ DONE 2026-07-24** were closed this session; see the file/verification pointers in each row instead of re-deriving them.

| Required metric | Status | Source / evidence | Recommended collection point | Change required | Priority |
|---|---|---|---|---|---|
| Bug discovery timestamp (elapsed) | ✅ | `crash.go` `ElapsedSec` in crash/unique JSONL | as-is | none | — |
| Request count at discovery | ◑ | `totalDone` global, not stamped per crash | add `request_index` to crash record | small | P1 |
| Unique/dedup signatures & clusters | ✅ | `crash.go`, `cluster.go` | as-is | none | — |
| Reproducibility rate | ✅ | `minimize.go`/`repro` in unique JSONL | as-is | none | — |
| Minimized reproducer | ✅ | `minimize.go`, PoC files | as-is | none | — |
| Oracle findings (BOLA/mass-assign/injection) | ✅ | `oracle.go` → unique JSONL | as-is | none | — |
| Final aggregate coverage | ✅ | `report.go` (`coverage_edges`, buckets) | as-is | none | — |
| **Coverage time-series** | ✅ DONE 2026-07-24 | `benchmarks/harness/coverage_poller.py` | external poller, `-interval`-cadence `GET /shm/coverage` → `coverage_event.jsonl` | external tool (no fuzzer change, as planned) | — |
| **Per-request event stream** (epoch, category, coverage_delta, seq_id, dict tokens, seed ancestry, identity, valid flag) | ◑ DONE 2026-07-24 (minus dict tokens) | `void/go -event-log` → `worker.go::logRequestEvent` | as-is | done | — |
| Epoch transitions | ✅ DONE 2026-07-24 | `worker.go::logEpochEvent` → `epoch_event.jsonl` | as-is | done | — |
| Mutation category per request | ✅ DONE 2026-07-24 | in `request_event.jsonl` (`mutation_category`=`MutationName`, `mutation_label` for the finer `mcat_*` tag) | as-is | done | — |
| Dictionary token usage | ❌ still open | dict values rendered but not accounted | `dict_tokens_used` is emitted as an always-empty `[]` placeholder in `request_event.jsonl` today (`worker.go::logRequestEvent`'s own doc comment says so) | fuzzer change | P1 |
| Corpus ancestry (enabling attribution) | ✅ DONE 2026-07-24 | `corpus_seed_idx` in `request_event.jsonl` (`res.Item.SeedIdx`) | as-is | done | — |
| Sequence identity & depth | ✅ DONE 2026-07-24 | `sequence_id`/`seq_depth` in `request_event.jsonl`; full `sequence_event.jsonl` stream (`sequence.go::logSequenceEvent`) | as-is | done | — |
| Entity harvesting events | ◑ DONE 2026-07-24 (partial) | `sequence_event.jsonl`'s `harvested_entities` field, logged once per terminal sequence (depth≥2), not per individual harvest event | as-is for now | small, if per-harvest granularity is later needed | — |
| Valid / state-changing request flags | ✅ DONE 2026-07-24 | `valid_flag`/`state_change_flag` in `request_event.jsonl` | as-is | done | — |
| Resource usage (tool+target CPU/RSS) | ✅ DONE 2026-07-24 | `benchmarks/harness/resource_sampler.py` (`docker stats` / `ps`) → `resource_sample.jsonl` | external tool (no fuzzer change, as planned) | — |
| Deterministic seed | ✅ DONE 2026-07-24 | `void/go -seed` flag, seeds `math/rand`'s global source (`main.go`) | as-is | done — **not** bit-for-bit deterministic under concurrency (documented in-code); still reduces variance substantially | — |
| RESTler coverage parity | ✅ DONE 2026-07-24 | `benchmarks/RESTLER_RUNBOOK.md` — verified RESTler runs (needs `DOTNET_ROLL_FORWARD=Major`) against the same instrumented target, same external poller applies unmodified | harness wiring (`run_cell.py`) | none in tools | — |

**Bottom line (updated):** all P0 telemetry gaps in this table are closed and individually verified against a live target (`fixtures/planted-bug-api/`), including a real 10-run pilot slice (`benchmarks/raw/pilot/`, C1+C3 only — see the top-of-file scope note for what that pilot does and doesn't cover). What remains open: dictionary-token accounting (P1, RQ2's token-level attribution chart is blocked on it, but the coarser dict-vs-no-dict comparison isn't), and the A6–A8 ablation flags (`-no-feedback`, single-epoch pin, harvest-only toggle — none of these exist yet, RQ6's core thesis is still untestable). Full campaign-scale execution (Phases 3–8, the 800–2000 core-hour matrices) has **not** been run — that remains a deliberate, separate scope decision, not a blocked-on-tooling gap.

---

## 17. Charts & tables

For each: axes, grouping, aggregation, uncertainty, purpose, misuse risk.

**Bug discovery**
- *Cumulative unique (distinct-root-cause) bugs over time* — x: elapsed (log), y: cumulative distinct bugs; group: config; median line + bootstrap band across reps; per target. *Misuse:* do not sum across targets; do not count oracle-only bugs in the RESTler-comparison panel.
- *Survival: P(≥1 confirmed bug within t)* — Kaplan–Meier per config, per target, with censoring; risk table beneath. *Misuse:* wide CIs at <10 reps → don't over-read.
- *Median TTU (first confirmed)* — bar per config with 95% CI; per target. 
- *Unique bugs by target × config* — grouped bars; separate robustness vs oracle panels.
- *Bug classes by config* — stacked bars (capability delta obvious).
- *Severity distribution* — stacked; note severity is heuristic, not CVSS.
- *Reproducibility rate* — box per config.
- *Duplicate:unique ratio* — bar per config (lower better).

**Coverage**
- *Cumulative external coverage over time* — median + band, per config, per target. *Misuse:* label as externally-measured (RESTler does not consume it); use raw edge/bucket counts not %.
- *Final coverage at budget* — box per config; Mann–Whitney annotation.
- *Time-to-plateau* — bar per config.
- *Coverage per million requests / per valid request / per CPU-min* — normalizers; per config.
- *Coverage contribution by epoch* — stacked area (UpsideFuzz); state attribution level used.
- *Coverage vs distinct bugs* — scatter, point per run, colored by config (is coverage buying bugs?).

**Sequences**
- *Successful sequence depth distribution* — violin, UpsideFuzz vs RESTler (mapped shapes), per stateful target.
- *Successful workflows over time*; *unique workflow shapes*; *bugs by required sequence depth* (histogram); *entity-reuse success rate* (bar).

**Dictionary**
- *Bugs / TTU with vs without dict* — paired, per tool (RQ2).
- *Coverage contribution from dict-token requests* — per tool.
- *Useful dict tokens by category* — bar (needs token accounting, §18).
- *Interaction plot* — dict effect for RESTler vs UpsideFuzz (does feedback amplify the dictionary?).

**Performance**
- RPS / valid-RPS per config; tool+target CPU/RSS over time; instrumentation overhead (4 builds); SHM vs HTTP overhead.

**Tables**
- Per-target summary (median±IQR for each metric × config).
- Aggregate rank-based summary (Friedman/Nemenyi; win-tie-loss).
- CI & effect-size table (Cliff's δ + CI per contrast).
- **Run-failure report** (infra fails per cell, completion rate).
- **Experiment coverage matrix** (which cells actually ran, N reps each) — reviewers demand this.
- Ground-truth detection table (recall/precision per tool on controlled targets).

---

## 18. Threats to validity & mitigations

| Threat | Mitigation |
|---|---|
| Target-selection bias | diverse suite across statefulness/size/auth; ≥1 externally-authored controlled target; report per-target |
| Implementation bias (self-authored fixture/tool) | second controlled target authored by another party; disclose dev history; Bitwarden illustrative-only |
| Dictionary bias | byte-identical generic dict; documented single conversion per tool; separate target-specific tier |
| Benchmark-tuning bias | four disclosed tuning tiers, never mixed; symmetric tuning or none |
| Known-vulnerability bias | recall/precision only on manifests with independent authorship; separate seeded vs natural bugs |
| Instrumentation bias | both tools on the same instrumented image; overhead sub-benchmark quantifies the tax |
| Coverage-map collisions | report distinct edges vs 256KB capacity; size bitmap from instrumented count where possible; flag high-collision targets |
| Hardware variability | pinned host for headline matrix; `host_id` as block if parallelized |
| Randomness / no seed (UpsideFuzz) | ≥10 reps; add `-seed` (P0); report variance honestly; survival analysis not point estimates |
| Flaky targets / races | reproducibility_rate gating; `flaky` bucket excluded from headline TP; burst-replay for races |
| Unequal feature maturity | capability-delta reported separately from head-to-head; never a single "N×" number |
| Unequal auth support | if RESTler can't do multi-identity, restrict cell to single-identity for both + note |
| Imperfect bug oracle | shared external judge + manual root-cause review on minimized reproducers |
| Target reset contamination | volume-snapshot restore + post-restore checksum gate; discard-and-retry on mismatch |
| Confirmation bias | pre-register RQs/hypotheses/analysis (this doc) before runs; blind triage where feasible (reviewer doesn't know which tool produced a finding) |
| Publication bias | report negative and flipped-by-budget results; publish the full experiment matrix incl. cells where RESTler wins |
| Epoch mis-attribution | three attribution levels (direct/enabling/ancestor); state which each claim uses |

---

## 19. Phased execution plan

| Phase | Objective | Key tasks | Prereqs | Outputs | Done when | Complexity | Risk |
|---|---|---|---|---|---|---|---|
| **0. Audit** | Confirm what can be logged today | reconcile this §16 vs current code; count endpoints per target; author manifests | repo access | gap table finalized; manifests | all metrics classified ✅/◑/❌ | Low | docs drift |
| **1. Schema & harness design** | Freeze contracts | finalize event schema (§12), reset contract (§13), tool_config files, dictionary + conversions | Phase 0 | schemas, configs, golden DB snapshots | dry-run produces valid empty artifacts | Med | schema churn later |
| **2. Pilot** | Validate methodology | 5 reps × T0 × C1–C4 × 10 min; run full analysis pipeline end-to-end | Phase 1 + P0 prereqs | pilot dataset, draft charts | pipeline reproduces charts from raw; variance sane | Med | reveals missing telemetry |
| **3. Controlled targets** | Detection accuracy & FP | T0 + external controlled; 10 reps × C1–C4 × 1 h; validation pipeline | Phase 2 | recall/precision, TTU, survival | manifests scored for both tools | Med | fixture too easy |
| **4. Real-world** | Practical applicability | T1,T2(,T3) × C1–C4 × 10 reps × 1 h; long 8 h on T1,T2 | Phase 3 | comparative dataset | full matrix cells filled or documented | High | reset cost, flakiness |
| **5. Ablation** | Isolate features | A1–A5 now; A6–A8 after flags land; UpsideFuzz × 3 targets × 10 reps | event log (§18) | ablation dataset | RQ3/RQ6 answerable | High | blocked on flags |
| **6. Statistics** | Normalized results | build processed/ from raw; survival, δ, CIs, FDR, rank aggregation | Phases 3–5 | charts, tables, effect sizes | all §17 outputs regenerate from raw | Med | p-hacking risk → pre-registered |
| **7. Manual validation** | Confirm & classify | reproduce, minimize, classify, document each distinct bug | Phases 3–5 | confirmed_bug records, PoCs | every headline bug has evidence | Med | labor-intensive |
| **8. Publication package** | Reproducible artifact | freeze commits/digests, publish raw+processed+harness, write results | Phases 6–7 | reproducible bundle | third party re-derives charts | Med | scope creep |

---

## 20. Deliverable tiers

**Immediate prerequisites (must exist before trustworthy runs):**
1. `-event-log` per-request JSONL (epoch, category, coverage_delta, seq_id, seed_idx, dict tokens, identity, valid/state-change flags) — *P0, blocks RQ3/RQ6 and epoch/dict charts*.
2. External **coverage poller** + **resource sampler** (no fuzzer change) — *P0, blocks all coverage-over-time and perf metrics, and RESTler coverage parity*.
3. `-seed` deterministic RNG flag — *P0 for reproducibility; until then, ≥10 reps and honest "unseeded" labeling*.
4. Golden **DB snapshot + checksum-gated reset** per target — *P0, blocks fairness*.
5. Ground-truth **manifests** for T0 + one external controlled target (independent authorship) — *P0 for accuracy claims*.
6. Shared **external judge** applying one taxonomy/dedup to both tools' findings — *P0 for fair comparison*.
7. RESTler runbook: Test + Fuzz-lean/Fuzz against the same instrumented image, auth parity — *P0*.

**Minimum viable benchmark (smallest useful evidence):** T0 + T1, C1–C4, 5 reps, 1 h, wall-clock budget, external coverage + resource sampling, distinct-root-cause bug counts + median TTU + final coverage + survival curve. Answers RQ1/RQ8 preliminarily and RQ7; explicitly *cannot* answer RQ3/RQ6.

**Conference-quality (BSides / Black Hat Arsenal / DEF CON):** MVP prereqs + full base matrix (4 targets × C1–C4 × 10 reps × 1 h) + one 8 h long run set + A1–A5 ablations + capability-delta table + overhead sub-benchmark. Survival curves, Cliff's δ with CIs, per-target + rank-aggregate. A live demo reproducing one confirmed bug per tool.

**Publication-quality:** 20 reps; A6–A8 ablations (after flags); epoch attribution (direct/enabling/ancestor); interaction analysis for dictionary; ≥5 targets incl. 2 controlled with independent manifests; full FDR-controlled statistics; pre-registration; fully reproducible artifact bundle; honest reporting of cells where RESTler wins.

---

## 21. Top 15 benchmarking tasks (ranked)

| # | Task | Priority | Effort | Depends on | Scientific value | Risk if omitted | Status |
|---|---|---|---|---|---|---|---|
| 1 | External coverage poller + resource sampler | P0 | S | — | High (all coverage/perf, RESTler parity) | no fair coverage comparison | ✅ DONE 2026-07-24 — `benchmarks/harness/{coverage_poller,resource_sampler}.py` |
| 2 | Golden DB snapshot + checksum-gated reset per target | P0 | M | — | High (fairness) | contaminated, non-comparable runs | ◑ DONE for T0 only — `benchmarks/harness/reset_target.py`; T1–T3 real-DB snapshot mechanics not built (documented in the script) |
| 3 | Shared external judge (taxonomy + dedup for both tools) | P0 | M | — | High (fair bug counting) | inflated/incomparable bug counts | ✅ DONE 2026-07-24 — `benchmarks/harness/shared_judge.py`, verified it merges the same real bug found independently by both tools into one cluster |
| 4 | Ground-truth manifests (T0 + external controlled) | P0 | M | — | High (accuracy, recall/precision) | no detection-accuracy claim | ◑ DONE for T0 only — `benchmarks/manifests/planted-bug-api.json`; external-controlled-target manifest still needed |
| 5 | RESTler runbook vs same instrumented image + auth parity | P0 | M | 1 | High (the baseline itself) | invalid or unfair baseline | ◑ DONE for no-auth targets — `benchmarks/RESTLER_RUNBOOK.md`, verified end to end on T0; multi-identity auth parity (needed for T1–T3) still open |
| 6 | Per-request `-event-log` in the fuzzer | P0 | M | — | High (RQ3/RQ6, epoch & dict charts) | can't attribute epochs/dict/feedback | ◑ DONE 2026-07-24 minus dict-token accounting — `void/go -event-log`, `worker.go::logRequestEvent`/`logEpochEvent`, `sequence.go::logSequenceEvent` |
| 7 | Harness: isolated compose runs, budget stop, resumable batches | P0 | L | 1,2 | High (execution at all) | manual runs, irreproducible | ✅ DONE 2026-07-24 — `benchmarks/harness/{run_cell,run_batch}.py`, both RESTler and UpsideFuzz branches verified end to end |
| 8 | Deterministic `-seed` flag | P0 | S | — | High (reproducibility, fewer reps) | high variance, weak claims | ✅ DONE 2026-07-24 — `void/go -seed` (not bit-for-bit under concurrency, documented) |
| 9 | Pilot (Phase 2) + full analysis pipeline from raw | P1 | M | 1–8 | High (validates methodology) | discover flaws mid-campaign | ◑ DONE, reduced scope — `benchmarks/raw/pilot/` (T0 only, C1+C3 only, no dict axis); statistical analysis pipeline (task 10 below) not yet run against it |
| 10 | Survival + Cliff's δ + bootstrap CI analysis code | P1 | M | 6,9 | High (defensible stats) | means-only, indefensible |
| 11 | Base matrix runs (4×C1–C4×10×1h) | P1 | L | 1–10 | High (answers RQ1/7/8) | no headline result |
| 12 | Ablations A1–A5 | P1 | M | 6,11 | Med–High (feature isolation) | can't show what matters |
| 13 | Instrumentation-overhead sub-benchmark | P2 | S | 1 | Med (RQ5, external validity) | overhead unquantified |
| 14 | Ablation flags `-no-feedback` / single-epoch / `-no-harvest` (A6–A8) | P2 | M | 6 | High (RQ6 core thesis) | central claim untestable |
| 15 | Long 8–24h discovery runs + manual validation | P2 | L | 11 | Med–High (rare bugs, plateau) | miss deep bugs, weaker story |

---

## 22. Verification checklist (this plan answers all)

- **Configurations compared:** C1–C4 (RESTler ±dict, UpsideFuzz ±dict) + ablations A1–A5 now, A6–A8 after flags (§3).
- **Targets:** T0 planted-bug + external controlled (Group 1), eShopOnWeb/SimplCommerce/BTCPayServer (Group 2), Bitwarden illustrative (Group 3), optional synthetic stress (Group 4) (§4).
- **How many runs:** conference tier ≈ 160 head-to-head + 150 ablation + 480 long ≈ **~800–900 core-hours** (§7).
- **Run duration:** smoke 10 m, comparative 1 h (primary), discovery 8 h / 24 h (§6).
- **Target reset:** volume-snapshot restore + checksum gate + `/shm/reset` (§13).
- **Data collected:** full metric catalogue (§9) via immutable JSONL data model (§12).
- **Bug validation:** shared judge, taxonomy, dedup by root cause, reproduce/minimize/classify pipeline (§8).
- **Epoch evaluation:** three-level attribution (direct/enabling/ancestor), per-epoch coverage/bug charts (§10, §17) — gated on event log.
- **Dictionary effectiveness:** per-tool paired + interaction test; token-level attribution (§11, §17) — gated on token accounting.
- **Fairness:** fairness contract (§5), multi-budget analysis (§6), capability-vs-head-to-head separation (§2).
- **Significance & effect size:** Mann–Whitney + Cliff's δ + bootstrap CIs + Kaplan–Meier + FDR + rank aggregation (§11).
- **Charts & tables:** enumerated with axes/uncertainty/misuse notes (§17).
- **Must be implemented first:** Immediate Prerequisites 1–7 (§20), Top-15 tasks 1–8 (§21).
