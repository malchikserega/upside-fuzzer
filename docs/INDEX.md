# UpsideFuzz Documentation Index

This is the central documentation index for the **UpsideFuzz** platform — a coverage-guided REST API fuzzer for .NET. Organized by what you're trying to do, not just an alphabetical file list. Start here or from [README.md](../README.md).

---

## 1. New here? Start with these, in order

| Document | What it gives you |
|----------|-------------|
| [README.md](../README.md) | 60-second overview: what this is, feature table, quick-start commands |
| [**HOW_IT_WORKS.md**](HOW_IT_WORKS.md) | **Read this first if you're new.** Plain-language explanation of the problem this solves, how instrumentation/coverage/grammar/sequences/scheduling actually work under the hood, and — in depth — what the BOLA/mass-assignment/injection/differential-auth-bypass oracles actually catch and why crash-only fuzzers miss them entirely |
| [INSTRUCTIONS.md](INSTRUCTIONS.md) | The complete step-by-step runbook: prerequisites → instrument → grammar → fuzz → analyze → troubleshoot |
| [**CLI.md**](CLI.md) | The `upsidefuzz` single-command orchestrator (Top-20 #19) — one command instead of four scripts, plus a zero-install Docker mode (`./upsidefuzz`) that needs nothing but Docker locally |

---

## 2. Running it against a target

Step-by-step guides for instrumenting and fuzzing specific real-world applications:

| Target | Auth Style | Quickstart |
|--------|-----------|-----------|
| **eShopOnWeb** | JWT (login flow) | [QUICKSTART_ESHOP.md](QUICKSTART_ESHOP.md) — smallest target, fastest way to see the whole pipeline work end to end |
| **SimplCommerce** | Cookie + anti-forgery | [QUICKSTART_SIMPLCOMMERCE.md](QUICKSTART_SIMPLCOMMERCE.md) |
| **BTCPayServer** | API key | [QUICKSTART_BTCPAYSERVER.md](QUICKSTART_BTCPAYSERVER.md) |
| **Bitwarden** | JWT (identity service) | [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md) — fresh, from-scratch setup |
| **Bitwarden** (already set up) | — | [BITWARDEN_FUZZ_RUNBOOK.md](BITWARDEN_FUZZ_RUNBOOK.md) — iterating against an *existing* `bitwarden_prep/` checkout, plus every gotcha found during setup. Use the quickstart for a fresh start; use this once you already have a working instrumented copy and just want to re-run or troubleshoot. |

Which target to pick first → [README.md §Quickstarts](../README.md#quickstarts). Adding a new target entirely → [TARGET_CANDIDATES.md](TARGET_CANDIDATES.md).

### Authentication & dictionaries

| Document | Description |
|----------|-------------|
| [FUZZER_AUTHENTICATION.md](FUZZER_AUTHENTICATION.md) | Canonical auth file schema, multi-identity scheduling, access-control campaign setup — required reading if you want BOLA/broken-auth findings, which need ≥2 identities to compare |
| [auth.identities.example.json](auth.identities.example.json) | Copyable example auth identity file |
| [MCP_INTEGRATION_GUIDE.md](MCP_INTEGRATION_GUIDE.md) | Using an MCP-connected AI agent to enrich `dict.json` from live database data |
| [INSTRUCTIONS.md §10](INSTRUCTIONS.md#10-custom-dictionary-format) | The `dict.json` format itself (flat key→values map) and how it interacts with grammar-derived and mutation-derived boundary values |

---

## 3. Internals, architecture, and contributing

| Document | For whom / what it covers |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The deep internals reference: instrumentation pipeline, SHM coverage protocol, grammar compilation (`grammarc/`+`dotnet/analyzer/`), Void engine component map, CI. For anyone modifying the pipeline. |
| [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) | A candid, no-marketing engineering audit reflecting **current state only** (resolved items are dropped, not tracked as a changelog — see git history for that): per-subsystem strengths/currently-open weaknesses, comparison to RESTler/EvoMaster/Schemathesis/DeepREST, and a prioritized (P0/P1/P2) open-improvements backlog. Read this to understand what's genuinely strong, what's a known gap, and what's planned next. |
| [AI_CONTEXT.md](AI_CONTEXT.md) | Terse, AI-agent-facing operational summary: component map, critical "do not revert" decisions, file-lookup table. Kept current — if you're an AI agent about to modify this repo, read this first. |
| [void/README.md](../void/README.md) | The Go fuzzer's own CLI reference: every flag, startup output, mutation categories, epoch schedule, crash JSONL format, cross-compile instructions |
| [ARTICLE.md](ARTICLE.md) | A full narrative technical write-up of the architecture and the engineering decisions behind it, with an honest accounting of what's novel, what's re-implementation of prior art, and what still doesn't work |

### Testing & CI

| Document | Description |
|----------|-------------|
| `.github/workflows/e2e.yml` + `scripts/e2e-test.sh` | The project's regression gate: instrument → coverage → grammar → fuzz → detect against `fixtures/planted-bug-api/` (a minimal planted-bug sample app), asserting the planted bug is actually found — not just that every step exits zero. Run `./scripts/e2e-test.sh` locally before trusting a pipeline/engine change. Documented in [ARCHITECTURE.md §11](ARCHITECTURE.md) and [INSTRUCTIONS.md §10a](INSTRUCTIONS.md#10a-running-the-e2e-regression-check-locally). |
| `fixtures/planted-bug-api/README.md` | What the planted bug is and why it's shaped the way it is |

---

## 4. Historical research artifacts (point-in-time, not living docs)

These are dated findings from specific fuzzing campaigns, kept for record — **not** reference documentation, and their numbers are not guaranteed reproducible against the current pipeline (several predate the RESTler retirement described in `ARCHITECTURE_REVIEW.md`'s Grammar Generation section). Each now carries a banner noting its date and status.

| Document | Target | Date | Type |
|----------|--------|------|------|
| [BITWARDEN_REPORT.md](reports/BITWARDEN_REPORT.md) | Bitwarden | 2026-07-13 | 30-min authenticated campaign findings |
| [BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md](reports/BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md) | Bitwarden | 2026-07-13 | 15-min multi-auth validation run |
| [BTCPAYSERVER_REPORT.md](reports/BTCPAYSERVER_REPORT.md) | BTCPayServer | 2026-07-07 | Initial fuzzing campaign findings (RESTler-era pipeline) |
| [BTCPAYSERVER_ESCALATION_ANALYSIS.md](reports/BTCPAYSERVER_ESCALATION_ANALYSIS.md) | BTCPayServer | 2026-07-13 | Crash escalation analysis (DDoS / RCE paths) |
| [SIMPLCOMMERCE_REPORT.md](reports/SIMPLCOMMERCE_REPORT.md) | SimplCommerce | 2026-07-07 | Baseline vs. professional-dictionary campaign comparison (RESTler-era pipeline) |

For a *current*, reproducible example of findings, see the "Example findings" sections in [QUICKSTART_ESHOP.md](QUICKSTART_ESHOP.md) and [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md), which were re-verified against today's pipeline.

---

## 5. Benchmarks & academic paper

| Document | Description |
|----------|-------------|
| [benchmarks/BENCHMARK_PLAN.md](../benchmarks/BENCHMARK_PLAN.md) | The living benchmark design doc: data model, head-to-head vs. capability-only separation, shared external judge, Top-15 prerequisite tasks and their status |
| [benchmarks/reports/RESULTS_REPORT.md](../benchmarks/reports/RESULTS_REPORT.md) | Consolidated, presentable results — RESTler-vs-UpsideFuzz head-to-head plus real Bitwarden/eShopOnWeb runs, with charts (`RESULTS_REPORT.html` in the same folder) |
| [benchmarks/reports/RESULTS_TABLE.md](../benchmarks/reports/RESULTS_TABLE.md) | Auto-generated raw table, regenerate via `python3 benchmarks/harness/build_results_table.py` |
| [benchmarks/docs/RESTLER_RUNBOOK.md](../benchmarks/docs/RESTLER_RUNBOOK.md) | How the RESTler baseline is actually run in this environment (`.NET 6` target, CLI quirks) |
| [BENCHMARK_AGENT_INSTRUCTIONS.md](BENCHMARK_AGENT_INSTRUCTIONS.md) | Historical reproducibility playbook for 20-minute RESTler-vs-Void benchmarks across 4 targets. Self-labeled as a historical rerun playbook — RESTler appears here deliberately, as the baseline being compared against, not as a live dependency of this project. |
| `arxiv_paper/` | Draft academic paper package (`paper.md`, `PLAN.md`, `SKETCH.md`). Separate audience/purpose from the rest of this index — not maintained in lockstep with the codebase. **Known gap**: `paper.md`'s methodology section still describes the retired RESTler-based grammar pipeline and needs a rewrite before submission. |

---

**→ [Back to README](../README.md)**
