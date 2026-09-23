# UpsideFuzz Documentation Index

This is the central documentation index for the **UpsideFuzz** platform — a coverage-guided REST API fuzzer for .NET. Organized by what you're trying to do, not just an alphabetical file list. Start here or from [README.md](../README.md).

---

## 1. New here? Start with these, in order

| Document | What it gives you |
|----------|-------------|
| [README.md](../README.md) | 60-second overview: what this is, feature table, quick-start commands |
| [**fixtures/demo-app/README.md**](../fixtures/demo-app/README.md) | The flagship demo target ("TeamFlow") — 57 endpoints, 42 planted vulnerabilities across every oracle class, no external target to clone. The fastest way to see the whole pipeline prove itself end to end. Past run results/pipeline-bugs-this-demo-exposed live separately in [fixtures/demo-app/HISTORY.md](../fixtures/demo-app/HISTORY.md). |
| [**getting-started/how-it-works.md**](getting-started/how-it-works.md) | **Read this first if you're new.** Plain-language explanation of the problem this solves, how instrumentation/coverage/grammar/sequences/scheduling actually work under the hood, and — in depth — what the BOLA/mass-assignment/injection/differential-auth-bypass oracles actually catch and why crash-only fuzzers miss them entirely |
| [getting-started/installation.md](getting-started/installation.md) | What to install before running UpsideFuzz on a new system (Docker, Python, .NET SDK, optional Go) |
| [getting-started/quickstart.md](getting-started/quickstart.md) | The complete step-by-step runbook: instrument → build → verify → grammar → fuzz → analyze → troubleshoot |
| [**getting-started/cli.md**](getting-started/cli.md) | The `upsidefuzz` single-command orchestrator (Top-20 #19) — one command instead of four scripts, plus a zero-install Docker mode (`./upsidefuzz`) that needs nothing but Docker locally |
| [guides/campaigns.md](guides/campaigns.md) | The `campaign.yaml` contract (`campaign.py`) — declare target/readiness/state reset-seed-cleanup/identities/policy/scenarios once as a reusable file instead of re-typing CLI flags per run |
| [guides/security-scenarios.md](guides/security-scenarios.md) | The `security_scenarios.yaml` declarative scenario library (`security_scenarios.py`) — every stateful security-scenario family (BOLA, tenant escape, mass assignment, workflow bypass, stale object, optimistic locking, idempotency, races, auth confusion, async workflows), each cross-checked against the real Go implementation so the catalog can't silently drift |
| [**guides/typed-structural-mutation.md**](guides/typed-structural-mutation.md) | Schema-aware object/array/`oneOf`-discriminator-aware request-body mutation (`-typed-body-mutation`/`-adversarial-body-rate`) — the 10 structural operators, which command finds which kind of bug, and a real measured A/B comparison against the legacy flat mutator on Bitwarden |

---

## 2. Running it against a target

Step-by-step guides for instrumenting and fuzzing specific real-world applications:

| Target | Auth Style | Quickstart |
|--------|-----------|-----------|
| **eShopOnWeb** | JWT (login flow) | [eshop-quickstart.md](guides/target-specific/eshop-quickstart.md) — smallest target, fastest way to see the whole pipeline work end to end |
| **SimplCommerce** | Cookie + anti-forgery | [simplcommerce-quickstart.md](guides/target-specific/simplcommerce-quickstart.md) |
| **BTCPayServer** | API key | [btcpayserver-quickstart.md](guides/target-specific/btcpayserver-quickstart.md) |
| **Bitwarden** | JWT (identity service) | [bitwarden-quickstart.md](guides/target-specific/bitwarden-quickstart.md) — fresh, from-scratch setup |
| **Bitwarden** (already set up) | — | [bitwarden-runbook.md](guides/target-specific/bitwarden-runbook.md) — iterating against an *existing* `bitwarden_prep/` checkout, plus every gotcha found during setup. Use the quickstart for a fresh start; use this once you already have a working instrumented copy and just want to re-run or troubleshoot. |
| **Jellyfin** | Static token (`MediaBrowser` scheme, not `Bearer`) | [jellyfin-quickstart.md](guides/target-specific/jellyfin-quickstart.md) — no pre-existing Dockerfile, generated from scratch; three real gotchas documented (ffmpeg, non-standard port, static-web-assets manifest) |

Which target to pick first → [README.md §Quickstarts](../README.md#quickstarts). Adding a new target entirely → [guides/target-candidates.md](guides/target-candidates.md).

### Authentication & dictionaries

| Document | Description |
|----------|-------------|
| [guides/authentication.md](guides/authentication.md) | Canonical auth file schema, multi-identity scheduling, access-control campaign setup — required reading if you want BOLA/broken-auth findings, which need ≥2 identities to compare |
| [guides/auth.identities.example.json](guides/auth.identities.example.json) | Copyable example auth identity file |
| [guides/mcp-integration.md](guides/mcp-integration.md) | Using an MCP-connected AI agent to enrich `dict.json` from live database data |
| [quickstart.md §10](getting-started/quickstart.md#10-custom-dictionary-format) | The `dict.json` format itself (flat key→values map) and how it interacts with grammar-derived and mutation-derived boundary values |

---

## 3. Internals, architecture, and contributing

| Document | For whom / what it covers |
|----------|-------------|
| [architecture/overview.md](architecture/overview.md) | The pipeline reference: source discovery, Docker build, instrumentation, SHM sync, coverage protocol, grammar compilation (`tools/grammar/grammarc/`+`tools/dotnet/analyzer/`), file map. Covers everything up to the point `void` starts running. |
| [architecture/engine.md](architecture/engine.md) | The Void fuzzing runtime itself, split out of the overview for length: component map, CmpLog/constant extraction, schema-conformance oracle, state-reward sequence search, the typed resource-lifecycle graph, epochs, mutation engine, triage/clustering/SARIF, vulnerability oracles. |
| [architecture/stateful-fuzzing.md](architecture/stateful-fuzzing.md) | The stateful-fuzzing architecture specifically: typed resource/lifecycle model, valid-workflow vs. adversarial-branch planning, producer→consumer bindings, reproducibility — implemented-vs-open status mapped file by file. |
| [architecture/testing.md](architecture/testing.md) | The E2E regression gate (`fixtures/planted-bug-api/`) and this project's unit/integration test coverage history by pass. See [tests/README.md](../tests/README.md) for how tests are organized on disk. |
| [development/architecture-review.md](development/architecture-review.md) | A candid, no-marketing engineering audit reflecting **current state only** (resolved items are dropped, not tracked as a changelog — see git history for that): per-subsystem strengths/currently-open weaknesses, comparison to RESTler/EvoMaster/Schemathesis/DeepREST, and a prioritized (P0/P1/P2) open-improvements backlog. Read this to understand what's genuinely strong, what's a known gap, and what's planned next. |
| [development/code-map.md](development/code-map.md) | Terse, AI-agent-facing operational summary: component map, critical "do not revert" decisions, file-lookup table. Kept current — if you're an AI agent about to modify this repo, read this first. Also the `.cursorrules` symlink target. |
| [**guides/repo-layout.md**](guides/repo-layout.md) | Where everything lives on disk: `src/void/` (Go module), `src/cli/upsidefuzz/` (Python CLI), `bin/`+`bin/compatibility/` (entrypoint scripts + back-compat wrappers), `.work/` (local working state) — the full old-path → new-path map from the 2026-07-31 repo cleanup |
| [cmd/void/README.md](../src/void/cmd/void/README.md) | The Go fuzzer's own CLI reference: every flag, startup output, mutation categories, epoch schedule, crash JSONL format, cross-compile instructions |
| [research/whitepaper.md](research/whitepaper.md) | The full whitepaper — builds fuzzing and coverage-guided fuzzing from zero, then walks the entire architecture and the engineering decisions behind it, with an honest accounting of what's novel, what's re-implementation of prior art, and what still doesn't work. The best single document to hand someone who wants to understand the whole project, diagrams included. |

No `development/contributing.md` exists yet — this repo has never had one; adding a
real one (not a boilerplate stub) is an open gap, not an oversight.

---

## 4. Historical research artifacts (point-in-time, not living docs)

These are dated findings from specific fuzzing campaigns, kept for record — **not** reference documentation, and their numbers are not guaranteed reproducible against the current pipeline (several predate the RESTler retirement described in `development/architecture-review.md`'s Grammar Generation section). Each now carries a banner noting its date and status.

| Document | Target | Date | Type |
|----------|--------|------|------|
| [reports/BITWARDEN_REPORT.md](reports/BITWARDEN_REPORT.md) | Bitwarden | 2026-07-13 | 30-min authenticated campaign findings |
| [reports/BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md](reports/BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md) | Bitwarden | 2026-07-13 | 15-min multi-auth validation run |
| [reports/BTCPAYSERVER_REPORT.md](reports/BTCPAYSERVER_REPORT.md) | BTCPayServer | 2026-07-07 | Initial fuzzing campaign findings (RESTler-era pipeline) |
| [reports/BTCPAYSERVER_ESCALATION_ANALYSIS.md](reports/BTCPAYSERVER_ESCALATION_ANALYSIS.md) | BTCPayServer | 2026-07-13 | Crash escalation analysis (DDoS / RCE paths) |
| [reports/SIMPLCOMMERCE_REPORT.md](reports/SIMPLCOMMERCE_REPORT.md) | SimplCommerce | 2026-07-07 | Baseline vs. professional-dictionary campaign comparison (RESTler-era pipeline) |
| [reports/JELLYFIN_REPORT.md](reports/JELLYFIN_REPORT.md) | Jellyfin | 2026-07-30 | 20-min `-profile security` campaign against today's pipeline — **current, not historical**; see below |

For a *current*, reproducible example of findings, see the "Example findings" sections in [eshop-quickstart.md](guides/target-specific/eshop-quickstart.md) and [bitwarden-quickstart.md](guides/target-specific/bitwarden-quickstart.md), which were re-verified against today's pipeline — or [reports/JELLYFIN_REPORT.md](reports/JELLYFIN_REPORT.md), a full campaign writeup with stack traces and repro commands for every finding.

---

## 5. Research & academic paper

| Document | Description |
|----------|-------------|
| [research/design-notes/](research/design-notes/) | Point-in-time design plans + measured-results reports (optimization pass, resource-state-graph work) — historical, not living reference docs; see each file's own status banner. |

---

**→ [Back to README](../README.md)**
