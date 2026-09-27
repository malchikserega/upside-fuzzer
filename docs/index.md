# UpsideFuzz Documentation Index

This is the central documentation index for the **UpsideFuzz** platform — a coverage-guided REST API fuzzer for .NET. Organized by what you're trying to do, not just an alphabetical file list. Start here or from [README.md](../README.md).

---

## 1. New here? Start with these, in order

| Document | What it gives you |
|----------|-------------|
| [README.md](../README.md) | 60-second overview: what this is, feature table, quick-start commands |
| [**fixtures/demo-app/README.md**](../fixtures/demo-app/README.md) | The flagship demo target ("TeamFlow") — 57 endpoints, 42 planted vulnerabilities across every oracle class, no external target to clone. The fastest way to see the whole pipeline prove itself end to end. |
| [**getting-started/how-it-works.md**](getting-started/how-it-works.md) | **Read this first if you're new.** Plain-language explanation of the problem this solves, how instrumentation/coverage/grammar/sequences/scheduling actually work under the hood, and — in depth — what the BOLA/mass-assignment/injection/differential-auth-bypass oracles actually catch and why crash-only fuzzers miss them entirely |
| [getting-started/installation.md](getting-started/installation.md) | What to install before running UpsideFuzz on a new system (Docker, Python, .NET SDK, optional Go) |
| [getting-started/quickstart.md](getting-started/quickstart.md) | The complete step-by-step runbook: instrument → build → verify → grammar → fuzz → analyze → troubleshoot |
| [**getting-started/cli.md**](getting-started/cli.md) | The `upsidefuzz` single-command orchestrator — one command instead of four scripts, plus a zero-install Docker mode (`./upsidefuzz`) that needs nothing but Docker locally |
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

Which target to pick first → [README.md §Quickstarts](../README.md#quickstarts).

> **Third-party targets.** Bitwarden, BTCPay Server, eShopOnWeb, Jellyfin and SimplCommerce are
> trademarks of their respective owners. UpsideFuzz is not affiliated with or endorsed by any of
> these projects; the guides only cover building and fuzzing their public source code in your own
> local test environment. Report anything you find in third-party software privately to its
> vendor rather than publishing it.

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
| [development/code-map.md](development/code-map.md) | Terse, AI-agent-facing operational summary: component map, critical "do not revert" decisions, file-lookup table. Kept current — if you're an AI agent about to modify this repo, read this first. Also the `.cursorrules` symlink target. |
| [**guides/repo-layout.md**](guides/repo-layout.md) | Where everything lives on disk: `src/void/` (Go module), `src/cli/upsidefuzz/` (Python CLI), `bin/`+`bin/compatibility/` (entrypoint scripts + back-compat wrappers), `.work/` (local working state) — the full old-path → new-path map from the 2026-07-31 repo cleanup |
| [cmd/void/README.md](../src/void/cmd/void/README.md) | The Go fuzzer's own CLI reference: every flag, startup output, mutation categories, epoch schedule, crash JSONL format, cross-compile instructions |
| [research/whitepaper.md](research/whitepaper.md) | The full whitepaper — builds fuzzing and coverage-guided fuzzing from zero, then walks the entire architecture and the engineering decisions behind it, with an honest accounting of what's novel, what's re-implementation of prior art, and what still doesn't work. The best single document to hand someone who wants to understand the whole project, diagrams included. |

No `development/contributing.md` exists yet — this repo has never had one; adding a
real one (not a boilerplate stub) is an open gap, not an oversight.

---

**→ [Back to README](../README.md)**
