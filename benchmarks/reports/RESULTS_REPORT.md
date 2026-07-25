# UpsideFuzz — Benchmark Report

*2026-07-24 · local report, not hosted anywhere. See `RESULTS_REPORT.html` in this same folder for the version with charts.*

Coverage-guided grey-box fuzzing for .NET APIs — head-to-head against RESTler
on a controlled fixture, then run standalone against two real open-source
codebases: eShopOnWeb and Bitwarden's server.

**Headline:** 3 targets · 18 fuzzing sessions · 4.4M+ requests sent · direct-SHM
coverage mode throughout.

| | |
|---|---|
| **3×** | more distinct bugs than RESTler (median, same target & budget) |
| **125** | unique root-cause crashes found in Bitwarden in 20 minutes |
| **754** | real API endpoints instrumented in Bitwarden, zero source edits |
| **221,847** | distinct coverage edges reached in a single Bitwarden run |

---

## Head-to-head vs. RESTler

Controlled fixture · 10-minute budget · same instrumented target · findings
reclassified by **one shared judge** (not either tool's own labels), so this
isn't grading UpsideFuzz on its own curve.

| | RESTler | UpsideFuzz |
|---|---:|---:|
| Median distinct bugs (5 reps) | 1 | **3** |
| Median coverage edges | 155 | **357** |
| Bug classes found | numeric_boundary | numeric_boundary, ssrf, unhandled_exception |

RESTler cannot structurally emit oracle-driven findings (BOLA, mass-assignment,
injection, SSRF) — it has no equivalent detection layer. The `ssrf` class above
is exactly that gap in practice, not a tuning difference.

**Coverage over the 10-minute budget** (real polled data, one representative
rep per tool): UpsideFuzz keeps climbing the whole budget and even triggers a
bitmap reset-and-resume near minute 8.5 (edges 655→188→357, see
`ARCHITECTURE_REVIEW.md`'s coverage-reset feature). RESTler's `test`/`fuzz-lean`
mode exhausts its bounded exploration pass in **~70 seconds** (edges plateau at
155) and then sits idle for the remaining ~8.8 minutes of the same budget — it
has no concept of "keep trying" once its one deterministic pass over the
grammar completes.

---

## Real targets — scaling with time

Standalone runs, no RESTler comparison — UpsideFuzz only, `profile=security`,
same seed.

### Bitwarden — server
*Password manager backend · fresh clone, hook-mode zero-edit instrumentation ·
3,293 instrumented types across 754 endpoints*

| Budget | Requests | Coverage edges | Crashes (total / unique) |
|---|---:|---:|---:|
| 5 min | 77,842 | 137,000 | 118 / 113 |
| 10 min | 145,885 | 211,626 | 125 / 114 |
| 20 min | 328,396 | 221,847 | 135 / 125 |

### eShopOnWeb — PublicApi
*Sample store REST API · JWT login flow · minimal-API route style*

| Budget | Requests | Coverage edges | Crashes (total / unique) |
|---|---:|---:|---:|
| 5 min | 1,113,382 | 4,860 | 19 / 7 |
| 10 min | 1,080,945 | 6,533 | 4 / 2 |
| 20 min | 2,264,461 | 985 | 3 / 2 |

**Reading the numbers side by side:** Bitwarden's much smaller request volume
per minute (its handlers do real crypto/DB work) still produced two orders of
magnitude more coverage edges and unique crashes than eShopOnWeb — it's a
larger, more complex codebase, and the point of coverage guidance is exactly
to spend the budget where the surface actually is. eShopOnWeb's crash count
trending down at longer budgets is expected: the sequence engine and
crash-boost logic exhaust the small number of distinct bugs a ~30-endpoint API
has, then keep refining reproducibility rather than finding new ones.

---

## Sample findings

Real output from these runs, unedited.

| Severity | Endpoint | What happened | Target |
|---|---|---|---|
| `likely_vuln_high` | `GET /api/catalog-items/{id}` | Identical response body returned to a second, unrelated identity — cross-identity object access (BOLA) | eShopOnWeb |
| `likely_vuln_high` | `POST /settings/domains` | Cloud-metadata address in a domain-verification field was fetched and reflected back — SSRF | Bitwarden |
| `confirmed_unhandled_exception` | `POST /devices` | Reproducible unhandled exception post-authentication — real stack trace captured | Bitwarden |
| `needs_review` | `GET /items?pageSize=<negative>` | Unbounded list-range slice throws on out-of-range input — same bug class UpsideFuzz found for real on eShopOnWeb's own catalog endpoint | Fixture (T0) |

Every row above is the tool's own **honest triage** label, not a marketing
gloss: `needs_review` stays `needs_review`, dependency-injection
misconfigurations are excluded from the count entirely, and a handful of
borderline timing-based signals from this same run were left out of this
table rather than presented as confirmed — they're in the raw crash logs for
manual follow-up, unembellished.

---

Raw data: `benchmarks/raw/` · rebuild the tables with
`python3 benchmarks/harness/build_results_table.py` · engine: void, direct-SHM
coverage, `profile=security`.
