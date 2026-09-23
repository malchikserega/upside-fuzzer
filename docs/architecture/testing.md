# Testing & CI

Split out of `docs/architecture/overview.md` §11 during the repo-architecture
refactor. Covers the E2E regression gate and this project's unit/integration
test coverage history. For how tests are *organized* on disk (colocated unit
tests vs. `tests/integration/`), see [tests/README.md](../../tests/README.md).

**→ [Back to README](../../README.md) · [Architecture overview](overview.md) · [Docs Index](../index.md)**

---

## Continuous Integration (E2E regression gate)

Top-20 #7 — this project's first CI of any kind, added 2026-07-23 as a direct regression
safety net for `tools/grammar/grammarc/`+`tools/dotnet/analyzer/` (#9/#10) and the mutation-engine changes (#14/#11),
none of which had any automated coverage before this existed.

`.github/workflows/e2e.yml` runs `scripts/e2e/e2e-test.sh` on every push/PR. The script proves
the **whole pipeline**, not just that each stage exits zero:

```
bin/fuzz-prep-multi.py (instrument fixtures/planted-bug-api)
        │
docker compose build && up -d
        │
bin/verify-hook.sh (zero-edit coverage hook sanity: /shm/create, /shm/health,
                 synthetic-404 attribution, real-endpoint edge growth)
        │
bin/compile-grammar.sh (OAS-only — no --src needed for this small fixture)
        │
void -time-budget 1  (short live fuzz run against the real container)
        │
assert: summary.json.coverage_end_edges > 0
assert: unique-crashes.jsonl contains a GET /items?...  status_code=500 record
        (the planted ArgumentOutOfRangeException — see fixtures/planted-bug-api/README.md)
```

`fixtures/planted-bug-api/` is deliberately minimal (in-memory data, no DB, no external
services) and nested under `src/PlantedBugApi/` — a flat single-project layout collides
with the generated Dockerfile's `COPY . ./` + implicit `**/*.cs` glob, which would also
pull in the tool's own sibling `instrumentor_src/Program.cs` (itself top-level
statements) into the same compile, producing `CS8802: Only one compilation unit can have
top-level statements`. Nesting one level down avoids this the same way every real target
in this repo already does. The fixture's `ListItems` handler also lives on a named,
non-lambda class (`ItemHandlers`) rather than inline in `app.MapGet(...)` — SharpFuzz
instrumentation blanket-excludes any type whose name contains `+<>c` (compiler-generated
lambda/closure classes) to prevent a real, previously-hit static-initializer crash class
(see `tools/dotnet/instrumentor/Program.cs::ShouldInstrument`'s own comment) — but that exclusion also
silently zeroes out coverage for logic written directly inline in minimal-API lambdas,
confirmed empirically while building this fixture (0 SHM edges from real traffic before
the restructuring, real edge growth after).

Building this fixture and script also surfaced and fixed three real, previously-unknown
bugs elsewhere in the pipeline: a substring-vs-path-segment matching bug in
`tools/dotnet/analyzer/RoslynUtil.IsTestPath`, `tools/dotnet/analyzer/RouteAuthWalker` never scanning top-level-
statement `Program.cs` files for minimal-API routes, and a bash-3.2-specific unbound-array
crash in `bin/compile-grammar.sh` when `--src` is omitted.

### Unit test coverage (2026-07-25)

The E2E gate above proves the pipeline works end-to-end on one fixture; it doesn't
protect individual functions from regressing in ways that don't happen to break that
one fixture's shape. Added as a second, faster-feedback layer underneath it:

- **`src/void/internal/engine/`** — statement coverage raised from 20.0% to 32.0% (`go test -coverprofile`).
  New: `crash_test.go` (crash signature generation, dedup, the root-cause cluster
  recording path), `minimize_test.go` (crash minimization + repro-stability check
  against a real `httptest` server), `auth_test.go` (the anti-forgery token
  lifecycle — register/prune/evict/harvest), `store_test.go` (`DictStore`'s
  key-fallback chain, `RuntimeStore.addValue`'s eviction), plus additions to
  `cluster_test.go`/`identity_test.go` covering `recordCluster`, identity parsing/
  weighted selection, and — the highest-value addition — `triageCrash`, the honest-
  triage classification taxonomy that decides whether a 500 is reported as a genuine
  vulnerability, a robustness bug, noise, or a build artifact, previously untested.
- **`tools/grammar/grammarc/`** — 2 test files → 8 (80 tests): `test_oas.py`, `test_body_serializer.py`,
  `test_boundary.py`, `test_dependencies.py`, `test_multipart.py`, `test_roslyn_merge.py`,
  alongside the existing `test_emit_dict.py`/`test_response_schemas.py`. Run any of them
  with `python3 -m unittest grammarc.test_oas -v` (stdlib-only, no pip install).
- **`tools/dotnet/instrumentor.Tests/`** and **`tools/dotnet/analyzer.Tests/`** (new xUnit projects —
  neither `tools/dotnet/instrumentor/` nor `tools/dotnet/analyzer/` had any automated test coverage
  before this). `instrumentor.Tests` required a small, behavior-preserving refactor first:
  `NamespaceMatcher` and `InstrumentationFilter` were extracted out of top-level
  statements into proper `internal` classes (C# can't expose a top-level-statements
  local function to another assembly via `InternalsVisibleTo` — it compiles to a
  `private` member of the synthesized `Program` class), verified to change zero
  observable behavior by rerunning the `Bit.Core`/`Bit.CoreUtilities` compiled-fixture
  namespace-matching check before and after the refactor. Run with `dotnet test` from
  either directory (the main `instrumentor`/`analyzer` projects still build and run
  exactly as before — `ProjectReference`, not a fork).

Writing this test suite directly found two more real, previously-unknown bugs:
`IsTestPath` still missed `UnitTests`-shaped directories after an earlier fix only
handling the bare `Tests`/`test` forms, and `tools/grammar/grammarc/oas.py` never handled Swagger
2.0's `in: body` parameter convention at all (only OpenAPI 3.x's `requestBody` was
handled — every v2 spec's request body was silently dropped).

### Resource state graph test coverage (2026-07-27)

The typed resource state graph / generalized extraction / coverage-directed
scheduling work (§ above, `resource_graph.go`/`resource_extraction.go`/
`resource_scheduling.go`) added 4 new test files and raised `src/void/internal/engine/`'s
statement coverage from 32.7–32.8% to **37.8%**: `resource_graph_test.go` (13
tests, including a `-race`-verified adversarial concurrent-caller test),
`resource_extraction_test.go` (20 tests, 9 of them regression tests each
proving `extractEntityIDs` blind and the new pipeline not, for GUID/slug/HAL/
JSON:API/nested-composite/no-"id"-substring shapes), `resource_scheduling_test.go`
(18 tests covering lifecycle-transition classification and coverage-directed
scheduling, including determinism under a fixed seed and a 50-trial
starvation-prevention check), and `resource_integration_test.go` (3 tests
driving the pipeline against a real `httptest` fixture server). Writing the
integration test directly found and fixed two real bugs before they shipped —
see `docs/research/design-notes/resource-state-graph-report.md`'s "Defects found and fixed during
this pass" for detail.
