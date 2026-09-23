# Test organization

One consistent style across all three languages in this repo: **unit tests
stay colocated with the module they test**, using each ecosystem's own
idiomatic, tool-expected convention --

| Language | Convention | Where |
|---|---|---|
| Go | `*_test.go` beside the source file, same package | `src/void/internal/engine/*_test.go`, `src/void/internal/config/` (currently none) |
| Python | `test_*.py` beside/inside the package, relative imports | `tools/grammar/grammarc/test_*.py`, `tools/prep/fuzzprep/test_fuzz_prep_multi.py`, `tools/campaign/test_*.py` |
| .NET | a sibling `.Tests` project, referenced via the `.sln`/`dotnet test` | `tools/dotnet/analyzer.Tests/`, `tools/dotnet/instrumentor.Tests/` |

This was a deliberate choice, not an oversight: `go test`, `python3 -m
unittest <package>.<module>`, and `dotnet test` all assume this layout by
default. Moving unit tests into a parallel `tests/unit/{go,python,dotnet}/`
tree would fight each tool's own discovery mechanism (Go in particular
*requires* same-package placement for whitebox tests -- a `_test.go` file
outside its module can't see unexported identifiers at all) for no benefit,
and would require maintaining two mirrored directory structures in sync by
hand.

`tests/` here is reserved for what's genuinely cross-cutting -- tests that
don't belong to any single module, or that exercise multiple
languages/processes together:

- **`tests/integration/`** — cross-module, same-process-or-adjacent checks.
  Currently: [`compatibility/`](integration/compatibility) (smoke tests for
  the repo-root compatibility wrappers -- `bin/fuzz-prep-multi.py`,
  `upsidefuzz.py`, `bin/compile-grammar.sh`, `./upsidefuzz`). The grammar
  compiler's own CLI-level regression suite lives at
  [`scripts/test/test-compile-grammar-cli.sh`](../scripts/test/test-compile-grammar-cli.sh)
  rather than being duplicated here -- it's already a real, working,
  CI-gated integration test; moving or copying it would be exactly the kind
  of mechanical reshuffling this refactor was told to avoid. Likewise, the
  stateful-security fixture matrix
  (`src/void/internal/engine/stateful_security_fixtures_test.go`) is a genuine
  integration test (real HTTP round trips against an in-process
  `httptest.Server`, real `Fuzzer.sendOne`/oracle/resource-graph code paths)
  but has to stay a Go `_test.go` file colocated with `internal/engine` for
  the same whitebox-access reason unit tests do -- see
  [`docs/architecture/testing.md`](../docs/architecture/testing.md) for the
  full rationale.
- **`tests/e2e/`** — the full instrument → build → verify → grammar → fuzz →
  detect pipeline, end to end, against a real Docker target. The one gate
  this repo currently has is
  [`scripts/e2e/e2e-test.sh`](../scripts/e2e/e2e-test.sh) (against
  `fixtures/planted-bug-api/`) -- referenced here rather than duplicated,
  same reasoning as above.

Every gate above (Go/Python/.NET unit tests, the bin/compile-grammar.sh CLI
regression suite, the compatibility-wrapper smoke tests, the stateful
security fixture matrix, and the full E2E run) is wired into
[`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml).
