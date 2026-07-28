# Changelog

This project did not previously keep a changelog; this file starts with the optimization/modernization
pass below. Entries are grouped by change, newest first. Full detail for the pass below is in
[`docs/optimization-report.md`](docs/optimization-report.md).

## Optimization & modernization pass (2026-07-27)

A verification-first pass across the whole repo (Go engine, two Python packages, two C# tools):
established baseline (build/vet/test/coverage across all three languages), dispatched independent
investigation across each language area plus CI/Docker, then fixed every finding and re-validated.

### Fixed
- **Go**: HTTP response bodies weren't drained to EOF before `Close()` when truncated, defeating
  connection-pool reuse at the engine's stated 1,000+ req/s target (`worker.go`).
- **Go**: `printFinalReport` silently swallowed summary/report/SARIF write errors, so a run could report
  success while never actually persisting its findings (`ui.go`).
- **Go**: the Web UI's stats channel was a single `chan` shared by every connected browser client —
  Go channel semantics meant only one client received any given update; replaced with a proper
  broadcast hub (`webui.go`, `fuzzer.go`, `ui.go`).
- **Go**: `RuntimeStore.customPayloadCandidates` recomputed an identical full map scan 4 times per call;
  a per-request identity-weight slice was reallocated every call instead of reusing a buffer (`store.go`,
  `identity.go`).
- **Go**: removed 4 confirmed-dead functions; simplified a fully-redundant nested `select`/`default` in
  the main scheduling loop; removed 2 no-op `break` statements; extended the shutdown drain deadline to
  match the configured request timeout instead of a shorter fixed constant (`mutation_engine.go`,
  `types.go`, `utils.go`, `worker.go`).
- **C#**: fixed the 2 `CS8632` nullable-context warnings in `dotnet/instrumentor/` (missing
  `<Nullable>enable</Nullable>`); aligned `dotnet/analyzer/`'s target framework from `net9.0` to `net8.0`
  to match the project's stated ".NET 8+" support and the sibling `instrumentor` tool (this also
  resolved a live CI risk — the workflow only installs the .NET 8.0.x SDK); deleted the confirmed-dead
  `Program.Generated.cs`; deduplicated an identical `FlattenNestedTypes` helper defined twice; replaced
  a hand-rolled, incompletely-escaped JSON string concatenation with `JsonSerializer.Serialize`.
- **Python**: eliminated a redundant duplicate schema-field walk in `grammarc/cli.py`; removed a
  redundant directory re-stat in `fuzzprep/coverage_helper_gen.py`; fixed a silently-swallowed file-read
  exception in `fuzzprep/analysis.py`'s namespace detection to log instead; made
  `MultiProjectAnalyzer.exclude_namespaces` a real typed field instead of an externally monkey-patched
  attribute; added an opt-in warning for `grammarc/emit_dict.py`'s external `--dict` parse-failure path;
  deleted 2 confirmed-dead functions; moved 2 function-local imports to module scope.
- **CI**: added the correct `cache-dependency-path` for `actions/setup-go@v5` (the Go module lives at
  `void/go/go.sum`, not the repo root, so the default cache lookup wouldn't find it).

### Added
- `void/go/coverage_bench_test.go`: correctness tests and the first-ever benchmarks for
  `SHMCoverageReader.GetEdges()` — the coverage-bitmap scan the entire scheduling/mutation feedback loop
  depends on, previously untested and unmeasured.
- `void/go/webui_test.go`: regression tests for the Web UI broadcast fix.
- 3 new tests in `grammarc/test_emit_dict.py` for the external-dict warning behavior.
- `docs/optimization-plan.md`, `docs/optimization-report.md`: the plan and full report for this pass.

### Documentation
- `README.md`: added the missing link to `docs/WHITEPAPER.md`.
- `docs/ARCHITECTURE.md`, `dotnet/instrumentor/README.md`: removed references to the deleted
  `Program.Generated.cs`.

No public interfaces, CLI flags, or on-disk/HTTP contracts changed. No dependencies were added or
removed.
