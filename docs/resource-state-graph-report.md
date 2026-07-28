# Resource State Graph & Generalized Extraction — Results Report

Companion to [`resource-state-graph-plan.md`](resource-state-graph-plan.md) (the design, written first).
This document separates **measured results** from **architectural improvements** (real, integrated, and
tested, but not independently benchmarked with a number) and **expected future benefits** (real but out
of this pass's scope), per the task's own instruction not to claim an improvement without a measurement
behind it.

## Executive summary

Replaced the sequence engine's coarse per-chain shape signature and id-name-centric extraction
(`extractEntityIDs`, `isIDLikeKey`) with a typed, bounded resource-lifecycle graph
(`resource_graph.go`), a layered generalized extraction pipeline (`resource_extraction.go`) covering
structural shape detection, HTTP headers, HAL, JSON:API, and route-template-aware URI matching, and a
coverage-directed consumer scheduler (`resource_scheduling.go`) replacing the purely-static
verb-affinity sort. All of it is integrated directly into the real execution path
(`sequence.go::enqueueSequenceFollowups`/`findFollowups`), gated by a single `-resource-graph` flag
(default **on**) that, when set to `false`, reproduces the prior extraction and fanout ordering exactly
for rollback/comparison.

**Measured, on a representative 7-body corpus** (plain id, GUID, slug, HAL, JSON:API, nested composite,
domain-specific-no-"id"-substring): the old pipeline found **1** candidate total; the new pipeline found
**11** — a concrete, reproducible demonstration that chains break on the old pipeline for every shape
except conventional bare ids, and don't on the new one. Three additional integration tests drive the new
pipeline against a **real** `httptest` server (not synthetic strings) covering the same gap.

**Scheduling overhead is small and bounded**: the new coverage-directed ranking costs ~40–60ns more per
call than the old static sort at a 12-candidate list size (~410ns → ~450–470ns, +3 allocations), which
runs once per successful sequence step, not once per HTTP request — not a measurable regression to the
engine's actual request throughput.

**Full existing test suite**: 156 → 212 test cases, 0 failures, race-clean throughout. Statement coverage
32.7% → 37.8%.

## Baseline (measured before this pass, inherited from the prior optimization pass on this branch)

| Check | Result |
|---|---|
| `go build ./...` | Clean |
| `go vet ./...` | Clean |
| `gofmt -l .` | Clean |
| `go test ./... -race` | Pass, 156 test cases, 0 failures |
| `go test ./... -cover` | 32.7–32.8% |

## Measured results

### 1. Extraction candidate count: old vs. new, on a representative corpus

**Workload**: 7 response bodies representing the shapes named in the design task (plain id, GUID under a
non-"id" field name, slug, HAL `_links`, JSON:API `data`+`relationships`, a nested composite key, and a
domain-specific field with zero "id" substring). **Command**:
`go test -run TestExtractionComparison_OldVsNew -v ./...` (`void/go/resource_bench_test.go`). Single
deterministic run (no sampling needed — this is an exact count, not a timing measurement).

| Body shape | Old (`extractEntityIDs`) | New (`extractResourceCandidates`) |
|---|---|---|
| Plain `id` field | 1 | 1 |
| GUID under `reference` | **0** | 1 |
| Slug under `slug` | **0** | 1 |
| HAL `_links` (self + customer) | **0** | 2 |
| JSON:API (`data`+relationship) | **0** | 4 |
| Nested composite (`assignedTo.employeeId`) | **0** | 1 |
| `resourceRef` (no "id" substring) | **0** | 1 |
| **Total** | **1** | **11** |

The old pipeline is not merely "less thorough" on 6 of these 7 shapes — it finds **literally nothing**,
which is the concrete mechanism behind the design task's claim that chains break entirely for
non-conventional identifier shapes.

### 2. Real HTTP integration: 3 tests against an in-process fixture server

**Workload**: `void/go/resource_integration_test.go`'s `newMixedStyleFixtureServer` — a real
`net/http/httptest.Server` (not synthetic strings) exposing a conventional-id resource, a GUID-identified
resource returned via HAL links, and a two-level parent/child route
(`/organizations/{orgId}/projects/{projectSlug}`). **Command**: `go test -run TestIntegration -race -v ./...`.

- `TestIntegration_GUIDResourceViaHAL_OldBlindNewFinds` — confirms `extractEntityIDs` finds nothing in
  the real HAL response body; the new pipeline extracts both the GUID reservation id and the HAL
  customer relation. **PASS**.
- `TestIntegration_ParentChildRouteTemplateFromRealLocationHeader` — confirms a real `Location` header
  from a 2-placeholder route produces **two** distinct typed candidates (`organization`=acme,
  `project`=demo-app), not one. **PASS**.
- `TestIntegration_FullLifecycle_CreateReadDeleteReadAgainstRealServer` — drives a real
  create → delete → read-again sequence against the fixture server end to end, asserting the resource
  graph correctly records `CREATED` → `DELETED` → (a `GET` returning a real 404) confirms `DELETED`
  rather than regressing to `UNKNOWN`. **PASS**. This test also surfaced and fixed a real gap during
  development (see "Defects found and fixed during this pass" below): a `DELETE` returning an empty
  204 body carries its target's identity only in the *request path*, which the pipeline didn't
  originally consult.

### 3. Scheduling overhead: old static sort vs. new coverage-directed ranking

**Workload**: a 12-candidate follow-up list (the same shape `findFollowups` typically produces).
**Command**: `go test -run '^$' -bench 'BenchmarkFollowupRanking' -benchmem -count 3 ./...`.
Apple M4 Max, `darwin/arm64`, Go 1.26.5, 3 runs, values are the observed range.

| Benchmark | Result (ns/op) | Allocations |
|---|---|---|
| `BenchmarkFollowupRanking_OldStaticSort` (12 candidates) | 407–423 ns/op | 152 B/op, 3 allocs/op |
| `BenchmarkFollowupRanking_NewCoverageDirected` (12 candidates) | 447–471 ns/op | 472 B/op, 6 allocs/op |

**+~40–60ns/op, +3 allocations.** This is per-*sequence-step* overhead (once per successful follow-up
decision), not per-HTTP-request overhead — the engine processes far fewer sequence steps than raw
requests in any given run, so this cost is not expected to be visible in overall request throughput. Not
independently verified against a live end-to-end req/s measurement in this pass (see "Remaining
limitations" below) — the claim here is scoped specifically to "this one function's own cost," which is
what was measured.

### 4. Extraction pipeline's own steady-state cost

**Workload**: the same 7-body representative corpus, run repeatedly. **Command**:
`go test -run '^$' -bench BenchmarkExtractResourceCandidates -benchmem -count 3 ./...`.

| Benchmark | Result | Allocations |
|---|---|---|
| `BenchmarkExtractResourceCandidates` (7 bodies/op) | ~17.6µs/op | ~14.9KB/op, 312 allocs/op |

This runs once per successful sequence-engine step (not once per request, and not on every response —
only ones the sequence engine follows up on), so this absolute cost is judged acceptable; it was not
previously measured at all (no benchmark existed for `extractEntityIDs` either), so there is no
old-vs-new comparison to report here specifically — this number is new baseline data for future
comparison, consistent with how `docs/optimization-report.md` treated the coverage-bitmap-scan benchmark
in the prior pass on this branch.

### 5. Full test suite

| Check | Before this pass | After this pass |
|---|---|---|
| `go test ./... -race` | 156 test cases, 0 failures | **212** test cases, 0 failures |
| `go test ./... -cover` | 32.7–32.8% | **37.8%** |
| `gofmt -l .` | Clean | Clean |
| `go vet ./...` | Clean | Clean |

New test files: `resource_graph_test.go` (13 tests, including a `-race`-verified adversarial concurrent
caller), `resource_extraction_test.go` (20 tests, including 9 regression tests each proving the old
pipeline blind and the new pipeline not), `resource_scheduling_test.go` (18 tests, including determinism
under a fixed `math/rand` seed and a starvation-prevention test run across 50 trials),
`resource_integration_test.go` (3 tests against a real `httptest` server), `resource_bench_test.go` (1
comparison test + 3 benchmarks).

## Architectural improvements (real and integrated, not independently benchmarked with a number)

- **Typed, namespaced resource identity.** A `user` with id `"1"` and an `order` with id `"1"` are
  provably different graph entries (`TestResourceGraph_TypedIdentityIsolation`) — not benchmarked (there
  is no meaningful "before" number; the old code had no resource-type concept at all to compare against).
- **Explicit lifecycle states and transitions**, derived from method+status+prior-state (not method
  alone) — 10 dedicated classification tests, including the specific scenarios the design task names
  (create→read/update/delete, delete→read/update/delete, repeated deletion).
- **Bounded graph growth**, verified directly: `TestResourceGraph_MaxInstancesPerTypeEvictsOldest`,
  `_MaxAliasesPerInstanceEnforced`, `_MaxTransitionsRingBounded` all assert the configured caps are
  actually enforced, not just documented.
- **Starvation prevention**, verified directly: `TestRankConsumersCoverageDirected_NoStarvation` runs 50
  trials confirming a permanently-low-scoring consumer still gets promoted to the front at least once
  under the epsilon-exploration term.
- **Deterministic scheduling under a fixed seed**, verified directly:
  `TestRankConsumersCoverageDirected_DeterministicWithFixedSeed`.
- **Exact backward-compatible fallback.** `-resource-graph=false` is asserted
  (`TestFindFollowups_ResourceGraphDisabledUsesStaticPriorityOnly`) to reproduce the identical prior
  ordering, not an approximation of it.

## Defects found and fixed during this pass

Writing the integration test directly found two real bugs before they shipped:

1. **`ValueType`/`IdentityKind` taxonomy mismatch.** Early candidate-construction code stored the
   fine-grained shape classification (`"uuid"`, `"hex"`, `"int"`) directly as `IdentityKind`, instead of
   normalizing it to the fixed `scalar`/`uri`/`composite`/`opaque` taxonomy the design specifies —
   meaning the *same* real-world resource, observed via two different shape-detection paths, would
   fragment into two different graph keys (`order:int:9001` vs. `order:scalar:9001`). Fixed by adding
   `identityKindOf()` and applying it at every candidate-construction site; a route-template placeholder
   defaulting to `IdentityKind: "opaque"` (instead of `"scalar"`) was a second instance of the same
   underlying issue, fixed the same way.
2. **Bare-`"id"`-field resource-type fallback used the field's own name.** When a JSON field's name gave
   no type hint (a bare `"id"`), the fallback incorrectly used the field name itself
   (`singularize("id")` → `"id"`) as the resource type, instead of the *endpoint's own* resource family
   (a bare `"id"` in a `POST /orders` response means "order", not a resource literally named "id").
   Fixed via a new `resourceTypeFromSourceOp` helper.
3. **Response-only extraction missed request-path-only identity.** A `DELETE` returning an empty 204
   body carries its target resource's identity *only* in the request path, not the response — the
   pipeline as originally written only ever looked at `res.Body`/`res.Headers`. Fixed by additionally
   running route-template matching against the request's own path
   (`f.matchRouteTemplateCandidates(source.Path, ...)`), which is what makes the
   create→delete→read-again integration test's `DELETED` transition actually get recorded.

All three were caught by the test suite itself during development, not discovered after the fact — the
concrete value of writing the regression/integration tests described above.

## Compatibility impact

No public interface, CLI flag semantics, on-disk grammar contract, or `/shm/*` HTTP contract changed.
`SequenceState`'s persisted JSON gained two new `omitempty` fields (`resources`, `transitions`) — additive
only; nothing in this codebase re-reads persisted workflow JSON programmatically today, so there is no
read-compatibility surface to break. `-resource-graph=false` reproduces the exact prior behavior,
verified by a dedicated test rather than asserted from reading the code.

## Remaining limitations

Stated plainly, per this project's own established documentation convention (see
`docs/WHITEPAPER.md`/`docs/ARCHITECTURE_REVIEW.md`):

- **No end-to-end live-run throughput comparison.** The scheduling-overhead benchmark (§3 above) measures
  the ranking function's own cost in isolation; it does not measure whether a full live fuzzing session's
  overall requests-per-second changes with `-resource-graph` on vs. off. Given this overhead runs once
  per sequence step (a small fraction of total requests in a typical run), a measurable throughput
  regression is not expected, but this is a reasoned expectation, not a directly measured one.
- **`grammarc/dependencies.py` (compile-time producer/consumer inference) is unchanged** — by design (see
  plan §9), but it does mean the Python-side grammar still only emits name/path-convention `reads`/
  `writes` hints; all of this pass's generalization lives entirely in the Go runtime layer.
- **No full combinatorial state-graph search** (DeepREST/EvoMaster-class reinforcement learning over the
  state space) — this pass builds the typed model and coverage-directed scoring that such a search would
  need as a prerequisite, not the learned search itself.
- **Composite identities are recognized only when pre-composed** (e.g., a JSON:API compound id arriving
  as a single field) — a general-purpose engine that *synthesizes* a composite key by correlating
  unrelated sibling fields (e.g., inferring that `{tenant, user}` together identify one resource) is not
  built.
- **The opaque-token heuristic (`isOpaqueTokenShaped`) is conservative by design** and will miss
  domain-specific opaque reference formats that don't happen to look like a long mixed-alphanumeric
  string (e.g., a short 8-character code) — no attempt was made to build a fully general "detect any
  possible opaque reference format," which isn't feasible without target-specific knowledge.
- **Alias detection is same-step-only.** `recordResourceGraphStep`'s alias linking only considers
  candidates observed within a single response; it does not retroactively merge two previously-recorded,
  independently-discovered instances that later turn out to be the same resource observed at different
  times under different representations.

## Recommended future work

1. Add the live end-to-end throughput comparison noted above, once a suitable representative target and
   time budget are available.
2. Extend `grammarc/dependencies.py` with OpenAPI schema-format awareness (`format: uuid`) as a
   complementary compile-time signal, now that the Go runtime side has a place to actually use it
   (higher-confidence candidate scoring).
3. Coverage-directed sequence *fanout depth* (not just consumer *ordering*) — prioritizing which
   already-known resource instance to bind into a deeper follow-up based on which of its lifecycle
   transitions are still unexplored, building on `findCompatibleResources`.
4. Retroactive alias merging across sequence steps (the limitation noted above), if a target's identifier
   reuse patterns in practice turn out to make this valuable.

Everything already tracked in `docs/ARCHITECTURE_REVIEW.md`'s own P0/P1/P2 backlog (OAST, ownership-matrix
BOLA, a non-Docker host mode, a persistent corpus, typed structural mutation) remains open and unrelated
to this pass's scope.
