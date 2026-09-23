# Stateful API Fuzzing Architecture

Companion to [ARCHITECTURE.md](overview.md) (the pipeline as a whole),
[ARCHITECTURE_ENGINE.md](engine.md) (the fuzzing runtime, including the
resource-graph component map itself), and
[resource-state-graph-plan.md](../research/design-notes/resource-state-graph-plan.md)/
[resource-state-graph-report.md](../research/design-notes/resource-state-graph-report.md) (the design and
measured results of the resource graph specifically). This document is the map from
the target 5-stage stateful-fuzzing architecture onto **actual code in this repo**,
file by file — what already exists, what this pass added, and what's still open. It
exists so "does the engine do X" has one place to check instead of re-deriving it
from source every time.

**→ [Back to README](../../README.md) · [ARCHITECTURE.md](overview.md) · [ARCHITECTURE_ENGINE.md](engine.md) · [Docs Index](../index.md)**

---

## 1. The target pipeline

```
OpenAPI + source + runtime observations
              ↓
      Stateful API model
              ↓
 Valid workflow planner / executor
              ↓
 Adversarial branch generator
              ↓
 Oracles → repro → minimize → report
```

**The hard rule this architecture is built around: valid-workflow construction and
attack-branch generation never mix.** The engine first builds a correct business
chain with real IDs, tokens, tenant context, and lifecycle state; only *then* does it
create a minimally-different attacking branch from that already-confirmed-valid
chain. Sending a stranger's `taskId` cold almost always yields an ordinary 404/400 —
weak, ambiguous signal. Reusing a resource `A` genuinely created, then having a
*different* identity `B` operate on that exact resource and getting 200, is strong,
explainable evidence of BOLA. This is why the resource graph, the extraction
pipeline, and the tenant-aware substitution logic below all exist: they're the
infrastructure that makes "the resource is real and A created it" a fact the engine
can actually check, not an assumption.

## 2. Stage-by-stage: design vs. implementation

### 2.1 OpenAPI + source + runtime observations → typed candidates

| Source | Module | Status |
|---|---|---|
| OpenAPI spec | `tools/grammar/grammarc/` (Python, compile-time) | Implemented — compiles the spec into typed request templates, `reads`/`writes` producer/consumer hints by path/name convention |
| C# source (Roslyn) | `tools/dotnet/analyzer/` | Implemented — `roslyn-constraints.json`: DataAnnotations, FluentValidation rules, route/auth attributes. **Not yet consumed for lifecycle/state-machine inference** (see §2.3) |
| JSON body (structural, by value shape not field name) | `src/void/internal/engine/resource_extraction.go::extractStructuralCandidates` | Implemented |
| `Location`/`Content-Location`/`Link` headers | `resource_extraction.go::extractHeaderCandidates` | Implemented |
| HAL `_links` | `resource_extraction.go::extractHALCandidates` | Implemented |
| JSON:API `data`/`relationships` | `resource_extraction.go::extractJSONAPICandidates` | Implemented |
| Route-template-aware URI matching (multi-segment parent/child) | `resource_extraction.go::matchRouteTemplateCandidates` | Implemented |
| `Set-Cookie` | `resource_extraction.go::extractCookieCandidates` | Implemented |
| Request/response URL query parameters (async-operation poll ids) | `resource_extraction.go::extractQueryParamCandidates` | Implemented |
| Request's own path (not just response) | `sequence.go::recordResourceGraphStep` | Implemented — needed for e.g. a `DELETE` returning empty 204, whose target id only lives in the request path |

Every candidate carries **provenance and a confidence score**
(`ExtractedCandidate{Strategy, JSONPath/HeaderName/LinkRelation, Confidence}`) — no
signal is silently trusted as "this is an id." See `docs/research/design-notes/resource-state-graph-report.md`
§"Measured results" for the concrete old-vs-new extraction-coverage numbers.

### 2.2 Stateful API model — the typed resource record

Target shape (from the task spec):

```json
{
  "type": "project", "id": "prj-42",
  "parent": {"type": "organization", "id": "org-7"},
  "owner_identity": "tenant-a-admin",
  "created_by": "POST /organizations/org-7/projects",
  "state": "created", "version": "\"etag-3\"",
  "attributes": {"status": "draft"}, "confidence": 0.95
}
```

Implementation: `src/void/internal/engine/resource_graph.go::ResourceInstance`.

| Field | Struct field | Notes |
|---|---|---|
| type + id | `ResourceType` + `Canonical.RawValue` | |
| parent relationship | `ParentKey` | compound `ResourceType|NormalizedValue` key, not a nested object — same compound-key convention this codebase already uses elsewhere (`graphKey()`) |
| tenant relationship | `TenantKey` | root ancestor's graph key, resolved by walking `ParentKey` (`resolveTenantKey`) — distinct from `ParentKey` once a chain is >1 level deep |
| owner identity | `OwnerIdentity` | first-writer-wins: a later cross-identity read never relabels who created it |
| created_by | `SourceOperation` | `"METHOD /norm/path"` |
| lifecycle state | `Lifecycle` (`LifecycleState`) | derived from method+status+prior-state, never method alone (`deriveLifecycleTransition`, `resource_scheduling.go`) |
| version/ETag | `Version` | from the `ETag` response header |
| attributes | `Attributes` | bounded (≤8 fields), sorted-key-deterministic snapshot of top-level scalar response fields |
| confidence | `Confidence` | |
| lifetime/validity | `ObservedCount`, `LastSeenOrder` | logical-clock-based (deterministic under `-seed`), not wall-clock — this engine has no wall-clock TTL concept anywhere, by design |

Bounded growth (`ResourceGraphLimits`: max instances/type, max aliases/instance, max
transitions), verified directly by test, not just documented.

### 2.3 Lifecycle and business transitions

Implemented: `resource_graph.go::ResourceTransition` (`From`, `To`, `ProducerOp`,
`ConsumerOp`, `Result: "valid"|"invalid"|"unknown"`), derived by
`resource_scheduling.go::deriveLifecycleTransition` from method+status+prior-state.

Transitions are now also typed by a *named business action*, not just lifecycle
state: `ResourceTransition.Action` (`resource_graph.go`) and its
`TransitionLabel()` renderer produce exactly the target format
(`invoice:READABLE --pay--> invoice:MODIFIED`). `POST /orders/{id}/approve` and
`POST /orders/{id}/refund` are now distinguishable by `Action`, not just both
generic `MODIFIED`.

**Transition-source priority chain** (`resource_scheduling.go::deriveTransitionActionForTemplate`):

| Tier | Source | Status |
|---|---|---|
| 1 | Explicit `x-state-transition` OpenAPI vendor extension | Implemented — `tools/grammar/grammarc/oas.py::parse_x_state_transition` (object form `{"from","to","action"}` or string shorthand `"from->action->to"`), passed through `emit_templates.py` into `Template.XStateTransition`. Real-world specs essentially never declare this (not a standardized extension) — support exists for when they do, not expected to fire often against real targets. |
| 2 | Source-code signal | Implemented, narrower than the original design's "enum/status fields, state-machine handlers" — uses the C# controller action *method name* Roslyn already extracts (`tools/dotnet/analyzer/`'s `EndpointInfo.Action`, matched via `tools/grammar/grammarc/roslyn_merge.py::RoslynIndex.endpoint_for_operation`), filtered to exclude generic ASP.NET boilerplate names (`Get`, `Post`, `Index`, ...) that carry no more signal than Tier 4. Full state-machine/enum-field static analysis is **not** implemented. |
| 3 | Runtime observation | Collapsed into Tier 4 in this implementation — there is no separate historical action-name store to consult; the live request/method/path *is* what Tier 4 classifies. |
| 4 | Heuristic fallback | Implemented — `deriveTransitionAction`: a REST action-verb vocabulary (`approve`, `refund`, `restore`, ...) matched against the request's trailing path segment, falling back to a generic method-derived action (`create`/`read`/`update`/`delete`). |

Novelty detection (`ResourceTransition.signature()`) deliberately stays keyed on
`ConsumerOp` (the full method+path, which already embeds any action-suffix segment)
rather than `Action` — `Action` is an additive, more-readable label for reporting,
not a replacement for the existing novelty granularity.

### 2.4 Valid workflow planner vs. adversarial branch planner

**Valid-chain construction** (`sequence.go`):
- `findFollowups`/`followupPriority` — dependency-based next-endpoint selection (static verb-affinity table, one input among several)
- `resource_scheduling.go::scoreConsumer`/`rankConsumersCoverageDirected` — coverage-directed scoring: historical edge yield (`f.endpointStats[...].NewEdges`), "never reached" bonus, "repeated failure" penalty, bounded epsilon-exploration so a low scorer is never *permanently* starved
- `sequence.go::pickFollowupPathValue` — **the actual value-binding mechanism**: prefers a resource-graph-tracked, tenant-scoped, still-alive instance of the consumer's expected type over the old first-hit extraction; this is the fix that makes real producer→consumer ID chains happen at all (see `resource-state-graph-report.md`'s "Follow-up pass" section)
- `SequenceState.TenantKey` — sticky per-chain tenant scope, adopted once the chain reaches a resource with a resolved `TenantKey`; `pickFollowupPathValue`/`findCompatibleResourcesInTenant` refuse to substitute a same-typed resource from a *different* tenant into a valid chain
- `pagination.go::maybeEnqueuePaginationFollowup` — a paginated list response continues with a follow-up to the SAME endpoint's next page (cursor/next-page field or Link `rel="next"`), a shape `findFollowups` structurally excludes (its same-family fallback skips a template following up on its own exact method+path) and so needed its own direct mechanism

**Nested body-field binding** (`body_bind.go`, added 2026-07-31) extends this exact
tenant-scoping discipline from path parameters to *nested request-body fields* — a body
leaf shaped like an id (`customerId`, `organizationId`, …) resolves through a path-qualified
`RuntimeStore` lookup, then `findCompatibleResourcesInTenant` (the same call
`pickFollowupPathValue` already uses), then the flat dictionary pool, in that order; a chain
scoped to one tenant never binds another tenant's id into a nested body field either. See
[`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md).

`scoreConsumer` (`resource_scheduling.go`) also now includes two of the design's
remaining scoring terms: **success probability** (a candidate's own historical 2xx
rate, `f.endpointStats[...].S2xx/Reqs`, weighted by `-resource-graph-success-prob-weight`)
and **lifecycle-state satisfiability** (a bonus, `-resource-graph-availability-weight`,
when a resource instance of the candidate's expected type is actually available right
now, tenant-scoped via `findCompatibleResourcesInTenant` — a candidate that
structurally cannot succeed no longer ties with one that can). Both default-on,
both independently disable via weight `0`.

**Gap**: there is no single, separately-named "valid workflow planner" component —
the pieces above jointly perform that role, spread across `sequence.go`/
`resource_scheduling.go`. Formalizing them into one explicit planner type is open
work, as is the one still-missing scoring term: explicit **identity compatibility**
(does the currently-acting identity have any track record of succeeding at this
consumer at all) — this would need a new per-identity-per-endpoint outcome store this
engine doesn't have yet, unlike the other terms which all reuse existing tracking.

**Adversarial branch generation** (`adversarial.go`, new): three oracles, each
requiring a resource the graph has ALREADY confirmed is real before firing —
distinct from `oracle.go`'s pre-existing BOLA/mass-assignment/differential
probes, which replay the *current* request under a different identity/no-auth/
parser-confusion variant rather than starting from confirmed resource-graph
state:
- **Stale object** — direct detection, no replay needed: `recordResourceGraphStep`
  (`sequence.go`) already classifies a request against a known-deleted resource as
  `LifecycleStale`/`LifecycleInvalidated`/repeated-`LifecycleDeleted`
  (`deriveLifecycleTransition`) — `recordStaleObjectFinding` turns that
  classification directly into a finding the moment it happens.
- **Stale ETag** — active probe (`maybeEnqueueStaleETagProbe`): replays a
  just-succeeded write against a resource with a known `Version` (ETag), but with
  a deliberately wrong `If-Match`; accepted (2xx) instead of rejected
  (409/412/428) means optimistic locking isn't enforced.
- **Workflow bypass** — direct detection, Tier-1-gated: when an action endpoint
  declares `x-state-transition` (§2.3's Tier 1), `recordResourceGraphStep` compares
  the target resource's own `Attributes["status"]` against the declared
  predecessor; a mismatch that still succeeded means the required predecessor
  state was skipped. Deliberately narrow — real specs rarely declare
  `x-state-transition`, so this rarely fires without one; a general-purpose
  version that infers the required predecessor without an explicit annotation is
  explicitly out of scope for this pass (see `adversarial.go`'s own doc comment).

All three share one dedup → finding pipeline (`recordAdversarialFinding`,
mirroring `oracle.go::recordAccessControlFinding`'s existing shape) and are
independently toggleable (`-probe-stale-object`, `-probe-stale-etag`,
`-probe-workflow-bypass`, all under the existing `-access-probe` master gate).

**Still open**: `identity.go::enqueueRaceBurst` (generic conflict bursts) hasn't
been folded into this same "confirmed-resource-first" model, and duplicate-
idempotency-key / parallel-execution / foreign-parent modifications aren't
implemented at all yet (Phase 4 — races/idempotency).

### 2.5 Security scenario families: implemented vs. open

| Family | Status | Where |
|---|---|---|
| BOLA/IDOR (read/update/delete) | Implemented | `oracle.go::maybeEnqueueAccessProbes`, `recordAccessControlFinding` |
| Mass assignment | Implemented, valid-chain-gated | `oracle.go::maybeEnqueueMassAssignProbe` + `adversarial.go::requestPathHasConfirmedContext` |
| Auth confusion (verb/content-type/route-case/param-location) | Implemented | `oracle.go::maybeEnqueueDifferentialProbes` |
| Injection (SQLi, time-based) | Implemented | `oracle.go::checkInjectionOracle` |
| Races (burst-based + outcome oracle) | Implemented | `identity.go::enqueueRaceBurst` (broadened keyword set) + `race.go::recordRaceBurstResult` (flags >1 success among N concurrent identical requests) |
| Tenant escape (child of tenant A under parent tenant B) | Partially — the resource graph can now *detect* this shape (`TenantKey`), but no dedicated oracle actively probes for it yet | — |
| Stale/deleted-object testing (`DELETE` → `GET`/`PUT`/action) | Implemented | `adversarial.go::recordStaleObjectFinding` |
| Optimistic locking (stale/missing ETag) | Implemented | `adversarial.go::maybeEnqueueStaleETagProbe` |
| Idempotency (replay create/payment/refund) | Implemented | `idempotency.go::maybeEnqueueIdempotencyReplayProbe` |
| Workflow/state bypass (approve without required predecessor state) | Implemented, Tier-1-gated (rarely fires without an `x-state-transition`-annotated spec) | `adversarial.go::recordWorkflowBypassFinding` |
| Async workflows (submit → poll → consume/cancel/retry) | Implemented, poll-bias only (no explicit "consume" step type) | `async.go` + `resource_scheduling.go::scoreConsumer`'s `asyncPollBonus` |

### 2.6 Reward signal

Implemented terms (`sequence.go`/`worker.go`): per-request coverage delta
(`Energy += CoverageDelta`), workflow-shape novelty (`stateNoveltyBonus`), a
fanout-width search-budget bonus for reaching a never-seen `(from, to, consumerOp)`
resource transition, **and now also a direct Energy bonus for that same transition
novelty** (`transitionNoveltyBonus`, raising the chain's long-term corpus-retention
priority, not just this step's exploration breadth), **and a `valid_chain_depth`
term** (`maxChainDepthBonus`/`nextChainDepthAndEnergy`): a "personal best" bonus the
first time a run reaches a new maximum sequence-chain depth. **Not yet implemented**:
`producer_consumer_binding_quality`, `cross_identity_novelty`, or an
`oracle_signal`/`repeated_4xx_penalty` term feeding back into the *same* composite
score — today's coverage/sequence reward and the oracle-finding logic are separate
systems that don't share a unified reward function.

### 2.7 Reproducibility

- **Chain trace**: `WorkItem.Trace []TraceStep` (`identity.go`), attached to every
  built item, now carries `Method`, `Path`, `Mutation`, `Identity` (known at
  build time), and `Status` (patched in once the response is known —
  `patchTraceStatus`, called from `handleResult`). Deliberately does **not** carry
  full per-step request/response headers/bodies (cost concern: this trace exists on
  every item the engine sends, not just crashes) — full detail for the one request
  that actually crashed lives in `CrashFinding` (`RequestHeads`, `Response`,
  `Exception`, `AuthContext`, `CurlCommand`, `Repro`, `Minimized`) instead.
- **Producer→consumer bindings**: `sequence.go::ProducerConsumerBinding` — an
  explicit, typed, bounded log of "this request field was bound to this value,
  extracted from this producer response field" events, recorded at the primary
  path-substitution site (`pickFollowupPathValue`'s call site in
  `enqueueSequenceFollowups`). **Not yet extended** to the body/query-field bias path
  (`store.go::graphBiasedPayloadCandidates`) — documented as an explicit scope note
  in that function.
- **Minimization**: `minimize.go` — `minimizeCrashCandidate` shrinks the single
  crash-triggering request's own fields (query/form/JSON/path). `minimizeChainCandidate`
  (Phase 5 #126) is the complementary whole-chain pass: for a crash reached through a
  multi-step `SequenceState.History`, it walks the earlier steps backward and greedily
  drops each one, keeping the drop only if replaying the resulting shorter chain (each
  remaining step resent verbatim via its own already-captured `Method`/`Path`/`Headers`/
  `Body`) still ends in a ≥500 on the final step. Gated by `-minimize-chain` (default
  `true`, requires `-minimize-crash`) and shares `-minimize-max-probes` as its own probe
  budget, separate from the field-minimizer's own budget spent earlier in the same crash
  path (`crash.go`). Deliberately does **not** re-derive producer→consumer bindings for
  the shrunk chain — a dropped step's produced value is not re-substituted into later
  steps, which still replay with whatever value they originally captured; stated as a
  known limitation in the function's own doc comment rather than built around, since
  every replayed step is an exact resend of what was actually sent, not a re-planned
  chain.
- **Run manifest** (Phase 5 #127, `manifest.go`): `buildRunManifest()` assembles a
  reproducibility manifest — run_id, seed, profile, target host, grammar dir, the
  exported templates JSON path plus a **locally verifiable** SHA-256 of its actual
  content (`Fuzzer.templatesHash`, computed once in `NewFuzzer` from the exact file
  bytes this run loaded), and started/generated timestamps — surfaced under
  `run_manifest` in the JSON report (`report.go`) and under `runs[0].properties.
  run_manifest` in SARIF (`sarif.go`), so a SARIF-only consumer doesn't lose it.
  Also carries three **pass-through-only** provenance labels void cannot itself
  verify — `target_image_digest`, `openapi_spec_hash`, `campaign_config`
  (new `-target-image-digest`/`-openapi-spec-hash`/`-campaign-config` flags,
  `Config`) — honestly distinguished in the function's own doc comment from the
  locally-hashed templates field, since void has no way to independently confirm a
  running container's digest or the document a grammar was generated from.
- **Chain-level trace in reports**: `CrashFinding` (`identity.go`) gained
  `SequenceID`/`ChainTrace []SequenceStep` (via `cloneChainTrace`, a defensive copy
  so the finding doesn't alias the live `SequenceState`'s backing slice), populated
  in `crash.go` from `pocItem.SeqState` **after** whole-chain minimization runs — so
  a sequence-originated bug's report/SARIF entry shows the already-shrunk chain, not
  the original. Surfaced as `bugs[].chain` (method/path/status/coverage_delta/
  mutation_label per step) in the JSON report and `results[].properties.chain` in
  SARIF; both are the JSON literal `null`/absent for any non-sequence finding, not
  an empty object (a `map[string]any` boxed into an `any` field is a classic Go
  typed-nil-in-interface trap here — worked around by declaring the holder as plain
  `any` and only ever assigning it a real map, never a nil-but-typed one).
- **Checkpoint/resume**: implemented (`checkpoint.go`) — `-checkpoint-path` periodically
  (`-checkpoint-interval-sec`, default 60s) and on graceful exit snapshots the corpus
  and full resource graph (instances + transitions, `ResourceGraph.exportAll`/`importAll`)
  to a single JSON file; `-resume` loads it back at startup instead of a fresh baseline
  corpus. Deliberately excludes `f.seenStateSigs`/endpoint stats/coverage bitmap state
  (cheap to rebuild or deliberately run-scoped — see `checkpoint.go`'s own doc comment).
  Fixed a real latent bug found while wiring this: `LifecycleState` had `MarshalJSON`
  but no `UnmarshalJSON`, so it never actually round-tripped through JSON anywhere
  (including `persistWorkflow`'s existing `resources`/`transitions` output) — now fixed.

## 3. What this pass added, concretely

This is the file-level summary of the Phase 1 work landed in this pass (see git log
for the actual commits):

- `resource_graph.go`: `ResourceInstance.{TenantKey, OwnerIdentity, Version, Attributes}`,
  `resolveTenantKey`, `findCompatibleResourcesInTenant`, `RecordInstanceOpts`.
- `resource_extraction.go`: `extractCookieCandidates`, `extractQueryParamCandidates`,
  `extractVersionHeader`, `extractTopLevelAttributes`.
- `sequence.go`: `SequenceState.TenantKey` (sticky per-chain tenant scope),
  `ProducerConsumerBinding` + `recordProducerConsumerBinding`, `pickFollowupPathValue`
  now tenant-scoped and returns the source `*ResourceInstance` for binding records.
- `identity.go`/`worker.go`: `TraceStep.{Identity, Status}`, `patchTraceStatus`.
- `poc.go`: PoC script comments and the exploit-timeline mermaid diagram now show
  each intermediate step's real identity and status instead of a generic
  `success/transition` placeholder.
- `resource_graph.go`: `ResourceTransition.Action` + `TransitionLabel()`.
- `resource_scheduling.go`: `deriveTransitionAction` (path/method heuristic),
  `deriveTransitionActionForTemplate` (full Tier 1→4 priority chain),
  `isGenericRoslynActionName`.
- `tools/grammar/grammarc/oas.py`: `Operation.x_state_transition` + `parse_x_state_transition`.
- `tools/grammar/grammarc/emit_templates.py`: emits `x_state_transition`/`roslyn_action` onto
  compiled templates when available.
- `types.go`: `Template`/`TemplateMeta` gained `XStateTransition`/`RoslynAction`;
  `Config` gained `ResourceGraphSuccessProbWeight`/`ResourceGraphAvailabilityWeight`.
- `resource_scheduling.go`: `scoreConsumer`/`rankConsumersCoverageDirected`/
  `findFollowups` are now tenant-scoped end to end and score two more valid-workflow-
  planner terms (success probability, resource availability).
- `checkpoint.go` (new): `SaveCheckpoint`/`LoadCheckpoint`/`maybeSaveCheckpoint` --
  corpus + resource-graph checkpoint/resume, wired into `fuzzer.go::Run()` and
  `worker.go::mainLoop()`.
- `resource_graph.go`: `LifecycleState.UnmarshalJSON` (was write-only before --
  never actually round-tripped through JSON), `ResourceGraph.exportAll`/`importAll`.
- `adversarial.go` (new): the adversarial branch planner -- stale-object (direct
  detection), stale-ETag (active probe), workflow-bypass (direct detection,
  Tier-1-gated) oracles, sharing `recordAdversarialFinding`. Wired into
  `sequence.go::recordResourceGraphStep` (stale-object, workflow-bypass) and
  `worker.go::handleResult`/`oracle.go::handleOracleResult` (stale-ETag). Also
  `requestPathHasConfirmedContext`, reused by `oracle.go::maybeEnqueueMassAssignProbe`
  to valid-chain-gate mass assignment (Phase 3 #117).
- `idempotency.go` (new): idempotency-replay oracle -- verbatim POST replay,
  flags a second/different created id as non-idempotent processing.
- `race.go` (new): race-burst outcome oracle -- `WorkItem.BurstID`/`BurstSize`/
  `BurstAction` (types.go) tag every member of one `enqueueRaceBurst` group;
  `recordRaceBurstResult` flags more than one success among N concurrent
  identical requests. `identity.go::isRaceCandidatePath` also broadened beyond
  the original commerce-cart keyword set to approve/cancel/redeem/withdraw/
  transfer/refund/reject/accept/confirm.
- `async.go` (new): async-operation model -- `isAsyncSubmission` (202, or any
  2xx with `Retry-After`) tags a resource `Attributes["async_submitted"]` in
  `sequence.go::recordResourceGraphStep`; `isAsyncOperationPending`/
  `isAsyncTerminalStatusValue` let `scoreConsumer` bias GET follow-ups toward
  finishing an in-flight poll (`asyncPollBonus`) rather than treating a
  pending job like an ordinary resolved resource. No separate "consume" step
  type -- once terminal, the operation just stops earning the poll bonus and
  ordinary follow-up scoring takes back over (its own result fields, e.g. a
  download URL, are picked up by the pre-existing generic extraction
  pipeline, not a new dedicated mechanism).
- `multipart_chain.go` (new): multipart upload→process→download chain
  modeling -- `isMultipartUpload` (checks `TemplateMeta.ContentType`) tags a
  just-created resource `Attributes["source_multipart"]`; `scoreConsumer`
  biases a download/export-shaped GET candidate (`looksLikeDownloadEndpoint`)
  toward it (`multipartDownloadBonus`). `knownTransitionActionVerbs`
  (resource_scheduling.go) also gained process/scan/convert/transcode/validate
  so a "process" step between upload and download gets a proper `Action` name
  instead of falling through to the generic CRUD fallback.
  **Found and fixed a real pre-existing bug while wiring this**:
  `resourceTypeFromEndpointPath` inferred the resource type from an endpoint's
  LAST path segment unconditionally, so an action-suffixed endpoint like
  `/files/{id}/download` inferred "download" instead of "file" -- silently
  breaking every resource-graph lookup keyed off that endpoint's own inferred
  type (availability/poll/download-bonus scoring, workflow-bypass detection)
  for ANY action-verb-suffixed path, not just this feature's own new
  download-bonus check. Fixed to prefer the preceding segment when the last
  one is a known action verb. Also surfaced (and fixed) a second bug in
  `recordResourceGraphStep`: once that fix made two candidates within one step
  correctly agree on the same resource, the second candidate's "prior state"
  read observed the first candidate's own already-applied update instead of
  the true prior state, both misreporting a workflow-bypass violation's
  `actual_state` and double-firing the finding -- fixed with a per-step
  first-candidate-only guard on the finding-emitting checks.
- `webhook.go` (new): webhook/event callback lifecycle modeling. Honest scope
  note: this engine sends HTTP requests and has no inbound listener, so
  genuinely observing "did the target actually fire a callback" is out of
  scope (a listener is a materially different, riskier feature than anything
  else added this session) -- SSRF-style probing of the webhook URL field
  itself was already covered before this pass (`mutations.go`'s SSRF
  payloads, `identity.go::exploitationSignals`'s `ssrf_metadata_reflected`
  marker). What's implemented: `isSoftDisabledAttributes` recognizes a
  resource explicitly turned off via `active:false`/`enabled:false` (the
  convention webhook/subscription APIs commonly use instead of DELETE);
  `recordDisabledResourceStillActiveFinding` fires when a trigger-shaped
  action (`webhookTriggerActionVerbs`: trigger/fire/execute/invoke/notify/
  test/run) succeeds against a resource in that state anyway -- the same bug
  class as #114's stale-object oracle, reached through a non-DELETE lifecycle
  path #114 alone can't see.
- `campaign.py` + `docs/guides/campaigns.md` + `campaign.yaml.example` (new, Python):
  the `campaign.yaml` contract -- declares target/readiness/state
  reset-seed-cleanup/identities/policy/scenarios once, translated into the
  `TARGET_HOST`/`SHM_HOST` env vars and `void` CLI flags documented above.
  Stdlib-only (`parse_simple_yaml`, a deliberately bounded YAML SUBSET
  parser -- see `docs/guides/campaigns.md` for exactly what it does and doesn't
  support), matching this repo's own established Python convention. Does
  NOT itself launch the `void` binary in this pass -- `run` composes and
  prints the invocation; see `docs/guides/campaigns.md`'s own "what run actually
  does" section for the precise, non-overclaimed scope.
- `security_scenarios.py` + `security_scenarios.yaml` + `docs/guides/security-scenarios.md`
  (new, Python): the declarative security-scenario library -- 14 scenarios
  covering all ten required families (BOLA read/update/delete/nested, tenant
  escape, mass assignment, workflow bypass, stale object ×2, optimistic
  locking, idempotency, races, auth confusion, async workflows), each with
  `requires`/`valid`/`attack`/`confirm`/`request_budget`/
  `minimization_strategy`/`implemented_by`. **A validated catalog and drift
  check, not a runtime rule interpreter** -- `verify_catalog_matches_implementation`
  greps `src/void/internal/engine/*.go` to confirm every `implemented_by` symbol still exists,
  run as part of the test suite against the shipped file itself so the
  catalog can't silently drift from the code. One scenario
  (`async_premature_consume`) is honestly cataloged as not yet having a
  dedicated Go finding, only the scheduler's poll bias. `parse_simple_yaml`
  (`campaign.py`) gained one bounded extension for this file:
  `key: [a, b, c]` inline scalar lists (needed for `status_in: [200, 201]`),
  still rejecting flow mappings and nested flow structures.
- `minimize.go` (extended, Go): `minimizeChainCandidate` — whole-chain
  minimization, dropping non-essential `SequenceStep`s from a crash's
  `SeqState.History` rather than only shrinking the final step's own fields
  (`minimizeCrashCandidate`, pre-existing). Backward walk so earlier indices
  stay valid after a removal; each remaining step is resent as an exact,
  already-concrete `WorkItem` (no re-derivation of dynamic bindings — see
  §2.7). New `Config.MinimizeChain` / `-minimize-chain` flag (default `true`
  in both the `fast` and `deep` profiles, mirroring `-minimize-crash`'s
  existing pattern), wired into `crash.go` right after the existing
  field-minimization block: on a successful shrink, `pocItem.SeqState` is
  replaced with a copy carrying the shrunk `History`, and
  `minimized["chain_changed"/"chain_probes"/"chain_steps"]` are recorded
  alongside the existing field-minimization result. Six new tests in
  `minimize_test.go` cover the nil/single-step/zero-budget no-ops, a
  genuine non-essential-step drop, refusal to drop an essential step, and
  probe-budget enforcement.
- `manifest.go` (new, Go): `sha256FileHash` + `buildRunManifest` — the run
  manifest (see §2.7). New `Config.TargetImageDigest`/`OpenAPISpecHash`/
  `CampaignConfig` fields and matching `-target-image-digest`/
  `-openapi-spec-hash`/`-campaign-config` flags; new `Fuzzer.templatesPath`/
  `templatesHash` fields, set once in `NewFuzzer` right after `loadTemplates`.
  Wired into `report.go::buildStructuredCrashReport` (`run_manifest` key) and
  `sarif.go::buildSARIFReport` (`runs[0].properties.run_manifest`).
- `identity.go`/`crash.go`/`report.go`/`sarif.go` (extended, Go): chain-level
  trace on findings (see §2.7) — `CrashFinding.SequenceID`/`ChainTrace`,
  `cloneChainTrace`, populated in `crash.go` after whole-chain minimization;
  surfaced as `bugs[].chain` (`report.go`) and `results[].properties.chain`
  (`sarif.go`, via `sarifChainProperty`). New `manifest_test.go`,
  `report_test.go` (didn't previously exist), and extensions to
  `crash_test.go`/`sarif_test.go` cover hash stability, manifest field
  presence/pass-through defaults, and chain presence/absence on both output
  formats.
- `sequence.go`/`identity.go`/`crash.go`/`report.go`/`sarif.go` (extended, Go,
  Phase 5 #128): producer-consumer-binding provenance closed the gap between
  `ProducerConsumerBinding`'s own pre-existing doc comment (which already
  claimed it was "consulted by report/SARIF chain-trace output") and reality
  (it was recorded but never read anywhere) — new `bindingsForSequence`
  (sequence.go), `CrashFinding.Bindings`, wired into `crash.go` alongside
  `ChainTrace`/`SequenceID`, and surfaced as `chain.bindings` in both
  `report.go` and `sarif.go`'s chain property.
- `stateful_security_fixtures_test.go` (new, Go, Phase 5 #128): a 9-test,
  real-HTTP-round-trip fixture matrix — one small httptest fixture server with
  a genuinely vulnerable (or, for the async case, correctly-behaving contrast)
  endpoint per named stateful-security property from the original spec: nested
  tenant resource (chain depth + producer-binding provenance + parent/tenant
  relations, all asserted together), cross-tenant read (BOLA, via a real
  cross-identity replay), deleted-resource-still-mutable, approval bypass
  (workflow-state bypass), ignored ETag (optimistic locking), double payment
  (idempotency-replay), async import job (submit→poll→terminal), and
  privileged mass-assignment gated on real valid-chain context (asserting
  single-factor differentiation: an identical probe attempt is suppressed for
  an unconfirmed org and fires once — and only once — that same org is
  confirmed via a genuine prior response). A ninth test proves
  minimized-chain validity end to end: a real `recordCrash` run through a
  crash reached via a real, deliberately-shrinkable 3-step chain confirms the
  ALREADY-MINIMIZED chain (not the original) reaches `CrashFinding.ChainTrace`,
  and that `Bindings` correctly filters to just that crash's own sequence ID.
  Distinct from `resource_integration_test.go` (Phase 1 #107, which proves
  real responses drive resource-graph *extraction* correctly): this file
  proves the *adversarial/finding* side of the same real-HTTP pipeline.
  Wired into CI as its own named gate (`.github/workflows/e2e.yml`'s
  "Stateful-security E2E fixture matrix" step) rather than only being swept up
  in the blanket `go test ./...` step already there.

All additive, gated where relevant by the existing `-resource-graph` flag, verified
by `go build`/`go vet`/`gofmt -l`/`go test -race` staying clean throughout (see the
test files alongside each module above for the specific coverage).

## 4. What's still open (Phases 2-5)

Tracked as the remaining backlog from the original stateful-fuzzing architecture
task — not reproduced here in full since task state changes faster than a doc
should; see the project's own task tracker for current status. Grouped by the same
phases as §2 above:

- **Phase 2 (lifecycle)**: a formalized, separately-named valid-workflow-planner
  component and its still-missing identity-compatibility scoring term,
  binding-quality/cross-identity/oracle-signal reward terms. (Typed named
  transitions, the transition-source priority chain, two of three remaining
  planner scoring terms, the chain-depth + transition-novelty Energy reward
  terms, and checkpoint/resume are done — §2.3/§2.4/§2.6/§2.7.)
- **Phase 3 (attacks)**: none — fully done (adversarial-branch planner, its three
  oracles, and valid-chain-gated mass assignment — §2.4/§2.5).
- **Phase 4 (complex scenarios)**: none — fully done (idempotency-replay,
  race-outcome evaluation, the async submit→poll model, pagination/cursor-aware
  chaining, multipart upload→process→download, and webhook/event lifecycle
  modeling — §2.5, `idempotency.go`/`race.go`/`async.go`/`pagination.go`/
  `multipart_chain.go`/`webhook.go`).
- **Phase 5 (operational maturity)**: none — fully done. `campaign.yaml`
  contract, the declarative `security_scenarios.yaml` catalog, whole-chain
  minimization, run-manifest capture, chain-level SARIF/report output
  (including producer-binding provenance), and the stateful-security E2E
  fixture matrix wired into CI are all done — `campaign.py`/
  `docs/guides/campaigns.md`, `security_scenarios.py`/`docs/guides/security-scenarios.md`,
  `minimize.go::minimizeChainCandidate`, `manifest.go`,
  `stateful_security_fixtures_test.go` — §2.7.

This closes all 5 phases of the original stateful-fuzzing architecture task. The
one still-open item overall is Phase 2's valid-workflow-planner formalization
(a separately-named component plus its identity-compatibility/binding-quality/
cross-identity/oracle-signal scoring terms) noted above.
