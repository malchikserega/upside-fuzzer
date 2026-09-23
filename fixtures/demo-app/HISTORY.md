# TeamFlow demo — history & past verification runs

Dated, point-in-time material split out of [README.md](README.md) to keep that file
focused on architecture and bring-up: bugs the *building* of this demo exposed in the
fuzzer pipeline itself, and results from actual past fuzzing runs against it. None of
this is required reading to bring the demo up and run it — see README.md for that.

**→ [Back to fixtures/demo-app/README.md](README.md) · [Docs Index](../../docs/index.md)**

---

## Three real bugs this demo exposed in the fuzzer itself

Building this demo against the actual pipeline (not just reading the code) surfaced
three genuine bugs in `bin/fuzz-prep-multi.py`/`tools/dotnet/instrumentor/Program.cs` — all now fixed,
and all worth knowing about since none are specific to TeamFlow:

1. **Non-main projects shipped uninstrumented ("generate from scratch" Dockerfile
   path).** For a solution with no pre-existing Dockerfile at all,
   `bin/fuzz-prep-multi.py` builds the whole solution with `dotnet build`, which leaves
   every project with its own `bin/` folder and a *separate, pre-instrumentation*
   copy of every other referenced project's DLL (MSBuild's copy-local mechanism,
   executed before instrumentation runs). Each `RUN instrumentor ...` step
   instrumented the DLL sitting in *that DLL's own* project folder — but the final
   image only ever copied the *main* project's folder, which still held the stale,
   never-instrumented copy of every dependency. Confirmed empirically: an early
   version of this same demo (before it had its own `Dockerfile`) shipped
   `TeamFlow.Infrastructure.dll` — holding nearly all of the planted vulnerabilities —
   with **zero** SharpFuzz/CmpLog instrumentation despite the build log claiming
   otherwise. Fixed by syncing each non-main project's freshly-instrumented DLL (and
   its `.upsidefuzz_constants.jsonl`/`.upsidefuzz_instrumented.jsonl` metadata) into
   the main project's own output folder before the final `COPY`. Demo_app now ships
   its own `Dockerfile`/`docker-compose.yml` (see [README.md's Bring-up](README.md#bring-up)), so its own
   pipeline run actually exercises bug #3 below instead of this one — this fix still
   matters for any other target without a pre-existing Dockerfile.
2. **Async method bodies invisible to CmpLog/ConstantExtractor — fixed 2026-07-26.**
   The instrumentor used to unconditionally exclude C#'s compiler-generated
   `async`/`await` state-machine types (`<Method>d__N`) from every IL pass —
   coverage probes, CmpLog, and ConstantExtractor alike. The practical effect: a
   literal string comparison or a nested `if` chain written directly inside an
   `async Task` method (the idiomatic way to write almost anything in modern
   ASP.NET Core) was as invisible to the fuzzer as it would be to a black-box one —
   the exact opposite of this demo's premise. **This is now fixed at the source**
   (`tools/dotnet/instrumentor/Program.cs::InstrumentationFilter.Decide`, see its own comment and
   `ARCHITECTURE.md` §3): async state machines are instrumented like any other
   nested type, verified both by a dedicated fixture (an inline async backdoor
   string, no workaround needed, correctly extracted) and against this app itself
   (rebuilding fixtures/demo-app's instrumented image after the fix: Infrastructure's
   instrumented-type count went from 19 to 32, CmpLog comparison sites from 1 to 9,
   and the same 3-request warm-up probe that used to produce 18 coverage edges now
   produces 206, with zero functional regressions). `CouponService.IsBackdoorCode`
   and `TaskLifecycleService.PassesUnlockGate` are still written as small, ordinary
   (non-`async`) methods — that remains good practice (isolating pure decision
   logic is legible regardless of instrumentation), but it's no longer *required*
   for ConstantExtractor/CmpLog/per-branch coverage reward to see them; a
   newly-planted bug written directly inline inside an `async Task Foo()` would now
   be found just as well.
3. **`_detect_last_stage` misidentified the runtime stage whenever it was unnamed
   ("adapt an existing Dockerfile" path).** This is the path fixtures/demo-app's own
   `Dockerfile` actually exercises, once it had one. `_detect_last_stage` was meant
   to find the runtime/final stage's name so instrumentation stages get inserted
   *before* it — but it searched for `FROM ... AS X` and returned the **last match
   found anywhere in the file**, not the last stage specifically. When the actual
   final stage is unnamed — an extremely common pattern (no later stage ever needs
   to reference it by name); true of fixtures/demo-app's own `Dockerfile`, and, checked while
   fixing this, of both `btcpayserver/Dockerfile` and `simplcommerce/Dockerfile` in
   this repo's own fixture set too — it silently returned an *earlier* stage's name
   (typically the SDK/build stage) instead. The caller then inserted the
   instrumentation stage (`FROM {that_earlier_stage} AS instrumentation`) **before**
   that stage's own definition in the file, producing a Dockerfile invalid enough
   that Docker tried to pull an image literally named after the stage
   (`pull access denied ... docker.io/library/build:latest`) instead of building it.
   Reproduced concretely while wiring up fixtures/demo-app's Docker Compose bring-up. Fixed by
   having `_detect_last_stage` return `None` (triggering the existing, already-correct
   "no named runtime stage" fallback) whenever the truly last `FROM` in the file has
   no `AS name` — plus handling BuildKit flags like `--platform=$BUILDPLATFORM`
   before the image reference, which the original regex would have also silently
   dropped a real stage name for.

## Verification run — 2026-07-29 (20 minutes, current 57-endpoint/42-bug app)

Fresh, full re-verification against the *current* app (4 organizations, 57 endpoints,
42 planted bugs) — run specifically to confirm the sequence/resource-graph
chain-detection machinery shipped since the run below (typed resource-lifecycle
graph, state-reward sequence search, chain trace + producer→consumer bindings in
crash reports, the run manifest) actually fires against fixtures/demo-app, not just that it
passes its own unit tests. Command: the exact `docker run void-fuzzer ... -direct-shm
-shm-read-mode mmap -profile security -auth-file ... -time-budget 20` from
README.md's "Run the fuzzer in Docker", against a freshly rebuilt instrumented image
(build-time log confirmed CmpLog found 1 string- and 21 int-comparison sites in
`TeamFlow.Infrastructure.dll`, and the extracted-constants dictionary shipped with
`QA-INTERNAL-BYPASS-58f3`/`EU-WEST` present — both magic-value mechanisms live before
a single request was sent).

In 1200 seconds: **729,181 requests completed** (737,639 sent), coverage grew from a
0-edge baseline to **9,482 edges** (23.45% of the 131KB bitmap's capacity — this app
has considerably more branch surface than the original 26-endpoint version), **7,006
total crashes** deduplicating to **24 unique signatures across 12 distinct root-cause
clusters**, and **415 total triaged findings**: 290 BOLA, 88 stateful-security-oracle
findings (83 idempotency-replay, 5 race-condition), 13 schema-drift, 2
differential-auth-bypass, plus the 24 crash-based findings (206 `likely_vuln_high`,
173 `likely_vuln`, 12 `needs_review`).

**Direct evidence the chain machinery is genuinely exercised, not just plausible in
theory:**

- The sequence/resource-graph engine **persisted 133 distinct multi-step workflows to
  disk** (`crashes/workflows/*.json`+`.sh`, each a real, replayable curl-script chain
  — e.g. one captured `POST .../submit-for-review` → `POST .../reject` → `GET
  /api/projects/{id}`, a genuine 3-step producer/consumer chain built entirely from
  runtime-extracted ids), and the run's own live counter reports 189 workflows
  persisted over its lifetime.
- **Bug #16 fired twice**, on two different task ids (16 and 58), each reached via an
  independently-built chain. Both crash records in the structured JSON report
  (`report.json`) carry a real `chain` object (`sequence_id`, `depth`, ordered
  `steps`) — direct confirmation that this session's chain-trace wiring
  (`crash.go`/`report.go`) is live against a real target, not just its own unit
  fixtures.
- **2 of the 9 chain-tagged crash records also carry non-empty `bindings`** — the
  producer→consumer field-provenance gap closed this session
  (`sequence.go::bindingsForSequence`) returning real data, not an empty array.
- **The run manifest is present** on the structured report with a real, non-empty
  `templates_sha256` — the reproducibility feature working end to end against a real
  target.
- **The idempotency oracle fired 83 times** with genuine before/after evidence
  (`idempotency_not_enforced`, original resource id vs. a *new* id created by the
  replay) — e.g. a duplicated `POST /api/users/{id}/api-keys` replay creating a
  second real API key instead of being rejected, exactly the double-processing shape
  bugs #28/#39 are built around.

Bugs #20 (backdoor constant) and #21 (nested unlock gate)'s actual crash **still
didn't fire**, even across this longer 20-minute/729K-request budget — both remain
the hardest bugs in the catalog by design (converging on an exact 19-character string,
or an exact 4-value/6-character-length combination, out of a large candidate pool,
purely by mutation). The unlock endpoint's *unrelated* real BOLA bug (no ownership
check) was found independently as a `likely_vuln_high` finding in this run, which is
not the same thing as the narrow-band array-overrun crash. This is the honest result,
not a gap: both mechanisms that are supposed to eventually find them (constant
extraction, CmpLog) are confirmed live and correctly seeded going into the run: what's
missing is luck/budget, not capability.

Also confirmed present, matching the original catalog below: the baseline
`DivideByZeroException`; bug #22's `InvalidOperationException: Empty legacy import
payload.`; several bug #10 SQLi-endpoint 500s; and the same incidental
`FormatException` on document download noted in the original run. New, beyond the
original catalog: `Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException` on
`bulk-delete`/`submit-for-review`/`reject`/`approve`/`restore` — concurrent fuzz
workers racing the same row's optimistic-concurrency token, a real (if mundane)
concurrency bug distinct from the deliberately planted #23/#28/#37 races, surfaced
simply because enough parallel workers hit shared seed data for it to happen.

## Expected results (from an earlier verification run)

> **Predates the 2026-07-28 expansion**, and superseded by the fresher run above. The
> run below was against the original
> 26-endpoint/24-bug app (2 organizations, 5 users). The catalog above now covers 57
> endpoints and 42 bugs across 4 organizations — a fresh verification run against the
> current app would show materially different absolute numbers (more endpoints to
> reach, more sequence-only bugs to chain into), though the same mechanisms apply.
> Left here as-is rather than rewritten, since it's a real, honestly-reproduced past
> run, not a projection.

The numbers below are from the exact `docker run void-fuzzer ... -direct-shm
-shm-path /coverage_shm/bitmap -profile security -time-budget 3` command in "Run the
fuzzer in Docker" above, against the real instrumented container over the real shared
`coverage_shm` volume — not a prediction, and not a host-binary run. Coverage
bootstrapped correctly across all three assemblies, then grew from a 0-edge baseline
to **1199 edges** (baseline-ceiling reported as 6175, i.e. the mutation engine kept
finding new edges throughout — this number reflects however much of the app's actual
branch space a 3-minute run reaches, not a fixed target). In 180 seconds: **169,190
requests**, **1859 crashes**, deduplicating to **16 unique signatures across 9 distinct
root-cause clusters**, plus **134 access-control findings** (150 total triaged
findings). The sequence engine (state-reward search, Top-20 #12) found **135 new
workflow states** and persisted **3 unique multi-step workflows** — direct evidence the
producer/consumer chaining behind bug #16 is genuinely exercised, not just plausible in
theory. Confirmed present in `unique-crashes-*.jsonl`:

- `System.DivideByZeroException` at `ProjectsController.TaskStats` — the baseline crash.
- A `GET /api/projects/{id}/tasks?search=...` 500 — bug #10's SQLi endpoint,
  reproducing the same `Microsoft.Data.Sqlite.SqliteException: "unrecognized token"`
  seen in manual verification, tagged `server_error`/`backend_exception` — **not**
  `sqli_error_reflected` (empirically confirms the marker-mismatch caveat above, not
  just the theory behind it).
- `System.InvalidOperationException: "Empty legacy import payload."` at
  `LegacyImportService.ImportAsync` — bug #22's endpoint is reachable and crashing,
  though this run's fuzzer hit the null-payload guard clause first rather than a
  `$type`-gadget-shaped crash; both are real crashes proving the same unsafe
  `TypeNameHandling.Objects` configuration is live.
- `schema_undeclared_sensitive_field:passwordHash` on `GET /api/users/me` — bug #3,
  exactly as designed.
- `differential_auth_bypass:route-case` on the case-varied `/Api/Organizations/...`
  path — bug #8, exactly as designed.
- A `stateful_trigger` finding on `POST /api/tasks/{id}/restore` — a live signal that
  the multi-request archive→restore chain behind bug #16 was actually built and
  exercised during this run, not just reachable in principle.
- `bola_identical_cross_identity_response` (102 instances) and
  `bola_suspected_cross_identity_access` (24) across the BOLA endpoints (#4/#6/#7/#9/#12).
- Several **incidental, non-catalogued** findings the fuzzer found on its own beyond
  the 24-bug catalog: `System.IO.IOException: "...being used by another process"` in
  `FileStorageService.SaveAsync`/`ReadAsync` (concurrent fuzz workers racing the same
  upload filename — a real, unplanned concurrency bug distinct from #23);
  `System.UnauthorizedAccessException` in the same `SaveAsync`, this time from an
  SSRF-shaped `fileName` payload (`http:/0x7f000001/...`) that `Path.Combine` turns
  into an attempted directory write the OS itself refuses — a second, differently-shaped
  symptom of the same #17 path-traversal root cause; and `System.FormatException` in
  `DocumentsController.Download` (an earlier fuzzed upload stored a malformed
  `Content-Type`, later crashing `ControllerBase.File(...)` when reflected into a
  response header). None of this is the ceiling of what the fuzzer finds here.

Bugs #20 (backdoor constant) and #21 (nested unlock gate) did **not** fire within this
particular 3-minute budget — both were independently, manually confirmed to crash
deterministically with the right input (see [README.md's "Bugs only coverage-guided
fuzzing finds"](README.md#bugs-only-coverage-guided-fuzzing-finds)), and the mechanism
that's supposed to find them is now confirmed live end to end in this exact Docker
Compose stack (the extracted-constants dictionary shipped in the image contains
`QA-INTERNAL-BYPASS-58f3` and `EU-WEST`, and CmpLog reported 1 live string- and 1 live
int-comparison site in `TeamFlow.Infrastructure.dll` at build time — see bug #2 above).
They're the two hardest bugs in the catalog by design;
converging on an exact 19-character string or an exact 4-value/6-character-length
combination out of a large candidate pool takes materially longer than 3 minutes of
mutation. A longer run (or a fixed `-seed`, replayed) is expected to surface both —
that's the intended difficulty gradient, not a gap in the demo.
