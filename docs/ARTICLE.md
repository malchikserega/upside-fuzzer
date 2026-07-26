# Grey-Box Fuzzing for .NET Web APIs Without Touching the Source

*Coverage-guided REST fuzzing, zero-edit runtime instrumentation, and vulnerability oracles that produce evidence instead of stack traces.*

---

## Abstract

Most REST API fuzzers are black-box: they read an OpenAPI spec, generate requests, and treat an HTTP 500 as the only interesting signal. That approach plateaus quickly and finds shallow bugs. Kernel and native-code fuzzers left that world a decade ago — AFL, libFuzzer and honggfuzz are coverage-guided because coverage is what lets a fuzzer discover its own way through a program. The reason REST fuzzers rarely are is not that coverage is a bad idea for web APIs; it is that wiring coverage feedback into a *running, multi-tenant, framework-heavy* web server is genuinely awkward, and the payoff (finding *real* vulnerabilities, not just robustness bugs) requires machinery beyond the coverage loop itself.

UpsideFuzz is an attempt to build that machinery for the .NET/ASP.NET Core ecosystem. It combines SharpFuzz IL rewriting, a shared-memory coverage bitmap read by a Go fuzzing engine, zero-source-edit instrumentation via `DOTNET_STARTUP_HOOKS`, a Roslyn-based constraint extractor, and a set of *positive* vulnerability oracles (BOLA/IDOR, broken authentication, mass assignment, injection, parser-confusion differentials) that emit evidence rather than exceptions. This article is a walk through the architecture and the engineering decisions behind it, with an honest accounting of what is genuinely new, what is a pragmatic re-implementation of prior art, and what still does not work.

The project is open source and in active development. Several of the subsystems described here are marked "partial" in the codebase's own roadmap; I have kept those labels here rather than smoothing them over.

---

## Motivation

Consider what it takes to fuzz a real .NET API — say, an e-commerce backend with JWT auth, EF Core, a validation layer, and forty controllers.

A black-box fuzzer sends `POST /api/orders` with a garbage body, gets a `400 Bad Request` because the model binder rejected it, and moves on. It never learns that the body needed a `CustomerId` that is a valid GUID, an `Items` array with at least one element, and a `Currency` from a three-value enum. It bounces off the validation layer forever and never reaches the business logic behind it — the part where the interesting bugs live (price manipulation, negative quantities, cross-tenant object access, workflow-order violations).

A coverage-guided fuzzer, in principle, does better: when a mutation happens to satisfy one more validation rule and executes one more basic block, the fuzzer *sees* the new coverage and keeps that input as a seed. Over time it climbs the validation wall the way AFL climbs a parser. But to get that feedback signal out of an ASP.NET app you have to solve several problems that native fuzzers get for free:

1. **The target is a long-running server, not a `main(int argc, char** argv)`.** There is no fork-per-input. Coverage accumulates across concurrent requests handled by a thread pool.
2. **The code you care about is spread across many assemblies**, each with its own copy of the SharpFuzz trace type, and some of them load lazily (plugin modules, `ApplicationPart`s) after startup.
3. **You usually cannot modify the target.** For a security engagement the target is someone else's code; even for your own code, forcing every fuzz target to add a NuGet package and edit `Program.cs` is friction that kills adoption.
4. **A 500 is not a vulnerability.** An unhandled `NullReferenceException` is a robustness bug. The bugs a security researcher is paid to find — broken object-level authorization, privilege escalation via over-posting, injection — usually return `200 OK`. The coverage loop alone will never surface them, because they are not crashes.

UpsideFuzz exists because each of these has a concrete engineering answer in the .NET ecosystem, and no existing tool assembles all four.

---

## Existing Solutions

**RESTler** (Microsoft) is the reference stateful black-box REST fuzzer. Its grammar compiler and its producer-consumer inference (a `POST` that creates a resource yields an id that a later `GET`/`PUT`/`DELETE` consumes) are excellent, and UpsideFuzz's original grammar path was built directly on RESTler's compiler. But RESTler is black-box: it has no coverage feedback, so it cannot tell whether a mutation reached new code. Its bug oracle is essentially "5xx or spec violation."

**EvoMaster** is the strongest of the academic tools and the closest in spirit. Its white-box mode instruments JVM/.NET bytecode and uses *branch distance* as a search-based fitness function — it can measure how close an input came to flipping a specific branch and gradient-descend toward it. That is a genuinely stronger coverage signal than the edge-hit feedback UpsideFuzz uses. EvoMaster also builds a fully typed test genome and exports runnable regression tests. Where it is weaker for this project's goals: its instrumentation requires a controller/driver you write per target, and its security oracles are narrower than a dedicated offensive toolkit.

**Schemathesis** is the best property-based option. It derives Hypothesis strategies from JSON Schema and validates responses *against the schema* — a whole class of conformance bugs UpsideFuzz still ignores. It is black-box, fast, and pleasant in CI. It does not model application state deeply and has no coverage feedback or access-control oracles.

**DeepREST** represents the current research direction: reinforcement learning to discover operation orderings and parameter values that reach deep states. It is the state-of-the-art answer to the "how do I reach step 7 of a workflow" problem that UpsideFuzz addresses with much coarser heuristics.

The gap UpsideFuzz targets is specific: **grey-box coverage feedback on arbitrary .NET web APIs, combined with security oracles that produce exploitation evidence, with instrumentation that requires no changes to the target.** None of the above occupies that exact point. The individual techniques are mostly known; the assembly is what is new.

---

## Design Goals

- **Grey-box, on real .NET apps.** Coverage feedback from the actual instrumented binaries, not a proxy.
- **Zero-edit instrumentation.** No NuGet package added to the target, no `Program.cs` patch, ideally no rebuild of the target's own project.
- **Fail-closed, self-verifying.** If instrumentation silently produced no coverage, the run must refuse to start — a green run with zero coverage is the worst possible outcome for a security tool, because it reads as "no bugs."
- **Evidence-based oracles.** A finding must carry a concrete exploitation signal (a cross-identity 2xx, a reflected privileged field, a time delay), not just a status code.
- **Honest reporting.** Distinguish "reproducible 500" from "proven vulnerability" from "the way we built the image broke DI." Over-claiming destroys researcher trust faster than missing a bug.

---

## Architecture Overview

Three processes, joined by files on disk and an HTTP/shared-memory contract:

```
  .NET solution (source)
        │
        │  fuzz-prep-multi.py         dotnet/analyzer/ (Roslyn)      grammarc/ (OpenAPI→grammar)
        │  • detect projects/Docker    • per-property           • typed request model
        │  • generate instrumentor      constraints             • boundary synthesis
        │  • generate coverage hook     [Authorize]/routes       • producer/consumer deps
        ▼      (UpsideFuzz.Coverage)         │                        │
  Docker image                                └──── roslyn-constraints.json ──┐
        │  SharpFuzz IL rewrite of app DLLs                                   ▼
        │  DOTNET_STARTUP_HOOKS = /coverage/UpsideFuzz.Coverage.dll     templates.export.json
        │  /coverage_shm/bitmap  (tmpfs, 256KB default)                       │
        ▼                                                                     ▼
  Running API  ──── mmap bitmap / X-Coverage-Delta header ────►  void engine (Go)
                                                                  • epoch scheduler + MOpt
                                                                  • stateful sequences
                                                                  • oracles (BOLA/mass-assign/…)
                                                                  • crash cluster + triage + PoC
```

The prep tool (`fuzz-prep-multi.py`) is the .NET-facing half: it analyzes a solution, generates the instrumentor and the coverage hook assembly, and adapts the Dockerfile. `grammarc/` and `dotnet/analyzer/` build the request grammar. `void/` (Go) is the actual fuzzer. The three halves communicate through explicit, boring artifacts: a shared-memory bitmap, a set of `/shm/*` HTTP endpoints, a `roslyn-constraints.json`, and a `templates.export.json`. That boundary is deliberately dumb so each half can be rewritten independently — the grammar path was in fact rewritten from RESTler to a first-party compiler without the engine noticing.

---

## Instrumentation

### Why instrument at all, and why IL rewriting

Coverage feedback needs per-branch instrumentation of the target's own code. For .NET the practical options are the CLR Profiler API (heavyweight, native, complex), a source-level Roslyn rewriter (requires rebuilding the target from source), or IL rewriting of the compiled assemblies with Mono.Cecil. UpsideFuzz uses the last, via **SharpFuzz**, which injects an AFL-style `prev ^ cur` edge-tracking probe at every basic block and writes hit counts into a shared bitmap.

IL rewriting wins here because it operates on the *published* DLLs — it does not need the source to build, it works uniformly across a multi-project solution, and it composes with Docker: rewrite happens as a build stage over the publish output.

The instrumentor (`dotnet/instrumentor/Program.cs`) is a thin CLI over `SharpFuzz.Fuzzer.Instrument` with a type filter. The filter is where the target-specific pain lives. Two exclusions matter and are not obvious:

```csharp
// Entry-point types AND their compiler-generated closures fire coverage probes
// during type initialization, BEFORE the coverage runtime binds the SHM pointer,
// causing AccessViolationException at startup.
if (fullName.EndsWith(".Program") || fullName.Contains(".Program+")
    || fullName.Contains("+<>c")          // lambda-cache classes (static-init)
    || fullName.Contains("<Main>"))       // top-level-statements entry point
    return false;
```

This is a scar from a real failure: blanket instrumentation crashed Bitwarden in `Bit.Api.Program+<>c..cctor`, because a probe executed while the trace type's `SharedMem` was still null. The lesson generalizes — *anything that can run before your coverage runtime is initialized must be excluded from instrumentation*, and in .NET that includes the compiler-generated closure and lambda-cache classes nested under the entry point, not just `Program` itself.

### Zero-edit instrumentation via startup hooks

The original design injected a `CoverageExtensions.cs` file into the target's main project and edited `Program.cs`/`Startup.cs` with regex to register middleware. That works but violates the zero-edit goal and is fragile against the endless variety of `Program.cs` shapes (minimal hosting, `Startup` classes, top-level statements, `ConfigureRequestPipeline` conventions).

The current default (`--inject-mode hook`) uses two .NET runtime features that most people know from APM agents, applied to coverage:

**`DOTNET_STARTUP_HOOKS`** points the runtime at a managed assembly whose `StartupHook.Initialize()` runs *before* `Main`. This is where the coverage runtime maps the shared bitmap and links SharpFuzz — with no target code change at all. The generated `UpsideFuzz.Coverage` assembly does this:

```csharp
internal class StartupHook            // global namespace, exact name required
{
    public static void Initialize() => CoverageRuntime.Bootstrap();
}
```

`Bootstrap()` does three things worth calling out:

```csharp
// 1. Resolve our own assembly + SharpFuzz.Common from /coverage, which is NOT on
//    the app's probing path — so the target directory stays untouched.
AssemblyLoadContext.Default.Resolving += (ctx, name) => {
    var candidate = Path.Combine(hookDir, name.Name + ".dll");
    return File.Exists(candidate) ? ctx.LoadFromAssemblyPath(candidate) : null;
};

InitializeShm();

// 2. Link every assembly already loaded...
foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) LinkAssembly(a);
// 3. ...and every assembly loaded LATER. This is the fix for lazily/dynamically
//    loaded modules whose coverage was previously lost.
AppDomain.CurrentDomain.AssemblyLoad += (s, e) => LinkAssembly(e.LoadedAssembly);
```

The `AssemblyLoad` handler is the part that matters. Earlier the runtime linked SharpFuzz once at startup, which silently dropped coverage for any assembly loaded after that point — exactly what happens with plugin-style module loading (SimplCommerce's store modules are the canonical example). Linking on the load event closes that gap: each assembly's `SharpFuzz.Common.Trace.SharedMem` is pointed at the shared bitmap the instant it loads, before its methods JIT.

**`ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`** is the ASP.NET-specific companion. A hosting startup assembly's `IHostingStartup.Configure` runs during host build, again with no target edit, and can register an `IStartupFilter` that inserts middleware. UpsideFuzz uses it to add one middleware that both serves the `/shm/*` control endpoints inline and does per-request coverage attribution.

The honest tradeoff: an `IStartupFilter` middleware sits *outside* the app's own pipeline, so if the target has a global `UseExceptionHandler` that swallows exceptions and writes its own 500, our middleware may not see the exception type. The legacy `--inject-mode source` (which places the middleware *inside* the pipeline) is retained precisely for the cases where maximal exception-type fidelity in production mode matters. This is a genuine limitation of the zero-edit approach, not a detail I want to paper over.

### Fail-closed self-verification

Because "silently no coverage" is the failure mode that matters most, the engine probes the target's health before it starts and refuses to run if instrumentation is dead (`void/go/coverage.go::checkCoverageHealth`). The hook exposes `GET /shm/health` returning `{"linked_assemblies": N, "shm_bound": true, ...}`; the engine treats `shm_bound=false` or zero linked app assemblies as fatal unless `-allow-degraded-coverage` is passed. There is a unit test asserting the fail-closed behavior (`coverage_health_test.go`). This is unglamorous but it is the single most trust-relevant piece of the instrumentation layer.

---

## Coverage Pipeline

### From bitmap to feedback

SharpFuzz writes an AFL-style bitmap: one byte per edge, incremented on each hit. The engine reads it two ways. In Docker sidecar mode it `mmap`s `/coverage_shm/bitmap` directly. Otherwise the ASP.NET middleware returns a per-request coverage delta in a response header, so the engine gets attribution without a second round trip.

Two decisions in this path are worth the detail.

**Hit-count buckets.** Counting "edge touched or not" throws away loop depth: an edge executed once looks identical to one executed 5,000 times, so a fuzzer that maximizes distinct edges plateaus the moment every edge has been hit once. AFL solved this long ago with log-scale hit-count buckets (`1, 2, 3, 4–7, 8–15, …`); a new *bucket* for an edge counts as new coverage. UpsideFuzz classifies each byte through a 256-entry lookup on both sides (`coverage.go::countClass`, and the same table in the C# `MergeAndCountNovel`) and tracks a bucketed virgin map. This is not novel — it is table stakes borrowed from AFL — but it is the difference between a fuzzer that keeps making progress inside pagination/retry/state-machine code and one that stalls.

**First-observer-wins per-request attribution.** Attributing coverage to individual requests in a concurrent server is the hard part. The naive approach — read a global edge count before and after each request — is wrong twice: it scans the whole 256KB bitmap twice per request in the hot path, and under concurrency two requests that both reach new code each get credited the full delta ("smearing"), which corrupts the energy and mutation-weight signals that feed on it.

The current approach computes novelty once, after the pipeline runs, by merging the live bitmap into a *shared* bucketed virgin map under a short lock and returning the count of buckets *this request was the first to observe*:

```csharp
// CoverageRuntime.MergeAndCountNovel(), simplified
lock (covLock) {
    for (int i = 0; i < SHM_SIZE; i += 8) {
        if (*(ulong*)(b + i) == 0) continue;        // skip empty 8-byte words
        for (int j = 0; j < 8; j++) {
            byte bucket = CountClass[b[i + j]];
            if ((seenBuckets[i + j] & bucket) == 0) { seenBuckets[i + j] |= bucket; novel++; }
        }
    }
    totalClasses += novel;
}
```

This is not true per-thread isolation — SharpFuzz writes into one shared buffer, and doing genuine per-request buffers would require changing the injected probe. What it *does* fix is the double-counting: whichever concurrent request reaches the merge first claims each new bucket; the others see it already recorded and are credited zero. It also halves the scan cost (one pass, with an all-zero-word fast path). It is a pragmatic answer to a real problem, and I would call it "good enough and honest" rather than "solved."

### Production-mode exception attribution

In non-Development mode ASP.NET's exception handler starts the response and clears headers before our middleware's `finally` runs, which historically left most production 500s unattributable. The middleware detects fuzzer traffic by an `X-Fuzz-Request-Id` header and, on an unhandled exception for *fuzzer requests only*, short-circuits with its own 500 carrying `X-Exception-Type`/`X-Exception-Message` (sanitized). Real traffic is re-thrown untouched. This keeps crash clustering precise even without a dev-mode stack trace — the exception message feeds the cluster key.

---

## Roslyn Analysis

The point of static analysis here is narrow and practical: learn what the validation layer wants so the fuzzer can get past it. The original implementation regex-scraped C# for `[StringLength]`/`[Range]` and attributed constraints by field name *globally* — so a `Name` with `[StringLength(50)]` in one DTO constrained every `name` field in the app. That is wrong, and it is the kind of wrong that a proper parser fixes for free.

The `dotnet/analyzer/` project is a real Roslyn syntax-tree analyzer (`Microsoft.CodeAnalysis.CSharp`). It is deliberately scoped to syntax trees, *not* a full semantic model — there is no `MSBuildWorkspace`/NuGet restore, because requiring the target to restore-and-build inside the analyzer is exactly the fragility we are trying to avoid. It extracts, per type and per property:

- Data-annotation constraints (`min/max length`, `range`, `pattern`, `required`, `email`, `url`), enum values (both named and numeric), and `partial` class merges.
- FluentValidation rule chains (`FluentValidationWalker`), including a flag for conditional (`When`/`Unless`) rules.
- Route and authorization metadata (`RouteAuthWalker`) in *both* controller style (`[Route]`/`[HttpGet]` on class + method) and minimal-API/`IEndpoint` style (`app.MapPost("route", [Authorize] ...)`). The latter matters because eShopOnWeb's PublicApi uses it exclusively, and naming-convention heuristics miss it entirely.

The design decision I find most tasteful is the **`unmodeled_validation` list** in the output (`dotnet/analyzer/Models.cs`). When the walker sees a validation construct it cannot faithfully model — a custom `ValidationAttribute`, an `IValidatableObject.Validate`, a non-literal enum — it records a note rather than silently dropping it or guessing. The grammar consumer can then decide to fuzz that field harder, and the human reading the output knows exactly where the constraint model is blind. Honest instrumentation of your own blind spots is rare and worth copying.

A property constraint crosses the C#→Python boundary as flat JSON:

```json
"Currency": { "clr_type": "string", "max_length": 3, "enum_values": ["USD","EUR","GBP"],
              "required": true, "source": ["StringLengthAttribute","RequiredAttribute"] }
```

`grammarc/` merges this with the OpenAPI-derived field hints and synthesizes boundary values (`grammarc/boundary.py`): for `max_length: 3` it emits length-2, length-3, length-4 and an oversized string; for a numeric `minimum`/`maximum` it emits the bound, bound±1, and overflow. The value pool becomes both the `dict.json` per-key candidates and the `custom_payload` segment candidates the engine renders.

---

## Request Generation

### Grammar

`grammarc/` is a first-party OpenAPI→grammar compiler that replaced the RESTler dependency. It parses the spec into a typed request model, resolves producer-consumer dependencies (`dependencies.py`), serializes bodies (`body_serializer.py`, including multipart), and emits templates the Go engine renders. Replacing RESTler was less about RESTler being bad and more about the three-language, two-serialization-hop pipeline (Python emits Python that a Go parser re-reads) being undebuggable, and about wanting the grammar quality to be a function of code we control rather than an external tool's OpenAPI coverage.

A template is a list of typed segments — static text, `custom_payload` (dictionary-backed), `fuzzable` (typed value with constraints), and `dynamic` (producer-consumer dependency). The engine renders segments to a raw HTTP request and then mutates.

### Mutation

The mutation engine (`void/go/mutation_engine.go`) is MOpt-style: mutations are grouped into weighted categories (`sqli`, `xss`, `cmdi`, `ssti`, `ssrf`, `json` structural, `.NET $type` deserialization gadgets, …) and a category's weight rises when it discovers new coverage (`weight = 1 + hitRate*4`). Structural JSON mutations stack — type-confuse a field, then wrap it in 100 levels of nesting, then inject a `$type` gadget — which synthesizes complex payloads that would be tedious to hardcode.

The constraint-aware part (roadmap #14, marked partial) blends the per-field bounds from the grammar additively into the primitive mutators: `mutateInt`/`mutateNumber` bias toward the real `minimum`/`maximum`±1, `mutateStringCategorized` toward `maxLength` boundaries and enum values. It is "partial" because the mutation still happens on the flattened value after the template is rendered to bytes — there is no typed-model structural mutation that respects `oneOf`/discriminators. That is honest: constraint-*aware* boundary generation works; constraint-*driven* structural mutation does not yet exist.

### CMPLOG-lite from validation errors

One cheap idea earns its keep. When a request comes back `400` with an ASP.NET `ValidationProblemDetails`/ModelState body, `worker.go::mineClientErrorFields` parses the `{"errors": {"Field": ["must be one of: A, B, C"]}}` shape and extracts the candidate values the validator actually named, feeding them into the runtime store:

```go
// {"errors": {"Currency": ["The Currency field must be one of: USD, EUR, GBP."]}}
//   -> out["Currency"] = ["USD", "EUR", "GBP"]
```

This is a black-box analog of AFL's CMPLOG/RedQueen: instead of instrumenting comparisons, it reads the values the server volunteers in its own error messages. It is defensive — a non-matching body yields an empty map, and it refuses to treat an unrelated JSON object (`{"count": 5}`) as a field map. It is not a substitute for real comparison instrumentation (that is roadmap #21, and it is where the biggest depth gains still are), but it is the highest value-per-line change in the grammar path: on validation-heavy APIs it smashes walls the coverage loop would take thousands of requests to climb.

### Scheduling

The time budget is split into epochs (Baseline → Harvest → Deterministic → Havoc → Splicing) with adaptive rebalancing that steals budget from unproductive phases. Seeds live in a corpus with Fenwick-tree energy sampling; energy gets a "surprise" bonus scaled by `log2(requests)` when a heavily-fuzzed endpoint suddenly yields a new edge, which favors deep rare transitions over shallow surface mapping. Endpoint selection is health-weighted: 4xx-walls, crash-loops, and edge-stalled endpoints get down-weighted, and a freshly crashing endpoint gets a temporary boost so a first crash triggers intensive follow-up. None of this is novel relative to AFL++; it is a careful port of known ideas to the request-scheduling domain, and it only pays off because the coverage signal underneath it was made trustworthy first.

---

## Stateful Fuzzing

Real bugs live behind workflows: create a resource, then act on it. The sequence engine (`void/go/sequence.go`) builds producer→consumer chains. On a successful write it harvests entity ids from the response body (`id`/`Id`/`data[].id`) and the `Location` header, binds them into a per-chain state, finds consumer templates via a dependency index plus same-family path matching, and fans out follow-ups in `POST→GET→PUT→DELETE` priority. State is cloned per branch so chains explore independently, and deep successful workflows are persisted as replayable curl scripts.

The interesting decision is **rewarding new *state shapes*, not just new edges** (roadmap #12, partial). Each chain gets a coarse state signature — the sequence of `(method, route-template, status-class)` steps, with concrete ids normalized away so a chain is not "new" just because it touched a different GUID:

```go
// POST /orders:2xx | GET /orders/{id}:2xx | PUT /orders/{id}:4xx
func sequenceStateSignature(state *SequenceState) string {
    parts := []string{}
    for _, step := range state.History {
        parts = append(parts, fmt.Sprintf("%s %s:%d",
            step.Method, normalizeEndpointPath(step.Path), statusClass(step.Status)))
    }
    return strings.Join(parts, "|")
}
```

A never-before-seen shape earns a state-novelty energy bonus and an extra fan-out branch; persisted workflows are de-duplicated by final shape. This is a deliberately cheap stand-in for the state-graph search that EvoMaster and DeepREST do properly. It is not a real state model — there is no resource-lifecycle tracking, no notion of "this object is now in the deleted state" — and the codebase says so. But rewarding workflow-shape novelty at all moves the fuzzer off pure edge-chasing toward the multi-step business-logic bugs that edge coverage cannot see.

---

## Vulnerability Oracles

This is where the project stops being "a coverage-guided fuzzer" and becomes a security tool. A 500 is a robustness signal; the bugs that matter usually return 200. The oracles (`void/go/oracle.go`) reuse the multi-identity and mutation machinery to produce *positive* evidence.

**BOLA/IDOR and broken authentication.** After any successful, resource-scoped request under an authenticated identity, the identical request is replayed under every other configured identity and with no credentials at all. A 2xx with a substantial body to a different or anonymous principal is a candidate finding. The false-positive engineering is the real work here:

- The no-credential probe only fires on endpoints already observed rejecting unauthenticated access (`authRequiredEndpoints`, tracked with a strength: 2 = we saw it 401/403 a guest). A genuinely public endpoint never accumulates evidence, so it is never flagged — this eliminates the dominant public-endpoint false positive.
- Trivial and empty-collection bodies are skipped (`isTrivialBody`), because two fresh accounts return identical empty responses almost everywhere.
- A path only counts as resource-scoped if it contains a real object handle — a UUID, a numeric id, or a dashed token *containing a digit* — so hyphenated route words (`is-country-supported`) are not mistaken for object ids.
- Identical cross-identity bodies score `likely_vuln_high`; differing 2xx bodies score `likely_vuln` and are flagged for manual verification, because a different body might be the shadow identity's own data.

The honest limitation: this detects *shared-endpoint* auth failures well, but true cross-tenant BOLA where each user sees a different valid object needs an ownership matrix — seed known-B-owned ids, request them as A — which is not yet implemented (roadmap #8). Body comparison is a proxy for object ownership, not a substitute.

**Mass assignment.** After a successful write with a JSON object body, the body is re-sent with privileged fields over-posted (`isAdmin:true`, `role:"SuperAdmin"`, `accessLevel:99999`, …), chosen to be values unlikely to be a natural default so reflection is strong evidence. If the response echoes an injected field with its injected value, the server accepted an over-posted field.

**Injection.** On non-crash responses where a security-category payload was applied, the engine detects time-based SQLi (latency past a threshold *and* ≥3× the running baseline, only on `sleep`/`benchmark`/`pg_sleep`/`waitfor` payloads), evaluated SSTI (rare arithmetic markers like `{{1337*1337}}` → `1787569` present but not merely reflected), and reflected XSS.

**Parser/router-confusion differentials** (`maybeEnqueueDifferentialProbes`). Same logical request sent two ways, gated on endpoints known to enforce auth (strength 2), so a hit means the *confusion itself* bypassed a real check: verb confusion (`GET`→`HEAD`, chosen because HEAD is semantically "GET minus body" so a HEAD bypass is a genuine same-data finding), content-type confusion (JSON→`text/plain`, same bytes), route-case, and parameter-location. This is a small, targeted set rather than a general HTTP-desync fuzzer, but it covers the common ASP.NET routing/parser-confusion bypasses cheaply.

Every finding is written with origin→shadow identity provenance, a classification tier, and a de-duplication key. And the classification is honest: `likely_vuln*` requires a concrete exploitation signal; a reproducible 500 is `confirmed_unhandled_exception` (a robustness/DoS bug, *not* a proven vuln); a DI/service-resolution failure is `target_misconfiguration` and excluded from the vuln count; malformed-input parse errors are down-ranked to `needs_review` so they stop masquerading as code bugs.

---

## Crash Triage and Clustering

A coverage-guided fuzzer generates thousands of crashing inputs for a handful of real bugs. UpsideFuzz uses a two-level identity scheme (`crash.go`, `cluster.go`). The fine-grained *signature* folds in path and mutation, useful for forensic dedup of repro variants. The *cluster key* groups by root cause: the normalized backend exception message plus the first *application* stack frame (framework frames skipped), falling back to `(method, status, route-template)` in production mode where no stack trace is available. A real run produced 933 "unique" crashes for roughly 5 actual bugs; the cluster key is what collapses that back to an honest "distinct root causes" number. This is the sort of thing that sounds like a detail and turns out to be the difference between a report a human will read and one they will close.

---

## Interesting Engineering Decisions

A few choices generalize beyond this project.

**Instrument early, exclude the pre-init window.** The single most valuable line in the instrumentor is the exclusion of `Program+<>c` and lambda-cache closures. The rule — *anything that can execute before your coverage runtime initializes must not be instrumented* — is easy to state and easy to violate, and violating it produces an `AccessViolationException` at startup that looks like a SharpFuzz bug rather than an ordering bug.

**Make the coverage runtime resolve itself from outside the app.** Dropping `UpsideFuzz.Coverage.dll` and `SharpFuzz.Common.dll` into a `/coverage` directory that is *not* on the app's probing path, and wiring an `AssemblyLoadContext.Default.Resolving` handler to load them, is what makes the instrumentation genuinely zero-edit. The app directory is never modified; the hook resolves its own dependencies. This is a clean pattern for any agent that must attach to a .NET app it does not own.

**First-observer-wins instead of per-thread buffers.** Faced with "correct but requires rewriting SharpFuzz's probe" versus "approximate but a localized change," the project chose the approximation and documented it. The right call for a research tool: the approximation removes the *pathological* error (double-counting) while leaving a small residual (ordering effects under concurrency) that decays in the aggregate. Perfect attribution was not worth a fork of the instrumentation library.

**Evidence-gated oracle firing.** The `authRequiredEndpoints` strength tracking is the design idea that makes the access-control oracles usable rather than a false-positive cannon. The oracle does not ask "is this endpoint public?"; it accumulates observed evidence that the endpoint rejects unauthenticated callers, and only then treats a no-credential 2xx as a finding. Letting the fuzzer's own traffic build the precondition, rather than assuming it, is what keeps the signal-to-noise ratio high.

**Track your own blind spots.** The analyzer's `unmodeled_validation` list and the codebase's habit of marking features "partial" in its own roadmap are the same instinct applied to static analysis and to project management. A tool that tells you where it is blind is more trustworthy than one that pretends to see everything.

---

## Lessons Learned

The coverage signal is the foundation, and everything above it inherits its quality. The scheduler, the MOpt weights, the seed energy, the epoch rebalancing — all of them learn from the per-request coverage delta. When that delta was binary (edge/no-edge) and smeared across concurrent requests, the sophisticated machinery on top was learning from noise. Fixing buckets and attribution *retroactively* made the existing scheduler more effective with no scheduler changes. The lesson: do not build clever search on top of a coverage signal you have not validated. The order of operations is signal first, search second.

The second lesson is that *trust is a feature*, and for a security tool it may be the most important one. The fail-closed health check, the honest classification taxonomy, the `unmodeled_validation` notes, the cluster key that reports 5 bugs instead of 933 — none of these find a single additional vulnerability. All of them are the difference between a researcher acting on the output and ignoring it. A green run that silently produced no coverage is worse than a red run, because a red run tells you something is wrong.

The third is mundane and cost real time: startup ordering and readiness. The whole zero-edit hook is elegant until the target's database migration takes 60 seconds and your smoke test probes at 45. Grey-box fuzzing a stateful server means the boring orchestration problems — readiness gating, DB seeding, port discovery — are not beneath the architecture; they are part of it.

---

## Current Limitations

Stated plainly, because a research tool that hides its limitations is not a research tool.

- **No out-of-band interaction server (OAST).** Blind SSRF, blind XXE, RCE, and blind SQLi are detected only when they happen to produce an in-band signal. For serious vulnerability hunting this is the largest single gap.
- **BOLA is body-comparison, not ownership-aware.** True cross-tenant object access where bodies differ is under-detected without a seeded ownership matrix.
- **No per-input path novelty and no real comparison instrumentation.** Coverage is bucketed edge-hit feedback; there is no branch-distance signal (EvoMaster) and no IL-level CMPLOG (only the error-body mining). Magic-value checks that the validation layer does not volunteer remain hard to pass.
- **Docker-only grey-box.** The coverage channel assumes a container and a tmpfs bitmap; there is no non-Docker host mode yet.
- **Production-mode exception fidelity is reduced in hook mode.** The outermost `IStartupFilter` middleware cannot always see exceptions a global handler swallows; `--inject-mode source` is the fallback.
- **No structural, schema-driven body mutation.** Constraints inform value generation but not `oneOf`/discriminator-respecting structural mutation.
- **No deterministic record/replay.** Runs are not yet bit-for-bit repeatable (the RNG is unseeded), which is a real reproducibility gap for a security tool.
- **REST only.** gRPC, GraphQL, and SignalR — all common in .NET — are outside the grammar.

---

## Future Work

The roadmap that would move this from "credible research tool" to "default choice" is, in rough priority:

1. **Deterministic record/replay + a global seed.** The cheapest remaining credibility win — a finding you cannot reproduce bit-for-bit is a finding a researcher distrusts.
2. **IL-level CMPLOG/RedQueen.** The project owns the Cecil pipeline; capturing comparison operands at rewrite time is the .NET analog of AFL++'s biggest depth feature and the largest bug-depth win available.
3. **An OAST server.** The gate for blind-vulnerability detection.
4. **Ownership-matrix BOLA.** Seed known-owned ids per identity and cross-replay them, turning body-comparison heuristics into ground-truth object-access tests.
5. **Response-schema conformance oracle.** Nearly free given the grammar already parses the spec, and it opens a whole class of contract bugs.
6. **Non-REST protocols and a non-Docker host mode** for reach.

---

## Conclusion

UpsideFuzz is not a new fuzzing algorithm. Its scheduler is AFL++ ideas ported to request selection, its coverage buckets are AFL's, its producer-consumer chaining is RESTler's idea, and its IL rewriting is SharpFuzz. What is new is the *assembly*: grey-box coverage feedback on arbitrary .NET web APIs, delivered through zero-edit runtime instrumentation that survives lazily loaded assemblies, feeding a fuzzer whose bug oracle produces exploitation evidence instead of stack traces — and which is honest, in code and in reporting, about where it is blind.

For a security researcher the interesting parts are concrete and reusable: the startup-hook + hosting-startup pattern for attaching coverage to a .NET app you do not own; the first-observer-wins attribution that makes per-request coverage usable under concurrency; the evidence-gated access-control oracles that keep false positives down; and the discipline of tracking your own blind spots in the output. Whether or not you fuzz .NET, those decisions are the useful takeaways.

The project is open source and the roadmap above is real and public. The instrumentation and oracle layers are the parts I would point a fellow researcher at first — and the parts I would most like to see torn apart, improved, and argued with.
