# How UpsideFuzz Works (and why it exists)

*A plain-language introduction. If you already know what coverage-guided fuzzing is and just want commands, go to [INSTRUCTIONS.md](quickstart.md) or a [quickstart](../index.md). If you want implementation-level detail, go to [ARCHITECTURE.md](../architecture/overview.md). This page is the bridge between "what is this tool" and those two.*

---

## The problem

Say you have a REST API — dozens or hundreds of endpoints, backed by a real database, with authentication, authorization rules, and validation logic scattered across the codebase. You want to know: **does it have exploitable bugs?** Not "does it crash," but specifically: can one user read another user's data? Can a normal user assign themselves admin rights by sending an extra JSON field? Is there a SQL injection hiding behind a validation layer that only *looks* like it sanitizes input?

Manually auditing every endpoint doesn't scale. Automated tools exist, but they mostly fall into two categories, each with a real gap:

- **Black-box REST fuzzers** (RESTler, Dredd, Schemathesis) send lots of requests derived from the API's OpenAPI spec, but they have no idea what's actually happening inside the server. They can't tell "this input reached deep, rarely-tested code" from "this input got rejected by the first validation check and never went anywhere." They also, almost universally, only look for crashes (500s) — not for the access-control and business-logic bugs that make REST APIs actually dangerous to attack. A tool that finds a 500 error told you the app is *fragile*. It told you nothing about whether it's *insecure*.
- **Static analyzers / SAST tools** read the code without running it. They're good at some classes of bug but can't observe runtime behavior — they don't know which validation rules are actually enforced, which routes require auth in practice, or what a real response looks like when one identity requests another identity's resource.

UpsideFuzz exists to close both gaps at once: real coverage feedback from *inside* the running .NET process, combined with fuzzing logic that specifically looks for the bug classes that matter most for REST APIs (broken access control, mass assignment, injection) — not just crashes.

## The idea, in one paragraph

UpsideFuzz rewrites the target .NET application's compiled IL (via [SharpFuzz](https://github.com/Metalnem/sharpfuzz)) so that every basic block it executes marks a bit in a shared-memory bitmap the fuzzer can read in real time. This means the fuzzer *knows* whether a given request reached new code — the same core idea as AFL/libFuzzer for binaries, applied to a live REST API instead of a single binary input. On top of that coverage signal, it builds a typed request grammar directly from the target's OpenAPI spec (optionally sharpened with real C# validation constraints extracted via Roslyn, so generated values are more likely to pass validation and reach interesting code), and it runs a Go-based mutation engine that doesn't just try to make the server crash — it actively tests specific hypotheses about the bug classes real REST APIs are most often vulnerable to.

## How the pieces fit together

```
 Your .NET source                Your running API                 The grammar
        │                               │                               │
        ▼                               ▼                               │
 ┌──────────────┐              ┌────────────────┐                       │
 │ Instrument    │─────build───▶│ Instrumented   │◀─────coverage────┐   │
 │ (SharpFuzz IL │              │ container      │   read via SHM/  │   │
 │  rewriting,   │              │ (zero source   │   HTTP           │   │
 │  zero edits)  │              │  edits needed) │                  │   │
 └──────────────┘              └───────┬────────┘                  │   │
                                        │  HTTP requests             │   │
                                        │◀───────────────────────────┘   │
                                        │                                 │
 ┌──────────────────┐          ┌───────▼────────┐              ┌────────▼───────┐
 │ tools/dotnet/analyzer/  │─constraints▶│                │◀─────grammar─│ tools/grammar/grammarc/       │
 │ (Roslyn: real     │          │  Void engine   │              │ (OpenAPI parser,│
 │  per-field        │          │  (Go)          │              │  no RESTler)    │
 │  validation       │          └───────┬────────┘              └─────────────────┘
 │  rules)           │                  │
 └──────────────────┘                  ▼
                                 findings: crashes, BOLA,
                                 mass-assignment, injection,
                                 differential auth-bypass —
                                 triaged and deduplicated
```

Three things are happening simultaneously, and all three feed each other:

1. **Coverage feedback** tells the engine which requests are "interesting" (reached new code) so it can spend more time mutating variations of those, instead of wasting requests on inputs that get rejected before they do anything.
2. **A typed grammar** tells the engine what a *valid* request even looks like for each endpoint — required fields, types, and (where source is available) the real length/range/pattern/enum constraints the server will actually enforce — so mutation starts from something the server accepts, then deliberately breaks it in targeted ways, rather than firing garbage that never gets past basic validation.
3. **Vulnerability oracles** run continuously alongside ordinary fuzzing, replaying successful requests under different conditions to test specific security hypotheses (see below) — this is the part most other REST fuzzers don't have at all.

For the literal step-by-step commands that produce this pipeline, see [INSTRUCTIONS.md](quickstart.md). For per-file implementation detail, see [ARCHITECTURE.md](../architecture/overview.md).

---

## Instrumentation & coverage: how the fuzzer knows what code actually ran

This is the foundation everything else sits on, so it's worth explaining in plain terms before anything else.

**The core trick:** before your app runs, UpsideFuzz edits the *compiled* .NET assemblies (never your `.cs` source files) to insert a tiny "check-in" at every branch of every method — think of it like a fingerprint scanner at every doorway in a building. Every time a request walks through a doorway (executes a branch of code), it leaves a mark in a block of memory shared between the running app and the fuzzer (a "bitmap"). The fuzzer reads that shared memory after every request and asks one question: *did this request open any doors nobody has opened before?* If yes, that request is "interesting" and gets mutated further; if it just walked through doors already marked, it's less interesting. This is the same core idea binary fuzzers like AFL use, applied to a live REST API's execution instead of a single program's input.

Two details make this more than a crude "did anything new happen" check:

- **Hit counts, not just presence.** A door being opened *once* vs. *5,000 times* are recorded differently (in log-scale buckets: 1, 2, 3, 4–7, 8–15, …). Why this matters: a loop, a pagination handler, or a retry mechanism only *looks* interesting once you push it deeper than the first iteration — a fuzzer that only asks "was this door opened at all" plateaus instantly and never learns that "opened it 500 times" is a meaningfully different (and more bug-prone) situation than "opened it once."
- **Zero source edits, by default.** Instead of editing your `Program.cs`/`Startup.cs` to wire the coverage hook in, UpsideFuzz uses a .NET feature (`DOTNET_STARTUP_HOOKS`) that injects the hook at process startup from *outside* your code entirely — so the target you're testing is built exactly the way it would ship, not a special "instrumented fork" of it.

**Why the bitmap size matters (and used to be a problem):** the shared-memory scoreboard has a fixed number of slots. A tiny app and a massive one (think: a small internal tool vs. Bitwarden's whole API surface) used to get the *same* fixed 256KB scoreboard — which meant a big app's many code paths kept landing on the same slots by coincidence ("hash collisions"), corrupting the signal, while a small app wasted most of a scoreboard it never touched. UpsideFuzz now measures, at build time, how much of the app it actually instrumented, and sizes the scoreboard accordingly (roughly 64KB for a small app up to 8MB for a very large one) — like using a net sized to the pond you're actually fishing in, instead of always the same net. Relatedly, the engine used to wipe the whole scoreboard clean the instant it got "too full," even mid-way through productively learning new things — now it only wipes when the board is *both* nearly full *and* has genuinely stopped teaching it anything new for a while, so a fixed percentage threshold never throws away real progress.

**Trust, but verify:** instrumentation can silently fail (wrong Docker image, wrong source path, a namespace accidentally excluded) — and a fuzzer that doesn't notice will happily burn its whole time budget "testing" an app it never actually instrumented, reporting a clean run that means nothing. Before a real run starts, UpsideFuzz sends a few real warm-up requests and checks the scoreboard actually moved; if it didn't, it refuses to start rather than silently fuzzing blind (you can override this, but it's opt-in, not the default).

## The grammar: what a valid request even looks like

Random bytes almost never look like a valid API request, so a fuzzer that mutates blindly spends nearly all its time being rejected by basic input validation before it ever reaches interesting code. UpsideFuzz avoids this by building a **typed grammar** directly from your OpenAPI/Swagger spec first: for every endpoint it knows the required fields, their types, and — where your C# source is available — the *actual* server-side validation rules (`[Range(0,100)]`, `[StringLength(50)]`, `[RegularExpression(...)]`, enum values, FluentValidation rules), extracted by parsing the real syntax tree of your code (not guessing from names). Mutation then starts from something the server is likely to accept, and deliberately breaks it in targeted ways — for a field with a max length of 50, it specifically tries 49, 50, and 51 characters (the exact boundary a bug is most likely to hide at) instead of a random string that's either obviously fine or obviously garbage.

The grammar also keeps learning while the fuzzer runs: when the server rejects a request with a helpful validation error (`"errors": {"Email": ["must be a valid email"]}` — the standard shape ASP.NET produces), UpsideFuzz reads that error text and feeds the required field names / valid-looking values it mentions back into its own dictionary, the same pool it draws from for future requests — so a validation-heavy API doesn't just block the fuzzer, it accidentally teaches it what it wants. It also learns from checks the server never *tells* anyone about: at instrumentation time, a second pass rewrites the target's own compiled code so that every `if (code == "SOME_HARDCODED_STRING")`-style comparison quietly reports the literal string or number it's comparing against, before the check even runs. Those recovered "magic values" — the kind no API spec or dictionary could ever guess — flow straight back into mutation too.

## Sequences: testing workflows, not just single requests

Some of the most damaging bugs don't live in any single endpoint — they live in the *order* of operations. `PUT /orders/{id}` is meaningless without a real order id, which only exists after a successful `POST /orders` created one; a coupon-then-refund or transfer-then-reverse business-logic bug only shows up if the fuzzer actually chains those steps together, not if it hammers each endpoint in isolation with made-up IDs.

UpsideFuzz's sequence engine watches successful writes: when a `POST` creates something and the response includes an id (in the JSON body or a `Location` header), the engine remembers it and feeds that *real* id into follow-up requests that need one — `GET`/`PUT`/`DELETE` on the same resource, prioritized in a realistic order. If a step in the chain fails (no real id available), it doesn't just give up — it falls back to a plausible fake id, so even a broken chain still gets to test whether downstream endpoints properly reject an id that shouldn't exist or isn't the caller's.

On top of that, the engine specifically rewards discovering a *new kind of workflow*, not just a workflow that happens to touch new code. It keeps a rough "shape" of every chain it's tried so far (which endpoints, in what order, roughly what kind of result each step got — success/redirect/rejected/error) and gives extra priority to continuing a chain the moment it recognizes the shape as one it's never explored before. This matters because ordinary code-coverage feedback can't tell "the 3rd identical `GET` after a `POST`" apart from "the 1st one" — they touch the same code — even though only the first one taught the fuzzer anything about workflow behavior. Rewarding *new workflow shapes* on top of *new code* is a coarse but real step toward finding logic bugs that only exist across multiple steps, not inside any one of them.

## Scheduling & mutation: deciding what to try next

With a huge space of possible requests and a limited time budget, *what to try next* matters as much as *what's possible to try*. UpsideFuzz splits its run into phases: first it sends every known request once, completely unmutated, to establish a baseline of what "normal" traffic reaches; then it systematically tweaks one field at a time (methodical, exhaustive-ish); then it starts stacking multiple aggressive mutations on top of each other at once (faster, messier, better at finding deep/weird bugs); and finally it starts splicing two different successful requests together, mixing their fields. Time is continuously reallocated *while running* — a phase that's stopped teaching the fuzzer anything new automatically loses budget to a phase that's still productive.

Within any phase, not every past request gets equal attention: ones that led to new code being reached earn more "energy" (a priority weight) and get revisited/mutated more, the same way a gambler puts more chips behind a strategy that's been paying off — while requests that consistently get rejected or lead nowhere new get gradually deprioritized so they don't eat the whole time budget.

## The oracles: what they actually catch, and why fuzzers usually miss this

A crash tells you code is fragile. It doesn't tell you code is *insecure* — plenty of unhandled exceptions are just sloppy error handling, not exploitable. The oracle families below are UpsideFuzz's answer to "how do you find bugs a crash-only fuzzer structurally cannot see," because in each case **the response is a normal, successful-looking 2xx** — nothing crashes, nothing looks wrong unless you know to check. The full, up-to-date list of every finding *type* (with the literal tag each one carries in the report) is the table in [README.md § Vulnerability Classes Detected](../../README.md#vulnerability-classes-detected) — this section explains the reasoning behind the ones that need it most.

### 1. Broken access control (BOLA / IDOR)

**The bug:** `GET /orders/482` returns order #482's details. If the API doesn't check that order #482 actually belongs to the user making the request, then any authenticated user can read (or modify, or delete) *anyone's* data just by changing the number in the URL. This is BOLA (Broken Object-Level Authorization) / IDOR (Insecure Direct Object Reference) — consistently one of the most common and most damaging classes of API vulnerability in the wild (it tops the OWASP API Security Top 10).

**Why it's invisible to crash-only tools:** the response is a perfectly normal 200 with a well-formed JSON body. There's no error, no stack trace, no signal at all unless you specifically compare *who is asking* against *whose data comes back*.

**What UpsideFuzz does:** whenever a request under one identity succeeds, the engine automatically replays the exact same request under every *other* configured identity, and once more with no credentials at all. If a different (or anonymous) identity gets back the same or another user's real data, that's flagged as a BOLA/broken-auth finding. This requires multi-identity support (see [docs/guides/authentication.md](../guides/authentication.md)) — the engine needs at least two distinct logged-in identities to compare against each other, which is why quickstarts for real targets walk through setting up multiple test accounts.

### 2. Mass assignment

**The bug:** a `PUT /users/me` endpoint that binds the incoming JSON straight onto a database model will happily accept fields the client was never supposed to be able to set — `isAdmin`, `role`, `accountBalance`, `verified` — if the server-side code doesn't explicitly restrict which fields are bindable. A regular user sends `{"name": "Alice", "isAdmin": true}` and, if the field isn't blocked server-side, becomes an admin.

**Why it's invisible to crash-only tools:** again, the response is a normal success. The client has to specifically send fields it shouldn't have access to, and then check whether they took effect.

**What UpsideFuzz does:** on successful write requests, it re-sends the same request with plausible privilege-escalation fields injected (`isAdmin`, `role: "SuperAdmin"`, `permissions: ["*"]`, and similar). If the field gets reflected back as accepted (or a follow-up read shows it took effect), that's a mass-assignment finding.

### 3. Positive injection detection

**The bug:** classic injection (SQL, template/SSTI) that a WAF-style "does this response contain an error message" check would miss entirely, because a well-behaved app under injection doesn't always error — it might just take longer, or evaluate an expression it shouldn't.

**What UpsideFuzz does:** rather than only looking for error strings, it runs *positive* checks — sending a time-delay SQL payload (`sleep(5)`-style) and measuring whether the response actually took ~5 seconds longer than baseline (time-based SQLi), or sending a template expression like `{{7*7}}` and checking whether the literal string `49` comes back evaluated in the response (server-side template injection). Reflected XSS is checked the same way — did the exact payload come back unescaped in the response body. These are *positive* signals: the server did something it should structurally never do, not just "returned an error."

### 4. Differential / parser-confusion auth bypass

**The bug:** an endpoint can enforce authorization for the *obvious* form of a request and still forget to enforce it for a slightly different-looking form of the exact same request. A login check written only with `GET` in mind might never fire for a `HEAD` request to the same route (technically the same operation, minus a response body). Middleware that only inspects requests declared as `Content-Type: application/json` can be skipped entirely by sending the identical bytes labeled `text/plain` while the app still happily parses them as JSON. Routing that's case-insensitive by default can sit behind a custom authorization check that isn't. None of these are "missing auth" in the simple sense — the check exists and works for the normal case; it just doesn't cover every equivalent way of asking the same question.

**Why it's invisible to crash-only tools (and to a plain auth-bypass check):** a plain "does this work with no login at all" test already gets correctly rejected here — the bug only appears when the *disguised* version of the same request is tried. A tool that only tests the literal, undisguised case will report the endpoint as properly protected and move on, missing exactly the bug that exists.

**What UpsideFuzz does:** it only tries this once it already knows an endpoint requires authentication — because a plain, literal request with no credentials was already confirmed to get rejected. On exactly those endpoints, it replays the request with no credentials again, but disguised four different ways: **verb confusion** (a `GET` reissued as `HEAD`), **content-type confusion** (identical body bytes, but declared as `text/plain` instead of `application/json`), **route-case confusion** (the same path with letter casing flipped), and **param-location confusion** (the same resource id duplicated as a query parameter instead of only living in the path). If a request that was correctly blocked in its plain form succeeds in one of these disguised forms, that's strong evidence the disguise itself — not general carelessness — broke the check, which is a more precise (and more fixable) finding than "auth is missing here."

### 5. Stateful business-logic oracles (stale objects, ignored ETags, workflow bypass, double-processing)

**The bug:** the four oracles above all replay a *single* request under different conditions. A whole other class of bug only exists across *multiple* requests in sequence — a resource that's still mutable after being deleted, a write that ignores the version/ETag it was supposed to check, an approval step that can be skipped entirely, or a payment that gets processed twice because a retry wasn't recognized as a duplicate.

**Why it's invisible to crash-only tools (and to the single-request oracles above):** none of these bugs are visible from one request in isolation — you have to have already established *prior state* (this exact resource was deleted three requests ago; this exact ETag was returned by an earlier GET; this exact invoice was created as `draft` and never `sent`) and then check whether a later request respects it.

**What UpsideFuzz does:** the typed resource-lifecycle graph (`-resource-graph`, on by default) tracks every resource instance's own state — created/readable/modified/deleted/stale — across the whole run, not just within one sequence chain. On top of that: a write or read against a resource already known deleted is flagged directly (stale-object); a write is replayed with a deliberately wrong `If-Match` header against a resource with a known real ETag (ignored optimistic locking); an action endpoint whose OpenAPI spec declares an `x-state-transition` is checked against the resource's actually-observed state before that action ran (workflow/approval bypass); and a just-succeeded create/payment POST is verbatim-replayed to see whether the server recognizes it as a duplicate or silently processes it again (idempotency / double-payment). See [docs/architecture/stateful-fuzzing.md](../architecture/stateful-fuzzing.md) for the full design.

### Why this combination is rare

Most open-source REST fuzzers do one of: black-box request generation (RESTler), schema-conformance checking (Schemathesis), or basic crash-finding — but not real .NET grey-box coverage *and* this oracle set *in the same tool*. That combination is UpsideFuzz's actual differentiator: the coverage signal makes fuzzing *deep* (it reaches code a black-box tool would never trigger), and the oracles make findings *meaningful* (a security researcher gets "user A can read user B's private data," not "endpoint X sometimes returns 500").

### How findings are reported honestly

Not every anomaly is a vulnerability, and UpsideFuzz doesn't pretend otherwise. Every finding is classified:

| Classification | What it means |
|---|---|
| `likely_vuln_high` / `likely_vuln` | A concrete exploitation signal fired (BOLA, mass assignment, time-based SQLi, evaluated SSTI, reflected XSS, stale-object/ETag, workflow bypass, idempotency, ...) |
| `confirmed_unhandled_exception` | A reproducible 500 with a real stack trace — a robustness bug, not a proven vulnerability |
| `needs_review` | A 500 that couldn't be confidently attributed (including down-ranked malformed-input parse errors) |
| `target_misconfiguration` | A dependency-injection/service-resolution failure from how the test image was built — excluded from the vulnerability count entirely |

This distinction matters: a tool that reports every 500 as a "vulnerability" trains its users to stop trusting it. See `triage.go`/`oracle.go` if you want the exact rules, or [ARCHITECTURE_REVIEW.md](../development/architecture-review.md) for a candid, no-marketing assessment of where this triage is strong and where it still has gaps.

---

## What's *not* magic here

Worth being upfront about, since overclaiming erodes trust fast in a security tool:

- Coverage feedback only helps as much as the target is actually instrumented — if a project's business logic lives somewhere the instrumentor's exclusion rules miss (see `ARCHITECTURE_REVIEW.md`'s subsystem reviews for known gaps), the fuzzer degrades to something closer to black-box.
- The oracles catch *specific, well-defined* signatures — BOLA/mass-assignment/injection/differential-auth-bypass plus the stateful family (stale object, ignored ETag, workflow bypass, idempotency) — they are not a general "did anything security-relevant happen" detector, and won't catch every possible logic flaw. `-probe-workflow-bypass` specifically only fires when the OpenAPI spec declares `x-state-transition`, which real-world specs rarely do. See [docs/architecture/stateful-fuzzing.md](../architecture/stateful-fuzzing.md) for what's still open in the stateful-fuzzing design, or `ARCHITECTURE_REVIEW.md` for the broader roadmap.
- A clean run (no findings) is not proof the API is secure. It means this specific run, with this specific grammar and time budget, didn't trigger a detectable signature. Treat it as one input to a security assessment, not the whole assessment.

## Where to go next

- **Run it against a real target**: pick a [quickstart](../index.md) (eShopOnWeb is the fastest way to see the whole pipeline work end to end).
- **Understand every step in depth**: [ARCHITECTURE.md](../architecture/overview.md) (pipeline: discovery → instrumentation → grammar) and [ARCHITECTURE_ENGINE.md](../architecture/engine.md) (the fuzzing runtime itself).
- **See the full command reference**: [INSTRUCTIONS.md](quickstart.md), [void/README.md](../../src/void/cmd/void/README.md).
- **See what's strong, what's weak, and what's planned**: [ARCHITECTURE_REVIEW.md](../development/architecture-review.md) — a genuinely candid engineering self-review, not a marketing page.
