# How UpsideFuzz Works (and why it exists)

*A plain-language introduction. If you already know what coverage-guided fuzzing is and just want commands, go to [INSTRUCTIONS.md](../INSTRUCTIONS.md) or a [quickstart](../docs/INDEX.md). If you want implementation-level detail, go to [ARCHITECTURE.md](../ARCHITECTURE.md). This page is the bridge between "what is this tool" and those two.*

---

## The problem

Say you have a REST API — dozens or hundreds of endpoints, backed by a real database, with authentication, authorization rules, and validation logic scattered across the codebase. You want to know: **does it have exploitable bugs?** Not "does it crash," but specifically: can one user read another user's data? Can a normal user assign themselves admin rights by sending an extra JSON field? Is there a SQL injection hiding behind a validation layer that only *looks* like it sanitizes input?

Manually auditing every endpoint doesn't scale. Automated tools exist, but they mostly fall into two categories, each with a real gap:

- **Black-box REST fuzzers** (RESTler, Dredd, Schemathesis) send lots of requests derived from the API's OpenAPI spec, but they have no idea what's actually happening inside the server. They can't tell "this input reached deep, rarely-tested code" from "this input got rejected by the first validation check and never went anywhere." They also, almost universally, only look for crashes (500s) — not for the access-control and business-logic bugs that make REST APIs actually dangerous to attack. A tool that finds a 500 error told you the app is *fragile*. It told you nothing about whether it's *insecure*.
- **Static analyzers / SAST tools** read the code without running it. They're good at some classes of bug but can't observe runtime behavior — they don't know which validation rules are actually enforced, which routes require auth in practice, or what a real response looks like when one identity requests another identity's resource.

UpsideFuzz exists to close both gaps at once: real coverage feedback from *inside* the running .NET process, combined with fuzzing logic that specifically looks for the bug classes that matter most for REST APIs (broken access control, mass assignment, injection) — not just crashes.

## The idea, in one paragraph

UpsideFuzz rewrites the target .NET application's compiled IL (via [SharpFuzz](https://github.com/Metalnem/sharpfuzz)) so that every basic block it executes marks a bit in a shared-memory bitmap the fuzzer can read in real time. This means the fuzzer *knows* whether a given request reached new code — the same core idea as AFL/libFuzzer for binaries, applied to a live REST API instead of a single binary input. On top of that coverage signal, it builds a typed request grammar directly from the target's OpenAPI spec (optionally sharpened with real C# validation constraints extracted via Roslyn, so generated values are more likely to pass validation and reach interesting code), and it runs a Go-based mutation engine that doesn't just try to make the server crash — it actively tests specific hypotheses about the three bug classes real REST APIs are most often vulnerable to.

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
 ┌──────────────┐              ┌───────▼────────┐              ┌────────▼───────┐
 │ analyzer/     │──constraints▶│                │◀─────grammar─│ grammarc/       │
 │ (Roslyn: real  │              │  Void engine   │              │ (OpenAPI parser,│
 │  per-field     │              │  (Go)          │              │  no RESTler)    │
 │  validation    │              └───────┬────────┘              └─────────────────┘
 │  rules)        │                      │
 └──────────────┘                      ▼
                                 findings: crashes,
                                 BOLA, mass-assignment,
                                 injection — triaged and
                                 deduplicated
```

Three things are happening simultaneously, and all three feed each other:

1. **Coverage feedback** tells the engine which requests are "interesting" (reached new code) so it can spend more time mutating variations of those, instead of wasting requests on inputs that get rejected before they do anything.
2. **A typed grammar** tells the engine what a *valid* request even looks like for each endpoint — required fields, types, and (where source is available) the real length/range/pattern/enum constraints the server will actually enforce — so mutation starts from something the server accepts, then deliberately breaks it in targeted ways, rather than firing garbage that never gets past basic validation.
3. **Vulnerability oracles** run continuously alongside ordinary fuzzing, replaying successful requests under different conditions to test specific security hypotheses (see below) — this is the part most other REST fuzzers don't have at all.

For the literal step-by-step commands that produce this pipeline, see [INSTRUCTIONS.md](../INSTRUCTIONS.md). For per-file implementation detail, see [ARCHITECTURE.md](../ARCHITECTURE.md).

---

## The oracles: what they actually catch, and why fuzzers usually miss this

A crash tells you code is fragile. It doesn't tell you code is *insecure* — plenty of unhandled exceptions are just sloppy error handling, not exploitable. The three oracle families below are UpsideFuzz's answer to "how do you find bugs a crash-only fuzzer structurally cannot see," because in each case **the response is a normal, successful-looking 200 OK** — nothing crashes, nothing looks wrong unless you know to check.

### 1. Broken access control (BOLA / IDOR)

**The bug:** `GET /orders/482` returns order #482's details. If the API doesn't check that order #482 actually belongs to the user making the request, then any authenticated user can read (or modify, or delete) *anyone's* data just by changing the number in the URL. This is BOLA (Broken Object-Level Authorization) / IDOR (Insecure Direct Object Reference) — consistently one of the most common and most damaging classes of API vulnerability in the wild (it tops the OWASP API Security Top 10).

**Why it's invisible to crash-only tools:** the response is a perfectly normal 200 with a well-formed JSON body. There's no error, no stack trace, no signal at all unless you specifically compare *who is asking* against *whose data comes back*.

**What UpsideFuzz does:** whenever a request under one identity succeeds, the engine automatically replays the exact same request under every *other* configured identity, and once more with no credentials at all. If a different (or anonymous) identity gets back the same or another user's real data, that's flagged as a BOLA/broken-auth finding. This requires multi-identity support (see [docs/FUZZER_AUTHENTICATION.md](FUZZER_AUTHENTICATION.md)) — the engine needs at least two distinct logged-in identities to compare against each other, which is why quickstarts for real targets walk through setting up multiple test accounts.

### 2. Mass assignment

**The bug:** a `PUT /users/me` endpoint that binds the incoming JSON straight onto a database model will happily accept fields the client was never supposed to be able to set — `isAdmin`, `role`, `accountBalance`, `verified` — if the server-side code doesn't explicitly restrict which fields are bindable. A regular user sends `{"name": "Alice", "isAdmin": true}` and, if the field isn't blocked server-side, becomes an admin.

**Why it's invisible to crash-only tools:** again, the response is a normal success. The client has to specifically send fields it shouldn't have access to, and then check whether they took effect.

**What UpsideFuzz does:** on successful write requests, it re-sends the same request with plausible privilege-escalation fields injected (`isAdmin`, `role: "SuperAdmin"`, `permissions: ["*"]`, and similar). If the field gets reflected back as accepted (or a follow-up read shows it took effect), that's a mass-assignment finding.

### 3. Positive injection detection

**The bug:** classic injection (SQL, template/SSTI) that a WAF-style "does this response contain an error message" check would miss entirely, because a well-behaved app under injection doesn't always error — it might just take longer, or evaluate an expression it shouldn't.

**What UpsideFuzz does:** rather than only looking for error strings, it runs *positive* checks — sending a time-delay SQL payload (`sleep(5)`-style) and measuring whether the response actually took ~5 seconds longer than baseline (time-based SQLi), or sending a template expression like `{{7*7}}` and checking whether the literal string `49` comes back evaluated in the response (server-side template injection). Reflected XSS is checked the same way — did the exact payload come back unescaped in the response body. These are *positive* signals: the server did something it should structurally never do, not just "returned an error."

### Why this combination is rare

Most open-source REST fuzzers do one of: black-box request generation (RESTler), schema-conformance checking (Schemathesis), or basic crash-finding — but not real .NET grey-box coverage *and* this oracle set *in the same tool*. That combination is UpsideFuzz's actual differentiator: the coverage signal makes fuzzing *deep* (it reaches code a black-box tool would never trigger), and the oracles make findings *meaningful* (a security researcher gets "user A can read user B's private data," not "endpoint X sometimes returns 500").

### How findings are reported honestly

Not every anomaly is a vulnerability, and UpsideFuzz doesn't pretend otherwise. Every finding is classified:

| Classification | What it means |
|---|---|
| `likely_vuln_high` / `likely_vuln` | A concrete exploitation signal fired (BOLA, mass assignment, time-based SQLi, evaluated SSTI, reflected XSS) |
| `confirmed_unhandled_exception` | A reproducible 500 with a real stack trace — a robustness bug, not a proven vulnerability |
| `needs_review` | A 500 that couldn't be confidently attributed (including down-ranked malformed-input parse errors) |
| `target_misconfiguration` | A dependency-injection/service-resolution failure from how the test image was built — excluded from the vulnerability count entirely |

This distinction matters: a tool that reports every 500 as a "vulnerability" trains its users to stop trusting it. See `triage.go`/`oracle.go` if you want the exact rules, or [ARCHITECTURE_REVIEW.md](../ARCHITECTURE_REVIEW.md) for a candid, no-marketing assessment of where this triage is strong and where it still has gaps.

---

## What's *not* magic here

Worth being upfront about, since overclaiming erodes trust fast in a security tool:

- Coverage feedback only helps as much as the target is actually instrumented — if a project's business logic lives somewhere the instrumentor's exclusion rules miss (see `ARCHITECTURE_REVIEW.md`'s subsystem reviews for known gaps), the fuzzer degrades to something closer to black-box.
- The oracles catch *specific, well-defined* signatures of BOLA/mass-assignment/injection — they are not a general "did anything security-relevant happen" detector, and won't catch every possible logic flaw (multi-step business-logic bugs, for instance, are an acknowledged open area — see the roadmap in `ARCHITECTURE_REVIEW.md`).
- A clean run (no findings) is not proof the API is secure. It means this specific run, with this specific grammar and time budget, didn't trigger a detectable signature. Treat it as one input to a security assessment, not the whole assessment.

## Where to go next

- **Run it against a real target**: pick a [quickstart](INDEX.md) (eShopOnWeb is the fastest way to see the whole pipeline work end to end).
- **Understand every step in depth**: [ARCHITECTURE.md](../ARCHITECTURE.md).
- **See the full command reference**: [INSTRUCTIONS.md](../INSTRUCTIONS.md), [void/README.md](../void/README.md).
- **See what's strong, what's weak, and what's planned**: [ARCHITECTURE_REVIEW.md](../ARCHITECTURE_REVIEW.md) — a genuinely candid engineering self-review, not a marketing page.
