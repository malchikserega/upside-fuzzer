# planted-bug-api — E2E regression fixture

A minimal, self-contained ASP.NET Core minimal-API project (no database, no external
services) used by `scripts/e2e-test.sh` / `.github/workflows/e2e.yml` (Top-20 #7) to
prove the whole pipeline — instrument → coverage → grammar → fuzz → detect — actually
works end to end, not just that each stage runs without error.

## The planted bug

`GET /items?pageSize=&pageIndex=` (`Program.cs`) computes `skip = pageIndex * pageSize`
and calls `items.GetRange(skip, Math.Min(pageSize, items.Count - skip))` with **no bounds
check**. Any negative `pageSize` (or a `pageIndex` that pushes the computed count
negative) throws `ArgumentOutOfRangeException` → unhandled 500 — deterministically, with
no dependency on prior state (it crashes even against an empty list, so no `POST /items`
sequencing is required first).

This mirrors a real bug class this project's own fuzzer found for real on eShopOnWeb
during this session's verification runs (`GET /api/catalog-items?pageSize=-2` → 500) —
a realistic planted bug, not a synthetic one, and one that Top-20 #14's constraint-aware
integer boundary mutation (`{min-1, min, min+1, max-1, max, max+1}` blended into
`mutateInt`) reaches fast, which is why this fixture became feasible for a short CI time
budget.

**This fixture has already earned its keep once.** Top-20 #4's first implementation
attempt computed a per-assembly "linked" verdict inside `/shm/health` by checking whether
each app assembly itself defined SharpFuzz's `Trace` type — which is never true by
construction (that type lives only in `SharpFuzz.Common.dll`), so it flagged this fixture
(a genuinely healthy target) as degraded. `scripts/e2e-test.sh` failed immediately with
`run failed: coverage instrumentation degraded: ...`, catching the bug before it shipped.
The fix moved the verdict to the Go engine (`coverage.go::checkCoverageHealth`), which
sends a real warm-up probe and checks whether the bitmap actually gains edges instead.

Nested under `src/PlantedBugApi/` (not flat at the fixture root) deliberately — matching
the same multi-project-solution layout convention every real target in this repo uses
(`eshprep/src/PublicApi/`, `bitwarden_prep/src/Api/`, etc). `fuzz-prep-multi.py`'s
generated Dockerfile does `COPY . ./` then relies on the SDK-style project's own
`**/*.cs` glob; a flat single-project layout would pull the tool's own generated sibling
`instrumentor_src/Program.cs` (also top-level statements) into the same compile,
producing `CS8802: Only one compilation unit can have top-level statements`. Nesting the
project one level down avoids this exactly the way real multi-project targets already do.

## Running it standalone (outside the E2E script)

```bash
cd fixtures/planted-bug-api/src/PlantedBugApi
dotnet run
# in another terminal:
curl "http://localhost:5000/items?pageSize=-2&pageIndex=0"   # -> 500, planted bug
curl "http://localhost:5000/items?pageSize=10&pageIndex=0"   # -> 200, empty list
```

## Running it through the real pipeline

Same commands a real target would use — see `scripts/e2e-test.sh` for the exact sequence
this fixture is exercised with in CI:

```bash
python3 fuzz-prep-multi.py --src fixtures/planted-bug-api --out /tmp/planted-bug-prep --main PlantedBugApi
cd /tmp/planted-bug-prep && docker compose build && docker compose up -d
# ... compile-grammar.sh, void -direct-shm, etc.
```
