# RESTler Runbook — Baseline Tool for BENCHMARK_PLAN.md

Validated 2026-07-24 against a live `fixtures/planted-bug-api/` instrumented
container (the same target and the same instrumented image UpsideFuzz fuzzes —
required by `BENCHMARK_PLAN.md` §5's fairness contract: "RESTler runs against
the *same instrumented image* so coverage is observed externally without
feeding RESTler"). This is Top-15 task #5 (`BENCHMARK_PLAN.md` §21).

## Environment finding

`restler_bin/restler/Restler.dll` targets `.NETCoreApp,Version=v6.0`. This
machine only has .NET 9/10 runtimes installed (.NET 6 is EOL). RESTler runs
fine anyway via runtime roll-forward:

```bash
export DOTNET_ROLL_FORWARD=Major
```

This must be set for every RESTler invocation (compile, test, fuzz-lean, fuzz,
replay) in the harness (`benchmarks/harness/`).

**Global options (`--python_path`, `--disable_log_upload`, etc.) must precede
the mode keyword** (`compile`/`test`/`fuzz-lean`/`fuzz`/`replay`), not follow
it — RESTler's CLI parses `restler [global options] <mode> [mode options]`.
Passing `--python_path` after `test` fails with `ERROR: Invalid argument:
--python_path` and dumps the help text instead of erroring clearly; this cost
real debugging time during validation and is worth documenting so nobody hits
it twice.

## Step 1: Compile the grammar from the target's live swagger

Uses the exact same `swagger.json` snapshot the `grammarc/` path would use —
required by the fairness contract (§5: "same `swagger.json` snapshot feeds
both `grammarc/` and the RESTler compiler").

```bash
curl -s http://localhost:<PORT>/swagger/v1/swagger.json -o swagger.json

cd restler_bin/restler
export DOTNET_ROLL_FORWARD=Major
dotnet Restler.dll compile --api_spec /abs/path/to/swagger.json \
  --python_path "$(which python3)"
```

Output lands in `./Compile/` (relative to cwd, i.e. `restler_bin/restler/Compile/`):
`grammar.py`, `dict.json`, `engine_settings.json`, `dependencies.json`. These
three feed `test`/`fuzz-lean`/`fuzz` mode.

**Verified on `fixtures/planted-bug-api/`:** compiled cleanly from a 3-endpoint
swagger (`/items`, `/items/{id}`, `/health`) in a few seconds, no errors.

## Step 2: Run against the live instrumented target

`test` mode (C1/C2 in `BENCHMARK_PLAN.md` §3 — "Test + Fuzz-lean, zero-config"
for C1; `fuzz-lean`/`fuzz` for deeper/longer campaigns):

```bash
cd restler_bin/restler
export DOTNET_ROLL_FORWARD=Major
dotnet Restler.dll --python_path "$(which python3)" test \
  --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --target_ip <target-host> --target_port <port> --no_ssl
```

For a dictionary-enabled config (C2/C4), swap `--dictionary_file` to point at
the shared `benchmarks/dictionaries/generic-sec.json` converted to RESTler's
flat dictionary shape (see `benchmarks/dictionaries/README.md`, §18 below) —
not yet authored, tracked separately.

For `fuzz` mode (long discovery runs, §6/§19 Phase 4), add
`--time_budget <hours>` and pick `--search_strategy` (default `bfs-fast`).

Output lands in `./Test/RestlerResults/experiment<N>/` (a fresh, incrementing
experiment directory per run — **the harness must capture this path per run,
it is not stable/predictable in advance**):
- `bug_buckets/bug_buckets.txt` — human-readable bug bucket summary (the
  RESTler-native classification; per `BENCHMARK_PLAN.md` §8, this is **not**
  used for the head-to-head comparison — the shared external judge, task #62,
  re-classifies both tools' raw findings with one taxonomy).
- `bug_buckets/bug_buckets.json`, `<bucket>_<n>.json`, `<bucket>_<n>.replay.txt`
  — the actual request/response evidence + a replayable repro script (feeds
  `replay` mode for the validation pipeline's reproduction step, §8).
- `../coverage_failures_to_investigate.txt` — RESTler's own coverage notion;
  per the fairness contract this is **not** used for coverage comparison
  either — the external poller (task #56) hitting `/shm/coverage` is the
  shared, tool-agnostic coverage measurement for both tools.

**Verified end-to-end:** compiled grammar tested against the live
`planted-bug-api` container on port 7777 found a real bug
(`main_driver_500: 1`, triggered by `GET /items?pageSize=1&pageIndex=1`) in
under a minute. Confirms RESTler is a viable, working baseline in this
environment without any patching.

## Step 3: Replay / reproduce (validation pipeline, §8)

```bash
cd restler_bin/restler
export DOTNET_ROLL_FORWARD=Major
dotnet Restler.dll --python_path "$(which python3)" replay \
  --replay_log Test/RestlerResults/experiment<N>/bug_buckets/<bucket>_<n>.replay.txt \
  --target_ip <target-host> --target_port <port> --no_ssl
```
Run against a freshly-reset target (§13) N times to compute
`reproducibility_rate`, same as UpsideFuzz's own repro pipeline.

## Auth parity (open item)

Not yet validated: RESTler's `--token_refresh_command` mechanism against this
project's multi-identity `auth.identities.json` format. `planted-bug-api` has
no auth, so this pilot target doesn't exercise it. **Must be resolved before
T1/T2/T3 (auth-bearing targets) can run fairly** — if RESTler cannot consume
a multi-identity file the way UpsideFuzz does, `BENCHMARK_PLAN.md` §5 says to
restrict that cell to single-identity for *both* tools and note it. Tracked
as a follow-up, not blocking the T0-only smoke pilot (task #65).

## Known limitation carried into the benchmark

RESTler exposes limited/no equivalent of `-seed`; combined with UpsideFuzz's
own current lack of a seed flag (task #59, landing alongside this), every
repetition in the benchmark is an independent random draw for both tools —
per §7, compensate with repetition count, not by pretending determinism
exists on either side today.
