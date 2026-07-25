# Running a 1-hour session against eShopOnWeb and Bitwarden

Verified stands (2026-07-24): `eshprep/` (eShopOnWeb, port 5200) and
`bitwarden_prep_clean/` (fresh Bitwarden checkout, hook-mode instrumented,
port 4000). Both already have compiled grammars (`grammars/eshop`,
`grammars/bitwarden-clean`) and both stacks are already running -- these
commands assume that's still true. If not, see QUICKSTART_ESHOP.md /
QUICKSTART_BITWARDEN.md for bring-up from scratch.

Both commands use **direct-shm** mode (`void-fuzzer` as a sidecar container
on the target's own Docker network, reading the coverage bitmap via a shared
tmpfs volume) -- faster than HTTP coverage polling, no per-request round trip.

## eShopOnWeb, 1 hour

```bash
cd /Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer
mkdir -p benchmarks/raw/eshop-1h

docker run --rm \
  --network eshprep_default \
  -v eshprep_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/eshop":/grammar:ro \
  -v "$(pwd)/benchmarks/raw/eshop-1h":/fuzzer/crashes \
  -v "$(pwd)/benchmarks/raw/eshop-1h":/fuzzer/summaries \
  -e TARGET_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e SHM_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e AUTH_URL=/api/authenticate \
  -e AUTH_BODY='{"username":"admin@microsoft.com","password":"Pass@word1"}' \
  -e AUTH_TOKEN_FIELD=token \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 60 \
  -concurrency 16 \
  -sequence-prob 0.40 \
  -sequence-max-depth 4 \
  -profile security \
  -seed 1 \
  -run-id eshop-1h \
  -no-ui
```

Run this **in the background** (or under `nohup`/`tmux`) -- it will run for a
full hour and most shells/CI runners have a shorter default command timeout.

## Bitwarden, 1 hour

Auth token in `bitwarden_prep_clean/fuzzer.env` expires ~1 hour after
`get_apikey.py` was run (see the JWT's own `exp` claim) -- if it's stale,
re-run `python3 examples/bitwarden/get_apikey.py` from
`bitwarden_prep_clean/` first (safe to re-run any time; it registers a fresh
user each time).

```bash
cd /Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer
mkdir -p benchmarks/raw/bitwarden-1h

docker run --rm \
  --network bitwarden_prep_clean_default \
  -v bitwarden_prep_clean_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/bitwarden-clean":/grammar:ro \
  -v "$(pwd)/benchmarks/raw/bitwarden-1h":/fuzzer/crashes \
  -v "$(pwd)/benchmarks/raw/bitwarden-1h":/fuzzer/summaries \
  --env-file bitwarden_prep_clean/fuzzer.env \
  -e TARGET_HOST=http://bitwarden_prep_clean-api-1:5000 \
  -e SHM_HOST=http://bitwarden_prep_clean-api-1:5000 \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 60 \
  -concurrency 16 \
  -sequence-prob 0.40 \
  -sequence-max-depth 4 \
  -profile security \
  -seed 1 \
  -run-id bitwarden-1h \
  -no-ui
```

**For a real multi-identity BOLA/access-control campaign** (recommended for
Bitwarden specifically -- it's the one target here with rich org/collection/
cipher ownership semantics worth testing cross-user): first run, from
`bitwarden_prep_clean/`:
```bash
python3 ../examples/bitwarden/make_bola_identities.py   # user-a, user-b, guest -> auth.identities.json
python3 ../examples/bitwarden/populate_data.py --auth-file auth.identities.json
```
then add `-auth-file /grammar/../auth.identities.json` (mount
`bitwarden_prep_clean/auth.identities.json` into the container alongside the
grammar, or copy it in) and `-identity-include-guest=true` to the `docker
run` command above. See `docs/FUZZER_AUTHENTICATION.md`.

## What to expect at 1 hour vs the 5/10/20-minute smoke tests

At 5–20 minutes on these two real targets (dozens to hundreds of endpoints,
not T0's 3), coverage and unique-finding counts were still climbing, unlike
T0 (which plateaus almost immediately -- see
`DURATION_SCALING_AND_1HOUR_GUIDE.md`'s T0-specific analysis). A 1-hour
budget on eShopOnWeb/Bitwarden should meaningfully increase:
- **Coverage edges** -- more of the epoch schedule (Deterministic/Havoc/
  Splicing, not just Baseline/Harvest) gets exercised at scale, and deeper
  sequence chains (`-sequence-max-depth 4` above) get time to actually
  execute.
- **Distinct root-cause bugs**, especially on Bitwarden's much larger surface
  (754 endpoints vs eShopOnWeb's ~30) -- the 5-minute Bitwarden run alone
  already found 8 distinct `likely_vuln`/`confirmed_unhandled_exception`
  findings across unrelated endpoint families; an hour gives the sequence
  engine and access-control oracles far more chances to chain into
  deeper/rarer combinations.
- **Reproducibility confidence** on findings already seen at 5–20 minutes
  (more replay/repro attempts against the same root cause).

## Known gaps that matter more at 1h than at 5–20min (be aware, not blocked)

- **No golden-DB-snapshot reset yet for these two targets**
  (`benchmarks/harness/reset_target.py` only has the full contract for T0,
  which has no database -- see `BENCHMARK_PLAN.md` §21 task #2). A 1-hour
  run will leave the database in a different state than it started (new
  catalog items, new ciphers/orgs, etc.) -- fine for a single illustrative
  run, but re-running without a reset means the *next* run starts from
  different data, which matters if you're trying to compare two 1-hour runs
  head-to-head later.
- **Disk usage** -- the 5/10/20-minute Bitwarden/eShopOnWeb runs here
  produced tens of MB of crash JSONL each; expect **hundreds of MB to
  low-GB** for a hedge 1-hour run at higher concurrency, especially on
  Bitwarden's much larger endpoint surface. Make sure
  `benchmarks/raw/{eshop,bitwarden}-1h/` has room, and note it's gitignored
  (`benchmarks/raw/`) -- these artifacts are local-only by design.
- **No `-event-log`/`-seed` reproducibility guarantee under concurrency** --
  `-seed 1` above removes most run-to-run variance but is not bit-for-bit
  deterministic with `-concurrency 16` (documented limitation, see
  `void/go/main.go`'s `-seed` flag help text).
