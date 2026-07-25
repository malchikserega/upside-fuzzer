# Duration scaling (T0) and how to run a 1-hour session

Results from three UpsideFuzz runs against `fixtures/planted-bug-api/` (T0) at
5, 10, and 20 minutes, run on an isolated standalone container
(`bench-t0-standalone`, port 7778 — deliberately separate from the
`bench-planted-bug-prep-instrumented-1` container the `BENCHMARK_PLAN.md`
pilot batch was using concurrently on port 7777, to avoid corrupting either
run). Same grammar (`/tmp/bench-grammar`), same `-seed 501` across all three,
fresh container restart + `/shm/reset` between each run.

## Results

| Duration | requests_done | coverage_end_edges | crashes_total | crashes_unique | distinct_root_causes |
|---|---|---|---|---|---|
| 5 min  | 625,031   | 616 | 74,746  | 4 | 2 |
| 10 min | 1,022,068 | 534 | 145,265 | 4 | 2 |
| 20 min | 1,710,151 | 195 | 527,968 | 4 | 2 |

Raw artifacts: `benchmarks/raw/duration-scaling/{crashes,unique,summary,report}-{5,10,20}min.json*`.

**What this shows:** against a target this small (3 real endpoints), UpsideFuzz
finds the same 2 distinct root causes within the first 5 minutes and plateaus
— `coverage_end_edges` doesn't even monotonically increase run-to-run (616 →
534 → 195 across the three independent runs) because each run started from a
*fresh* container with its own random `Items` id sequence and the
coverage-percentage-of-baseline metric is a proxy, not a hard ceiling (see
`ARCHITECTURE.md`'s coverage section for why). What *does* scale monotonically
with duration is raw request volume (625K → 1.02M → 1.71M requests) and crash
volume (74.7K → 145K → 528K) — i.e. the same 2 bugs get hit far more often,
not new ones discovered. Extra time here buys **confidence**
(`reproducibility_rate`, `variant_signatures` climbing from the same 2
clusters) and volume, not new bug classes — expected and correct for a
3-endpoint fixture, and not representative of what longer budgets buy against
a real target with dozens/hundreds of endpoints (see below).

## How to run a 1-hour session yourself

### Against T0 (this fixture) — for further harness/duration validation only

```bash
# 1. Bring up a fresh, isolated instance (don't reuse a container another
#    benchmark run might still be using — check `docker ps` first).
docker run -d --name my-t0-1h -p 7779:8080 -e ASPNETCORE_ENVIRONMENT=Development \
  bench-planted-bug-prep-instrumented:latest
curl -s -X POST http://localhost:7779/shm/reset

# 2. Compile the grammar once if you don't already have one:
curl -s http://localhost:7779/swagger/v1/swagger.json -o /tmp/t0-swagger.json
./compile-grammar.sh /tmp/t0-swagger.json --out /tmp/t0-grammar-1h

# 3. Run for 60 minutes:
TARGET_HOST=http://localhost:7779 ./void/go/void \
  -grammar /tmp/t0-grammar-1h -time-budget 60 -seed <pick-one> \
  -crash-file benchmarks/raw/duration-scaling/crashes-60min.jsonl \
  -unique-crash-file benchmarks/raw/duration-scaling/unique-60min.jsonl \
  -summary-file benchmarks/raw/duration-scaling/summary-60min.json \
  -no-ui
```

On T0 specifically, do not expect new bug classes at 60 minutes beyond what
5 minutes already finds — this fixture only has the two root causes described
above. A 1-hour run here is useful for confirming stability/reproducibility
numbers and for stress-testing the harness itself (memory growth, artifact
file sizes — `crashes.jsonl` alone was already tens of MB by the 10-minute
mark; expect several hundred MB by 60 minutes at this request rate), not for
finding anything new.

### Against a real target (T1 eShopOnWeb / T2 SimplCommerce / T3 BTCPayServer / Bitwarden) — where 1 hour actually matters

This is the budget tier `BENCHMARK_PLAN.md` §6 calls "Comparative (medium)"
— the primary comparative budget for a real head-to-head. Use the CLI
(`docs/CLI.md`) or the per-target `QUICKSTART_*.md`, and just raise the
budget:

```bash
# Example: eShopOnWeb (see QUICKSTART_ESHOP.md for the full from-scratch setup)
upsidefuzz fuzz --grammar grammars/eshop --target http://localhost:5200 \
  --profile security --time-budget 60

# Example: Bitwarden (see QUICKSTART_BITWARDEN.md)
upsidefuzz fuzz --grammar grammars/bitwarden --target http://localhost:4000 \
  --profile security --skip-endpoint-on-500 --time-budget 60 \
  --auth-file bitwarden_prep/auth.identities.json
```

For a **benchmark-grade** 1-hour run (not just an ad-hoc one-off) instead of
the raw CLI, drive it through the harness this session built so you get the
full artifact set (`request_event.jsonl`, `coverage_event.jsonl`,
`resource_sample.jsonl`, `confirmed_bug.json`) instead of just the crash
JSONLs:

```bash
python3 benchmarks/harness/run_cell.py \
  --run-id <target>-60min-<n> --experiment-id manual --out-dir benchmarks/raw/manual/<run-id> \
  --target-dir <prep-dir> --compose-file docker-compose.instrumented.yml \
  --readiness-url http://localhost:<port>/health --coverage-base http://localhost:<port> \
  --target-container <container-name> \
  --tool upsidefuzz --void-bin void/go/void --grammar-dir <grammar-dir> \
  --budget-minutes 60 --seed <n>
```

**Before committing to a real 1-hour run against T1–T3, be aware of two open
gaps from `BENCHMARK_PLAN.md` that matter more at this budget than they did
for the 5/10/20-minute T0 smoke runs above:**
- No golden-DB-snapshot reset exists yet for T1–T3 (real SQL Server/Postgres
  databases) — `reset_target.py` only fully implements the reset contract for
  DB-free T0 today (see its own docstring). For a real target, reset the
  database yourself before each run (`docker compose down -v && up -d` at
  minimum) or accept that a 1-hour run accumulates state across runs.
- Disk usage scales with request volume, not wall-clock alone — expect
  gigabyte-scale `crashes.jsonl`/`request_event.jsonl` at 60 minutes against
  a real target with more endpoints than T0's three. Point `-crash-file`
  etc. somewhere with headroom, and consider `-event-log` only when you
  actually need per-request attribution (it's optional, off unless passed).
