#!/usr/bin/env python3
"""run_batch.py -- BENCHMARK_PLAN.md §15/§21 task #7: loops run_cell.py over
(config x repetition), serialized on this host (§15: "serialize on a single
pinned host for the headline comparative matrix -- eliminates noisy-neighbor
confounding"). Resumable: run_cell.py itself skips any run_id whose out-dir
already has a DONE marker, so re-running this script after an interruption
only executes what's left.

Batch spec (JSON): a list of "cell templates", each a dict of run_cell.py
flags MINUS --run-id/--out-dir/--experiment-id (this script fills those in)
PLUS a "reps" integer and a "config_id" label used to build run_ids. See
benchmarks/configs/pilot_t0.json for the smoke-pilot example this was built
to drive (BENCHMARK_PLAN.md §19 Phase 2 pilot, scaled down per this repo's
single-host/14-core reality).

Usage:
  run_batch.py --spec benchmarks/configs/pilot_t0.json \
    --experiment-id pilot --raw-dir benchmarks/raw
"""
import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True, help="Path to a batch spec JSON (list of cell templates)")
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--raw-dir", required=True, help="raw/<experiment_id>/ lands under here")
    ap.add_argument("--dry-run", action="store_true", help="Print planned run_ids without executing")
    args = ap.parse_args()

    spec = json.loads(Path(args.spec).read_text())
    experiment_root = Path(args.raw_dir) / args.experiment_id
    experiment_root.mkdir(parents=True, exist_ok=True)

    plan = []
    for cell in spec:
        cell = dict(cell)
        reps = cell.pop("reps", 1)
        config_id = cell.pop("config_id", "config")
        for rep in range(reps):
            run_id = f"{config_id}-rep{rep+1}-{uuid.uuid4().hex[:8]}"
            plan.append((run_id, cell))

    print(f"[run_batch] {len(plan)} run(s) planned across {len(spec)} cell template(s)", file=sys.stderr)
    if args.dry_run:
        for run_id, _ in plan:
            print(run_id)
        return

    failures = []
    for i, (run_id, cell) in enumerate(plan, 1):
        out_dir = experiment_root / run_id
        print(f"\n[run_batch] === run {i}/{len(plan)}: {run_id} ===", file=sys.stderr)
        cmd = [sys.executable, str(HERE / "run_cell.py"),
               "--run-id", run_id, "--experiment-id", args.experiment_id,
               "--out-dir", str(out_dir)]
        for k, v in cell.items():
            flag = "--" + k.replace("_", "-")
            if isinstance(v, list):
                cmd.append(flag)
                cmd += [str(x) for x in v]
            elif isinstance(v, bool):
                if v:
                    cmd.append(flag)
            else:
                cmd += [flag, str(v)]
        r = subprocess.run(cmd)
        if r.returncode != 0:
            failures.append(run_id)

    print(f"\n[run_batch] complete: {len(plan) - len(failures)}/{len(plan)} ok", file=sys.stderr)
    if failures:
        print(f"[run_batch] failed run_ids: {failures}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
