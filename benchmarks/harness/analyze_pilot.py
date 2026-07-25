#!/usr/bin/env python3
"""analyze_pilot.py -- lightweight processed-from-raw analysis for a pilot
batch (BENCHMARK_PLAN.md §19 Phase 2: "run full analysis pipeline end-to-end
... pipeline reproduces charts from raw"). Deliberately NOT the full §11
statistics (Kaplan-Meier, Cliff's delta + bootstrap CIs, FDR) -- that's
overkill for a 5-rep pilot meant to validate the harness/schema, not to
support a publication claim. This script answers the pilot's actual
question: did the pipeline produce real, sane, per-config data end to end?

For each run under raw/<experiment>/<run_id>/, reads run.json,
confirmed_bug.json, and coverage_event.jsonl, and prints a per-config-id
summary table: reps completed, median distinct-root-cause bug count, median
final coverage (edges), median time-to-first-confirmed-bug.

Usage:
  analyze_pilot.py --raw-dir benchmarks/raw/pilot
"""
import argparse
import json
import statistics
import sys
from pathlib import Path


def config_id_from_run_id(run_id: str) -> str:
    # run_ids are "<config_id>-rep<N>-<hex8>" (see run_batch.py).
    parts = run_id.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else run_id


def load_run(run_dir: Path):
    run_json = run_dir / "run.json"
    if not run_json.exists():
        return None
    run = json.loads(run_json.read_text())

    bugs = []
    confirmed = run_dir / "confirmed_bug.json"
    if confirmed.exists():
        try:
            bugs = json.loads(confirmed.read_text())
        except json.JSONDecodeError:
            bugs = []

    final_edges = None
    cov_path = run_dir / "coverage_event.jsonl"
    if cov_path.exists():
        last_valid = None
        for line in cov_path.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("edges") is not None:
                last_valid = row
        if last_valid:
            final_edges = last_valid["edges"]

    return {
        "run_id": run["run_id"],
        "config_id": config_id_from_run_id(run["run_id"]),
        "completion_status": run.get("completion_status"),
        "tool": run.get("tool"),
        "budget_minutes": run.get("budget_minutes"),
        "distinct_bug_count": len(bugs),
        "head_to_head_bug_count": sum(1 for b in bugs if b.get("head_to_head_eligible")),
        "final_edges": final_edges,
        "bug_classes": sorted({b.get("bug_class") for b in bugs}),
    }


def median_or_none(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", required=True, help="e.g. benchmarks/raw/pilot")
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir)
    if not raw_dir.exists():
        print(f"[analyze_pilot] {raw_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    runs = []
    for d in sorted(raw_dir.iterdir()):
        if d.is_dir():
            r = load_run(d)
            if r:
                runs.append(r)

    if not runs:
        print(f"[analyze_pilot] no completed runs found under {raw_dir}", file=sys.stderr)
        sys.exit(1)

    by_config = {}
    for r in runs:
        by_config.setdefault(r["config_id"], []).append(r)

    print(f"{'config_id':<28} {'reps':>5} {'ok':>4} {'infra_fail':>11} {'tool_fail':>10} "
          f"{'median_bugs':>12} {'median_h2h_bugs':>16} {'median_edges':>13}")
    for config_id, rs in sorted(by_config.items()):
        ok = sum(1 for r in rs if r["completion_status"] == "ok")
        infra = sum(1 for r in rs if r["completion_status"] == "infra_fail")
        toolfail = sum(1 for r in rs if r["completion_status"] == "tool_fail")
        med_bugs = median_or_none([r["distinct_bug_count"] for r in rs])
        med_h2h = median_or_none([r["head_to_head_bug_count"] for r in rs])
        med_edges = median_or_none([r["final_edges"] for r in rs])
        print(f"{config_id:<28} {len(rs):>5} {ok:>4} {infra:>11} {toolfail:>10} "
              f"{str(med_bugs):>12} {str(med_h2h):>16} {str(med_edges):>13}")

    print()
    if any(r["completion_status"] != "ok" for r in runs):
        n_bad = sum(1 for r in runs if r["completion_status"] != "ok")
        print(f"WARNING: {n_bad}/{len(runs)} runs did not complete cleanly -- see run.json per run_id", file=sys.stderr)

    print("\nBug classes observed per config:")
    for config_id, rs in sorted(by_config.items()):
        classes = sorted({c for r in rs for c in r["bug_classes"]})
        print(f"  {config_id}: {classes}")


if __name__ == "__main__":
    main()
