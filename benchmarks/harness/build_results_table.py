#!/usr/bin/env python3
"""build_results_table.py -- consolidates every heterogeneous run under
benchmarks/raw/ (run_cell.py-style nested experiments AND flat one-off
`docker run void-fuzzer` sessions) into one presentable results table.

Two directory shapes are handled:
  1. Nested experiment (e.g. raw/pilot/<run_id>/run.json + confirmed_bug.json)
     -- aggregated per config_id (see run_batch.py's run_id convention).
  2. Flat single-run dir (e.g. raw/eshop-5m/summary-*.json + unique-*.jsonl)
     -- read directly, one row per directory.

Usage:
  build_results_table.py --raw-dir benchmarks/raw --out benchmarks/reports/RESULTS_TABLE.md
"""
import argparse
import glob
import json
import statistics
from pathlib import Path


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def count_jsonl(path):
    try:
        return sum(1 for line in open(path, encoding="utf-8") if line.strip())
    except Exception:
        return 0


def bug_classes_from_unique_jsonl(path):
    classes = set()
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            triage = row.get("triage", {}) or {}
            cls = triage.get("classification") or ("access_control" if row.get("access_control") else None) \
                or ("injection" if row.get("injection") else None) or "unhandled_exception"
            classes.add(cls)
    except Exception:
        pass
    return classes


def flat_run_row(label, dir_path: Path):
    summaries = sorted(dir_path.glob("summary*.json"))
    if not summaries:
        summaries = sorted(dir_path.glob("summary/*.json"))
    if not summaries:
        return None
    summary = load_json(summaries[-1])
    if not summary:
        return None
    uniques = sorted(dir_path.glob("unique*.jsonl")) or sorted(dir_path.glob("unique*crashes*.jsonl"))
    classes = bug_classes_from_unique_jsonl(uniques[-1]) if uniques else set()
    return {
        "label": label,
        "tool": "upsidefuzz",
        "requests_done": summary.get("requests_done"),
        "coverage_edges": summary.get("coverage_end_edges"),
        "crashes_total": summary.get("crashes_total"),
        "crashes_unique": summary.get("crashes_unique"),
        "elapsed_secs": summary.get("elapsed_secs"),
        "bug_classes": sorted(classes),
    }


def nested_experiment_rows(label_prefix, dir_path: Path):
    rows = []
    by_config = {}
    for run_dir in sorted(dir_path.iterdir()):
        if not run_dir.is_dir():
            continue
        run_json = load_json(run_dir / "run.json")
        if not run_json:
            continue
        config_id = run_json["run_id"].rsplit("-", 2)[0]
        bugs = load_json(run_dir / "confirmed_bug.json") or []
        cov_events = run_dir / "coverage_event.jsonl"
        final_edges = None
        if cov_events.exists():
            for line in Path(cov_events).read_text().splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("edges") is not None:
                    final_edges = row["edges"]
        by_config.setdefault(config_id, []).append({
            "tool": run_json.get("tool"),
            "distinct_bugs": len(bugs),
            "h2h_bugs": sum(1 for b in bugs if b.get("head_to_head_eligible")),
            "final_edges": final_edges,
            "completion": run_json.get("completion_status"),
            "classes": {b.get("bug_class") for b in bugs},
        })
    for config_id, runs in sorted(by_config.items()):
        classes = sorted({c for r in runs for c in r["classes"] if c})
        med_edges = statistics.median([r["final_edges"] for r in runs if r["final_edges"] is not None]) if any(
            r["final_edges"] is not None for r in runs) else None
        rows.append({
            "label": f"{label_prefix}/{config_id}",
            "tool": runs[0]["tool"],
            "reps": len(runs),
            "median_distinct_bugs": statistics.median([r["distinct_bugs"] for r in runs]),
            "median_h2h_bugs": statistics.median([r["h2h_bugs"] for r in runs]),
            "median_final_edges": med_edges,
            "ok_reps": sum(1 for r in runs if r["completion"] == "ok"),
            "bug_classes": classes,
        })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir)
    flat_rows = []
    nested_rows = []

    for d in sorted(raw_dir.iterdir()):
        if not d.is_dir():
            continue
        has_run_json_children = any((c / "run.json").exists() for c in d.iterdir() if c.is_dir())
        if has_run_json_children:
            nested_rows.extend(nested_experiment_rows(d.name, d))
        else:
            r = flat_run_row(d.name, d)
            if r:
                flat_rows.append(r)

    lines = []
    lines.append("# UpsideFuzz -- Consolidated Results Table\n")
    lines.append("Auto-generated by `benchmarks/harness/build_results_table.py` from `benchmarks/raw/`. "
                  "Do not hand-edit -- re-run the script after new runs land.\n")

    lines.append("## Single-run sessions (real targets, one run each)\n")
    lines.append("| Run | Requests done | Coverage edges | Crashes (total/unique) | Elapsed (s) | Bug classes seen |")
    lines.append("|---|---:|---:|---:|---:|---|")
    for r in flat_rows:
        lines.append(f"| {r['label']} | {r['requests_done']:,} | {r['coverage_edges']:,} | "
                      f"{r['crashes_total']}/{r['crashes_unique']} | {r['elapsed_secs']:.0f} | "
                      f"{', '.join(r['bug_classes']) or '—'} |")

    lines.append("\n## Multi-rep experiments (median across reps, distinct-root-cause dedup)\n")
    lines.append("| Experiment/config | Tool | Reps (ok) | Median distinct bugs | Median head-to-head-eligible bugs | Median final coverage edges | Bug classes seen |")
    lines.append("|---|---|---|---:|---:|---:|---|")
    for r in nested_rows:
        lines.append(f"| {r['label']} | {r['tool']} | {r['reps']} ({r['ok_reps']}) | "
                      f"{r['median_distinct_bugs']} | {r['median_h2h_bugs']} | "
                      f"{r['median_final_edges'] if r['median_final_edges'] is not None else '—'} | "
                      f"{', '.join(r['bug_classes']) or '—'} |")

    Path(args.out).write_text("\n".join(lines) + "\n")
    print(f"[build_results_table] {len(flat_rows)} flat run(s), {len(nested_rows)} experiment config(s) -> {args.out}")


if __name__ == "__main__":
    main()
