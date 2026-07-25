#!/usr/bin/env python3
"""run_cell.py -- BENCHMARK_PLAN.md §15/§21 task #7: runs ONE (target, tool
config, budget) cell end to end and preserves artifacts under
raw/<experiment>/<run_id>/, per §12's data model. This is the unit run_batch.py
loops over for repetitions; it is also directly usable standalone for a pilot.

Sequence (§13 reset & warm-up contract, §15 harness capabilities):
  1. reset_target.py  -- recreate the target stack, wait for real readiness,
     zero the coverage bitmap.
  2. Start coverage_poller.py + resource_sampler.py in the background.
  3. Run the fuzzing tool (RESTler test/fuzz-lean/fuzz, or void) for the
     budget. UpsideFuzz gets -event-log/-run-id/-seed wired automatically;
     RESTler is driven via benchmarks/docs/RESTLER_RUNBOOK.md's validated
     invocation.
  4. Stop poller/sampler (SIGTERM, they flush and exit).
  5. Run shared_judge.py against whatever the tool produced.
  6. Write run.json (§12) and a DONE marker (empty file) -- run_batch.py's
     resumability checks for this marker, not just directory existence, so a
     run killed mid-way is correctly re-attempted rather than skipped.

Usage (UpsideFuzz):
  run_cell.py --run-id <id> --out-dir raw/<experiment>/<run_id> \
    --target-dir /tmp/bench-planted-bug-prep --compose-file docker-compose.instrumented.yml \
    --readiness-url http://localhost:7777/health --coverage-base http://localhost:7777 \
    --target-container bench-planted-bug-prep-instrumented-1 \
    --tool upsidefuzz --void-bin /path/to/void --grammar-dir /tmp/bench-grammar \
    --budget-minutes 10 --seed 1

Usage (RESTler):
  run_cell.py --run-id <id> --out-dir raw/<experiment>/<run_id> \
    --target-dir /tmp/bench-planted-bug-prep --compose-file docker-compose.instrumented.yml \
    --readiness-url http://localhost:7777/health --coverage-base http://localhost:7777 \
    --target-container bench-planted-bug-prep-instrumented-1 \
    --tool restler --restler-dir /path/to/restler_bin/restler \
    --restler-grammar Compile/grammar.py --restler-dict Compile/dict.json \
    --restler-settings Compile/engine_settings.json --restler-target-port 7777 \
    --budget-minutes 10
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sh(cmd, cwd=None, env=None, check=True):
    print(f"$ {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    return subprocess.run(cmd, cwd=cwd, env=env, check=check)


def start_background(cmd, cwd=None, env=None):
    print(f"$ {' '.join(str(c) for c in cmd)}  (background)", file=sys.stderr)
    return subprocess.Popen(cmd, cwd=cwd, env=env)


def stop_background(proc, name):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        print(f"[run_cell] {name} did not exit within 15s, killing", file=sys.stderr)
        proc.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--experiment-id", default="pilot")
    ap.add_argument("--out-dir", required=True)

    ap.add_argument("--target-dir", required=True)
    ap.add_argument("--compose-file", default="docker-compose.instrumented.yml")
    ap.add_argument("--target-services", nargs="*", default=[])
    ap.add_argument("--readiness-url", required=True)
    ap.add_argument("--coverage-base", required=True, help="Base URL for /shm/coverage, /shm/reset (external poller + reset_target)")
    ap.add_argument("--target-container", required=True)

    ap.add_argument("--tool", required=True, choices=["upsidefuzz", "restler"])
    ap.add_argument("--budget-minutes", type=float, required=True)
    ap.add_argument("--seed", type=int, default=0, help="UpsideFuzz only")
    ap.add_argument("--dict-tag", default="none", help="Cosmetic label for run.json (e.g. none|generic-sec) -- does not itself select a dictionary file")

    # UpsideFuzz-specific
    ap.add_argument("--void-bin", default=None)
    ap.add_argument("--grammar-dir", default=None)
    ap.add_argument("--void-extra-args", nargs="*", default=[])

    # RESTler-specific
    ap.add_argument("--restler-dir", default=None)
    ap.add_argument("--restler-mode", default="test", choices=["test", "fuzz-lean", "fuzz"])
    ap.add_argument("--restler-grammar", default=None)
    ap.add_argument("--restler-dict", default=None)
    ap.add_argument("--restler-settings", default=None)
    ap.add_argument("--restler-target-host", default="localhost")
    ap.add_argument("--restler-target-port", default=None)

    ap.add_argument("--poll-interval", type=float, default=1.0)
    ap.add_argument("--sample-interval", type=float, default=2.0)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    done_marker = out_dir / "DONE"
    if done_marker.exists():
        print(f"[run_cell] {args.run_id} already DONE, skipping (resumable batch)", file=sys.stderr)
        return

    start_ts = time.time()

    # 1. Reset.
    reset_cmd = [
        sys.executable, str(HERE / "reset_target.py"),
        "--dir", args.target_dir, "--compose-file", args.compose_file,
        "--readiness-url", args.readiness_url,
        "--coverage-reset-url", args.coverage_base.rstrip("/") + "/shm/reset",
        "--timeout", "90",
    ]
    for svc in args.target_services:
        reset_cmd += ["--services", svc]
    r = sh(reset_cmd, check=False)
    if r.returncode != 0:
        (out_dir / "run.json").write_text(json.dumps({
            "run_id": args.run_id, "completion_status": "infra_fail",
            "stage": "reset", "start_ts": start_ts,
        }, indent=2))
        print("[run_cell] ABORT: reset_target.py failed", file=sys.stderr)
        sys.exit(1)

    # 2. Start poller + sampler.
    poller = start_background([
        sys.executable, str(HERE / "coverage_poller.py"),
        "--run-id", args.run_id, "--target", args.coverage_base,
        "--out", str(out_dir / "coverage_event.jsonl"),
        "--interval", str(args.poll_interval),
    ])
    sampler = start_background([
        sys.executable, str(HERE / "resource_sampler.py"),
        "--run-id", args.run_id, "--target-container", args.target_container,
        "--out", str(out_dir / "resource_sample.jsonl"),
        "--interval", str(args.sample_interval),
    ])

    completion_status = "ok"
    try:
        # 3. Run the tool.
        if args.tool == "upsidefuzz":
            if not args.void_bin or not args.grammar_dir:
                raise SystemExit("--void-bin and --grammar-dir are required for --tool upsidefuzz")
            env = dict(os.environ)
            env["TARGET_HOST"] = args.coverage_base
            cmd = [
                args.void_bin,
                "-grammar", args.grammar_dir,
                "-time-budget", str(args.budget_minutes),
                "-run-id", args.run_id,
                "-event-log", str(out_dir / "request_event.jsonl"),
                "-crash-file", str(out_dir / "crashes.jsonl"),
                "-unique-crash-file", str(out_dir / "unique-crashes.jsonl"),
                "-summary-file", str(out_dir / "summary.json"),
                "-no-ui",
            ]
            if args.seed:
                cmd += ["-seed", str(args.seed)]
            cmd += args.void_extra_args
            r = sh(cmd, env=env, check=False)
            if r.returncode != 0:
                completion_status = "tool_fail"
        else:
            if not (args.restler_dir and args.restler_grammar and args.restler_dict and args.restler_settings and args.restler_target_port):
                raise SystemExit("--restler-dir/--restler-grammar/--restler-dict/--restler-settings/--restler-target-port are required for --tool restler")
            env = dict(os.environ)
            env["DOTNET_ROLL_FORWARD"] = "Major"
            cmd = [
                "dotnet", "Restler.dll", "--python_path", sys.executable, args.restler_mode,
                "--grammar_file", args.restler_grammar,
                "--dictionary_file", args.restler_dict,
                "--settings", args.restler_settings,
                "--target_ip", args.restler_target_host,
                "--target_port", str(args.restler_target_port),
                "--no_ssl",
            ]
            if args.restler_mode == "fuzz":
                cmd += ["--time_budget", str(max(args.budget_minutes / 60.0, 1 / 60))]
            r = sh(cmd, cwd=args.restler_dir, env=env, check=False)
            if r.returncode != 0:
                completion_status = "tool_fail"
            # Copy whichever experiment dir RESTler just created for this mode
            # (Test/RestlerResults/experiment<N> or Fuzz/... -- capture it now
            # since the number isn't predictable in advance).
            mode_dir = {"test": "Test", "fuzz-lean": "Test", "fuzz": "Fuzz"}[args.restler_mode]
            results_root = Path(args.restler_dir) / mode_dir / "RestlerResults"
            if results_root.exists():
                candidates = sorted(results_root.glob("experiment*"), key=lambda p: p.stat().st_mtime)
                if candidates:
                    latest = candidates[-1]
                    dest = out_dir / "restler_experiment"
                    if dest.exists():
                        import shutil
                        shutil.rmtree(dest)
                    import shutil
                    shutil.copytree(latest, dest)
                    print(f"[run_cell] captured RESTler results: {latest} -> {dest}", file=sys.stderr)
    finally:
        # 4. Stop poller/sampler regardless of tool success/failure -- a
        # truncated time-series is still useful signal, an unbounded
        # background process leaking past this run is not.
        stop_background(poller, "coverage_poller")
        stop_background(sampler, "resource_sampler")

    # 5. Shared judge (best-effort; a judge failure shouldn't erase the run).
    judge_out = out_dir / "confirmed_bug.json"
    try:
        if args.tool == "upsidefuzz":
            unique_path = out_dir / "unique-crashes.jsonl"
            if unique_path.exists():
                sh([sys.executable, str(HERE / "shared_judge.py"),
                    "--tool", "upsidefuzz", "--run-id", args.run_id,
                    "--upsidefuzz-jsonl", str(unique_path), "--out", str(judge_out)], check=False)
        else:
            bucket_dir = out_dir / "restler_experiment" / "bug_buckets"
            if bucket_dir.exists():
                sh([sys.executable, str(HERE / "shared_judge.py"),
                    "--tool", "restler", "--run-id", args.run_id,
                    "--restler-bug-buckets", str(bucket_dir), "--out", str(judge_out)], check=False)
    except Exception as e:  # noqa: BLE001
        print(f"[run_cell] WARNING: shared_judge failed: {e}", file=sys.stderr)

    # 6. run.json + DONE marker.
    (out_dir / "run.json").write_text(json.dumps({
        "run_id": args.run_id,
        "experiment_id": args.experiment_id,
        "tool": args.tool,
        "dict_tag": args.dict_tag,
        "seed": args.seed if args.tool == "upsidefuzz" else None,
        "budget_minutes": args.budget_minutes,
        "start_ts": start_ts,
        "stop_ts": time.time(),
        "completion_status": completion_status,
    }, indent=2))
    done_marker.write_text("")
    print(f"[run_cell] {args.run_id} done, status={completion_status}", file=sys.stderr)


if __name__ == "__main__":
    main()
