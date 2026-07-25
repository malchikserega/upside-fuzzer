#!/usr/bin/env python3
"""resource_sampler.py -- BENCHMARK_PLAN.md Top-15 task #1 (resource sampler
half). Samples CPU/RSS for the target and (optionally) the fuzzing tool at a
fixed cadence and appends resource_sample.jsonl rows, external to both
fuzzers (BENCHMARK_PLAN.md §16: "not collected by engine ... external sampler
(cgroups/`docker stats`)").

The tool under test may be a Docker container (UpsideFuzz's Docker CLI mode,
or a containerized RESTler invocation) or a plain local process (RESTler's
Restler.exe/dotnet process, or `void` run natively) -- both are supported so
the same sampler works for every configuration in BENCHMARK_PLAN.md §3.

Usage:
  resource_sampler.py --run-id <id> \
      --target-container bench-planted-bug-prep-instrumented-1 \
      [--tool-container <name> | --tool-pid <pid>] \
      --out raw/<experiment>/<run_id>/resource_sample.jsonl \
      [--interval 2.0] [--duration 3600]

Stops on SIGINT/SIGTERM (flushes and exits 0) or when --duration elapses.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

_STOP = False


def _handle_stop(signum, frame):
    global _STOP
    _STOP = True


def sample_container(name: str):
    """One-shot `docker stats --no-stream` sample for a single container.
    Returns (cpu_pct, rss_mb) or (None, None) if the container isn't running
    (expected right after a reset/restart -- not an error worth aborting for).
    """
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}\t{{.MemUsage}}", name],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None, None
        cpu_raw, mem_raw = out.stdout.strip().splitlines()[0].split("\t")
        cpu_pct = float(cpu_raw.strip().rstrip("%"))
        # MemUsage looks like "123.4MiB / 2GiB" -- take the used side.
        used = mem_raw.split("/")[0].strip()
        rss_mb = _parse_mem_to_mb(used)
        return cpu_pct, rss_mb
    except Exception:  # noqa: BLE001 -- a missed sample must not kill the run
        return None, None


def sample_pid(pid: int):
    """One-shot `ps` sample for a local process by PID. Returns (cpu_pct, rss_mb)
    or (None, None) if the process has exited."""
    try:
        out = subprocess.run(
            ["ps", "-o", "%cpu=,rss=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        line = out.stdout.strip()
        if out.returncode != 0 or not line:
            return None, None
        cpu_raw, rss_raw = line.split()
        return float(cpu_raw), float(rss_raw) / 1024.0  # ps rss is in KB
    except Exception:  # noqa: BLE001
        return None, None


def _parse_mem_to_mb(s: str) -> float:
    s = s.strip()
    for suffix, mult in (("GiB", 1024.0), ("MiB", 1.0), ("KiB", 1.0 / 1024.0),
                         ("GB", 1000.0), ("MB", 1.0), ("KB", 1.0 / 1000.0), ("B", 1.0 / 1_000_000)):
        if s.endswith(suffix):
            try:
                return float(s[: -len(suffix)]) * mult
            except ValueError:
                return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--target-container", required=True, help="Docker container name/id running the instrumented target")
    ap.add_argument("--tool-container", default=None, help="Docker container name/id running the fuzzing tool, if containerized")
    ap.add_argument("--tool-pid", type=int, default=None, help="Local PID of the fuzzing tool, if run natively (alternative to --tool-container)")
    ap.add_argument("--out", required=True, help="Path to resource_sample.jsonl (appended)")
    ap.add_argument("--interval", type=float, default=2.0, help="Sample cadence in seconds (default 2.0)")
    ap.add_argument("--duration", type=float, default=0.0, help="Stop after this many seconds (0 = run until signaled)")
    args = ap.parse_args()

    if args.tool_container and args.tool_pid:
        print("[resource_sampler] specify at most one of --tool-container / --tool-pid", file=sys.stderr)
        sys.exit(2)

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    start = time.time()
    n = 0

    with open(args.out, "a", buffering=1) as f:
        while not _STOP:
            now = time.time()
            elapsed = now - start
            if args.duration > 0 and elapsed >= args.duration:
                break

            target_cpu, target_rss = sample_container(args.target_container)
            if args.tool_container:
                tool_cpu, tool_rss = sample_container(args.tool_container)
            elif args.tool_pid:
                tool_cpu, tool_rss = sample_pid(args.tool_pid)
            else:
                tool_cpu, tool_rss = None, None

            row = {
                "run_id": args.run_id,
                "ts": now,
                "elapsed_s": round(elapsed, 3),
                "target_cpu": target_cpu,
                "target_rss_mb": target_rss,
                "tool_cpu": tool_cpu,
                "tool_rss_mb": tool_rss,
            }
            f.write(json.dumps(row) + "\n")
            n += 1

            time.sleep(max(0.0, args.interval))

    print(f"[resource_sampler] stopped after {n} samples, run_id={args.run_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
