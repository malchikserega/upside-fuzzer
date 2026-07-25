#!/usr/bin/env python3
"""reset_target.py -- BENCHMARK_PLAN.md §13 target reset & warm-up contract
(Top-15 task #2). Recreates a target's compose stack from a clean state,
waits for real readiness (not a fixed sleep), and resets the coverage bitmap
so both tools start every run from edges=0.

Scope note (honest, matches this repo's current target suite): T0
(fixtures/planted-bug-api) has NO database -- it's an in-memory
List<Item>, so "reset" is exactly `docker compose down -v && up -d`, which
is what this script does. For T1-T3 (eShopOnWeb/SimplCommerce/BTCPayServer),
each has a real SQL Server/Postgres database and needs a golden-snapshot
volume restore + a post-restore checksum/row-count gate before it's safe to
call "reset" -- that per-target snapshot mechanism is NOT built yet (it needs
each target's schema/seed data authored individually) and is intentionally
out of scope for the T0-only smoke pilot this script currently supports.
--db-checksum-url is accepted as a forward-compatible hook for when that
lands: if given, GET it after startup and abort on a value mismatch instead
of silently continuing on a contaminated dataset.

Usage:
  reset_target.py --dir /tmp/bench-planted-bug-prep \
      --compose-file docker-compose.instrumented.yml \
      --readiness-url http://localhost:7777/health \
      [--coverage-reset-url http://localhost:7777/shm/reset] \
      [--services instrumented] [--timeout 90]
"""
import argparse
import subprocess
import sys
import time
import urllib.error
import urllib.request


def run(cmd, cwd=None):
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    r = subprocess.run(cmd, cwd=cwd)
    return r.returncode


def wait_for_http_ok(url: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1.0)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="Target's prep directory (cwd for docker compose)")
    ap.add_argument("--compose-file", default="docker-compose.instrumented.yml")
    ap.add_argument("--services", nargs="*", default=[], help="Specific services to bring up (default: all)")
    ap.add_argument("--readiness-url", required=True, help="Polled until it returns HTTP 200")
    ap.add_argument("--coverage-reset-url", default=None, help="POSTed after readiness to zero the coverage bitmap (e.g. http://host:port/shm/reset)")
    ap.add_argument("--db-checksum-url", default=None, help="Forward-compat hook, not yet backed by real snapshot infra -- see module docstring")
    ap.add_argument("--expected-checksum", default=None)
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()

    down = ["docker", "compose", "-f", args.compose_file, "down", "-v"]
    if run(down, cwd=args.dir) != 0:
        print("[reset_target] WARNING: compose down failed (may be first run, continuing)", file=sys.stderr)

    up = ["docker", "compose", "-f", args.compose_file, "up", "-d"] + args.services
    if run(up, cwd=args.dir) != 0:
        print("[reset_target] FAIL: compose up failed", file=sys.stderr)
        sys.exit(1)

    print(f"[reset_target] waiting up to {args.timeout}s for {args.readiness_url} ...", file=sys.stderr)
    if not wait_for_http_ok(args.readiness_url, args.timeout):
        print(f"[reset_target] FAIL: {args.readiness_url} never returned 200 within {args.timeout}s -- "
              f"treat this run as infra_fail per BENCHMARK_PLAN.md §8, do not proceed", file=sys.stderr)
        sys.exit(1)
    print("[reset_target] target ready", file=sys.stderr)

    if args.db_checksum_url:
        try:
            with urllib.request.urlopen(args.db_checksum_url, timeout=10) as resp:
                got = resp.read().decode("utf-8", errors="replace").strip()
        except Exception as e:  # noqa: BLE001
            print(f"[reset_target] FAIL: --db-checksum-url set but unreachable: {e}", file=sys.stderr)
            sys.exit(1)
        if args.expected_checksum is not None and got != args.expected_checksum:
            print(f"[reset_target] FAIL: dataset checksum mismatch (got {got!r}, expected {args.expected_checksum!r}) "
                  f"-- discard and retry per BENCHMARK_PLAN.md §13, do not run a contaminated dataset", file=sys.stderr)
            sys.exit(1)
        print(f"[reset_target] dataset checksum OK: {got}", file=sys.stderr)

    if args.coverage_reset_url:
        req = urllib.request.Request(args.coverage_reset_url, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status != 200:
                    print(f"[reset_target] WARNING: coverage reset returned HTTP {resp.status}", file=sys.stderr)
                else:
                    print("[reset_target] coverage bitmap reset to 0", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[reset_target] WARNING: coverage reset request failed: {e}", file=sys.stderr)

    print("[reset_target] OK", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
