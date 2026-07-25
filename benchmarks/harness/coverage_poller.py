#!/usr/bin/env python3
"""coverage_poller.py -- BENCHMARK_PLAN.md Top-15 task #1 (external coverage
poller). Polls a target's GET /shm/coverage endpoint at a fixed cadence and
appends coverage_event.jsonl rows, with NO changes to either fuzzer under
test. This is what makes the coverage-over-time comparison fair (BENCHMARK_PLAN.md
§5: "the engine falls back to periodic polling ... coverage measurement for
the benchmark must use the external poll, not the header") and tool-agnostic:
the same script runs unmodified against a RESTler run and a UpsideFuzz run,
since both point at the same instrumented target.

Usage:
  coverage_poller.py --run-id <id> --target http://localhost:7777 \
      --out raw/<experiment>/<run_id>/coverage_event.jsonl \
      [--interval 1.0] [--duration 3600]

Stops on SIGINT/SIGTERM (flushes and exits 0) or when --duration elapses,
whichever first. Designed to be started by the batch harness (task #7)
immediately after the target's coverage bitmap is reset (BENCHMARK_PLAN.md
§13: "Coverage reset: POST /shm/reset immediately before the measured window
so edges start at 0 for both tools").
"""
import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request

_STOP = False


def _handle_stop(signum, frame):
    global _STOP
    _STOP = True


def poll_once(target: str, timeout: float = 5.0):
    """Fetch /shm/coverage once. Returns (edges, hits, size) or None on failure.
    A failure (connection refused, non-200, bad JSON) is expected transiently
    around target startup/reset -- the caller logs it and keeps polling rather
    than aborting, since a poller crash mid-run would silently truncate the
    coverage time-series for that run.
    """
    url = target.rstrip("/") + "/shm/coverage"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None, f"http_status_{resp.status}"
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            return payload, None
    except urllib.error.URLError as e:
        return None, f"url_error:{e}"
    except (json.JSONDecodeError, ValueError) as e:
        return None, f"decode_error:{e}"
    except Exception as e:  # noqa: BLE001 -- deliberately broad, see docstring
        return None, f"error:{e}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--target", required=True, help="Base URL of the instrumented target, e.g. http://localhost:7777")
    ap.add_argument("--out", required=True, help="Path to coverage_event.jsonl (appended)")
    ap.add_argument("--interval", type=float, default=1.0, help="Poll cadence in seconds (default 1.0)")
    ap.add_argument("--duration", type=float, default=0.0, help="Stop after this many seconds (0 = run until signaled)")
    ap.add_argument("--source-label", default="poll", help="Value for the 'source' field (default: poll)")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    start = time.time()
    request_index = 0
    consecutive_errors = 0

    with open(args.out, "a", buffering=1) as f:
        while not _STOP:
            now = time.time()
            elapsed = now - start
            if args.duration > 0 and elapsed >= args.duration:
                break

            payload, err = poll_once(args.target)
            row = {
                "run_id": args.run_id,
                "ts": now,
                "elapsed_s": round(elapsed, 3),
                "request_index": request_index,
                "source": args.source_label,
            }
            if payload is not None:
                row["edges"] = payload.get("edges")
                row["hits"] = payload.get("hits")
                row["size"] = payload.get("size")
                consecutive_errors = 0
            else:
                row["error"] = err
                consecutive_errors += 1
            f.write(json.dumps(row) + "\n")
            request_index += 1

            if consecutive_errors and consecutive_errors % 30 == 0:
                print(f"[coverage_poller] {consecutive_errors} consecutive poll failures ({err}) -- target may be down", file=sys.stderr)

            time.sleep(max(0.0, args.interval))

    print(f"[coverage_poller] stopped after {request_index} polls, run_id={args.run_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
