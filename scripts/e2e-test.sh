#!/usr/bin/env bash
#
# e2e-test.sh — Top-20 #7: end-to-end regression gate on a planted-bug sample app.
#
# Proves the whole pipeline works, not just that each stage runs without error:
#   instrument (fuzz-prep-multi.py) -> coverage (SHM) -> grammar (compile-grammar.sh)
#   -> fuzz (void) -> detect (unique-crashes.jsonl contains the planted bug).
#
# Target: fixtures/planted-bug-api/ -- a minimal, DB-free ASP.NET Core app with one
# deliberate, deterministic bug (see fixtures/planted-bug-api/README.md). This is the
# regression safety net for grammarc/ + dotnet/analyzer/ (Top-20 #9/#10) and the
# constraint-aware mutation engine (Top-20 #14), none of which had any automated test
# coverage before this script existed.
#
# Usage:
#   ./scripts/e2e-test.sh
#
# Exits non-zero with a clear message on any failed assertion -- this is the actual gate.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREP_DIR="${PREP_DIR:-/tmp/e2e-planted-bug-prep}"
GRAMMAR_DIR="${GRAMMAR_DIR:-/tmp/e2e-planted-bug-grammar}"
RUN_DIR="${RUN_DIR:-/tmp/e2e-planted-bug-run}"
COMPOSE_FILE="docker-compose.instrumented.yml"
BASE_URL="http://localhost:7777"

red()   { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
hr()    { printf -- '----------------------------------------------------------------------\n'; }

FAILED=0
fail() { red "FAIL: $1"; FAILED=1; }

cleanup() {
    hr
    echo "Cleaning up..."
    ( cd "$PREP_DIR" 2>/dev/null && docker compose -f "$COMPOSE_FILE" down -v ) 2>/dev/null || true
}
trap cleanup EXIT

hr
echo "1. Instrumenting fixtures/planted-bug-api (fuzz-prep-multi.py)..."
rm -rf "$PREP_DIR"
python3 "$ROOT_DIR/fuzz-prep-multi.py" --src "$ROOT_DIR/fixtures/planted-bug-api" --out "$PREP_DIR" --main PlantedBugApi \
    || { fail "fuzz-prep-multi.py exited non-zero"; exit 1; }

hr
echo "2. Building + starting the instrumented container..."
( cd "$PREP_DIR" && docker compose -f "$COMPOSE_FILE" build ) \
    || { fail "docker compose build failed"; exit 1; }
( cd "$PREP_DIR" && docker compose -f "$COMPOSE_FILE" up -d ) \
    || { fail "docker compose up failed"; exit 1; }

echo "Waiting for $BASE_URL/health ..."
for _ in $(seq 1 60); do
    curl -fsS "$BASE_URL/health" >/dev/null 2>&1 && break
    sleep 2
done
curl -fsS "$BASE_URL/health" >/dev/null 2>&1 || { fail "target never became healthy at $BASE_URL/health"; exit 1; }
green "Target is up."

hr
echo "3. Verifying zero-edit coverage hook (verify-hook.sh)..."
if ! BASE_URL="$BASE_URL" PROBE="/items" "$ROOT_DIR/verify-hook.sh"; then
    fail "verify-hook.sh reported a failure"
fi

hr
echo "4. Compiling the grammar (compile-grammar.sh, no --src -- OAS-only is enough for this fixture)..."
rm -rf "$GRAMMAR_DIR"
curl -fsS "$BASE_URL/swagger/v1/swagger.json" -o /tmp/e2e-planted-bug-swagger.json \
    || { fail "could not download swagger.json"; exit 1; }
"$ROOT_DIR/compile-grammar.sh" /tmp/e2e-planted-bug-swagger.json --out "$GRAMMAR_DIR" \
    || { fail "compile-grammar.sh exited non-zero"; exit 1; }
[ -f "$GRAMMAR_DIR/templates.export.json" ] || { fail "templates.export.json was not produced"; exit 1; }

hr
echo "5. Building the fuzzer engine and running a short session..."
mkdir -p "$RUN_DIR"
( cd "$ROOT_DIR/void/go" && go build -o /tmp/e2e-smartfuzzergo . ) \
    || { fail "go build of the fuzzer engine failed"; exit 1; }

( cd "$RUN_DIR" && TARGET_HOST="$BASE_URL" /tmp/e2e-smartfuzzergo \
    -grammar "$GRAMMAR_DIR" -no-ui -time-budget 1 -concurrency 4 \
    -unique-crash-file "$RUN_DIR/crashes.jsonl" \
    -summary-file "$RUN_DIR/summary.json" \
    -poc-dir "$RUN_DIR/pocs" -timeline-dir "$RUN_DIR/timelines" ) \
    || { fail "fuzzer run exited non-zero"; exit 1; }

hr
echo "6. Asserting results..."

python3 - "$RUN_DIR/summary.json" "$RUN_DIR/crashes.jsonl" <<'PYEOF'
import json
import sys

summary_path, crashes_path = sys.argv[1], sys.argv[2]

ok = True

try:
    with open(summary_path) as f:
        summary = json.load(f)
except Exception as e:
    print(f"FAIL: could not read {summary_path}: {e}")
    sys.exit(1)

edges = summary.get("coverage_end_edges", 0)
if edges <= 0:
    print(f"FAIL: expected coverage_end_edges > 0, got {edges}")
    ok = False
else:
    print(f"OK: coverage_end_edges = {edges}")

found_planted_bug = False
try:
    with open(crashes_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if (
                str(rec.get("method", "")).upper() == "GET"
                and "/items" in str(rec.get("path", ""))
                and rec.get("status_code") == 500
            ):
                found_planted_bug = True
                print(f"OK: planted bug detected -> {rec.get('method')} {rec.get('path')} status={rec.get('status_code')}")
                break
except FileNotFoundError:
    pass

if not found_planted_bug:
    print(f"FAIL: no GET /items?...  status=500 record found in {crashes_path} (planted bug not detected)")
    ok = False

sys.exit(0 if ok else 1)
PYEOF
[ $? -eq 0 ] || FAILED=1

hr
if [ "$FAILED" -eq 0 ]; then
    green "E2E check PASSED."
    exit 0
else
    red "E2E check FAILED."
    exit 1
fi
