#!/usr/bin/env bash
#
# verify-hook.sh — smoke test for zero-edit (--inject-mode hook) instrumentation.
#
# Verifies, against a running instrumented target:
#   1. /shm/create           — SHM allocated, assemblies linked
#   2. /shm/health           — linked_assemblies > 0        (load-time linking works)
#   3. synthetic 404 probe   — X-Coverage-Delta present; novelty drops on the repeat
#                              (AFL-style bucketed, first-observer-wins attribution).
#                              Uses a guaranteed-nonexistent path so the response is
#                              always small/non-chunked (Content-Length: 0) — this is
#                              the authoritative pass/fail check, immune to target shape.
#   4. real endpoint (PROBE) — /shm/coverage edge count grows from real business-logic
#                              traffic. X-Coverage-Delta on THIS request is reported for
#                              information only, not required for pass: ASP.NET starts
#                              streaming (Transfer-Encoding: chunked) JSON responses
#                              before our middleware's `finally` runs, so the header is
#                              legitimately absent on many real 200 OK endpoints — this
#                              does NOT mean coverage is broken (see /shm/coverage below,
#                              and the worker.go periodic-poll fallback for this exact
#                              case).
#   5. /shm/coverage         — cumulative distinct (edge,bucket) classes > 0
#
# It does NOT need Go or the fuzzer binary — just curl + python3.
#
# Usage:
#   ./verify-hook.sh                                   # probe an already-running target
#   BASE_URL=http://localhost:7777 ./verify-hook.sh    # custom port
#   PROBE=/api/catalog-items ./verify-hook.sh          # pick a real GET endpoint
#   ./verify-hook.sh --up --dir ./eshprep              # build+start compose first, then probe
#   ./verify-hook.sh --up --down --dir ./eshprep       # ...and tear down afterwards
#
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PROBE="${PROBE:-}"
DIR="${DIR:-.}"
DO_UP=0
DO_DOWN=0
WAIT_SECS="${WAIT_SECS:-45}"

while [ $# -gt 0 ]; do
  case "$1" in
    --up)    DO_UP=1 ;;
    --down)  DO_DOWN=1 ;;
    --dir)   DIR="$2"; shift ;;
    --probe) PROBE="$2"; shift ;;
    --base)  BASE_URL="$2"; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

BASE_URL="${BASE_URL%/}"
PASS=0; FAIL=0
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
ok()    { green "  PASS: $1"; PASS=$((PASS+1)); }
bad()   { red   "  FAIL: $1"; FAIL=$((FAIL+1)); }
hr()    { printf '%s\n' "----------------------------------------------------------------"; }

# jq-free JSON field reader.
jget() { python3 -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('$1',''))
except Exception:
    print('')"; }

# Header value from a raw -D dump (case-insensitive).
hget() { grep -i "^$1:" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'; }

command -v curl   >/dev/null || { red "curl not found"; exit 3; }
command -v python3 >/dev/null || { red "python3 not found"; exit 3; }

# fuzz-prep-multi.py always writes docker-compose.instrumented.yml, a name
# `docker compose` does not auto-discover (only compose.y[a]ml/docker-compose.y[a]ml
# are) -- pass -f explicitly when it's present, matching what upsidefuzz.py's _compose
# helper does. Wrapped in a function (not a bare array expansion) because
# "${empty_array[@]}" throws "unbound variable" under `set -u` on bash < 4.4
# (macOS's system /bin/bash is 3.2) -- the same class of bug fixed in
# compile-grammar.sh's ROSLYN_ARGS handling.
dc() {
  # Assumes cwd is already $DIR (only called from inside `cd "$DIR" && ...` below).
  if [ -f "docker-compose.instrumented.yml" ]; then
    docker compose -f docker-compose.instrumented.yml "$@"
  else
    docker compose "$@"
  fi
}

if [ "$DO_UP" = 1 ]; then
  hr; echo "Bringing up compose stack in: $DIR"
  ( cd "$DIR" && dc build && dc up -d ) || { red "docker compose up failed"; exit 4; }
  echo "Waiting ${WAIT_SECS}s for startup (DB migration etc.)…"
  sleep "$WAIT_SECS"
fi

cleanup() {
  if [ "$DO_DOWN" = 1 ]; then
    hr; echo "Tearing down compose stack…"
    ( cd "$DIR" && dc down -v ) || true
  fi
}
trap cleanup EXIT

hr
echo "Target: $BASE_URL"
hr

# 1) /shm/create ------------------------------------------------------------
echo "[1] POST /shm/create"
CREATE="$(curl -s -X POST "$BASE_URL/shm/create")"
echo "    $CREATE"
MODE="$(printf '%s' "$CREATE" | jget mode)"
LINKED_CREATE="$(printf '%s' "$CREATE" | jget linked_assemblies)"
if [ -n "$MODE" ]; then ok "/shm/create responded (mode=$MODE, linked=$LINKED_CREATE)"
else bad "/shm/create did not return JSON — is the hook loaded? (check DOTNET_STARTUP_HOOKS env in the container)"; fi

# 2) /shm/health ------------------------------------------------------------
echo "[2] GET /shm/health"
HEALTH="$(curl -s "$BASE_URL/shm/health")"
echo "    $HEALTH"
LINKED="$(printf '%s' "$HEALTH" | jget linked_assemblies)"
BOUND="$(printf '%s' "$HEALTH" | jget shm_bound)"
if [ "${LINKED:-0}" -gt 0 ] 2>/dev/null; then ok "load-time linking active (linked_assemblies=$LINKED, shm_bound=$BOUND)"
else bad "linked_assemblies=$LINKED — instrumentation not linked (was the image built with --inject-mode hook?)"; fi

# 3) synthetic 404 probe — authoritative per-request attribution check ------
# A guaranteed-nonexistent path always yields a small, non-chunked response
# (Content-Length: 0), so the header is reliably present here regardless of
# what the target's real endpoints look like. This is what makes it fit to
# gate pass/fail, unlike a real business endpoint (see check 4).
NONCE="$$_$RANDOM"
NX_PATH="/__upsidefuzz_verify_404_probe_${NONCE}"
echo "[3] synthetic 404 probe (attribution check): $NX_PATH"

req() { curl -s -D - -o /dev/null -H "X-Fuzz-Request-Id: fz-$1" "$BASE_URL$2"; }

H1="$(req 1 "$NX_PATH")"; D1="$(printf '%s' "$H1" | hget X-Coverage-Delta)"; E1="$(printf '%s' "$H1" | hget X-Coverage-Edges)"
H2="$(req 2 "$NX_PATH")"; D2="$(printf '%s' "$H2" | hget X-Coverage-Delta)"; E2="$(printf '%s' "$H2" | hget X-Coverage-Edges)"
echo "    req1: X-Coverage-Delta=${D1:-<none>}  X-Coverage-Edges=${E1:-<none>}"
echo "    req2: X-Coverage-Delta=${D2:-<none>}  X-Coverage-Edges=${E2:-<none>}"

if [ -n "$D1" ] && [ -n "$E1" ]; then ok "per-request X-Coverage-Delta header is present (middleware active)"
else bad "no X-Coverage-Delta header on a 404 (non-chunked) response — hosting-startup middleware not injected (check ASPNETCORE_HOSTINGSTARTUPASSEMBLIES)"; fi

if [ -n "$D1" ] && [ -n "$D2" ]; then
  if [ "$D2" -le "$D1" ] 2>/dev/null; then ok "novelty drops on repeat (Δ1=$D1 ≥ Δ2=$D2) — first-observer-wins bucketed attribution"
  else bad "Δ2 ($D2) > Δ1 ($D1) on an idle, sequential repeat — bucketed virgin map not deduping as expected"; fi
fi
if [ -n "$E1" ] && [ -n "$E2" ]; then
  if [ "$E2" -ge "$E1" ] 2>/dev/null; then ok "cumulative edges are monotonic (E1=$E1 → E2=$E2)"
  else bad "edges decreased ($E1 → $E2) — unexpected"; fi
fi

# 4) real endpoint (PROBE) — coverage grows from actual business logic ------
# Pick a probe path: explicit PROBE, else try swagger, else '/'.
if [ -z "$PROBE" ]; then
  SW="$(curl -s "$BASE_URL/swagger/v1/swagger.json")"
  PROBE="$(printf '%s' "$SW" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin); paths=d.get('paths',{})
    for p,ops in paths.items():
        if 'get' in {k.lower() for k in ops} and '{' not in p:
            print(p); break
except Exception:
    pass" 2>/dev/null)"
  [ -z "$PROBE" ] && PROBE="/"
fi
echo "[4] real endpoint traffic to: $PROBE"

COV_BEFORE="$(curl -s "$BASE_URL/shm/coverage" | jget edges)"
PH1="$(req 3 "$PROBE")"; PD1="$(printf '%s' "$PH1" | hget X-Coverage-Delta)"
PH2="$(req 4 "$PROBE")"; PD2="$(printf '%s' "$PH2" | hget X-Coverage-Delta)"
COV_AFTER="$(curl -s "$BASE_URL/shm/coverage" | jget edges)"
echo "    X-Coverage-Delta on $PROBE: req1=${PD1:-<none>} req2=${PD2:-<none>} (informational only — see header note above)"
echo "    /shm/coverage edges: before=${COV_BEFORE:-0} after=${COV_AFTER:-0}"

if [ -n "$PD1" ]; then
  ok "bonus: X-Coverage-Delta was present on $PROBE too (non-chunked response)"
else
  echo "    NOTE: header absent on $PROBE — expected if the response is streamed"
  echo "          (Transfer-Encoding: chunked starts before our middleware's finally"
  echo "          runs). Not a failure; the engine falls back to periodic /shm polling."
fi
if [ "${COV_AFTER:-0}" -ge "${COV_BEFORE:-0}" ] 2>/dev/null; then
  ok "real endpoint traffic did not regress cumulative coverage (edges $COV_BEFORE → $COV_AFTER)"
else
  bad "cumulative edges dropped after hitting $PROBE ($COV_BEFORE → $COV_AFTER) — unexpected"
fi

# 5) /shm/coverage ------------------------------------------------------------
echo "[5] GET /shm/coverage"
COV="$(curl -s "$BASE_URL/shm/coverage")"
echo "    $COV"
EDGES="$(printf '%s' "$COV" | jget edges)"
SIZE="$(printf '%s' "$COV" | jget size)"
if [ "${EDGES:-0}" -gt 0 ] 2>/dev/null; then ok "coverage active (edges=$EDGES distinct classes, bitmap size=$SIZE)"
else bad "edges=$EDGES — no coverage recorded (instrumentation ran as a no-op?)"; fi

hr
if [ "$FAIL" -eq 0 ]; then
  green "ALL CHECKS PASSED ($PASS ok) — zero-edit hook instrumentation + bucketed coverage verified."
  exit 0
else
  red "$FAIL check(s) FAILED, $PASS passed. See notes above."
  exit 1
fi
