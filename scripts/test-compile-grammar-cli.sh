#!/usr/bin/env bash
#
# test-compile-grammar-cli.sh — fast, no-Docker regression test for compile-grammar.sh's
# own argument parsing.
#
# This is the exact class of bug a real user hit: an unrecognized flag (--main, which
# only fuzz-prep-multi.py supports) used to fall silently into the positional-argument
# catch-all and land in the dictionary-path slot, producing a confusing
# "Dictionary file not found: --main" error far from the real mistake. Fixed by failing
# loud on any unrecognized -prefixed argument. This script locks that fix in, plus a
# few other argument-handling edge cases compile-grammar.sh has never had a test for.
#
# Needs only python3 (stdlib) -- no Docker, no .NET SDK, no network. Safe to run in CI
# on every push.
#
# Usage: ./scripts/test-compile-grammar-cli.sh

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/compile-grammar.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

red()   { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }

FAILURES=0
assert() {
    local desc="$1"
    if eval "$2"; then
        green "  OK: $desc"
    else
        red "  FAIL: $desc"
        FAILURES=$((FAILURES + 1))
    fi
}

# A minimal, valid OpenAPI 3.0 spec -- just enough for the real grammar-compile
# success-path assertion below, without needing --src or a real target.
cat > "$TMP_DIR/swagger.json" <<'EOF'
{
  "openapi": "3.0.0",
  "info": {"title": "Test API", "version": "1.0"},
  "paths": {
    "/ping": {
      "get": {
        "operationId": "ping",
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}
EOF

echo "1) Unrecognized flag (the real bug this session hit: --main on compile-grammar.sh)"
OUT="$("$SCRIPT" "$TMP_DIR/swagger.json" --out "$TMP_DIR/out1" --main TeamFlow.Api 2>&1)"
RC=$?
assert "exits non-zero" "[ $RC -ne 0 ]"
assert "reports the actual unrecognized flag, not a misleading dictionary-file error" \
    '[[ "$OUT" == *"Unrecognized flag: --main"* ]] && [[ "$OUT" != *"Dictionary file not found"* ]]'

echo "2) No swagger path at all"
OUT="$("$SCRIPT" 2>&1)"
RC=$?
assert "exits non-zero" "[ $RC -ne 0 ]"
assert "prints a usage message" '[[ "$OUT" == *"Usage:"* ]]'

echo "3) Swagger path that does not exist"
OUT="$("$SCRIPT" "$TMP_DIR/does-not-exist.json" 2>&1)"
RC=$?
assert "exits non-zero" "[ $RC -ne 0 ]"
assert "reports the missing swagger file, not a generic error" '[[ "$OUT" == *"Swagger file not found"* ]]'

echo "4) --src pointing at a directory that does not exist"
OUT="$("$SCRIPT" "$TMP_DIR/swagger.json" --out "$TMP_DIR/out2" --src "$TMP_DIR/no-such-src" 2>&1)"
RC=$?
assert "exits non-zero" "[ $RC -ne 0 ]"
assert "reports the missing source directory" '[[ "$OUT" == *"Source directory not found"* ]]'

echo "5) Valid minimal invocation succeeds and writes real output files"
OUT="$("$SCRIPT" "$TMP_DIR/swagger.json" --out "$TMP_DIR/out3" 2>&1)"
RC=$?
assert "exits zero" "[ $RC -eq 0 ]"
assert "writes templates.export.json" "[ -f '$TMP_DIR/out3/templates.export.json' ]"
assert "writes dict.json" "[ -f '$TMP_DIR/out3/dict.json' ]"

echo "6) Short-flag forms (-o, -s) still work exactly like their long forms"
OUT="$("$SCRIPT" "$TMP_DIR/swagger.json" -o "$TMP_DIR/out4" 2>&1)"
RC=$?
assert "exits zero" "[ $RC -eq 0 ]"
assert "writes output to the -o path" "[ -f '$TMP_DIR/out4/templates.export.json' ]"

echo
if [ "$FAILURES" -eq 0 ]; then
    green "All compile-grammar.sh CLI checks passed."
    exit 0
else
    red "$FAILURES check(s) failed."
    exit 1
fi
