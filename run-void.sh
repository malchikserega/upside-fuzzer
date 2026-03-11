# run-void.sh — Quick launcher for the Void fuzzer (host mode, HTTP coverage).
# run-smart-fuzzer.sh — Quick launcher for the Go fuzzer (host mode, HTTP coverage).
# For Docker sidecar (direct SHM mode) use docker compose --profile fuzz-go instead.
set -euo pipefail

show_help() {
    cat <<'EOF'
run-void.sh — Launch the Void binary in host mode.

Reads target URL and auth from environment variables, then starts the fuzzer.
All bug-finding features are ON by default (triage, repro, minimization, race detection).

Usage:
  ./run-void.sh [fuzzer flags...]

Required environment variables:
  TARGET_HOST   Base URL of the instrumented API  (e.g. http://localhost:8080)
  AUTH_TOKEN    Bearer JWT for authenticated fuzzing

Optional environment variables:
  SHM_HOST      Coverage endpoint URL (defaults to TARGET_HOST)

Examples:
  # Minimal — 20 minutes, default settings
  TARGET_HOST=http://localhost:8080 AUTH_TOKEN=<jwt> ./run-void.sh

  # Custom grammar directory and time budget
  TARGET_HOST=http://localhost:8080 AUTH_TOKEN=<jwt> \
    ./run-void.sh -grammar ./grammars/myapi -time-budget 60

  # Fast scan (disable slow analysis)
  TARGET_HOST=http://localhost:8080 AUTH_TOKEN=<jwt> \
    ./run-void.sh \
      -concurrency 32 -request-timeout 2.5 -coverage-interval 6 \
      -crash-triage=false -repro-runs 0 -minimize-crash=false \
      -no-ui -time-budget 20

Fuzzer binary location:
  void/go/void-darwin-arm64  (macOS Apple Silicon)
  void/go/void               (Linux amd64, used in Docker)

For full flag reference:
  void/go/void-darwin-arm64 --help
  See: void/README.md
EOF
}

# Handle --help before passing to fuzzer
for arg in "$@"; do
    case "$arg" in
        --help|-h) show_help; exit 0 ;;
    esac
done

# Validate required env vars
if [ -z "${TARGET_HOST:-}" ]; then
    echo "❌ TARGET_HOST environment variable is required."
    echo "   Example: TARGET_HOST=http://localhost:8080 AUTH_TOKEN=<jwt> $0"
    exit 1
fi
if [ -z "${AUTH_TOKEN:-}" ]; then
    echo "⚠️  AUTH_TOKEN not set — fuzzer will run unauthenticated."
fi

# Locate binary (prefer darwin-arm64 on macOS, fall back to generic)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZER_BIN=""
for candidate in \
    "$SCRIPT_DIR/void/go/void-darwin-arm64" \
    "$SCRIPT_DIR/void/go/void-linux-amd64" \
    "$SCRIPT_DIR/void/go/void"; do
    if [ -x "$candidate" ]; then
        FUZZER_BIN="$candidate"
        break
    fi
done

if [ -z "$FUZZER_BIN" ]; then
    echo "❌ No fuzzer binary found in void/go/"
    echo "   Build it first: cd void/go && go build -o void ."
    exit 1
fi

export TARGET_HOST
export SHM_HOST="${SHM_HOST:-$TARGET_HOST}"
export AUTH_TOKEN

echo "🎯 Target:   $TARGET_HOST"
echo "📡 SHM host: $SHM_HOST"
echo "🔥 Binary:   $FUZZER_BIN"
echo ""

mkdir -p "$SCRIPT_DIR/void/crashes" "$SCRIPT_DIR/void/summaries"

exec "$FUZZER_BIN" -grammar "$SCRIPT_DIR/void" "$@"
