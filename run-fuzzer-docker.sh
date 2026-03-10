#!/usr/bin/env bash
#
# Launch SmartFuzzer as a sidecar container with direct SHM access.
#
# Usage:
#   ./run-fuzzer-docker.sh <prep-dir> [fuzzer-args...]
#
# Examples:
#   ./run-fuzzer-docker.sh eshprep --time-budget 5
#   ./run-fuzzer-docker.sh loyalty-prep --time-budget 2 --skip-on-crash
#
# Before running:
#   1. Start the target stack (e.g. docker compose --profile fuzz up -d)
#   2. Ensure grammar.py exists in smart_fuzzer/

set -euo pipefail

PREP_DIR="${1:?Usage: $0 <prep-dir> [fuzzer-args...]}"
shift

COMPOSE_FILE=""
for name in compose.yaml compose.yml docker-compose.yml docker-compose.yaml docker-compose.instrumented.yml; do
    if [ -f "$PREP_DIR/$name" ]; then
        COMPOSE_FILE="$PREP_DIR/$name"
        break
    fi
done

if [ -z "$COMPOSE_FILE" ]; then
    echo "ERROR: No compose file found in $PREP_DIR"
    exit 1
fi

echo "Using compose: $COMPOSE_FILE"
echo "Fuzzer args:   --direct-shm $*"

docker compose --profile fuzz -f "$COMPOSE_FILE" run --rm smartfuzzer --direct-shm "$@"
