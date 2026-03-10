#!/bin/bash
# deploy-grammar.sh — Copy compiled grammar to void/
# Requires ./compile-grammar.sh to have been run first.
set -e

show_help() {
    cat <<'EOF'
deploy-grammar.sh — Deploy compiled RESTler grammar to the smart fuzzer.

Copies grammar.py and dict.json from restler_output/Compile/ into void/
so the Go fuzzer can pick them up on the next run.

Usage:
  ./deploy-grammar.sh [--grammar-dir <dir>] [--dest <dir>]

Options:
  --grammar-dir DIR   Source directory with grammar.py + dict.json
                      (default: restler_output/Compile)
  --dest DIR          Destination directory
                      (default: smart_fuzzer)
  --help, -h          Show this help

Examples:
  ./deploy-grammar.sh
  ./deploy-grammar.sh --grammar-dir my_output/Compile --dest smart_fuzzer

Workflow:
  1. ./compile-grammar.sh swagger.json [--dict dict.json] [--src ./src]
  2. ./deploy-grammar.sh
  3. cd smart_fuzzer && TARGET_HOST=... AUTH_TOKEN=... ./go/void-darwin-arm64 -time-budget 60
EOF
}

GRAMMAR_DIR="restler_output/Compile"
DEST="smart_fuzzer"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --grammar-dir) GRAMMAR_DIR="$2"; shift 2 ;;
        --dest)        DEST="$2";        shift 2 ;;
        --help|-h)     show_help; exit 0 ;;
        *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

if [ ! -f "$GRAMMAR_DIR/grammar.py" ]; then
    echo "❌ grammar.py not found in $GRAMMAR_DIR"
    echo "   Run ./compile-grammar.sh first."
    exit 1
fi

echo "📦 Deploying Grammar to $DEST/ ..."
cp "$GRAMMAR_DIR/grammar.py" "$DEST/"
cp "$GRAMMAR_DIR/dict.json"  "$DEST/"
echo "✅ Deployed: grammar.py + dict.json → $DEST/"
echo "   Next: delete $DEST/templates.export.json so the fuzzer re-exports on next run"
echo "   Or pass -refresh-templates to force re-export."
