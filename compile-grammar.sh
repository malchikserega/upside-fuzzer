#!/bin/bash
set -euo pipefail

SWAGGER_PATH=""
INPUT_DICTIONARY_PATH=""
SOURCE_CODE_PATH="${SOURCE_PATH:-}"
OUT_DIR=""
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dict|-d)
            INPUT_DICTIONARY_PATH="${2:-}"
            shift 2
            ;;
        --src|-s)
            SOURCE_CODE_PATH="${2:-}"
            shift 2
            ;;
        --out|-o)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --help|-h)
            cat <<'EOF'
compile-grammar.sh — Generate a fuzzing grammar from an OpenAPI/Swagger spec.

First-party pipeline (RESTler retired — no Docker, no external compiler):
  1. Parses the OpenAPI/Swagger spec directly (grammarc/oas.py)
  2. If --src is given, runs analyzer/ (a real Microsoft.CodeAnalysis.CSharp
     syntax-tree analyzer) over the source tree to extract type/property-scoped
     C# validation constraints ([StringLength]/[Range]/FluentValidation/etc.),
     [Authorize]/route metadata — replacing the old regex-based SourceExtractor.
  3. Merges OpenAPI + Roslyn constraints (Roslyn wins per-field on a scoped match),
     infers producer/consumer id relationships by path/name convention, synthesizes
     boundary values, and serializes request bodies directly to segments
     (grammarc/cli.py).
  Output: templates.export.json + dict.json written directly to --out — no
  intermediate grammar.py, no manual `cp`, no separate export-templates.py step.

Usage:
  ./compile-grammar.sh <swagger.json> [--dict <dict.json>] [--src <source_dir>] [--out <dir>]
  ./compile-grammar.sh <swagger.json> [dict.json] [src_dir]   # positional form

Arguments:
  <swagger.json>          Path to the OpenAPI/Swagger JSON file (required)
  --dict, -d <file>       Custom dictionary JSON with domain-specific values (optional)
  --src,  -s <directory>  .NET source tree for Roslyn constraint extraction (optional)
  --out,  -o <directory>  Output directory (default: grammars/<swagger-basename>/)

Environment:
  SOURCE_PATH             Equivalent to --src (fallback)

Examples:
  ./compile-grammar.sh swagger.json
  ./compile-grammar.sh swagger.json --src ./MyProject/src --out grammars/myproject
  ./compile-grammar.sh swagger.json --dict my-dict.json --src ./MyProject/src

Requires: Python 3 (stdlib only) + .NET SDK 8+ if --src is used (for the analyzer).
No Docker involved in this step — Docker is only needed later for the target's own
instrumented container.
EOF
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -ge 1 ]; then
    SWAGGER_PATH="${POSITIONAL[0]}"
fi
if [ ${#POSITIONAL[@]} -ge 2 ] && [ -z "$INPUT_DICTIONARY_PATH" ]; then
    INPUT_DICTIONARY_PATH="${POSITIONAL[1]}"
fi
if [ ${#POSITIONAL[@]} -ge 3 ] && [ -z "$SOURCE_CODE_PATH" ]; then
    SOURCE_CODE_PATH="${POSITIONAL[2]}"
fi

if [ -z "$SWAGGER_PATH" ]; then
    echo "❌ Usage: ./compile-grammar.sh <path_to_swagger.json> [--dict custom_dict.json] [--src path_to_src_dir] [--out output_dir]"
    exit 1
fi

if [ ! -f "$SWAGGER_PATH" ]; then
    echo "❌ Swagger file not found: $SWAGGER_PATH"
    exit 1
fi

if [ -n "$INPUT_DICTIONARY_PATH" ] && [ ! -f "$INPUT_DICTIONARY_PATH" ]; then
    echo "❌ Dictionary file not found: $INPUT_DICTIONARY_PATH"
    exit 1
fi

if [ -n "$SOURCE_CODE_PATH" ] && [ ! -d "$SOURCE_CODE_PATH" ]; then
    echo "❌ Source directory not found: $SOURCE_CODE_PATH"
    exit 1
fi

if [ -z "$OUT_DIR" ]; then
    SWAGGER_BASENAME="$(basename "$SWAGGER_PATH")"
    SWAGGER_BASENAME="${SWAGGER_BASENAME%.*}"
    SWAGGER_BASENAME="${SWAGGER_BASENAME#swagger-}"
    OUT_DIR="$ROOT_DIR/grammars/$SWAGGER_BASENAME"
fi
mkdir -p "$OUT_DIR"

echo "⚙️  Generating grammar from $SWAGGER_PATH -> $OUT_DIR"

ROSLYN_ARGS=()
if [ -n "$SOURCE_CODE_PATH" ]; then
    ROSLYN_JSON="$OUT_DIR/roslyn-constraints.json"
    echo "🔎 Running Roslyn syntax-tree analyzer over $SOURCE_CODE_PATH..."
    ( cd "$ROOT_DIR/analyzer" && dotnet build -v quiet --nologo > /dev/null )
    dotnet run --no-build --project "$ROOT_DIR/analyzer" -- --src "$SOURCE_CODE_PATH" --out "$ROSLYN_JSON"
    ROSLYN_ARGS=(--roslyn "$ROSLYN_JSON")
fi

GRAMMARC_ARGS=(--swagger "$SWAGGER_PATH" --out "$OUT_DIR")
if [ -n "$INPUT_DICTIONARY_PATH" ]; then
    GRAMMARC_ARGS+=(--dict "$INPUT_DICTIONARY_PATH")
fi
if [ ${#ROSLYN_ARGS[@]} -gt 0 ]; then
    # Guarded expansion: bash 3.2 (macOS's system /bin/bash) treats
    # "${empty_array[@]}" as an unbound-variable error under `set -u` even when the
    # array was declared (just empty) -- a well-known bash<4.4 quirk. Unconditional
    # expansion here would make --src-less invocations (the common OAS-only case)
    # crash on macOS while working fine on newer bash (e.g. GitHub Actions' ubuntu
    # runners), so guard it explicitly rather than depending on the runner's bash version.
    GRAMMARC_ARGS+=("${ROSLYN_ARGS[@]}")
fi

echo "🧠 Compiling grammar (OpenAPI + Roslyn merge, dependency inference, boundary values)..."
( cd "$ROOT_DIR" && python3 -m grammarc.cli "${GRAMMARC_ARGS[@]}" )

echo "✅ Grammar generated: $OUT_DIR/templates.export.json"
echo "✅ Dictionary generated: $OUT_DIR/dict.json"
echo ""
echo "Point the fuzzer at it with: -grammar $OUT_DIR"
