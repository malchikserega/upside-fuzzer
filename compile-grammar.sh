#!/bin/bash
set -euo pipefail

SWAGGER_PATH=""
INPUT_DICTIONARY_PATH=""
SOURCE_CODE_PATH="${SOURCE_PATH:-}"
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
        --help|-h)
            cat <<'EOF'
compile-grammar.sh — Generate a RESTler fuzzing grammar from an OpenAPI/Swagger spec.

What it does:
  1. Sanitizes the swagger (removes deepObject/nested query params RESTler can't handle)
  2. Converts your custom dictionary to RESTler format
  3. Runs the RESTler compiler to produce grammar.py + dict.json
  4. Enhances grammar/dict with swagger + source heuristics (route names, enums, regexes)
  Output lands in: restler_output/Compile/

Usage:
  ./compile-grammar.sh <swagger.json> [--dict <dict.json>] [--src <source_dir>]
  ./compile-grammar.sh <swagger.json> [dict.json] [src_dir]   # positional form

Arguments:
  <swagger.json>          Path to the OpenAPI/Swagger JSON file (required)
  --dict, -d <file>       Custom dictionary JSON with domain-specific values (optional)
  --src,  -s <directory>  Source tree for route/enum heuristics (optional)

Environment:
  SOURCE_PATH             Equivalent to --src (fallback)

Examples:
  ./compile-grammar.sh swagger.json
  ./compile-grammar.sh swagger.json --dict my-dict.json
  ./compile-grammar.sh swagger.json --dict my-dict.json --src ./MyProject
  ./compile-grammar.sh swagger.json my-dict.json ./MyProject

After running:
  Copy output to void/:  ./deploy-grammar.sh
  Or manually:   cp restler_output/Compile/{grammar.py,dict.json} void/
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
    echo "❌ Usage: ./compile-grammar.sh <path_to_swagger.json> [path_to_custom_dictionary.json] [path_to_src_dir]"
    echo "   or: ./compile-grammar.sh <path_to_swagger.json> [--dict custom_dict.json] [--src path_to_src_dir]"
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

echo "⚙️  Generating Grammar from $SWAGGER_PATH..."

mkdir -p "$ROOT_DIR/restler_input" "$ROOT_DIR/restler_output"
cp "$SWAGGER_PATH" "$ROOT_DIR/restler_input/swagger.json"

CUSTOM_DICTIONARY_PATH="$ROOT_DIR/restler_input/custom_dict.json"
if [ -n "$INPUT_DICTIONARY_PATH" ]; then
    echo "🧩 Converting dictionary to RESTler format: $INPUT_DICTIONARY_PATH"
    python3 - "$INPUT_DICTIONARY_PATH" "$CUSTOM_DICTIONARY_PATH" <<'PY'
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

with src.open("r", encoding="utf-8") as f:
    raw = json.load(f)

template = {
    "restler_fuzzable_string": [],
    "restler_fuzzable_string_unquoted": [],
    "restler_fuzzable_datetime": ["2019-06-26T20:20:39+00:00"],
    "restler_fuzzable_datetime_unquoted": [],
    "restler_fuzzable_date": ["2019-06-26"],
    "restler_fuzzable_date_unquoted": [],
    "restler_fuzzable_uuid4": ["566048da-ed19-4cd3-8e0a-b7e0e1ec4d72"],
    "restler_fuzzable_uuid4_unquoted": [],
    "restler_fuzzable_int": ["1"],
    "restler_fuzzable_number": ["1.23"],
    "restler_fuzzable_bool": ["true"],
    "restler_fuzzable_object": ['{ "fuzz": false }'],
    "restler_custom_payload": {},
    "restler_custom_payload_unquoted": {},
    "restler_custom_payload_uuid4_suffix": {},
    "restler_custom_payload_header": {},
    "restler_custom_payload_query": {}
}

def uniq(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

def normalize_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if v is None:
        return ""
    return str(v)

is_uuid = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I).match
is_date = re.compile(r"^\d{4}-\d{2}-\d{2}$").match
is_datetime = re.compile(r"^\d{4}-\d{2}-\d{2}T").match

def add_fuzzable_values(values):
    for v in values:
        if isinstance(v, bool):
            template["restler_fuzzable_bool"].append(normalize_scalar(v))
            continue
        if isinstance(v, int):
            template["restler_fuzzable_int"].append(normalize_scalar(v))
            continue
        if isinstance(v, float):
            template["restler_fuzzable_number"].append(normalize_scalar(v))
            continue
        s = normalize_scalar(v)
        if is_uuid(s):
            template["restler_fuzzable_uuid4"].append(s)
        elif is_datetime(s):
            template["restler_fuzzable_datetime"].append(s)
        elif is_date(s):
            template["restler_fuzzable_date"].append(s)
        else:
            template["restler_fuzzable_string"].append(s)

if isinstance(raw, dict) and "dictionaries" in raw and isinstance(raw["dictionaries"], dict):
    source = raw["dictionaries"]
elif isinstance(raw, dict):
    source = raw
else:
    raise ValueError("Dictionary JSON must be an object")

for key, val in source.items():
    if key.startswith("restler_"):
        if key in template and isinstance(template[key], list):
            values = val if isinstance(val, list) else [val]
            template[key].extend([normalize_scalar(v) for v in values])
        elif key in template and isinstance(template[key], dict):
            if isinstance(val, dict):
                for sub_key, sub_vals in val.items():
                    seq = sub_vals if isinstance(sub_vals, list) else [sub_vals]
                    template[key][sub_key] = uniq([normalize_scalar(v) for v in seq])
            elif isinstance(val, list):
                template[key][key] = uniq([normalize_scalar(v) for v in val])
        continue

    values = val if isinstance(val, list) else [val]
    normalized = [normalize_scalar(v) for v in values]
    template["restler_custom_payload"][key] = uniq(normalized)
    add_fuzzable_values(values)

for k, v in template.items():
    if isinstance(v, list):
        template[k] = uniq(v)
    else:
        template[k] = {dk: uniq(dv) for dk, dv in v.items()}

with dst.open("w", encoding="utf-8") as f:
    json.dump(template, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
fi

DEFAULT_DICTIONARY_PATH="$ROOT_DIR/restler_input/default_dict.json"
if [ -z "$INPUT_DICTIONARY_PATH" ]; then
    cat > "$DEFAULT_DICTIONARY_PATH" <<'EOF'
{
  "restler_fuzzable_string": ["fuzzstring"],
  "restler_fuzzable_string_unquoted": [],
  "restler_fuzzable_datetime": ["2019-06-26T20:20:39+00:00"],
  "restler_fuzzable_datetime_unquoted": [],
  "restler_fuzzable_date": ["2019-06-26"],
  "restler_fuzzable_date_unquoted": [],
  "restler_fuzzable_uuid4": ["566048da-ed19-4cd3-8e0a-b7e0e1ec4d72"],
  "restler_fuzzable_uuid4_unquoted": [],
  "restler_fuzzable_int": ["1"],
  "restler_fuzzable_number": ["1.23"],
  "restler_fuzzable_bool": ["true"],
  "restler_fuzzable_object": ["{ \"fuzz\": false }"],
  "restler_custom_payload": {},
  "restler_custom_payload_unquoted": {},
  "restler_custom_payload_uuid4_suffix": {},
  "restler_custom_payload_header": {},
  "restler_custom_payload_query": {}
}
EOF
fi

# 0. Ensure RESTler binaries exist (One-time setup)
if [ ! -d "$ROOT_DIR/restler_bin/restler" ] || [ ! -d "$ROOT_DIR/restler_bin/compiler" ]; then
    echo "🔧 RESTler binaries not found. Extracting from Docker image (once)..."
    rm -rf "$ROOT_DIR/restler_bin"
    container_id=$(docker create --platform linux/amd64 mcr.microsoft.com/restlerfuzzer/restler)
    docker cp "$container_id:/RESTler/." "$ROOT_DIR/restler_bin/"
    docker rm "$container_id" > /dev/null
    echo "✅ Binaries extracted to ./restler_bin"
fi

COMPILER_CONFIG_PATH="$ROOT_DIR/restler_input/compiler_config.json"
CUSTOM_DICT_FOR_CONFIG="$DEFAULT_DICTIONARY_PATH"
if [ -n "$INPUT_DICTIONARY_PATH" ]; then
    CUSTOM_DICT_FOR_CONFIG="$CUSTOM_DICTIONARY_PATH"
fi

cat > "$COMPILER_CONFIG_PATH" <<EOF
{
  "SwaggerSpecFilePath": [
    "$ROOT_DIR/restler_input/swagger.json"
  ],
  "GrammarOutputDirectoryPath": "$ROOT_DIR/restler_output/Compile",
  "CustomDictionaryFilePath": "$CUSTOM_DICT_FOR_CONFIG",
  "IncludeOptionalParameters": true,
  "UseHeaderExamples": true,
  "UsePathExamples": false,
  "UseQueryExamples": true,
  "UseBodyExamples": true,
  "UseAllExamplePayloads": false,
  "DiscoverExamples": false,
  "ExamplesDirectory": "",
  "DataFuzzing": true,
  "ReadOnlyFuzz": false,
  "ResolveQueryDependencies": true,
  "ResolveBodyDependencies": true,
  "ResolveHeaderDependencies": false,
  "UseRefreshableToken": true,
  "AllowGetProducers": false,
  "TrackFuzzedParameterNames": false
}
EOF

echo "🚀 Running RESTler Compiler via Docker (Native)..."
mkdir -p "$ROOT_DIR/restler_output"

docker run --rm \
    -e DOTNET_ROLL_FORWARD=Major \
    -v "$ROOT_DIR":"$ROOT_DIR" \
    -w "$ROOT_DIR/restler_output" \
    mcr.microsoft.com/dotnet/sdk:8.0 \
    dotnet "$ROOT_DIR/restler_bin/restler/Restler.dll" compile "$COMPILER_CONFIG_PATH"

echo "🧠 Enhancing grammar and dictionary with swagger/source hints..."
ENHANCER_CMD=(
    python3 "$ROOT_DIR/enhance-grammar.py"
    --swagger "$ROOT_DIR/restler_input/swagger.json"
    --grammar "$ROOT_DIR/restler_output/Compile/grammar.py"
    --dict "$ROOT_DIR/restler_output/Compile/dict.json"
    --external-dict "$CUSTOM_DICT_FOR_CONFIG"
)
if [ -n "$SOURCE_CODE_PATH" ]; then
    ENHANCER_CMD+=(--src "$SOURCE_CODE_PATH")
fi
"${ENHANCER_CMD[@]}"

echo "✅ Grammar generated in $ROOT_DIR/restler_output/Compile/grammar.py"
echo "✅ Dictionary generated in $ROOT_DIR/restler_output/Compile/dict.json"
