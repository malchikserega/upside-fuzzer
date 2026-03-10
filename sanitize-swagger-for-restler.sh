#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./sanitize-swagger-for-restler.sh --in <openapi-file> [--out <sanitized-file>]
  ./sanitize-swagger-for-restler.sh <openapi-file> [sanitized-file]

What it does:
  - Removes query parameters that RESTler compiler cannot handle:
    - query params with object-like schemas (type=object, properties, allOf/anyOf/oneOf, object additionalProperties)
    - query params that are arrays of object-like schemas
    - query params with style=deepObject
  - Handles both inline parameters and local refs to #/components/parameters/*

Notes:
  - JSON input is always supported.
  - YAML input/output is supported when `yq` is installed.
USAGE
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

default_out_path() {
  local in="$1"
  local base="${in%.*}"
  local ext="${in##*.}"
  if [[ "$in" == "$base" ]]; then
    echo "${in}.restler.json"
    return
  fi
  case "${ext,,}" in
    json) echo "${base}.restler.json" ;;
    yml|yaml) echo "${base}.restler.${ext}" ;;
    *) echo "${in}.restler.json" ;;
  esac
}

is_yaml_path() {
  local p="$1"
  case "${p##*.}" in
    yml|yaml|YML|YAML) return 0 ;;
    *) return 1 ;;
  esac
}

is_json_path() {
  local p="$1"
  case "${p##*.}" in
    json|JSON) return 0 ;;
    *) return 1 ;;
  esac
}

IN=""
OUT=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --in|-i)
      IN="${2:-}"
      shift 2
      ;;
    --out|-o)
      OUT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$IN" && ${#POSITIONAL[@]} -ge 1 ]]; then
  IN="${POSITIONAL[0]}"
fi
if [[ -z "$OUT" && ${#POSITIONAL[@]} -ge 2 ]]; then
  OUT="${POSITIONAL[1]}"
fi

[[ -n "$IN" ]] || { usage; die "Missing input file"; }
[[ -f "$IN" ]] || die "Input file not found: $IN"
require_cmd jq

if [[ -z "$OUT" ]]; then
  OUT="$(default_out_path "$IN")"
fi

in_json_tmp="$(mktemp)"
out_json_tmp="$(mktemp)"
cleanup() {
  rm -f "$in_json_tmp" "$out_json_tmp"
}
trap cleanup EXIT

if is_json_path "$IN"; then
  cp "$IN" "$in_json_tmp"
elif is_yaml_path "$IN"; then
  require_cmd yq
  yq -o=json '.' "$IN" > "$in_json_tmp"
else
  die "Unsupported input extension. Use .json/.yaml/.yml"
fi

# Validate basic OpenAPI shape early (informative error).
jq -e '
  (type == "object")
  and ((.openapi? // .swagger?) != null)
  and (.paths? != null)
' "$in_json_tmp" >/dev/null || die "Input does not look like an OpenAPI document"

jq '
  . as $doc
  |
  def _objish($s):
    (
      ($s.type? == "object")
      or ($s.properties? != null)
      or ($s.allOf? != null)
      or ($s.anyOf? != null)
      or ($s.oneOf? != null)
      or (($s.additionalProperties? | type) == "object")
    );

  def _unsupported_query_inline:
    (.in? == "query")
    and (
      (.style? == "deepObject")
      or _objish(.schema // {})
      or (
        (.schema.type? == "array")
        and _objish(.schema.items // {})
      )
    );

  def _unsupported_query_param:
    if has("$ref")
       and (.["$ref"] | startswith("#/components/parameters/")) then
      ($doc.components.parameters[(.["$ref"] | split("/") | last)] // {})
      | _unsupported_query_inline
    else
      _unsupported_query_inline
    end;

  def _sanitize_params:
    map(select((_unsupported_query_param | not)));

  .paths |= with_entries(
    .value |= (
      if (.parameters? | type) == "array"
      then .parameters |= _sanitize_params
      else .
      end
      |
      with_entries(
        if (.key | test("^(get|put|post|delete|options|head|patch|trace)$"))
        then
          .value |= (
            if (.parameters? | type) == "array"
            then .parameters |= _sanitize_params
            else .
            end
          )
        else .
        end
      )
    )
  )
' "$in_json_tmp" > "$out_json_tmp"

param_count_expr='
  [
    .paths[] as $p
    | ($p.parameters // [] | length),
      (
        $p
        | to_entries[]
        | select(.key | test("^(get|put|post|delete|options|head|patch|trace)$"))
        | (.value.parameters // [] | length)
      )
  ] | add // 0
'

before_count="$(jq -r "$param_count_expr" "$in_json_tmp")"
after_count="$(jq -r "$param_count_expr" "$out_json_tmp")"
removed_count=$((before_count - after_count))

mkdir -p "$(dirname "$OUT")"
if is_yaml_path "$OUT"; then
  require_cmd yq
  yq -P -p=json '.' "$out_json_tmp" > "$OUT"
else
  jq . "$out_json_tmp" > "$OUT"
fi

echo "Sanitized OpenAPI written to: $OUT"
echo "Parameters before: $before_count"
echo "Parameters after:  $after_count"
echo "Removed:           $removed_count"

