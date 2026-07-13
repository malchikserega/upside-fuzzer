# AI Agent Reproduction Guide: 20-Minute Docker Benchmarks

This file explains how to reproduce the short Docker benchmarks used in the paper to compare:

- `RESTler` as the black-box baseline
- `Void` as the current Go runtime of the `UpsideFuzz` project

Targets:

- `eShopOnWeb`
- `CustomerLoyalty`
- `dotnet/eShop Catalog.API`
- `Jellyfin`

This guide is written for an AI agent working inside this repository. It assumes the repo root is the current working directory.

## 1. Non-Negotiable Comparison Rules

Follow these rules exactly. If any of them is violated, the run is not comparable to the paper.

1. Run every fuzzing campaign for exactly `20 minutes`.
2. Run `RESTler` against the vanilla Docker deployment.
3. Run `Void` against the instrumented Docker deployment.
4. Run `Void` in Docker mode with:
   - `-direct-shm`
   - `-skip-endpoint-on-500`
   - `-no-ui`
5. Do not compare raw `unique crash signatures` from `Void` to `RESTler` bug buckets.
6. The fair bug metric for the paper is:
   - `distinct HTTP 500 method+endpoint pairs`
7. For `RESTler`, this metric must be extracted from bug bucket JSON files with `status_code == 500`.
8. For `Void`, this metric must come from `buggy_method_endpoints_full` in `metrics.json`, produced by `benchmarks/collect_void_go_metrics.py`.
9. Use the current repository checkout as-is. Do not change target code, instrumentation scripts, or benchmark methodology while reproducing.

## 2. What Is Already in This Repo

The workspace already contains the materials needed to reproduce the exact paper runs:

- Raw targets in [to_test](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/to_test)
- Prepared instrumented copies in [benchmarks/prepared](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/prepared)
- Temporary compose/Dockerfile helpers in [benchmarks/tmp](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/tmp)
- Final benchmark helpers:
  - [compile-grammar.sh](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/compile-grammar.sh)
  - [sanitize-swagger-for-restler.sh](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/sanitize-swagger-for-restler.sh)
  - [collect_void_go_metrics.py](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/collect_void_go_metrics.py)
  - [build_fair_endpoint_comparison.py](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/build_fair_endpoint_comparison.py)

If the prepared copies are missing, regenerate them with `fuzz-prep-multi.py`.

## 3. One-Time Setup

Run these commands once.

```bash
set -euo pipefail

ROOT="/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1"
RESULTS="$ROOT/benchmarks/results"
TMP="$ROOT/benchmarks/tmp"
PREP="$ROOT/benchmarks/prepared"

mkdir -p "$RESULTS" "$TMP" "$PREP"
command -v docker >/dev/null
command -v python3 >/dev/null
command -v jq >/dev/null
```

### 3.1 Build the current `Void` Docker image

This uses the current `void/go` tree from this repo.

```bash
docker build -t void-go-main:latest -f - "$ROOT" <<'EOF'
FROM golang:1.22 AS build
WORKDIR /src
COPY void/go/ ./
RUN CGO_ENABLED=0 go build -o /out/void .

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/void /usr/local/bin/void
ENTRYPOINT ["/usr/local/bin/void"]
EOF
```

### 3.2 Build the official `RESTler` image

The paper runs used the official Dockerfile from `microsoft/restler-fuzzer` at commit `6d984deedbc54aad957fa3da0c7e9e5df23a2aee`.

```bash
RESTLER_SRC="$ROOT/to_test/restler-fuzzer"
if [ ! -d "$RESTLER_SRC/.git" ]; then
  git clone https://github.com/microsoft/restler-fuzzer.git "$RESTLER_SRC"
fi
git -C "$RESTLER_SRC" fetch origin
git -C "$RESTLER_SRC" checkout 6d984deedbc54aad957fa3da0c7e9e5df23a2aee
docker build -t restler-official:latest -f "$RESTLER_SRC/Dockerfile" "$RESTLER_SRC"
```

### 3.3 Reusable RESTler dictionary

Save this once and reuse it for all targets unless a target-specific dictionary is needed.

```bash
cat > "$TMP/default_restler_dict.json" <<'EOF'
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
  "restler_fuzzable_object": ["{}"],
  "restler_custom_payload": {},
  "restler_custom_payload_unquoted": {},
  "restler_custom_payload_uuid4_suffix": {},
  "restler_custom_payload_header": {},
  "restler_custom_payload_query": {}
}
EOF
```

## 4. Helper Patterns

### 4.1 Wait for Swagger

```bash
wait_for_url() {
  local url="$1"
  local tries="${2:-90}"
  local delay="${3:-2}"
  for _ in $(seq 1 "$tries"); do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
  done
  echo "Timed out waiting for $url" >&2
  return 1
}
```

### 4.2 Generic RESTler compiler config

For most targets:

```bash
cat > "$OUT/io/input/compiler_config.json" <<'EOF'
{
  "SwaggerSpecFilePath": ["/io/input/swagger.json"],
  "GrammarOutputDirectoryPath": "/io/output/Compile",
  "CustomDictionaryFilePath": "/io/input/default_dict.json",
  "IncludeOptionalParameters": true,
  "UseHeaderExamples": true,
  "DataFuzzing": true,
  "ReadOnlyFuzz": false,
  "ResolveQueryDependencies": true,
  "ResolveBodyDependencies": true,
  "UseRefreshableToken": false
}
EOF
```

### 4.3 Generic `Void` run

The grammar directory must contain:

- `grammar.py`
- `dict.json`
- `templates.export.json`

Then run:

```bash
docker run --rm \
  --network "$VOID_NETWORK" \
  -v "$VOID_COVERAGE_VOLUME:/coverage_shm" \
  -v "$VOID_GRAMMAR_DIR:/grammar:ro" \
  -v "$VOID_OUT:/results" \
  --env-file "$VOID_OUT/run.env" \
  void-go-main:latest \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -dict /grammar/dict.json \
  -direct-shm \
  -skip-endpoint-on-500 \
  -no-ui \
  -time-budget 20 \
  -summary-file /results/summary.json \
  -report-file /results/report.json \
  -crash-file /results/crashes.jsonl \
  -unique-crash-file /results/unique-crashes.jsonl \
  -poc-dir /results/pocs \
  -timeline-dir /results/timelines
```

### 4.4 Normalize a `RESTler` run into `metrics.json`

After every `RESTler` fuzz run, build a `metrics.json` file with the schema expected by the paper scripts:

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path

out = Path(os.environ["OUT"])
testing = next(out.glob("fuzz_run/**/testing_summary.json"))
bug_dir = next(out.glob("fuzz_run/**/bug_buckets"))
summary = json.loads(testing.read_text(encoding="utf-8"))

raw_requests = summary.get("total_requests_sent", 0)
if isinstance(raw_requests, dict):
    requests = sum(int(v or 0) for v in raw_requests.values())
else:
    requests = int(raw_requests or 0)

bucket_files = [
    p for p in bug_dir.glob("*.json")
    if p.name not in {"Bugs.json", "bug_buckets.json"}
]
buckets = [json.loads(p.read_text(encoding="utf-8")) for p in bucket_files]

metrics = {
    "requests": requests,
    "unique_bugs": len(bucket_files),
    "reproducible_unique_bugs": sum(1 for b in buckets if b.get("reproducible")),
    "final_spec_coverage": summary.get("final_spec_coverage"),
    "rendered_requests": summary.get("rendered_requests"),
    "rendered_requests_valid_status": summary.get("rendered_requests_valid_status"),
    "num_fully_valid": summary.get("num_fully_valid"),
    "num_sequence_failures": summary.get("num_sequence_failures"),
}

(out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
print(out / "metrics.json")
PY
```

Use it like this immediately after a `RESTler` run:

```bash
OUT="$RESULTS/eshop/restler-rerun"
export OUT
# then run the snippet above
```

## 5. Target Matrix

| Target | Vanilla Source | Instrumented Source | Swagger | Auth | Special Handling |
|---|---|---|---|---|---|
| eShopOnWeb | `to_test/eshop` | `benchmarks/prepared/eshop-20260313-144420` | `http://127.0.0.1:5200/swagger/v1/swagger.json` | `Void` auth bootstrap via `/api/authenticate` | none |
| CustomerLoyalty | `benchmarks/tmp/customer-loyalty-compose-5001.yml` | `benchmarks/prepared/customer-loyalty-20260313-151919` | `http://127.0.0.1:5001/swagger/v1/swagger.json` | none | apply EF migration before fuzzing |
| dotnet/eShop Catalog.API | `benchmarks/tmp/dotnet-eshop-catalog-vanilla.compose.yml` | `benchmarks/tmp/dotnet-eshop-catalog-instrumented.compose.yml` | internal `http://catalog-api:8080/openapi/v1.json` | none | remove picture endpoint, make `api-version` static `1.0` |
| Jellyfin | build temporary vanilla source image from `to_test/jellyfin` | `benchmarks/prepared/jellyfin-20260313-200500` | `http://127.0.0.1:8096/api-docs/openapi.json` or `http://127.0.0.1:8097/api-docs/openapi.json` | static `MediaBrowser` token for both tools | sanitize to 309 ops, exclude degraded `503` from fair metric |

## 6. eShopOnWeb

### 6.1 Vanilla + RESTler

```bash
OUT="$RESULTS/eshop/restler-rerun"
mkdir -p "$OUT/io/input" "$OUT/io/output/Compile" "$OUT/fuzz_run"

docker compose -f "$ROOT/to_test/eshop/docker-compose.yml" \
               -f "$ROOT/to_test/eshop/docker-compose.override.yml" \
               -p eshop_vanilla up -d

wait_for_url "http://127.0.0.1:5200/swagger/v1/swagger.json"
curl -sf "http://127.0.0.1:5200/swagger/v1/swagger.json" > "$OUT/io/input/swagger.json"
cp "$TMP/default_restler_dict.json" "$OUT/io/input/default_dict.json"
```

Create compiler config:

```bash
cat > "$OUT/io/input/compiler_config.json" <<'EOF'
{
  "SwaggerSpecFilePath": ["/io/input/swagger.json"],
  "GrammarOutputDirectoryPath": "/io/output/Compile",
  "CustomDictionaryFilePath": "/io/input/default_dict.json",
  "IncludeOptionalParameters": true,
  "UseHeaderExamples": true,
  "DataFuzzing": true,
  "ReadOnlyFuzz": false,
  "ResolveQueryDependencies": true,
  "ResolveBodyDependencies": true,
  "UseRefreshableToken": false
}
EOF
```

Compile and fuzz:

```bash
docker run --rm -v "$OUT/io:/io" restler-official:latest \
  dotnet /RESTler/restler/Restler.dll compile /io/input/compiler_config.json

docker run --rm -v "$OUT:/results" -w /results/fuzz_run \
  --add-host=host.docker.internal:host-gateway \
  restler-official:latest \
  dotnet /RESTler/restler/Restler.dll fuzz \
    --grammar_file /results/io/output/Compile/grammar.py \
    --dictionary_file /results/io/output/Compile/dict.json \
    --target_ip host.docker.internal \
    --target_port 5200 \
    --no_ssl \
    --time_budget 0.3334 \
    --search_strategy random-walk \
    --no_results_analyzer
```

Then normalize the run into `metrics.json` with the helper from section `4.4`.

### 6.2 Instrumented + `Void`

Reuse the prepared tree or regenerate it:

```bash
# optional regeneration
python3 "$ROOT/fuzz-prep-multi.py" \
  --src "$ROOT/to_test/eshop" \
  --out "$PREP/eshop-rerun" \
  --main PublicApi
```

Run the prepared instrumented stack:

```bash
docker compose -f "$PREP/eshop-20260313-144420/docker-compose.yml" \
               -f "$PREP/eshop-20260313-144420/docker-compose.override.yml" \
               -p eshop_upside up -d

wait_for_url "http://127.0.0.1:5200/swagger/v1/swagger.json"
curl -sf "http://127.0.0.1:5200/swagger/v1/swagger.json" > "$TMP/eshop.swagger.json"
curl -s -X POST "http://127.0.0.1:5200/shm/create" >/dev/null || true
```

Compile grammar and copy it to a per-run directory:

```bash
VOID_OUT="$RESULTS/eshop/void-go-main-skip-endpoint-rerun"
mkdir -p "$VOID_OUT"

"$ROOT/compile-grammar.sh" "$TMP/eshop.swagger.json" --src "$ROOT/to_test/eshop"
cp -R "$ROOT/restler_output/Compile" "$VOID_OUT/grammar"
```

Create `run.env`:

```bash
cat > "$VOID_OUT/run.env" <<'EOF'
TARGET_HOST=http://eshoppublicapi:8080
SHM_HOST=http://eshoppublicapi:8080
AUTH_BODY={"username":"admin@microsoft.com","password":"Pass@word1"}
AUTH_CONTENT_TYPE=application/json
AUTH_TOKEN_FIELD=token
EOF
```

Run `Void`:

```bash
VOID_NETWORK="eshop_upside_default"
VOID_COVERAGE_VOLUME="eshop_upside_coverage_shm"
VOID_GRAMMAR_DIR="$VOID_OUT/grammar"
docker run --rm --network "$VOID_NETWORK" \
  -v "$VOID_COVERAGE_VOLUME:/coverage_shm" \
  -v "$VOID_GRAMMAR_DIR:/grammar:ro" \
  -v "$VOID_OUT:/results" \
  --env-file "$VOID_OUT/run.env" \
  void-go-main:latest \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -dict /grammar/dict.json \
  -direct-shm \
  -skip-endpoint-on-500 \
  -no-ui \
  -time-budget 20 \
  -summary-file /results/summary.json \
  -report-file /results/report.json \
  -crash-file /results/crashes.jsonl \
  -unique-crash-file /results/unique-crashes.jsonl \
  -poc-dir /results/pocs \
  -timeline-dir /results/timelines
```

Collect comparable metrics:

```bash
python3 "$ROOT/benchmarks/collect_void_go_metrics.py" \
  --run-dir "$VOID_OUT" \
  --target "eShopOnWeb" \
  --runtime-image "void-go-main:latest" \
  --runtime-commit "current-main" \
  --network "$VOID_NETWORK" \
  --coverage-volume "$VOID_COVERAGE_VOLUME" \
  --target-url "http://eshoppublicapi:8080" \
  --auth-mode "explicit_auth_body" \
  --restler-metrics "$OUT/metrics.json" \
  --restler-buckets "$OUT/fuzz_run/Fuzz/RestlerResults/experiment30/bug_buckets" \
  --note "Explicit AUTH_BODY bootstrap used to authenticate against /api/authenticate" \
  --note "Use buggy_method_endpoints_full for fair HTTP 500 endpoint-level comparison"
```

## 7. CustomerLoyalty

### 7.1 Vanilla + RESTler

Use the saved port-5001 compose file because host port `5000` conflicts on macOS.

```bash
OUT="$RESULTS/customer-loyalty/restler-rerun"
mkdir -p "$OUT/io/input" "$OUT/io/output/Compile" "$OUT/fuzz_run"

docker compose -f "$ROOT/benchmarks/tmp/customer-loyalty-compose-5001.yml" \
               -p loyalty_vanilla up -d

wait_for_url "http://127.0.0.1:5001/swagger/v1/swagger.json"
curl -sf "http://127.0.0.1:5001/swagger/v1/swagger.json" > "$OUT/io/input/swagger.json"
cp "$TMP/default_restler_dict.json" "$OUT/io/input/default_dict.json"
```

Initialize the database from the existing EF migration before fuzzing:

```bash
docker run --rm \
  --network loyalty_vanilla_loyalty_network \
  -v "$ROOT/to_test/customer-loyalty:/src" \
  -w /src \
  -e ConnectionStrings__Database="Server=postgres_db_container;Port=5432;Database=CustomerLoyaltyDB;Username=postgres;Password=mysecretpassword;" \
  mcr.microsoft.com/dotnet/sdk:8.0 \
  bash -lc 'dotnet tool install --global dotnet-ef --version 8.* >/dev/null && export PATH="$PATH:/root/.dotnet/tools" && dotnet restore src/WebAPI/WebAPI.csproj >/dev/null && dotnet ef database update --project src/Infrastructure/Infrastructure.csproj --startup-project src/WebAPI/WebAPI.csproj'
```

Create compiler config, compile, and fuzz exactly as in the `eShopOnWeb` section, but target port `5001`.

Then normalize the run into `metrics.json` with the helper from section `4.4`.

### 7.2 Instrumented + `Void`

Reuse the prepared tree or regenerate it:

```bash
# optional regeneration
python3 "$ROOT/fuzz-prep-multi.py" \
  --src "$ROOT/to_test/customer-loyalty" \
  --out "$PREP/customer-loyalty-rerun" \
  --main WebAPI
```

Run the prepared instrumented stack with the port override:

```bash
docker compose -f "$PREP/customer-loyalty-20260313-151919/docker-compose.yml" \
               -f "$ROOT/benchmarks/tmp/customer-loyalty-port-override.yml" \
               -p loyalty_upside up -d

wait_for_url "http://127.0.0.1:5001/swagger/v1/swagger.json"
curl -sf "http://127.0.0.1:5001/swagger/v1/swagger.json" > "$TMP/customer-loyalty.swagger.json"
curl -s -X POST "http://127.0.0.1:5001/shm/create" >/dev/null || true
```

Initialize the instrumented database the same way:

```bash
docker run --rm \
  --network loyalty_upside_loyalty_network \
  -v "$PREP/customer-loyalty-20260313-151919:/src" \
  -w /src \
  -e ConnectionStrings__Database="Server=postgres_db_container;Port=5432;Database=CustomerLoyaltyDB;Username=postgres;Password=mysecretpassword;" \
  mcr.microsoft.com/dotnet/sdk:8.0 \
  bash -lc 'dotnet tool install --global dotnet-ef --version 8.* >/dev/null && export PATH="$PATH:/root/.dotnet/tools" && dotnet restore src/WebAPI/WebAPI.csproj >/dev/null && dotnet ef database update --project src/Infrastructure/Infrastructure.csproj --startup-project src/WebAPI/WebAPI.csproj'
```

Compile grammar, copy it to a per-run directory, create `run.env`, and run `Void`:

```bash
VOID_OUT="$RESULTS/customer-loyalty/void-go-main-skip-endpoint-rerun"
mkdir -p "$VOID_OUT"

"$ROOT/compile-grammar.sh" "$TMP/customer-loyalty.swagger.json" --src "$ROOT/to_test/customer-loyalty"
cp -R "$ROOT/restler_output/Compile" "$VOID_OUT/grammar"

cat > "$VOID_OUT/run.env" <<'EOF'
TARGET_HOST=http://loyalty_api:5000
SHM_HOST=http://loyalty_api:5000
EOF

VOID_NETWORK="loyalty_upside_loyalty_network"
VOID_COVERAGE_VOLUME="loyalty_upside_coverage_shm"
VOID_GRAMMAR_DIR="$VOID_OUT/grammar"
docker run --rm --network "$VOID_NETWORK" \
  -v "$VOID_COVERAGE_VOLUME:/coverage_shm" \
  -v "$VOID_GRAMMAR_DIR:/grammar:ro" \
  -v "$VOID_OUT:/results" \
  --env-file "$VOID_OUT/run.env" \
  void-go-main:latest \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -dict /grammar/dict.json \
  -direct-shm \
  -skip-endpoint-on-500 \
  -no-ui \
  -time-budget 20 \
  -summary-file /results/summary.json \
  -report-file /results/report.json \
  -crash-file /results/crashes.jsonl \
  -unique-crash-file /results/unique-crashes.jsonl \
  -poc-dir /results/pocs \
  -timeline-dir /results/timelines
```

Collect metrics with:

```bash
python3 "$ROOT/benchmarks/collect_void_go_metrics.py" \
  --run-dir "$VOID_OUT" \
  --target "CustomerLoyalty" \
  --runtime-image "void-go-main:latest" \
  --runtime-commit "current-main" \
  --network "$VOID_NETWORK" \
  --coverage-volume "$VOID_COVERAGE_VOLUME" \
  --target-url "http://loyalty_api:5000" \
  --auth-mode "none" \
  --restler-metrics "$OUT/metrics.json" \
  --restler-buckets "$OUT/fuzz_run/Fuzz/RestlerResults/experiment31/bug_buckets" \
  --note "No auth bootstrap used for this target" \
  --note "Use buggy_method_endpoints_full for fair HTTP 500 endpoint-level comparison"
```

## 8. dotnet/eShop Catalog.API

### 8.1 Vanilla + RESTler

Reuse the saved Dockerfile and compose file:

```bash
OUT="$RESULTS/dotnet-eshop-catalog/restler-rerun"
mkdir -p "$OUT/io/input" "$OUT/io/output/Compile" "$OUT/fuzz_run"

docker compose -f "$ROOT/benchmarks/tmp/dotnet-eshop-catalog-vanilla.compose.yml" \
               -p catalog_vanilla up -d

docker run --rm --network catalog_vanilla_default busybox \
  sh -lc "wget -qO- http://catalog-api:8080/openapi/v1.json" \
  > "$TMP/catalog.openapi.json"
```

Sanitize the spec to the shared 12-operation subset by removing the binary picture endpoint:

```bash
jq 'del(.paths["/api/catalog/items/{id}/pic"])' \
  "$TMP/catalog.openapi.json" > "$OUT/io/input/swagger.json"
cp "$TMP/default_restler_dict.json" "$OUT/io/input/default_dict.json"
```

Create compiler config, compile, and fuzz inside the same Docker network:

```bash
cat > "$OUT/io/input/compiler_config.json" <<'EOF'
{
  "SwaggerSpecFilePath": ["/io/input/swagger.json"],
  "GrammarOutputDirectoryPath": "/io/output/Compile",
  "CustomDictionaryFilePath": "/io/input/default_dict.json",
  "IncludeOptionalParameters": true,
  "UseHeaderExamples": true,
  "DataFuzzing": true,
  "ReadOnlyFuzz": false,
  "ResolveQueryDependencies": true,
  "ResolveBodyDependencies": true,
  "UseRefreshableToken": false
}
EOF

docker run --rm -v "$OUT/io:/io" restler-official:latest \
  dotnet /RESTler/restler/Restler.dll compile /io/input/compiler_config.json

docker run --rm --network catalog_vanilla_default \
  -v "$OUT:/results" -w /results/fuzz_run restler-official:latest \
  dotnet /RESTler/restler/Restler.dll fuzz \
    --grammar_file /results/io/output/Compile/grammar.py \
    --dictionary_file /results/io/output/Compile/dict.json \
    --target_ip catalog-api \
    --target_port 8080 \
    --no_ssl \
    --time_budget 0.3334 \
    --search_strategy random-walk \
    --no_results_analyzer
```

Then normalize the run into `metrics.json` with the helper from section `4.4`.

### 8.2 Instrumented + `Void`

Run the saved instrumented stack:

```bash
docker compose -f "$ROOT/benchmarks/tmp/dotnet-eshop-catalog-instrumented.compose.yml" \
               -p catalog_upside up -d
```

Use the same sanitized swagger as RESTler for `Void` grammar generation:

```bash
VOID_OUT="$RESULTS/dotnet-eshop-catalog/void-go-main-skip-endpoint-rerun"
mkdir -p "$VOID_OUT"

"$ROOT/compile-grammar.sh" "$OUT/io/input/swagger.json" --src "$ROOT/to_test/dotnet-eShop"
cp -R "$ROOT/restler_output/Compile" "$VOID_OUT/grammar"
```

Patch `api-version` to a static literal `1.0` in the copied grammar artifacts:

```bash
python3 - <<'PY'
import json
import re
from pathlib import Path

root = Path("/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/dotnet-eshop-catalog/void-go-main-skip-endpoint-rerun/grammar")

grammar = root / "grammar.py"
text = grammar.read_text(encoding="utf-8")
text = re.sub(
    r'(primitives\.restler_static_string\("api-version="\),\n\s*)primitives\.restler_fuzzable_string\("fuzzstring", quoted=False\)',
    r'\1primitives.restler_static_string("1.0")',
    text,
)
grammar.write_text(text, encoding="utf-8")

templates = root / "templates.export.json"
doc = json.loads(templates.read_text(encoding="utf-8"))
for template in doc.get("templates", []):
    segments = template.get("segments", [])
    for i, seg in enumerate(segments[:-1]):
        nxt = segments[i + 1]
        if seg.get("kind") == "static" and seg.get("value") == "api-version=":
          if nxt.get("kind") == "fuzzable":
            segments[i + 1] = {"kind": "static", "value": "1.0"}
templates.write_text(json.dumps(doc), encoding="utf-8")
PY

touch "$VOID_OUT/grammar/templates.export.json"
```

Create `run.env`, fuzz, and collect metrics:

```bash
cat > "$VOID_OUT/run.env" <<'EOF'
TARGET_HOST=http://catalog-api:8080
SHM_HOST=http://catalog-api:8080
EOF

VOID_NETWORK="catalog_upside_default"
VOID_COVERAGE_VOLUME="catalog_upside_coverage_shm"
VOID_GRAMMAR_DIR="$VOID_OUT/grammar"
docker run --rm --network "$VOID_NETWORK" \
  -v "$VOID_COVERAGE_VOLUME:/coverage_shm" \
  -v "$VOID_GRAMMAR_DIR:/grammar:ro" \
  -v "$VOID_OUT:/results" \
  --env-file "$VOID_OUT/run.env" \
  void-go-main:latest \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -dict /grammar/dict.json \
  -direct-shm \
  -skip-endpoint-on-500 \
  -no-ui \
  -time-budget 20 \
  -summary-file /results/summary.json \
  -report-file /results/report.json \
  -crash-file /results/crashes.jsonl \
  -unique-crash-file /results/unique-crashes.jsonl \
  -poc-dir /results/pocs \
  -timeline-dir /results/timelines

python3 "$ROOT/benchmarks/collect_void_go_metrics.py" \
  --run-dir "$VOID_OUT" \
  --target "dotnet/eShop Catalog.API" \
  --runtime-image "void-go-main:latest" \
  --runtime-commit "current-main" \
  --network "$VOID_NETWORK" \
  --coverage-volume "$VOID_COVERAGE_VOLUME" \
  --target-url "http://catalog-api:8080" \
  --auth-mode "none" \
  --restler-metrics "$OUT/metrics.json" \
  --restler-buckets "$OUT/fuzz_run/Fuzz/RestlerResults/experiment31/bug_buckets" \
  --note "api-version converted to static literal 1.0 in copied grammar artifacts consumed by the current Go runtime" \
  --note "Use buggy_method_endpoints_full for fair HTTP 500 endpoint-level comparison"
```

Important:

- Ignore the historical invalid catalog runs:
  - `void-go-main-skip-endpoint-20260317-225527`
  - `void-go-main-skip-endpoint-20260317-231021`
- The authoritative fixed run is the one with `static-version`.

## 9. Jellyfin

### 9.1 Vanilla + RESTler

Create a temporary vanilla Dockerfile from the source tree so both legs use the same source revision:

```bash
cat > "$TMP/jellyfin-vanilla.Dockerfile" <<'EOF'
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . ./
RUN dotnet restore Jellyfin.Server/Jellyfin.Server.csproj
RUN dotnet publish Jellyfin.Server/Jellyfin.Server.csproj \
    -c Release \
    -o /app/publish \
    -p:UseAppHost=false \
    --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
RUN apt-get update \
 && apt-get install --no-install-recommends --yes ffmpeg libfontconfig1 libfreetype6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/publish ./
EXPOSE 8096
ENTRYPOINT ["dotnet", "jellyfin.dll", "--nowebclient"]
EOF

cat > "$TMP/jellyfin-vanilla.compose.yml" <<EOF
services:
  vanilla:
    container_name: jellyfin-vanilla
    build:
      context: $ROOT/to_test/jellyfin
      dockerfile: $TMP/jellyfin-vanilla.Dockerfile
    ports:
      - "8096:8096"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
EOF
```

Start the vanilla server and fetch the published OpenAPI:

```bash
OUT="$RESULTS/jellyfin/restler-rerun"
mkdir -p "$OUT/io/input" "$OUT/io/output/Compile" "$OUT/fuzz_run"

docker compose -f "$TMP/jellyfin-vanilla.compose.yml" -p jellyfin_vanilla up -d
wait_for_url "http://127.0.0.1:8096/api-docs/openapi.json" 180 2
curl -sf "http://127.0.0.1:8096/api-docs/openapi.json" > "$TMP/jellyfin.openapi.json"
```

Sanitize the OpenAPI to the same 309-operation subset used in the paper:

```bash
"$ROOT/sanitize-swagger-for-restler.sh" --in "$TMP/jellyfin.openapi.json" --out "$TMP/jellyfin.restler.json"

jq '
  del(.paths["/Audio/{itemId}/stream"]) |
  del(.paths["/Videos/{itemId}/stream"]) |
  del(.paths["/Items/{itemId}/Images"]) |
  del(.paths["/Artists/{name}/Images"]) |
  del(.paths["/Genres/{name}/Images"]) |
  del(.paths["/MusicGenres/{name}/Images"]) |
  del(.paths["/Persons/{name}/Images"]) |
  del(.paths["/Studios/{name}/Images"]) |
  del(.paths["/UserImage"]) |
  del(.paths["/Playback/BitrateTest"]) |
  del(.paths["/FallbackFont/Fonts"]) |
  del(.paths["/Providers/Subtitles/Subtitles"]) |
  del(.paths["/System/Configuration/{key}"].post)
' "$TMP/jellyfin.restler.json" > "$OUT/io/input/swagger.json"

cp "$TMP/default_restler_dict.json" "$OUT/io/input/default_dict.json"
```

Compile with RESTler:

```bash
cat > "$OUT/io/input/compiler_config.json" <<'EOF'
{
  "SwaggerSpecFilePath": ["/io/input/swagger.json"],
  "GrammarOutputDirectoryPath": "/io/output/Compile",
  "CustomDictionaryFilePath": "/io/input/default_dict.json",
  "IncludeOptionalParameters": true,
  "UseHeaderExamples": true,
  "DataFuzzing": true,
  "ReadOnlyFuzz": false,
  "ResolveQueryDependencies": true,
  "ResolveBodyDependencies": true,
  "UseRefreshableToken": false
}
EOF

docker run --rm -v "$OUT/io:/io" restler-official:latest \
  dotnet /RESTler/restler/Restler.dll compile /io/input/compiler_config.json
```

Obtain a token from the running vanilla server and patch it into the compiled grammar:

```bash
JELLYFIN_RESTLER_TOKEN="$(
  curl -sS \
    -H 'Authorization: MediaBrowser Client="Void", DeviceId="void-1", Device="Void", Version="1.0"' \
    -H 'Content-Type: application/json' \
    --data '{"Username":"root","Pw":""}' \
    http://127.0.0.1:8096/Users/AuthenticateByName | jq -r '.AccessToken'
)"

python3 - <<'PY'
import os
import re
from pathlib import Path
token = os.environ["JELLYFIN_RESTLER_TOKEN"]
grammar = Path("/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/jellyfin/restler-rerun/io/output/Compile/grammar.py")
text = grammar.read_text(encoding="utf-8")
text = re.sub(r'Token=[0-9a-fA-F]+', f'Token={token}', text)
grammar.write_text(text, encoding="utf-8")
PY
```

Run RESTler in the same network namespace as `jellyfin-vanilla`:

```bash
docker run --rm --name jellyfin-restler-run \
  --network container:jellyfin-vanilla \
  -v "$OUT:/results" -w /results/fuzz_run \
  restler-official:latest \
  dotnet /RESTler/restler/Restler.dll fuzz \
    --grammar_file /results/io/output/Compile/grammar.py \
    --dictionary_file /results/io/output/Compile/dict.json \
    --target_ip 127.0.0.1 \
    --target_port 8096 \
    --no_ssl \
    --time_budget 0.3334 \
    --search_strategy random-walk \
    --no_results_analyzer
```

Then normalize the run into `metrics.json` with the helper from section `4.4`.

### 9.2 Instrumented + `Void`

Reuse the prepared instrumented Jellyfin tree:

```bash
docker compose -f "$PREP/jellyfin-20260313-200500/docker-compose.instrumented.yml" \
               -p jellyfin_upside up -d

wait_for_url "http://127.0.0.1:8097/api-docs/openapi.json" 180 2
curl -sf "http://127.0.0.1:8097/api-docs/openapi.json" > "$TMP/jellyfin.instrumented.openapi.json"
curl -s -X POST "http://127.0.0.1:8097/shm/create" >/dev/null || true
```

Reuse the same sanitized swagger, compile grammar, and patch in a fresh token from the instrumented server:

```bash
VOID_OUT="$RESULTS/jellyfin/void-go-main-skip-endpoint-rerun"
mkdir -p "$VOID_OUT"

"$ROOT/compile-grammar.sh" "$OUT/io/input/swagger.json" --src "$ROOT/to_test/jellyfin"
cp -R "$ROOT/restler_output/Compile" "$VOID_OUT/grammar"

JELLYFIN_VOID_TOKEN="$(
  curl -sS \
    -H 'Authorization: MediaBrowser Client="Void", DeviceId="void-1", Device="Void", Version="1.0"' \
    -H 'Content-Type: application/json' \
    --data '{"Username":"root","Pw":""}' \
    http://127.0.0.1:8097/Users/AuthenticateByName | jq -r '.AccessToken'
)"

python3 - <<'PY'
import os
import re
from pathlib import Path
token = os.environ["JELLYFIN_VOID_TOKEN"]
root = Path("/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/jellyfin/void-go-main-skip-endpoint-rerun/grammar")
for name in ("grammar.py", "templates.export.json"):
    p = root / name
    text = p.read_text(encoding="utf-8")
    text = re.sub(r'Token=[0-9a-fA-F]+', f'Token={token}', text)
    p.write_text(text, encoding="utf-8")
PY

touch "$VOID_OUT/grammar/templates.export.json"
```

Create `run.env`, fuzz, and collect comparable metrics:

```bash
cat > "$VOID_OUT/run.env" <<'EOF'
TARGET_HOST=http://instrumented:8096
SHM_HOST=http://instrumented:8096
EOF

VOID_NETWORK="jellyfin_upside_default"
VOID_COVERAGE_VOLUME="jellyfin_upside_coverage_shm"
VOID_GRAMMAR_DIR="$VOID_OUT/grammar"
docker run --rm --network "$VOID_NETWORK" \
  -v "$VOID_COVERAGE_VOLUME:/coverage_shm" \
  -v "$VOID_GRAMMAR_DIR:/grammar:ro" \
  -v "$VOID_OUT:/results" \
  --env-file "$VOID_OUT/run.env" \
  void-go-main:latest \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -dict /grammar/dict.json \
  -direct-shm \
  -skip-endpoint-on-500 \
  -no-ui \
  -time-budget 20 \
  -summary-file /results/summary.json \
  -report-file /results/report.json \
  -crash-file /results/crashes.jsonl \
  -unique-crash-file /results/unique-crashes.jsonl \
  -poc-dir /results/pocs \
  -timeline-dir /results/timelines

python3 "$ROOT/benchmarks/collect_void_go_metrics.py" \
  --run-dir "$VOID_OUT" \
  --target "Jellyfin" \
  --runtime-image "void-go-main:latest" \
  --runtime-commit "current-main" \
  --network "$VOID_NETWORK" \
  --coverage-volume "$VOID_COVERAGE_VOLUME" \
  --target-url "http://instrumented:8096" \
  --auth-mode "static_media_browser_token" \
  --restler-metrics "$OUT/metrics.json" \
  --restler-buckets "$OUT/fuzz_run/Fuzz/RestlerResults/experiment31/bug_buckets" \
  --note "Fresh MediaBrowser auth token injected into copied grammar artifacts before the run" \
  --note "Use buggy_method_endpoints_full for fair HTTP 500 endpoint-level comparison"
```

Important:

- `Jellyfin` often enters a degraded state that returns many `503 "Server is loading"` responses after repeated faulting.
- Do not count those `503`s in the fair paper metric.
- The fair paper metric still uses only `HTTP 500 method+endpoint pairs`.

## 10. Build the Fair Comparison Table

After all four targets have both a `RESTler` run and a `Void` run with `metrics.json`, regenerate the paper table:

```bash
python3 "$ROOT/benchmarks/build_fair_endpoint_comparison.py"
```

Important:

- [build_fair_endpoint_comparison.py](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/build_fair_endpoint_comparison.py) currently hardcodes the authoritative paper directories from section `12`.
- If you rerun into new directories such as `*-rerun`, either:
  - overwrite the authoritative paper directories with the fresh artifacts, or
  - update the `TARGETS` array in that script before regenerating the table.

This updates:

- [comparison_table.json](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/paper-results-20260313/comparison_table.json)
- [paper_table.tex](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/paper-results-20260313/paper_table.tex)

## 11. Rebuild the Paper PDF

The benchmark section in [paper.tex](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/arxiv_paper/paper.tex) is hardcoded and must match the regenerated table.

After updating the text, rebuild:

```bash
docker run --rm \
  -v "$ROOT/arxiv_paper:/work" \
  -w /work \
  mcr.microsoft.com/dotnet/sdk:9.0 \
  bash -lc "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y texlive-latex-base texlive-latex-recommended texlive-latex-extra texlive-publishers texlive-science && pdflatex -interaction=nonstopmode paper.tex && pdflatex -interaction=nonstopmode paper.tex" \
  > "$ROOT/arxiv_paper/build.log" 2>&1
```

Outputs:

- [paper.pdf](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/arxiv_paper/paper.pdf)
- [build.log](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/arxiv_paper/build.log)

## 12. Authoritative Final Run Directories From the Paper Session

Use these as reference when validating a rerun:

- `eShopOnWeb`
  - RESTler: [restler-official-20260313-123628](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/eshop/restler-official-20260313-123628)
  - Void current-main: [void-go-main-skip-endpoint-20260317-180545](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/eshop/void-go-main-skip-endpoint-20260317-180545)
- `CustomerLoyalty`
  - RESTler corrected baseline: [restler-official-20260313-141340](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/customer-loyalty/restler-official-20260313-141340)
  - Void current-main: [void-go-main-skip-endpoint-20260317-182658](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/customer-loyalty/void-go-main-skip-endpoint-20260317-182658)
- `dotnet/eShop Catalog.API`
  - RESTler sanitized baseline: [restler-official-20260313-165426](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/dotnet-eshop-catalog/restler-official-20260313-165426)
  - Void current-main fixed run: [void-go-main-skip-endpoint-static-version-20260317-231905](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/dotnet-eshop-catalog/void-go-main-skip-endpoint-static-version-20260317-231905)
- `Jellyfin`
  - RESTler authenticated sanitized baseline: [restler-official-20260313-195526](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/jellyfin/restler-official-20260313-195526)
  - Void current-main: [void-go-main-skip-endpoint-20260317-230418](/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1/benchmarks/results/jellyfin/void-go-main-skip-endpoint-20260317-230418)

## 13. Final Sanity Checks

Before declaring a rerun successful, verify all of the following:

1. Every run lasted `20 minutes`.
2. Every `Void` run used `-skip-endpoint-on-500`.
3. `CustomerLoyalty` had its DB migrated before fuzzing.
4. `Catalog.API` used the 12-operation sanitized swagger and static `api-version=1.0`.
5. `Jellyfin` used the 309-operation sanitized swagger and a fresh static `MediaBrowser` token in both tools.
6. The fair table was built from `HTTP 500` endpoint pairs, not raw crash signatures.
7. Historical invalid `Catalog.API` attempts were not mixed into the paper numbers.
