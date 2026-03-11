#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SRC_DIR=""
OUT_DIR="$ROOT_DIR/nopcommerce-prepared"
MAIN_PROJECT="Nop.Web"
SWAGGER_URL=""
SWAGGER_FILE=""
DICT_FILE=""
TARGET_SERVICE=""
SKIP_BUILD=0
SKIP_UP=0
SKIP_GRAMMAR=0

usage() {
  cat <<'USAGE'
Usage:
  ./prepare-nopcommerce.sh --src <path_to_nopCommerce_repo> [options]

Options:
  --src <dir>                Path to nopCommerce source root (required)
  --out <dir>                Output dir for instrumented copy (default: ./nopcommerce-prepared)
  --main <project>           Main web project name (default: Nop.Web)
  --swagger-url <url>        Swagger URL to download (recommended)
  --swagger-file <file>      Existing swagger.json file path
  --dict <file>              Optional external dictionary JSON
  --service <name>           Docker compose API service name (auto-detect if omitted)
  --skip-build               Skip docker compose build
  --skip-up                  Skip docker compose up -d
  --skip-grammar             Skip grammar compile/deploy phase
  -h, --help                 Show help

Examples:
  ./prepare-nopcommerce.sh \
    --src ~/src/nopCommerce \
    --swagger-url http://localhost/fuzz/openapi.json

  ./prepare-nopcommerce.sh \
    --src ~/src/nopCommerce \
    --swagger-file ~/tmp/swagger-nop.json \
    --dict ./my-nop-dict.json \
    --skip-build --skip-up
USAGE
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

enable_swagger_in_main_project() {
  local out_dir="$1"
  local main_project="$2"
  local csproj_path
  csproj_path="$(find "$out_dir" -type f -name "${main_project}.csproj" | head -n 1 || true)"
  [[ -n "$csproj_path" ]] || die "Could not find ${main_project}.csproj under $out_dir"
  local program_cs
  program_cs="$(dirname "$csproj_path")/Program.cs"
  [[ -f "$program_cs" ]] || die "Could not find Program.cs near $csproj_path"

  python3 - "$csproj_path" "$program_cs" <<'PY'
from pathlib import Path
import re
import sys

csproj_path = Path(sys.argv[1])
program_path = Path(sys.argv[2])
project_dir = program_path.parent

csproj = csproj_path.read_text(encoding="utf-8", errors="ignore")
if 'PackageReference Include="Swashbuckle.AspNetCore"' not in csproj:
    block = (
        "  <ItemGroup>\n"
        "    <PackageReference Include=\"Swashbuckle.AspNetCore\" Version=\"7.2.0\" />\n"
        "  </ItemGroup>\n\n"
    )
    if "</Project>" in csproj:
        csproj = csproj.replace("</Project>", block + "</Project>")
    else:
        csproj += "\n" + block
    csproj_path.write_text(csproj, encoding="utf-8")

program = program_path.read_text(encoding="utf-8", errors="ignore")

service_anchor = re.search(
    r'(?m)^(\s*)builder\.Services\.ConfigureApplicationServices\(builder\);\s*$',
    program
)
if service_anchor:
    indent = service_anchor.group(1)
    extra = []
    if "builder.Services.AddEndpointsApiExplorer();" not in program:
        extra.append(f"{indent}builder.Services.AddEndpointsApiExplorer();")
    if "builder.Services.AddSwaggerGen();" not in program:
        extra.append(f"{indent}builder.Services.AddSwaggerGen();")
    if extra:
        program = (
            program[:service_anchor.end()]
            + "\n"
            + "\n".join(extra)
            + program[service_anchor.end():]
        )

middleware_anchor = re.search(
    r'(?m)^(\s*)app\.UseCoverageMiddleware\(\);\s*$',
    program
)
if middleware_anchor:
    indent = middleware_anchor.group(1)
    extra = []
    if "app.UseSwagger();" not in program:
        extra.append(f"{indent}app.UseSwagger();")
    if "app.UseSwaggerUI();" not in program:
        extra.append(f"{indent}app.UseSwaggerUI();")
    if "app.UseRouteOpenApiBypass();" not in program:
        extra.append(f"{indent}app.UseRouteOpenApiBypass();")
    if extra:
        program = (
            program[:middleware_anchor.end()]
            + "\n"
            + "\n".join(extra)
            + program[middleware_anchor.end():]
        )

if "app.AddRouteOpenApiEndpoints();" not in program:
    route_export_anchor = re.search(
        r'(?m)^(\s*)app\.AddCoverageEndpoints\(\);\s*$',
        program
    )
    if route_export_anchor:
        indent = route_export_anchor.group(1)
        program = (
            program[:route_export_anchor.end()]
            + f"\n{indent}app.AddRouteOpenApiEndpoints();"
            + program[route_export_anchor.end():]
        )

helpers_dir = project_dir / "Helpers"
helpers_dir.mkdir(parents=True, exist_ok=True)
route_export_file = helpers_dir / "RouteOpenApiExtensions.cs"
route_export_file.write_text(
"""using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Nop.Web.Helpers;

public static class RouteOpenApiExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    public static IApplicationBuilder UseRouteOpenApiBypass(this IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path.Value ?? string.Empty;
            if (path.Equals("/fuzz/routes", StringComparison.OrdinalIgnoreCase))
            {
                var ds = context.RequestServices.GetRequiredService<EndpointDataSource>();
                await WriteJson(context, BuildRouteRows(ds));
                return;
            }

            if (path.Equals("/fuzz/openapi.json", StringComparison.OrdinalIgnoreCase))
            {
                var ds = context.RequestServices.GetRequiredService<EndpointDataSource>();
                await WriteJson(context, BuildOpenApiDocument(ds));
                return;
            }

            await next();
        });

        return app;
    }

    public static void AddRouteOpenApiEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/fuzz/routes", (EndpointDataSource ds) => Results.Json(BuildRouteRows(ds)));
        endpoints.MapGet("/fuzz/openapi.json", (EndpointDataSource ds) => Results.Json(BuildOpenApiDocument(ds)));
    }

    private static async Task WriteJson(HttpContext context, object payload)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json; charset=utf-8";
        await JsonSerializer.SerializeAsync(context.Response.Body, payload, JsonOptions);
    }

    private static List<Dictionary<string, object>> BuildRouteRows(EndpointDataSource ds)
    {
        var rows = ds.Endpoints
            .OfType<RouteEndpoint>()
            .Where(IsControllerAction)
            .Select(e => new
            {
                route = NormalizePath(e.RoutePattern.RawText),
                methods = GetMethods(e).ToArray(),
                displayName = e.DisplayName ?? string.Empty
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.route))
            .Where(x => !x.route.StartsWith("/shm/", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.route.StartsWith("/fuzz/", StringComparison.OrdinalIgnoreCase))
            .GroupBy(x => $"{x.route}|{string.Join(",", x.methods)}|{x.displayName}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(x => x.route, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.displayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = new List<Dictionary<string, object>>(rows.Count);
        foreach (var row in rows)
        {
            result.Add(new Dictionary<string, object>
            {
                ["route"] = row.route,
                ["methods"] = row.methods,
                ["displayName"] = row.displayName
            });
        }

        return result;
    }

    private static Dictionary<string, object> BuildOpenApiDocument(EndpointDataSource ds)
    {
        var paths = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        var endpointsList = ds.Endpoints
            .OfType<RouteEndpoint>()
            .Where(IsControllerAction)
            .ToList();

        foreach (var e in endpointsList)
        {
            var path = NormalizePath(e.RoutePattern.RawText);
            if (string.IsNullOrWhiteSpace(path) ||
                path.StartsWith("/shm/", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/fuzz/", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!paths.TryGetValue(path, out var methodsObj) || methodsObj is not Dictionary<string, object> methodMap)
            {
                methodMap = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                paths[path] = methodMap;
            }

            var action = e.Metadata.GetMetadata<ControllerActionDescriptor>();
            var tag = action?.ControllerName ?? "Web";
            var operationIdBase = $"{tag}_{action?.ActionName ?? "Action"}";
            var idx = 0;

            foreach (var method in GetMethods(e))
            {
                if (methodMap.ContainsKey(method))
                    continue;

                idx++;
                var op = new Dictionary<string, object>
                {
                    ["operationId"] = $"{operationIdBase}_{method}_{idx}",
                    ["tags"] = new[] { tag },
                    ["responses"] = new Dictionary<string, object>
                    {
                        ["200"] = new Dictionary<string, object> { ["description"] = "OK" }
                    }
                };

                var paramsList = BuildPathParameters(path);
                if (paramsList.Count > 0)
                    op["parameters"] = paramsList;

                if (method is "post" or "put" or "patch" or "delete")
                {
                    op["requestBody"] = new Dictionary<string, object>
                    {
                        ["required"] = false,
                        ["content"] = new Dictionary<string, object>
                        {
                            ["application/json"] = new Dictionary<string, object>
                            {
                                ["schema"] = new Dictionary<string, object>
                                {
                                    ["type"] = "object",
                                    ["additionalProperties"] = true
                                }
                            },
                            ["application/x-www-form-urlencoded"] = new Dictionary<string, object>
                            {
                                ["schema"] = new Dictionary<string, object>
                                {
                                    ["type"] = "object",
                                    ["additionalProperties"] = true
                                }
                            },
                            ["multipart/form-data"] = new Dictionary<string, object>
                            {
                                ["schema"] = new Dictionary<string, object>
                                {
                                    ["type"] = "object",
                                    ["additionalProperties"] = true
                                }
                            }
                        }
                    };
                }

                methodMap[method] = op;
            }
        }

        return new Dictionary<string, object>
        {
            ["openapi"] = "3.0.1",
            ["info"] = new Dictionary<string, object>
            {
                ["title"] = "nopCommerce Route Export",
                ["version"] = "1.0-route-export"
            },
            ["paths"] = paths
        };
    }

    private static bool IsControllerAction(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetMetadata<ControllerActionDescriptor>() is not null;

    private static IEnumerable<string> GetMethods(RouteEndpoint endpoint)
    {
        var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods;
        if (methods is null || methods.Count == 0)
            return new[] { "get" };
        return methods.Select(m => m.ToLowerInvariant()).Distinct();
    }

    private static string NormalizePath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "/";
        var path = raw.StartsWith("/") ? raw : "/" + raw;
        path = Regex.Replace(path, @"\{[*]{0,2}([^}:?=]+)(?:[^}]*)\}", "{$1}");
        return path;
    }

    private static List<Dictionary<string, object>> BuildPathParameters(string path)
    {
        var list = new List<Dictionary<string, object>>();
        var matches = Regex.Matches(path, @"\{([^}]+)\}");
        foreach (Match m in matches)
        {
            var name = m.Groups[1].Value.Trim();
            if (string.IsNullOrWhiteSpace(name))
                continue;
            list.Add(new Dictionary<string, object>
            {
                ["name"] = name,
                ["in"] = "path",
                ["required"] = true,
                ["schema"] = new Dictionary<string, object> { ["type"] = "string" }
            });
        }
        return list;
    }
}
""",
    encoding="utf-8",
)

program_path.write_text(program, encoding="utf-8")
PY

  echo "Enabled Swagger in: $program_cs"
}

ensure_rollforward_in_dockerfile() {
  local out_dir="$1"
  local dockerfile_path=""
  for name in Dockerfile dockerfile; do
    if [[ -f "$out_dir/$name" ]]; then
      dockerfile_path="$out_dir/$name"
      break
    fi
  done
  [[ -n "$dockerfile_path" ]] || return 0

  if grep -q "dotnet /instrumentor/bin/instrumentor.dll" "$dockerfile_path" && \
     ! grep -q "DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll" "$dockerfile_path"; then
    sed -i '' 's#dotnet /instrumentor/bin/instrumentor\\.dll#DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll#g' "$dockerfile_path"
    echo "Patched Dockerfile: enabled DOTNET_ROLL_FORWARD=Major for instrumentor runtime compatibility"
  fi
}

validate_program_cs_order() {
  local out_dir="$1"
  local status=0
  while IFS= read -r file; do
    python3 - "$file" <<'PY' || status=1
from pathlib import Path
import re
import sys

p = Path(sys.argv[1])
txt = p.read_text(encoding="utf-8", errors="ignore")
init = txt.find("CoverageExtensions.Initialize();")
ns = re.search(r'^\s*namespace\s+[A-Za-z0-9_.]+\s*;\s*$', txt, flags=re.MULTILINE)
if init >= 0 and ns and init < ns.start():
    print(f"Invalid order in {p}: CoverageExtensions.Initialize() appears before file-scoped namespace", file=sys.stderr)
    sys.exit(1)
PY
  done < <(find "$out_dir" -type f -name Program.cs)

  [[ "$status" -eq 0 ]] || die "Program.cs injection sanity check failed"
}

validate_compose() {
  local out_dir="$1"
  local compose_file="$2"
  if ! (cd "$out_dir" && docker compose -f "$compose_file" config >/dev/null); then
    die "docker compose validation failed for $compose_file"
  fi
}

is_nonempty_openapi() {
  local file_path="$1"
  python3 - "$file_path" <<'PY'
from pathlib import Path
import json
import sys

p = Path(sys.argv[1])
try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
paths = data.get("paths")
if isinstance(paths, dict) and len(paths) > 0:
    sys.exit(0)
sys.exit(1)
PY
}

detect_compose_file() {
  local dir="$1"
  local name
  for name in compose.yaml compose.yml docker-compose.yml docker-compose.yaml docker-compose.instrumented.yml; do
    if [[ -f "$dir/$name" ]]; then
      echo "$name"
      return 0
    fi
  done
  return 1
}

auto_detect_service() {
  local compose_path="$1"
  awk '
    /^services:/ {in_services=1; next}
    in_services && /^[^[:space:]]/ {in_services=0}
    in_services && /^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*$/ {
      name=$1
      sub(":$", "", name)
      print name
    }
  ' "$compose_path" | awk 'BEGIN{IGNORECASE=1} !/^(db|postgres|postgresql|mysql|mssql|sqlserver|redis|rabbitmq|kafka|zookeeper|elasticsearch|mailhog|minio|azurite|seq|jaeger)$/ {print; exit}'
}

abspath() {
  local p="$1"
  if [[ -d "$p" ]]; then
    (cd "$p" && pwd)
  else
    echo "$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src)
      SRC_DIR="${2:-}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --main)
      MAIN_PROJECT="${2:-}"
      shift 2
      ;;
    --swagger-url)
      SWAGGER_URL="${2:-}"
      shift 2
      ;;
    --swagger-file)
      SWAGGER_FILE="${2:-}"
      shift 2
      ;;
    --dict)
      DICT_FILE="${2:-}"
      shift 2
      ;;
    --service)
      TARGET_SERVICE="${2:-}"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-up)
      SKIP_UP=1
      shift
      ;;
    --skip-grammar)
      SKIP_GRAMMAR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$SRC_DIR" ]] || die "--src is required"
[[ -d "$SRC_DIR" ]] || die "Source directory not found: $SRC_DIR"
[[ -z "$SWAGGER_FILE" || -f "$SWAGGER_FILE" ]] || die "Swagger file not found: $SWAGGER_FILE"
[[ -z "$DICT_FILE" || -f "$DICT_FILE" ]] || die "Dictionary file not found: $DICT_FILE"

SRC_DIR="$(abspath "$SRC_DIR")"
OUT_DIR="$(abspath "$OUT_DIR")"
if [[ -n "$SWAGGER_FILE" ]]; then
  SWAGGER_FILE="$(abspath "$SWAGGER_FILE")"
fi
if [[ -n "$DICT_FILE" ]]; then
  DICT_FILE="$(abspath "$DICT_FILE")"
fi

echo "[1/6] Instrumenting nopCommerce source"
python3 "$ROOT_DIR/fuzz-prep-multi.py" \
  --src "$SRC_DIR" \
  --out "$OUT_DIR" \
  --main "$MAIN_PROJECT"

enable_swagger_in_main_project "$OUT_DIR" "$MAIN_PROJECT"
ensure_rollforward_in_dockerfile "$OUT_DIR"
validate_program_cs_order "$OUT_DIR"

COMPOSE_FILE="$(detect_compose_file "$OUT_DIR" || true)"
[[ -n "$COMPOSE_FILE" ]] || die "Compose file not found in $OUT_DIR"
validate_compose "$OUT_DIR" "$COMPOSE_FILE"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "[2/6] docker compose build"
  (cd "$OUT_DIR" && docker compose -f "$COMPOSE_FILE" build)
else
  echo "[2/6] Skipping build"
fi

if [[ "$SKIP_UP" -eq 0 ]]; then
  echo "[3/6] docker compose up -d"
  (cd "$OUT_DIR" && docker compose -f "$COMPOSE_FILE" up -d)
else
  echo "[3/6] Skipping up -d"
fi

SWAGGER_OUT="$ROOT_DIR/swagger-nopcommerce.json"
if [[ "$SKIP_GRAMMAR" -eq 0 ]]; then
  echo "[4/6] Obtaining swagger"
  if [[ -n "$SWAGGER_URL" ]]; then
    curl -fsSL "$SWAGGER_URL" -o "$SWAGGER_OUT"
    is_nonempty_openapi "$SWAGGER_OUT" || die "Downloaded document from $SWAGGER_URL is not a non-empty OpenAPI file"
    echo "Saved swagger from URL: $SWAGGER_OUT"
  elif [[ -n "$SWAGGER_FILE" ]]; then
    cp "$SWAGGER_FILE" "$SWAGGER_OUT"
    is_nonempty_openapi "$SWAGGER_OUT" || die "Provided --swagger-file is not a non-empty OpenAPI file: $SWAGGER_FILE"
    echo "Copied swagger file to: $SWAGGER_OUT"
  else
    SWAGGER_FOUND=0
    for candidate in \
      "http://localhost/fuzz/openapi.json" \
      "http://localhost:80/fuzz/openapi.json" \
      "http://localhost:8080/fuzz/openapi.json" \
      "http://localhost/swagger/v1/swagger.json" \
      "http://localhost:8080/swagger/v1/swagger.json"; do
      if curl -fsSL "$candidate" -o "$SWAGGER_OUT" && is_nonempty_openapi "$SWAGGER_OUT"; then
        echo "Saved swagger from auto endpoint: $candidate -> $SWAGGER_OUT"
        SWAGGER_FOUND=1
        break
      fi
    done
    [[ "$SWAGGER_FOUND" -eq 1 ]] || die "No valid OpenAPI document found. Pass --swagger-url or --swagger-file"
  fi

  echo "[5/6] Compiling and enhancing grammar"
  if [[ -n "$DICT_FILE" ]]; then
    "$ROOT_DIR/compile-grammar.sh" "$SWAGGER_OUT" --dict "$DICT_FILE" --src "$SRC_DIR"
  else
    "$ROOT_DIR/compile-grammar.sh" "$SWAGGER_OUT" --src "$SRC_DIR"
  fi

  echo "[6/6] Deploying grammar"
  "$ROOT_DIR/deploy-grammar.sh"

  mkdir -p "$ROOT_DIR/grammars/nopcommerce"
  cp "$ROOT_DIR/restler_output/Compile/grammar.py" "$ROOT_DIR/grammars/nopcommerce/grammar.py"
  cp "$ROOT_DIR/restler_output/Compile/dict.json" "$ROOT_DIR/grammars/nopcommerce/dict.json"
  echo "Saved snapshot grammar to: $ROOT_DIR/grammars/nopcommerce"
else
  echo "[4/6] Skipping grammar phase"
  echo "[5/6] Skipping grammar phase"
  echo "[6/6] Skipping grammar phase"
fi

if [[ -z "$TARGET_SERVICE" ]]; then
  TARGET_SERVICE="$(auto_detect_service "$OUT_DIR/$COMPOSE_FILE" || true)"
fi
if [[ -z "$TARGET_SERVICE" ]]; then
  TARGET_SERVICE="app"
  echo "Warning: service auto-detect failed, using fallback service name: $TARGET_SERVICE"
fi

FUZZ_OVERRIDE="$OUT_DIR/docker-compose.fuzz-go.yml"
cat > "$FUZZ_OVERRIDE" <<EOF2
services:
  smartfuzzer-go:
    profiles:
      - fuzz-go
    build:
      context: ../void
      dockerfile: Dockerfile.go
    volumes:
      - coverage_shm:/coverage_shm
      - ../void:/fuzzer
    environment:
      TARGET_HOST: \${TARGET_HOST:-http://${TARGET_SERVICE}:8080}
      SHM_HOST: \${SHM_HOST:-http://${TARGET_SERVICE}:8080}
      AUTH_TOKEN: \${AUTH_TOKEN:-}
      AUTH_COOKIE: \${AUTH_COOKIE:-}
      AUTH_HEADERS_JSON: \${AUTH_HEADERS_JSON:-}
      AUTH_URL: \${AUTH_URL:-}
      AUTH_METHOD: \${AUTH_METHOD:-}
      AUTH_BODY: \${AUTH_BODY:-}
      AUTH_CONTENT_TYPE: \${AUTH_CONTENT_TYPE:-}
      AUTH_TOKEN_FIELD: \${AUTH_TOKEN_FIELD:-}
    command:
      - --direct-shm
      - --shm-path
      - /coverage_shm/bitmap
      - --coverage-bitmap-size
      - "262144"
      - --grammar
      - /fuzzer
      - --refresh-templates
      - --time-budget
      - "30"
      - --concurrency
      - "16"
      - --adaptive-concurrency
      - --adaptive-content-type
      - --coverage-interval
      - "4"
      - --request-timeout
      - "2.5"
      - --sequence-prob
      - "0.55"
      - --sequence-max-depth
      - "5"
      - --sequence-fanout
      - "8"
    depends_on:
      - ${TARGET_SERVICE}

volumes:
  coverage_shm:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=4m
EOF2

cat <<EOF3

nopCommerce fuzzing prep completed.

Prepared project: $OUT_DIR
Compose file:      $COMPOSE_FILE
Fuzz override:     docker-compose.fuzz-go.yml
Target service:    $TARGET_SERVICE

Run target stack:
  cd "$OUT_DIR"
  docker compose -f "$COMPOSE_FILE" up -d

Run SmartFuzzer-Go (direct SHM):
  cd "$OUT_DIR"
  docker compose -f "$COMPOSE_FILE" -f docker-compose.fuzz-go.yml --profile fuzz-go run --rm smartfuzzer-go

Optional host override if app listens on :80 inside container:
  TARGET_HOST=http://${TARGET_SERVICE}:80 SHM_HOST=http://${TARGET_SERVICE}:80 \
  docker compose -f "$COMPOSE_FILE" -f docker-compose.fuzz-go.yml --profile fuzz-go run --rm smartfuzzer-go
EOF3
