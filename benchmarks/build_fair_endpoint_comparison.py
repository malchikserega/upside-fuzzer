#!/usr/bin/env python3
"""Build a fair benchmark comparison table for the paper artifacts.

The primary bug metric is:
  distinct buggy method+endpoint pairs that produced HTTP 500

For RESTler, this is the number of unique (verb, endpoint) pairs across the
bug bucket JSON files whose recorded status code is exactly 500.

For Void/UpsideFuzz, this is the normalized per-run endpoint aggregate recorded
in metrics.json as buggy_method_endpoints_full for the current Go runtime runs
executed with --skip-endpoint-on-500.

The table also reports OpenAPI endpoint coverage:
- RESTler: exact final OpenAPI/spec coverage reported by RESTler.
- Void: reconstructed OpenAPI coverage obtained by intersecting canonicalized
  runtime endpoint observations from summary.json with canonicalized OpenAPI
  templates from templates.export.json. When the runtime collapses path
  parameter types into a more generic placeholder, a template is credited only
  if that generalized observation matches exactly one remaining OpenAPI
  template for the same HTTP method.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path("/Users/sergeiovchinnikov/PycharmProjects/upside-fuzzer-1")
OUT_DIR = ROOT / "benchmarks" / "paper-results-20260313"


TARGETS = [
    {
        "id": "eshop",
        "name": "eShopOnWeb",
        "restler_metrics": ROOT / "benchmarks" / "results" / "eshop" / "restler-official-20260313-123628" / "metrics.json",
        "restler_buckets": ROOT / "benchmarks" / "results" / "eshop" / "restler-official-20260313-123628" / "fuzz_run" / "Fuzz" / "RestlerResults" / "experiment30" / "bug_buckets",
        "void_metrics": ROOT / "benchmarks" / "results" / "eshop" / "void-go-main-skip-endpoint-20260317-180545" / "metrics.json",
        "void_summary": ROOT / "benchmarks" / "results" / "eshop" / "void-go-main-skip-endpoint-20260317-180545" / "summary.json",
        "void_templates": ROOT / "benchmarks" / "results" / "eshop" / "void-go-main-skip-endpoint-20260317-180545" / "grammar" / "templates.export.json",
        "void_run_metadata": ROOT / "benchmarks" / "results" / "eshop" / "void-go-main-skip-endpoint-20260317-180545" / "run_metadata.json",
    },
    {
        "id": "loyalty",
        "name": "CustomerLoyalty",
        "restler_metrics": ROOT / "benchmarks" / "results" / "customer-loyalty" / "restler-official-20260313-141340" / "metrics.json",
        "restler_buckets": ROOT / "benchmarks" / "results" / "customer-loyalty" / "restler-official-20260313-141340" / "fuzz_run" / "Fuzz" / "RestlerResults" / "experiment31" / "bug_buckets",
        "void_metrics": ROOT / "benchmarks" / "results" / "customer-loyalty" / "void-go-main-skip-endpoint-20260317-182658" / "metrics.json",
        "void_summary": ROOT / "benchmarks" / "results" / "customer-loyalty" / "void-go-main-skip-endpoint-20260317-182658" / "summary.json",
        "void_templates": ROOT / "benchmarks" / "results" / "customer-loyalty" / "void-go-main-skip-endpoint-20260317-182658" / "grammar" / "templates.export.json",
        "void_run_metadata": ROOT / "benchmarks" / "results" / "customer-loyalty" / "void-go-main-skip-endpoint-20260317-182658" / "run_metadata.json",
    },
    {
        "id": "dotnet-eshop-catalog",
        "name": "dotnet/eShop Catalog.API",
        "restler_metrics": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "restler-official-20260313-165426" / "metrics.json",
        "restler_buckets": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "restler-official-20260313-165426" / "fuzz_run" / "Fuzz" / "RestlerResults" / "experiment31" / "bug_buckets",
        "void_metrics": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "void-go-main-skip-endpoint-static-version-20260317-231905" / "metrics.json",
        "void_summary": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "void-go-main-skip-endpoint-static-version-20260317-231905" / "summary.json",
        "void_templates": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "void-go-main-skip-endpoint-static-version-20260317-231905" / "grammar" / "templates.export.json",
        "void_run_metadata": ROOT / "benchmarks" / "results" / "dotnet-eshop-catalog" / "void-go-main-skip-endpoint-static-version-20260317-231905" / "run_metadata.json",
    },
    {
        "id": "jellyfin",
        "name": "Jellyfin",
        "restler_metrics": ROOT / "benchmarks" / "results" / "jellyfin" / "restler-official-20260313-195526" / "metrics.json",
        "restler_buckets": ROOT / "benchmarks" / "results" / "jellyfin" / "restler-official-20260313-195526" / "fuzz_run" / "Fuzz" / "RestlerResults" / "experiment31" / "bug_buckets",
        "void_metrics": ROOT / "benchmarks" / "results" / "jellyfin" / "void-go-main-skip-endpoint-20260317-230418" / "metrics.json",
        "void_summary": ROOT / "benchmarks" / "results" / "jellyfin" / "void-go-main-skip-endpoint-20260317-230418" / "summary.json",
        "void_templates": ROOT / "benchmarks" / "results" / "jellyfin" / "void-go-main-skip-endpoint-20260317-230418" / "grammar" / "templates.export.json",
        "void_run_metadata": ROOT / "benchmarks" / "results" / "jellyfin" / "void-go-main-skip-endpoint-20260317-230418" / "run_metadata.json",
    },
]

PLACEHOLDER_SEGMENTS = {"{param}", "{id}", "{uuid}", "{int}", "{hex}", "{long}"}
SAMPLE_RE = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ALL_DIGITS_RE = re.compile(r"\d+$")
HEX_LONG_RE = re.compile(r"[0-9a-fA-F]{16,}$")
BIZ_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,}$")


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def fmt_int(value: int) -> str:
    return f"{value:,}"


def normalize_seg(segment: str) -> str:
    s = segment.strip()
    if not s:
        return s
    if len(s) > 64:
        return "{long}"
    if s.startswith("{") and s.endswith("}"):
        return "{param}"
    low = s.lower()
    if low in {"fuzzstring", "fuzzint", "fuzzbool", "fuzzuuid4", "fuzzuuid", "fuzzdate", "fuzzdatetime"}:
        return "{param}"
    if low.startswith("fuzz") or low.startswith("custom_payload"):
        return "{param}"
    if any(ch in s for ch in "'\"<>$"):
        return "{param}"
    if UUID_RE.fullmatch(s):
        return "{uuid}"
    if ALL_DIGITS_RE.fullmatch(s):
        return "{int}"
    if HEX_LONG_RE.fullmatch(s):
        return "{hex}"
    if BIZ_ID_RE.fullmatch(s) and any(ch.isdigit() for ch in s):
        if "-" in s or "_" in s or len(s) >= 24:
            return "{id}"
    return s


def normalize_path(path: str) -> str:
    path = path.split("?", 1)[0].strip()
    if not path or path == "/":
        return "/"
    parts = [p for p in path.strip("/").split("/") if p]
    return "/" + "/".join(normalize_seg(p) for p in parts)


def template_path_and_key(template: dict) -> tuple[str, str]:
    method = ""
    values: list[str] = []
    state = "method"
    defaults = {
        "uuid": "566048da-ed19-4cd3-8e0a-b7e0e1ec4d72",
        "int": "1",
        "number": "1.23",
        "bool": "true",
        "string": "fuzzstring",
        "datetime": "2019-06-26T20:20:39+00:00",
    }

    for segment in template["segments"]:
        value = segment.get("value", "")
        if state == "method":
            if segment["kind"] == "static" and value.endswith(" "):
                method = value.strip().upper()
                state = "path"
            continue
        if segment["kind"] == "static" and " HTTP/1.1" in value:
            values.append(value.split(" HTTP/1.1", 1)[0])
            break
        if segment["kind"] == "static":
            values.append(value)
            continue
        values.append(defaults.get(segment.get("value_type", ""), "fuzzstring"))

    path = normalize_path("".join(values))
    return path, f"{method} {path}"


def parse_request_sample(line: str) -> str | None:
    match = SAMPLE_RE.match(line)
    if not match:
        return None
    method = match.group(1).upper()
    path = normalize_path(match.group(2))
    return f"{method} {path}"


def split_segments(path: str) -> list[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


def unique_shape_match(observed_key: str, template_keys: set[str], already_covered: set[str]) -> str | None:
    method, path = observed_key.split(" ", 1)
    observed_segments = split_segments(path)
    matches: list[str] = []

    for template_key in template_keys:
        if template_key in already_covered:
            continue
        template_method, template_path = template_key.split(" ", 1)
        if template_method != method:
            continue
        template_segments = split_segments(template_path)
        if len(observed_segments) != len(template_segments):
            continue
        if all(
            obs == tmpl or obs in PLACEHOLDER_SEGMENTS or (tmpl in PLACEHOLDER_SEGMENTS and obs in PLACEHOLDER_SEGMENTS)
            for obs, tmpl in zip(observed_segments, template_segments)
        ):
            matches.append(template_key)

    if len(matches) == 1:
        return matches[0]
    return None


def build_void_template_keys(target: dict) -> tuple[set[str], list[str]]:
    template_export = load_json(target["void_templates"])
    template_keys: set[str] = set()
    auth_templates: list[str] = []

    for template in template_export["templates"]:
        path, key = template_path_and_key(template)
        if key.startswith("GET /shm/") or key.startswith("POST /shm/"):
            continue
        template_keys.add(key)
        if "authenticate" in path.lower():
            auth_templates.append(key)

    return template_keys, auth_templates


def reconstruct_void_openapi_coverage(target: dict) -> dict:
    summary = load_json(target["void_summary"])
    metadata = load_json(target["void_run_metadata"])
    template_keys, auth_templates = build_void_template_keys(target)

    observed_keys: list[str] = []
    observed_keys.extend(summary.get("auth_blocked_endpoints", {}).keys())
    observed_keys.extend(summary.get("client_error_samples", {}).keys())
    observed_keys.extend(summary.get("blocked_endpoints_500", []))
    observed_keys.extend(f"{entry['method'].upper()} {entry['path']}" for entry in summary.get("endpoints_500_observed", []))
    observed_keys.extend(f"{entry['method'].upper()} {normalize_path(entry['path'])}" for entry in summary.get("top_findings", []))
    observed_keys.extend(
        sample_key for sample_key in (parse_request_sample(line) for line in summary.get("request_value_samples", [])) if sample_key
    )

    covered = template_keys.intersection(observed_keys)
    shape_reconciled: list[tuple[str, str]] = []
    for observed_key in observed_keys:
        match = unique_shape_match(observed_key, template_keys, covered)
        if match:
            covered.add(match)
            shape_reconciled.append((observed_key, match))

    if str(metadata.get("auth_mode", "")).startswith("explicit_auth"):
        covered.update(auth_templates)

    return {
        "covered": len(covered),
        "total": len(template_keys),
        "coverage": f"{len(covered)}/{len(template_keys)}",
        "shape_reconciled": shape_reconciled,
        "template_keys": sorted(template_keys),
        "covered_keys": sorted(covered),
    }


def parse_restler_pairs(bucket_dir: Path) -> dict:
    pairs_all = set()
    pairs_repro = set()
    bucket_count_all = 0
    bucket_count_repro = 0

    for path in sorted(bucket_dir.glob("*.json")):
        if path.name in {"Bugs.json", "bug_buckets.json"}:
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        if str(data.get("status_code", "")).strip() != "500":
            continue
        verb = data.get("verb")
        endpoint = data.get("endpoint")
        reproducible = bool(data.get("reproducible"))
        if verb and endpoint:
            pair = (verb, endpoint)
            pairs_all.add(pair)
            if reproducible:
                pairs_repro.add(pair)
        bucket_count_all += 1
        if reproducible:
            bucket_count_repro += 1

    return {
        "bucket_count_all": bucket_count_all,
        "bucket_count_reproducible": bucket_count_repro,
        "unique_method_endpoint_all": len(pairs_all),
        "unique_method_endpoint_reproducible": len(pairs_repro),
    }


def restler_row(target: dict) -> dict:
    metrics = load_json(target["restler_metrics"])
    pairs = parse_restler_pairs(target["restler_buckets"])
    coverage = str(metrics["final_spec_coverage"]).replace(" / ", "/")
    covered_str, total_str = coverage.split("/")
    return {
        "target": target["name"],
        "tool": "RESTler",
        "endpoints": int(total_str),
        "openapi_covered": int(covered_str),
        "openapi_total": int(total_str),
        "openapi_coverage": coverage,
        "requests": metrics["requests"],
        "buggy_method_endpoints": pairs["unique_method_endpoint_all"],
        "feedback": "Spec-guided",
        "raw_unique_bug_buckets": metrics.get("unique_bugs"),
        "reproducible_unique_bug_buckets": metrics.get("reproducible_unique_bugs"),
        "methodology_source": "unique verb+endpoint pairs across RESTler bug bucket JSON files",
        "openapi_coverage_source": "exact final_spec_coverage from RESTler testing summary",
    }


def void_row(target: dict) -> dict:
    metrics = load_json(target["void_metrics"])
    coverage = reconstruct_void_openapi_coverage(target)
    raw_bug_signatures = metrics.get("unique_crash_signatures", metrics.get("unique_crashes"))
    buggy_method_endpoints = metrics["buggy_method_endpoints_full"]
    methodology_source = "per-run normalized method+endpoint pairs that produced HTTP 500 in the Go runtime artifacts"

    return {
        "target": target["name"],
        "tool": "Void",
        "project": "UpsideFuzz",
        "endpoints": coverage["total"],
        "openapi_covered": coverage["covered"],
        "openapi_total": coverage["total"],
        "openapi_coverage": coverage["coverage"],
        "requests": metrics["requests"],
        "buggy_method_endpoints": buggy_method_endpoints,
        "feedback": f"{fmt_int(metrics['coverage_new_edges'])} edges",
        "raw_unique_crash_signatures": raw_bug_signatures,
        "methodology_source": methodology_source,
        "openapi_coverage_source": (
            "reconstructed from canonicalized runtime endpoint observations in summary.json "
            "intersected with canonicalized OpenAPI templates from templates.export.json; "
            "generic placeholder observations are credited only when they match exactly one remaining template"
        ),
        "shape_reconciled_count": len(coverage["shape_reconciled"]),
    }


def build_rows() -> list[dict]:
    rows: list[dict] = []
    for target in TARGETS:
        rows.append(restler_row(target))
        rows.append(void_row(target))
    return rows


def write_json(rows: list[dict]) -> None:
    out = {
        "targets": [t["id"] for t in TARGETS],
        "tools": ["restler", "void"],
        "methodology": {
            "metric_name": "buggy_method_endpoints",
            "definition": "Distinct HTTP method + endpoint pairs that produced at least one HTTP 500 during the 20-minute campaign.",
            "restler_source": "Unique verb+endpoint pairs extracted from RESTler bug bucket JSON files whose recorded status code is 500.",
            "void_source": "Normalized method+endpoint pairs recorded by the Go Void runtime as blocked after observing HTTP 500 under --skip-endpoint-on-500.",
            "openapi_coverage_restler": "Exact final_spec_coverage reported by RESTler.",
            "openapi_coverage_void": (
                "Reconstructed from canonicalized runtime endpoint observations serialized in summary.json "
                "intersected with canonicalized OpenAPI templates from templates.export.json."
            ),
        },
        "rows": rows,
    }
    path = OUT_DIR / "comparison_table.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")


def write_tex(rows: list[dict]) -> None:
    lines = [
        r"\begin{tabular}{llrrrl}",
        r"\toprule",
        r"\textbf{Target} & \textbf{Tool} & \textbf{OpenAPI Cov.} & \textbf{Requests} & \textbf{500 M+E} & \textbf{Feedback} \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{row['target']} & {row['tool']} & {row['openapi_coverage']} & {fmt_int(row['requests'])} & {row['buggy_method_endpoints']} & {row['feedback']} \\\\"
        )
    lines.extend([r"\bottomrule", r"\end{tabular}"])
    (OUT_DIR / "paper_table.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rows = build_rows()
    write_json(rows)
    write_tex(rows)
    print(json.dumps({"rows": rows}, indent=2))


if __name__ == "__main__":
    main()
