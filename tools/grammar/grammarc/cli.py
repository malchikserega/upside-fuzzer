#!/usr/bin/env python3
"""grammarc -- first-party OpenAPI (+ optional Roslyn constraints) -> grammar compiler.

Retires the RESTler dependency (docs/ARCHITECTURE_REVIEW.md Top-20 #9): parses the OpenAPI
spec directly, optionally merges real per-type/property C# validation constraints from
tools/dotnet/analyzer/'s roslyn-constraints.json (#10), infers producer/consumer relationships by
path/name convention, synthesizes boundary values, and emits templates.export.json +
dict.json directly -- collapsing the old compile -> cp -> export-templates.py dance
into one command, with zero Docker/RESTler involved.

Usage:
    python3 -m grammarc.cli --swagger swagger.json --out grammars/mytarget \
        [--roslyn grammars/mytarget/roslyn-constraints.json] [--dict external-dict.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .boundary import values_from_constraints
from .common import canonical_key
from .dependencies import infer as infer_dependencies
from .emit_dict import (
    CUSTOM_DICT_FILENAME,
    merge_custom_dict_convention,
    merge_external_dict,
    scaffold_custom_dict_if_missing,
    write_dict,
)
from .emit_templates import build_template, write_templates_export
from .multipart import build_multipart_template, multipart_dict_seeds
from .oas import OASParser
from .roslyn_merge import RoslynIndex, merge_operation_fields


def _build_dict_pool(operations, parser: OASParser, roslyn_idx, dep_plan) -> Dict[str, List[str]]:
    pool: Dict[str, List[str]] = {}

    def add(key: str, values: List[str]) -> None:
        if not values:
            return
        pool.setdefault(key, []).extend(values)

    for op_index, op in enumerate(operations):
        for p in op.path_params:
            key = dep_plan.payload_key.get(op_index, {}).get(p.name) or canonical_key(p.name)
            add(key, values_from_constraints(p))
        for p in op.query_params:
            add(canonical_key(p.name), values_from_constraints(p))
        for p in op.header_params:
            add(canonical_key(p.name), values_from_constraints(p))

        if op.request_schema:
            all_request_fields = parser._collect_schema_fields(op.request_schema)
            top_level = {f.name: f for f in all_request_fields if "." not in f.name}
            merged_top = merge_operation_fields(op, roslyn_idx, top_level)
            for f in all_request_fields:
                tail = f.name.split(".")[-1]
                if "." not in f.name:
                    hint = merged_top.get(f.name, f)
                    key = dep_plan.payload_key.get(op_index, {}).get(f.name) or canonical_key(tail)
                else:
                    hint = f
                    key = canonical_key(tail)
                add(key, values_from_constraints(hint))

        if op.response_schema:
            for f in parser._collect_schema_fields(op.response_schema):
                tail = f.name.split(".")[-1]
                add(canonical_key(tail), values_from_constraints(f))

    return pool


def compile_grammar(swagger_path: Path, out_dir: Path, roslyn_path: Path | None, external_dict_path: Path | None,
                     verbose: bool = False) -> int:
    try:
        spec = json.loads(swagger_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[grammarc] ERROR: failed to parse swagger JSON: {e}", file=sys.stderr)
        return 1

    parser = OASParser(spec)
    operations = parser.parse()

    roslyn_idx = None
    roslyn_types_matched = 0
    if roslyn_path and roslyn_path.exists():
        try:
            roslyn_data = json.loads(roslyn_path.read_text(encoding="utf-8"))
            roslyn_idx = RoslynIndex(roslyn_data)
        except Exception as e:
            print(f"[grammarc] WARNING: failed to parse roslyn constraints ({roslyn_path}): {e}", file=sys.stderr)

    dep_plan = infer_dependencies(operations)

    templates: List[Dict[str, Any]] = []
    skipped = 0
    next_id = 0
    for op_index, op in enumerate(operations):
        try:
            if roslyn_idx is not None and op.request_schema_ref_name and roslyn_idx.type_for_operation(op):
                roslyn_types_matched += 1
            tmpl = build_template(op, next_id, parser, roslyn_idx, dep_plan)
            templates.append(tmpl)
            next_id += 1
        except Exception as e:
            skipped += 1
            if verbose:
                print(f"[grammarc] WARNING: failed to serialize {op.method} {op.path}: {e}", file=sys.stderr)

    multipart_eps = parser.multipart_endpoints(operations)
    for ep in multipart_eps:
        try:
            templates.append(build_multipart_template(ep, next_id))
            next_id += 1
        except Exception as e:
            skipped += 1
            if verbose:
                print(f"[grammarc] WARNING: failed to serialize multipart {ep.method} {ep.path}: {e}", file=sys.stderr)

    pool = _build_dict_pool(operations, parser, roslyn_idx, dep_plan)
    for ep in multipart_eps:
        for k, vs in multipart_dict_seeds(ep).items():
            pool.setdefault(k, []).extend(vs)
    if external_dict_path:
        merge_external_dict(pool, external_dict_path, warn_on_parse_error=True)

    # Custom dictionary convention: scaffold a starter dict.custom.json the first
    # time this --out directory is compiled (never overwritten once it exists),
    # then always merge whatever's in it -- so domain-specific values a user adds
    # survive every future re-compile, without needing to remember --dict.
    scaffolded = scaffold_custom_dict_if_missing(out_dir)
    merge_custom_dict_convention(pool, out_dir)

    write_templates_export(templates, out_dir / "templates.export.json", skipped=skipped)
    write_dict(pool, out_dir / "dict.json")

    print(
        f"[grammarc] operations={len(operations)} templates={len(templates)} skipped={skipped} "
        f"multipart_endpoints={len(multipart_eps)} roslyn_matched_types={roslyn_types_matched} "
        f"dict_keys={len(pool)} -> {out_dir}"
    )
    if scaffolded:
        print(f"[grammarc] Created starter custom dictionary: {out_dir / CUSTOM_DICT_FILENAME}")
        print(f"[grammarc]   Add your own fuzzing values there -- it's merged automatically on every")
        print(f"[grammarc]   future compile and never overwritten. See docs/INSTRUCTIONS.md section 10.")
    else:
        print(f"[grammarc] Custom dictionary merged: {out_dir / CUSTOM_DICT_FILENAME}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="First-party OpenAPI -> grammar compiler (retires RESTler)")
    ap.add_argument("--swagger", required=True, help="Path to OpenAPI/Swagger JSON")
    ap.add_argument("--out", required=True, help="Output directory (templates.export.json + dict.json written here)")
    ap.add_argument("--roslyn", help="Path to tools/dotnet/analyzer/'s roslyn-constraints.json (optional)")
    ap.add_argument("--dict", dest="external_dict", help="Additional dictionary JSON to merge (optional)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    swagger_path = Path(args.swagger)
    if not swagger_path.exists():
        print(f"[grammarc] ERROR: swagger file not found: {swagger_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    roslyn_path = Path(args.roslyn) if args.roslyn else None
    external_dict_path = Path(args.external_dict) if args.external_dict else None

    return compile_grammar(swagger_path, out_dir, roslyn_path, external_dict_path, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
