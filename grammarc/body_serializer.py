"""Recursively serializes a resolved OpenAPI schema into the static/fuzzable/
custom_payload segment list void/go/template.go renders into request bytes.

This is genuinely new engineering with no prior first-party code to port -- RESTler's
own compiler did this before (enhance-grammar.py only ever *enriched* the dictionary
RESTler already produced; it never had to turn a schema into request bytes itself).

Design choices, all disclosed:
  - Objects -> `{"key":value,...}` interleaved static/value segments, joined by `,`.
  - Arrays -> a single representative element (matches today's non-exploding
    behavior; array structural fuzzing is an existing, separately-tracked limitation
    per docs/ARCHITECTURE_REVIEW.md subsystem-3 weakness #3, not a regression here).
  - oneOf/anyOf/discriminator -> first resolvable variant (same known limitation as
    today's RESTler-based pipeline had).
  - Leaf fields with a constrained or dictionary-worthy value pool (enum, pattern,
    length/range bound, id-like name) are emitted as `custom_payload` instead of
    `fuzzable` -- so dict.json's boundary pools (grammarc/boundary.py) and
    sequence/correlation values (dependencies.py's payload_key plan) actually reach
    the field at render time, which today's `fuzzable`-only RESTler output does not
    allow (void/go/template.go's `fuzzable` case never consults the dictionary).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .boundary import is_dictionary_worthy
from .common import canonical_key
from .dependencies import DependencyPlan
from .oas import FieldHint, OASParser


def seg_static(value: str) -> Dict[str, Any]:
    return {"kind": "static", "value": value}


def _constraint_fields(hint: Optional[FieldHint]) -> Dict[str, Any]:
    # Top-20 #14: carries the FieldHint's OpenAPI+Roslyn-merged constraints into the
    # segment JSON so void/go/mutation_engine.go can do field-aware boundary mutation
    # instead of purely generic candidates. Omitted entirely when unset, keeping old
    # consumers/diffs unaffected and templates.export.json lean.
    if hint is None:
        return {}
    out: Dict[str, Any] = {}
    if hint.min_length is not None:
        out["min_length"] = hint.min_length
    if hint.max_length is not None:
        out["max_length"] = hint.max_length
    if hint.minimum is not None:
        out["minimum"] = hint.minimum
    if hint.maximum is not None:
        out["maximum"] = hint.maximum
    if hint.pattern:
        out["pattern"] = hint.pattern
    if hint.enum_values:
        out["enum_values"] = list(hint.enum_values)
    return out


def seg_fuzzable(value_type: str, default: str, quoted: bool = False, hint: Optional[FieldHint] = None) -> Dict[str, Any]:
    seg = {"kind": "fuzzable", "value_type": value_type, "default": default, "quoted": quoted}
    seg.update(_constraint_fields(hint))
    return seg


def seg_payload(payload_key: str, quoted: bool = False, hint: Optional[FieldHint] = None) -> Dict[str, Any]:
    # THE bug fix, by construction: JSON key is "payload_key" (matching
    # void/go/types.go's Segment.PayloadKey json tag), not "name" as the old
    # export-templates.py::seg_payload() emitted.
    seg = {"kind": "custom_payload", "payload_key": payload_key, "quoted": quoted}
    seg.update(_constraint_fields(hint))
    return seg


_DEFAULTS = {"string": "fuzzstring", "integer": "1", "number": "1.23", "boolean": "true", "object": "{}"}


def _default_for(hint: FieldHint) -> str:
    if hint.examples:
        return hint.examples[0]
    if hint.enum_values:
        return hint.enum_values[0]
    return _DEFAULTS.get((hint.type_name or "string").lower(), "fuzzstring")


def _is_quoted(type_name: str) -> bool:
    return (type_name or "string").lower() not in ("integer", "number", "boolean")


def _field_hint_from_schema(name: str, rs: Dict[str, Any], required: bool = False) -> FieldHint:
    from .common import safe_float, safe_int, to_scalar, uniq
    p_type = str(rs.get("type", "string"))
    p_fmt = str(rs.get("format", ""))
    p_enum = [str(v) for v in rs.get("enum", [])] if isinstance(rs.get("enum"), list) else []
    examples: List[str] = []
    if "example" in rs:
        examples.append(to_scalar(rs.get("example")))
    if "default" in rs:
        examples.append(to_scalar(rs.get("default")))
    return FieldHint(
        name=name, type_name=p_type, fmt=p_fmt,
        enum_values=uniq([x for x in p_enum if x]), examples=uniq([x for x in examples if x]),
        min_length=safe_int(rs.get("minLength")), max_length=safe_int(rs.get("maxLength")),
        minimum=safe_float(rs.get("minimum")), maximum=safe_float(rs.get("maximum")),
        pattern=str(rs.get("pattern")) if rs.get("pattern") is not None else None,
        required=required,
    )


def _merge_object_props(rs: Dict[str, Any], parser: OASParser) -> tuple[Dict[str, Any], Set[str]]:
    merged_props: Dict[str, Any] = {}
    merged_required: Set[str] = set(rs.get("required", []) if isinstance(rs.get("required"), list) else [])
    for key in ("allOf", "oneOf", "anyOf"):
        entries = rs.get(key)
        if isinstance(entries, list):
            for sub in entries:
                sub_rs = parser.resolve_schema(sub)
                if not sub_rs:
                    continue
                props = sub_rs.get("properties")
                if isinstance(props, dict):
                    merged_props.update(props)
                req = sub_rs.get("required")
                if isinstance(req, list):
                    merged_required.update(req)
    props = rs.get("properties")
    if isinstance(props, dict):
        merged_props.update(props)
    return merged_props, merged_required


def _leaf_segments(
    hint: FieldHint, field_name: str, op_index: int, dep_plan: Optional[DependencyPlan],
    force_unquoted: bool = False,
) -> List[Dict[str, Any]]:
    # `quoted` wraps the rendered value in literal `"` characters -- correct for a
    # JSON-body string field, but never correct for a URL path/query segment or an HTTP
    # header value (found live against Bitwarden: string-typed path params like
    # `organizationId` were rendering as `/organizations/"<guid>"/...`, a URL that can
    # never route correctly, and getting mutated -> guaranteed-malformed-path crash
    # noise instead of real endpoint traffic). `force_unquoted=True` is passed by every
    # non-body caller (emit_templates.py's path/query/header segment builders); only
    # body_serializer.py's own JSON-body recursion leaves it False.
    quoted = False if force_unquoted else _is_quoted(hint.type_name)
    override = dep_plan.payload_key.get(op_index, {}).get(field_name) if dep_plan else None
    worthy = is_dictionary_worthy(hint) or override is not None
    if worthy:
        key = override or canonical_key(field_name)
        return [seg_payload(key, quoted=quoted, hint=hint)]
    return [seg_fuzzable(hint.type_name or "string", _default_for(hint), quoted=quoted, hint=hint)]


def serialize_body(
    schema: Dict[str, Any],
    parser: OASParser,
    top_level_merged: Dict[str, FieldHint],
    dep_plan: Optional[DependencyPlan],
    op_index: int,
) -> List[Dict[str, Any]]:
    return _serialize_node(schema, parser, path_prefix="", depth=0, top_level_merged=top_level_merged,
                            dep_plan=dep_plan, op_index=op_index)


def _serialize_node(
    schema: Any, parser: OASParser, path_prefix: str, depth: int,
    top_level_merged: Dict[str, FieldHint], dep_plan: Optional[DependencyPlan], op_index: int,
) -> List[Dict[str, Any]]:
    rs = parser.resolve_schema(schema)
    if not rs or depth > 6:
        return [seg_static("null")]

    merged_props, merged_required = _merge_object_props(rs, parser)

    if merged_props:
        segs: List[Dict[str, Any]] = [seg_static("{")]
        first = True
        for prop_name, prop_schema in merged_props.items():
            segs.append(seg_static("," if not first else ""))
            first = False
            segs.append(seg_static(f'"{prop_name}":'))
            full_path = f"{path_prefix}.{prop_name}" if path_prefix else prop_name
            p_rs = parser.resolve_schema(prop_schema)
            nested_props, _ = _merge_object_props(p_rs, parser)
            p_type = str(p_rs.get("type") or ("object" if nested_props else "string"))

            if nested_props or p_type == "object":
                segs.extend(_serialize_node(prop_schema, parser, full_path, depth + 1, top_level_merged, dep_plan, op_index))
            elif p_type == "array":
                items = p_rs.get("items")
                segs.append(seg_static("["))
                if isinstance(items, dict):
                    segs.extend(_serialize_node(items, parser, full_path, depth + 1, top_level_merged, dep_plan, op_index))
                segs.append(seg_static("]"))
            elif depth == 0 and prop_name in top_level_merged:
                segs.extend(_leaf_segments(top_level_merged[prop_name], prop_name, op_index, dep_plan))
            else:
                hint = _field_hint_from_schema(prop_name, p_rs, required=prop_name in merged_required)
                segs.extend(_leaf_segments(hint, prop_name, op_index, dep_plan))
        segs.append(seg_static("}"))
        return segs

    p_type = str(rs.get("type", "string"))
    if p_type == "array":
        items = rs.get("items")
        out = [seg_static("[")]
        if isinstance(items, dict):
            out.extend(_serialize_node(items, parser, path_prefix, depth + 1, top_level_merged, dep_plan, op_index))
        out.append(seg_static("]"))
        return out

    leaf_name = path_prefix.split(".")[-1] if path_prefix else "value"
    if depth == 0 and leaf_name in top_level_merged:
        return _leaf_segments(top_level_merged[leaf_name], leaf_name, op_index, dep_plan)
    hint = _field_hint_from_schema(leaf_name, rs)
    return _leaf_segments(hint, leaf_name, op_index, dep_plan)
