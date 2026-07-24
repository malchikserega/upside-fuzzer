"""Assembles full request templates (method + path + query + headers + body) from a
parsed Operation, and writes the final templates.export.json in the exact shape
void/go/types.go's TemplateExport already unmarshals -- with seg_payload() emitting
"payload_key" (the bug fix from Grounding fact #1, done by construction here; zero Go
changes needed since Go already reads that field, it just never received it before).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .body_serializer import _field_hint_from_schema, _leaf_segments, seg_static, serialize_body
from .dependencies import DependencyPlan
from .oas import Operation, OASParser
from .roslyn_merge import RoslynIndex, merge_operation_fields


def _query_string_segments(op: Operation, dep_plan: Optional[DependencyPlan], op_index: int) -> List[Dict[str, Any]]:
    if not op.query_params:
        return []
    segs: List[Dict[str, Any]] = [seg_static("?")]
    for i, p in enumerate(op.query_params):
        if i > 0:
            segs.append(seg_static("&"))
        segs.append(seg_static(f"{p.name}="))
        segs.extend(_leaf_segments(p, p.name, op_index, dep_plan, force_unquoted=True))
    return segs


def _path_segments(op: Operation, dep_plan: Optional[DependencyPlan], op_index: int) -> List[Dict[str, Any]]:
    import re
    segs: List[Dict[str, Any]] = []
    parts = re.split(r"(\{[^}]+\})", op.path)
    for part in parts:
        if part == "":
            continue
        if part.startswith("{") and part.endswith("}"):
            pname = part[1:-1].strip()
            match = next((p for p in op.path_params if p.name == pname), None)
            hint = match if match is not None else _field_hint_from_schema(pname, {"type": "string"})
            segs.extend(_leaf_segments(hint, pname, op_index, dep_plan, force_unquoted=True))
        else:
            segs.append(seg_static(part))
    return segs


def _header_segments(op: Operation, dep_plan: Optional[DependencyPlan], op_index: int) -> List[Dict[str, Any]]:
    segs: List[Dict[str, Any]] = []
    for p in op.header_params:
        if p.name.lower() in ("authorization", "content-type", "accept", "host"):
            continue  # already emitted as fixed headers below
        segs.append(seg_static(f"{p.name}: "))
        segs.extend(_leaf_segments(p, p.name, op_index, dep_plan, force_unquoted=True))
        segs.append(seg_static("\r\n"))
    return segs


def build_template(
    op: Operation, op_index: int, parser: OASParser, roslyn_idx: Optional[RoslynIndex],
    dep_plan: Optional[DependencyPlan],
) -> Dict[str, Any]:
    segs: List[Dict[str, Any]] = [seg_static(f"{op.method} ")]
    segs.extend(_path_segments(op, dep_plan, op_index))
    segs.extend(_query_string_segments(op, dep_plan, op_index))
    segs.append(seg_static(" HTTP/1.1\r\n"))
    segs.append(seg_static("Accept: application/json\r\n"))
    segs.append(seg_static("Host: \r\n"))

    body_segs: List[Dict[str, Any]] = []
    if op.request_schema and not op.is_multipart:
        top_level = parser._collect_schema_fields(op.request_schema)
        top_level_by_name = {f.name: f for f in top_level if "." not in f.name}
        merged = merge_operation_fields(op, roslyn_idx, top_level_by_name)
        body_segs = serialize_body(op.request_schema, parser, merged, dep_plan, op_index)
        segs.append(seg_static("Content-Type: "))
        segs.append(seg_static(op.request_content_type or "application/json"))
        segs.append(seg_static("\r\n"))

    segs.extend(_header_segments(op, dep_plan, op_index))
    segs.append(seg_static("Authorization: Bearer TOKEN\r\n"))
    segs.append(seg_static("\r\n"))
    segs.extend(body_segs)
    segs.append(seg_static("\r\n"))

    reads = list(dict.fromkeys((dep_plan.reads.get(op_index, []) if dep_plan else [])))
    writes = list(dict.fromkeys((dep_plan.writes.get(op_index, []) if dep_plan else [])))

    return {
        "id": op_index,
        "request_id": f"{op.method}{op.path}",
        "segments": segs,
        "reads": reads,
        "writes": writes,
    }


def write_templates_export(templates: List[Dict[str, Any]], out_path: Path, skipped: int = 0) -> None:
    data = {"count": len(templates), "skipped": skipped, "templates": templates}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
