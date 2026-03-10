#!/usr/bin/env python3
"""
Enhance RESTler outputs (grammar.py + dict.json) using swagger + source hints.

Goals:
1) Keep RESTler as baseline compiler.
2) Improve dictionary quality from OpenAPI constraints/examples + C# source validation hints.
3) Add multipart seed request templates when OpenAPI declares multipart/form-data.

This script is intentionally generic (no endpoint hardcoding).
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _uniq(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _to_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None


def _py_string_literal(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _key_variants(name: str) -> List[str]:
    raw = str(name or "").strip()
    if not raw:
        return []
    dot_parts = [p for p in raw.split(".") if p]
    keep_raw = len(dot_parts) <= 4 and len(raw) <= 80
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", raw) if p]
    if not parts:
        return [raw]

    pascal = "".join(p[:1].upper() + p[1:] for p in parts)
    camel = pascal[:1].lower() + pascal[1:] if pascal else raw
    lower = "".join(parts).lower()
    dotted_tail = raw.split(".")[-1]

    variants: List[str] = [dotted_tail, pascal, camel, lower]
    if keep_raw:
        variants.insert(0, raw)
    return _uniq([v for v in variants if v])


def _looks_like_id_name(name: str) -> bool:
    c = _canonical_key(name)
    return c == "id" or c.endswith("id")


def _default_id_values(name: str) -> List[str]:
    base = re.sub(r"Id$", "", str(name or ""), flags=re.IGNORECASE)
    base = re.sub(r"[^A-Za-z0-9]+", "", base)
    if not base:
        base = "ID"
    prefix = base[:3].upper() if len(base) >= 3 else base.upper()
    if not prefix:
        prefix = "ID"
    return [
        f"{prefix}-0001",
        f"{prefix}-0042",
        f"{prefix}-1234-0001",
        f"{prefix}-1234-5678-0001",
    ]


# ---------------------------------------------------------------------------
# OpenAPI extraction
# ---------------------------------------------------------------------------

@dataclass
class FieldHint:
    name: str
    type_name: str = "string"
    fmt: str = ""
    enum_values: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    pattern: Optional[str] = None
    required: bool = False
    multipart_file: bool = False


@dataclass
class MultipartEndpoint:
    method: str
    path: str
    fields: List[FieldHint] = field(default_factory=list)


class OpenAPIExtractor:
    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec

    def _resolve_ref(self, ref: str) -> Dict[str, Any]:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        node: Any = self.spec
        for part in ref.lstrip("#/").split("/"):
            if not isinstance(node, dict):
                return {}
            node = node.get(part)
            if node is None:
                return {}
        return node if isinstance(node, dict) else {}

    def _resolve_schema(self, schema: Any, seen: Optional[Set[str]] = None, depth: int = 0) -> Dict[str, Any]:
        if seen is None:
            seen = set()
        if depth > 12 or not isinstance(schema, dict):
            return {}
        ref = schema.get("$ref")
        if isinstance(ref, str):
            if ref in seen:
                return {}
            target = self._resolve_ref(ref)
            return self._resolve_schema(target, seen | {ref}, depth + 1)
        return schema

    def _collect_schema_fields(
        self,
        schema: Dict[str, Any],
        prefix: str = "",
        required: Optional[Set[str]] = None,
        depth: int = 0,
        seen_nodes: Optional[Set[Tuple[int, str]]] = None,
    ) -> List[FieldHint]:
        out: List[FieldHint] = []
        if seen_nodes is None:
            seen_nodes = set()
        if depth > 5:
            return out
        rs = self._resolve_schema(schema)
        if not rs:
            return out
        node_sig = (id(rs), prefix)
        if node_sig in seen_nodes:
            return out
        seen_nodes = set(seen_nodes)
        seen_nodes.add(node_sig)

        if required is None:
            required = set(rs.get("required", [])) if isinstance(rs.get("required"), list) else set()

        # Merge combinators conservatively.
        merged_props: Dict[str, Any] = {}
        merged_required: Set[str] = set(required)
        for key in ("allOf", "oneOf", "anyOf"):
            entries = rs.get(key)
            if isinstance(entries, list):
                for sub in entries:
                    sub_rs = self._resolve_schema(sub)
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

        if merged_props:
            for prop_name, prop_schema in merged_props.items():
                p_rs = self._resolve_schema(prop_schema)
                if not p_rs:
                    continue
                full = f"{prefix}.{prop_name}" if prefix else prop_name
                p_type = str(p_rs.get("type", "string"))
                p_fmt = str(p_rs.get("format", ""))
                p_enum = [str(v) for v in p_rs.get("enum", [])] if isinstance(p_rs.get("enum"), list) else []
                examples: List[str] = []
                if "example" in p_rs:
                    examples.append(_to_scalar(p_rs.get("example")))
                if "default" in p_rs:
                    examples.append(_to_scalar(p_rs.get("default")))

                hint = FieldHint(
                    name=full,
                    type_name=p_type,
                    fmt=p_fmt,
                    enum_values=_uniq([x for x in p_enum if x != ""]),
                    examples=_uniq([x for x in examples if x != ""]),
                    min_length=_safe_int(p_rs.get("minLength")),
                    max_length=_safe_int(p_rs.get("maxLength")),
                    minimum=_safe_float(p_rs.get("minimum")),
                    maximum=_safe_float(p_rs.get("maximum")),
                    pattern=str(p_rs.get("pattern")) if p_rs.get("pattern") is not None else None,
                    required=prop_name in merged_required,
                    multipart_file=(p_type == "string" and p_fmt == "binary"),
                )
                out.append(hint)

                # Recurse into nested object/array fields.
                if p_type == "object" or "properties" in p_rs or "$ref" in p_rs:
                    out.extend(self._collect_schema_fields(p_rs, prefix=full, depth=depth + 1, seen_nodes=seen_nodes))
                elif p_type == "array":
                    items = p_rs.get("items")
                    if isinstance(items, dict):
                        out.extend(self._collect_schema_fields(items, prefix=full, depth=depth + 1, seen_nodes=seen_nodes))
            return out

        # Leaf schema.
        leaf_name = prefix if prefix else "value"
        p_type = str(rs.get("type", "string"))
        p_fmt = str(rs.get("format", ""))
        p_enum = [str(v) for v in rs.get("enum", [])] if isinstance(rs.get("enum"), list) else []
        examples: List[str] = []
        if "example" in rs:
            examples.append(_to_scalar(rs.get("example")))
        if "default" in rs:
            examples.append(_to_scalar(rs.get("default")))
        out.append(
            FieldHint(
                name=leaf_name,
                type_name=p_type,
                fmt=p_fmt,
                enum_values=_uniq([x for x in p_enum if x != ""]),
                examples=_uniq([x for x in examples if x != ""]),
                min_length=_safe_int(rs.get("minLength")),
                max_length=_safe_int(rs.get("maxLength")),
                minimum=_safe_float(rs.get("minimum")),
                maximum=_safe_float(rs.get("maximum")),
                pattern=str(rs.get("pattern")) if rs.get("pattern") is not None else None,
                multipart_file=(p_type == "string" and p_fmt == "binary"),
            )
        )
        return out

    def _iter_operations(self) -> Iterable[Tuple[str, str, Dict[str, Any], Dict[str, Any]]]:
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return []
        methods = ("get", "post", "put", "delete", "patch", "head", "options")
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in methods:
                op = path_item.get(method)
                if isinstance(op, dict):
                    yield method.upper(), str(path), op, path_item

    def extract(self) -> Tuple[List[FieldHint], List[MultipartEndpoint]]:
        all_fields: List[FieldHint] = []
        multipart_eps: List[MultipartEndpoint] = []
        is_v2 = "swagger" in self.spec and "openapi" not in self.spec

        global_consumes = self.spec.get("consumes", []) if isinstance(self.spec.get("consumes"), list) else []

        for method, path, op, path_item in self._iter_operations():
            local_params: List[Dict[str, Any]] = []
            for src in (path_item.get("parameters"), op.get("parameters")):
                if isinstance(src, list):
                    for p in src:
                        if isinstance(p, dict):
                            local_params.append(p)

            op_fields: List[FieldHint] = []
            multipart_here = False
            multipart_fields: List[FieldHint] = []

            # OpenAPI v3 requestBody
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                if "$ref" in rb:
                    rb = self._resolve_ref(str(rb.get("$ref")))
                content = rb.get("content")
                if isinstance(content, dict):
                    for ctype, media in content.items():
                        if not isinstance(media, dict):
                            continue
                        schema = media.get("schema")
                        if isinstance(schema, dict):
                            fields = self._collect_schema_fields(schema)
                            op_fields.extend(fields)
                            if "multipart/form-data" in str(ctype).lower():
                                multipart_here = True
                                multipart_fields.extend(fields)
                        if "example" in media:
                            ex = media.get("example")
                            if isinstance(ex, dict):
                                for k, v in ex.items():
                                    op_fields.append(FieldHint(name=str(k), examples=[_to_scalar(v)]))
                # requestBody.required is already implicit for payload existence.

            # Parameters (v2 + v3)
            for p in local_params:
                if "$ref" in p:
                    p = self._resolve_ref(str(p.get("$ref")))
                if not isinstance(p, dict):
                    continue
                pname = str(p.get("name", "param"))
                p_required = bool(p.get("required", False))
                p_schema = p.get("schema") if isinstance(p.get("schema"), dict) else p
                p_rs = self._resolve_schema(p_schema)
                p_type = str(p_rs.get("type", "string"))
                p_fmt = str(p_rs.get("format", ""))
                p_enum = [str(v) for v in p_rs.get("enum", [])] if isinstance(p_rs.get("enum"), list) else []
                p_examples: List[str] = []
                if "example" in p:
                    p_examples.append(_to_scalar(p.get("example")))
                if "default" in p:
                    p_examples.append(_to_scalar(p.get("default")))
                if "example" in p_rs:
                    p_examples.append(_to_scalar(p_rs.get("example")))
                in_loc = str(p.get("in", "")).lower()

                hint = FieldHint(
                    name=pname,
                    type_name=p_type,
                    fmt=p_fmt,
                    enum_values=_uniq([x for x in p_enum if x != ""]),
                    examples=_uniq([x for x in p_examples if x != ""]),
                    min_length=_safe_int(p_rs.get("minLength")),
                    max_length=_safe_int(p_rs.get("maxLength")),
                    minimum=_safe_float(p_rs.get("minimum")),
                    maximum=_safe_float(p_rs.get("maximum")),
                    pattern=str(p_rs.get("pattern")) if p_rs.get("pattern") is not None else None,
                    required=p_required,
                    multipart_file=(p_type == "file" or (p_type == "string" and p_fmt == "binary")),
                )
                op_fields.append(hint)
                if in_loc == "formdata":
                    consumes = op.get("consumes", global_consumes)
                    if isinstance(consumes, list) and any("multipart/form-data" in str(x).lower() for x in consumes):
                        multipart_here = True
                        multipart_fields.append(hint)

            all_fields.extend(op_fields)

            if multipart_here and method in ("POST", "PUT", "PATCH"):
                # Deduplicate multipart fields by canonical name.
                seen: Set[str] = set()
                deduped: List[FieldHint] = []
                for f in multipart_fields:
                    ck = _canonical_key(f.name)
                    if ck in seen:
                        continue
                    seen.add(ck)
                    deduped.append(f)
                multipart_eps.append(MultipartEndpoint(method=method, path=path, fields=deduped))

        return all_fields, multipart_eps


# ---------------------------------------------------------------------------
# Source hints extraction
# ---------------------------------------------------------------------------

@dataclass
class SourceFieldHint:
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    pattern: Optional[str] = None
    enum_values: List[str] = field(default_factory=list)
    required: bool = False
    email: bool = False
    url: bool = False


class SourceExtractor:
    def __init__(self, src_dir: Optional[Path]):
        self.src_dir = src_dir
        self.hints: Dict[str, SourceFieldHint] = {}
        self.enum_types: Dict[str, List[str]] = {}

    @staticmethod
    def _strip_cs_comments(text: str) -> str:
        # Remove block and line comments to reduce regex false positives.
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"//.*", "", text)
        return text

    @staticmethod
    def _enum_type_candidates(type_text: str) -> List[str]:
        raw = str(type_text or "").strip()
        if not raw:
            return []
        raw = raw.replace("?", "")

        out: List[str] = []

        def _add_token(token: str) -> None:
            tok = str(token or "").strip()
            if not tok:
                return
            tok = re.sub(r"\[\]$", "", tok)
            tail = tok.split(".")[-1]
            if tail:
                out.append(tail)

        _add_token(raw)
        for inner in re.findall(r"<([^<>]+)>", raw):
            for part in inner.split(","):
                _add_token(part)
        return _uniq(out)

    @staticmethod
    def _parse_enum_values(enum_body: str) -> List[str]:
        body = re.sub(r"\[[^\]]+\]", "", enum_body or "")
        values: List[str] = []
        current_int = -1

        for part in body.split(","):
            token = part.strip()
            if not token:
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*([^,\s]+))?$", token)
            if not m:
                continue
            name = m.group(1)
            assigned = (m.group(2) or "").strip()
            if assigned:
                parsed = _safe_int(assigned)
                if parsed is None:
                    try:
                        parsed = int(assigned, 0)
                    except Exception:
                        parsed = None
                if parsed is not None:
                    current_int = parsed
                else:
                    current_int += 1
            else:
                current_int += 1

            values.append(name)
            if current_int >= 0:
                values.append(str(current_int))
        return _uniq(values)

    def _merge_hint(self, key: str, hint: SourceFieldHint) -> None:
        ck = _canonical_key(key)
        if not ck:
            return
        cur = self.hints.get(ck, SourceFieldHint())
        if hint.min_length is not None:
            cur.min_length = hint.min_length if cur.min_length is None else max(cur.min_length, hint.min_length)
        if hint.max_length is not None:
            cur.max_length = hint.max_length if cur.max_length is None else min(cur.max_length, hint.max_length)
        if hint.minimum is not None:
            cur.minimum = hint.minimum if cur.minimum is None else max(cur.minimum, hint.minimum)
        if hint.maximum is not None:
            cur.maximum = hint.maximum if cur.maximum is None else min(cur.maximum, hint.maximum)
        if hint.pattern:
            cur.pattern = hint.pattern
        if hint.enum_values:
            cur.enum_values = _uniq(cur.enum_values + [str(v) for v in hint.enum_values if str(v)])
        cur.required = cur.required or hint.required
        cur.email = cur.email or hint.email
        cur.url = cur.url or hint.url
        self.hints[ck] = cur

    def _parse_attribute_block(self, attrs: str) -> SourceFieldHint:
        out = SourceFieldHint()
        m = re.search(r"StringLength\s*\(\s*(\d+)\s*\)", attrs, re.IGNORECASE)
        if m:
            out.max_length = _safe_int(m.group(1))
            mmin = re.search(r"MinimumLength\s*=\s*(\d+)", attrs, re.IGNORECASE)
            if mmin:
                out.min_length = _safe_int(mmin.group(1))
        m = re.search(r"MaxLength\s*\(\s*(\d+)\s*\)", attrs, re.IGNORECASE)
        if m:
            out.max_length = _safe_int(m.group(1))
        m = re.search(r"MinLength\s*\(\s*(\d+)\s*\)", attrs, re.IGNORECASE)
        if m:
            out.min_length = _safe_int(m.group(1))
        m = re.search(r"Range\s*\(\s*([-\d\.]+)\s*,\s*([-\d\.]+)\s*\)", attrs, re.IGNORECASE)
        if m:
            out.minimum = _safe_float(m.group(1))
            out.maximum = _safe_float(m.group(2))
        m = re.search(r"RegularExpression\s*\(\s*\"([^\"]+)\"", attrs, re.IGNORECASE)
        if m:
            out.pattern = m.group(1)
        if re.search(r"\bRequired\b", attrs, re.IGNORECASE):
            out.required = True
        if re.search(r"\bEmailAddress\b", attrs, re.IGNORECASE):
            out.email = True
        if re.search(r"\bUrl\b", attrs, re.IGNORECASE):
            out.url = True
        return out

    def _parse_fluent_chain(self, chain: str) -> SourceFieldHint:
        out = SourceFieldHint()
        m = re.search(r"MaximumLength\s*\(\s*(\d+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.max_length = _safe_int(m.group(1))
        m = re.search(r"MinimumLength\s*\(\s*(\d+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.min_length = _safe_int(m.group(1))
        m = re.search(r"Length\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.min_length = _safe_int(m.group(1))
            out.max_length = _safe_int(m.group(2))
        m = re.search(r"InclusiveBetween\s*\(\s*([-\d\.]+)\s*,\s*([-\d\.]+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.minimum = _safe_float(m.group(1))
            out.maximum = _safe_float(m.group(2))
        m = re.search(r"GreaterThanOrEqualTo\s*\(\s*([-\d\.]+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.minimum = _safe_float(m.group(1))
        m = re.search(r"LessThanOrEqualTo\s*\(\s*([-\d\.]+)\s*\)", chain, re.IGNORECASE)
        if m:
            out.maximum = _safe_float(m.group(1))
        m = re.search(r"Matches\s*\(\s*\"([^\"]+)\"\s*\)", chain, re.IGNORECASE)
        if m:
            out.pattern = m.group(1)
        if re.search(r"\bNotEmpty\s*\(", chain, re.IGNORECASE):
            out.required = True
        if re.search(r"\bEmailAddress\s*\(", chain, re.IGNORECASE):
            out.email = True
        return out

    def extract(self) -> Dict[str, SourceFieldHint]:
        if not self.src_dir or not self.src_dir.exists():
            return {}

        files = [p for p in self.src_dir.rglob("*.cs") if "/bin/" not in str(p) and "/obj/" not in str(p)]
        file_texts: List[str] = []
        for fp in files:
            try:
                file_texts.append(fp.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

        # Pass 1: collect enum type -> values from source.
        enum_decl_re = re.compile(
            r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\:\s*[A-Za-z0-9_\.]+)?\s*\{(.*?)\}",
            re.DOTALL,
        )
        for text in file_texts:
            clean = self._strip_cs_comments(text)
            for m in enum_decl_re.finditer(clean):
                enum_name = m.group(1) or ""
                enum_body = m.group(2) or ""
                vals = self._parse_enum_values(enum_body)
                if not enum_name or not vals:
                    continue
                self.enum_types[_canonical_key(enum_name)] = vals

        prop_re = re.compile(
            r"((?:\[[^\]]+\]\s*)*)\s*(?:public|internal|protected)\s+([A-Za-z0-9_<>,\.\?\[\]]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
            re.MULTILINE,
        )
        fluent_re = re.compile(
            r"RuleFor\(\s*\w+\s*=>\s*\w+\.([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*([^;]*);",
            re.MULTILINE,
        )

        # Pass 2: property attributes + fluent validators + enum-typed properties.
        for text in file_texts:
            text = self._strip_cs_comments(text)

            for m in prop_re.finditer(text):
                attrs = m.group(1) or ""
                ptype = m.group(2) or ""
                prop = m.group(3) or ""
                hint = self._parse_attribute_block(attrs)
                for type_name in self._enum_type_candidates(ptype):
                    enum_vals = self.enum_types.get(_canonical_key(type_name))
                    if enum_vals:
                        hint.enum_values = _uniq(hint.enum_values + enum_vals)
                self._merge_hint(prop, hint)

            for m in fluent_re.finditer(text):
                prop = m.group(1) or ""
                chain = m.group(2) or ""
                hint = self._parse_fluent_chain(chain)
                self._merge_hint(prop, hint)

        return self.hints


# ---------------------------------------------------------------------------
# Dictionary enhancer
# ---------------------------------------------------------------------------

def _empty_restler_dict() -> Dict[str, Any]:
    return {
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
        "restler_custom_payload_query": {},
    }


class DictionaryEnhancer:
    def __init__(
        self,
        restler_dict: Dict[str, Any],
        source_hints: Dict[str, SourceFieldHint],
    ):
        self.d = _empty_restler_dict()
        self._merge_dict(restler_dict)
        self.source_hints = source_hints
        self.stats_added = 0

    def _merge_dict(self, other: Dict[str, Any]) -> None:
        if not isinstance(other, dict):
            return
        for key, value in other.items():
            if key not in self.d:
                self.d[key] = value
                continue
            if isinstance(self.d[key], list) and isinstance(value, list):
                self.d[key].extend([_to_scalar(v) for v in value])
            elif isinstance(self.d[key], dict) and isinstance(value, dict):
                for sk, sv in value.items():
                    seq = sv if isinstance(sv, list) else [sv]
                    cur = self.d[key].setdefault(str(sk), [])
                    if isinstance(cur, list):
                        cur.extend([_to_scalar(v) for v in seq])
                    else:
                        self.d[key][str(sk)] = [_to_scalar(v) for v in seq]
            else:
                self.d[key] = value

    def _add_list_value(self, key: str, value: str) -> None:
        if key not in self.d or not isinstance(self.d[key], list):
            return
        val = _to_scalar(value)
        if val == "":
            return
        if val not in self.d[key]:
            self.d[key].append(val)
            self.stats_added += 1

    def _add_payload_value(self, container: str, key: str, value: str) -> None:
        c = self.d.get(container)
        if not isinstance(c, dict):
            return
        skey = str(key)
        val = _to_scalar(value)
        if not skey or val == "":
            return
        arr = c.setdefault(skey, [])
        if not isinstance(arr, list):
            arr = [_to_scalar(arr)]
            c[skey] = arr
        if val not in arr:
            arr.append(val)
            self.stats_added += 1

    def _apply_field_value(self, field_name: str, field_type: str, value: str) -> None:
        for kv in _key_variants(field_name):
            self._add_payload_value("restler_custom_payload", kv, value)
            if field_type in ("integer", "number", "boolean"):
                self._add_payload_value("restler_custom_payload_unquoted", kv, value)

        if field_type == "integer":
            self._add_list_value("restler_fuzzable_int", value)
        elif field_type == "number":
            self._add_list_value("restler_fuzzable_number", value)
        elif field_type == "boolean":
            self._add_list_value("restler_fuzzable_bool", value)
        elif field_type == "object":
            self._add_list_value("restler_fuzzable_object", value)
        else:
            self._add_list_value("restler_fuzzable_string", value)

    def _values_from_constraints(self, f: FieldHint, sh: Optional[SourceFieldHint]) -> List[str]:
        out: List[str] = []
        t = (f.type_name or "string").lower()
        fmt = (f.fmt or "").lower()

        out.extend([_to_scalar(x) for x in f.examples if _to_scalar(x) != ""])
        out.extend([_to_scalar(x) for x in f.enum_values if _to_scalar(x) != ""])

        if fmt == "uuid":
            out.extend([
                "566048da-ed19-4cd3-8e0a-b7e0e1ec4d72",
                "00000000-0000-0000-0000-000000000000",
            ])
        elif fmt in ("date-time", "datetime"):
            out.extend(["2024-01-15T00:00:00Z", "2020-02-29T12:00:00Z"])
        elif fmt == "date":
            out.extend(["2024-01-15", "2020-02-29"])
        elif fmt in ("email",):
            out.extend(["fuzzer@example.com", "devnull@example.org"])
        elif fmt in ("uri", "url"):
            out.extend(["https://example.com", "http://localhost"])

        if sh:
            if sh.email:
                out.extend(["fuzzer@example.com", "devnull@example.org"])
            if sh.url:
                out.extend(["https://example.com", "http://localhost"])

        if t in ("integer", "number"):
            minv = f.minimum
            maxv = f.maximum
            if sh:
                if sh.minimum is not None:
                    minv = sh.minimum if minv is None else max(minv, sh.minimum)
                if sh.maximum is not None:
                    maxv = sh.maximum if maxv is None else min(maxv, sh.maximum)
            if minv is not None:
                out.append(str(int(minv) if t == "integer" else float(minv)))
                out.append(str(int(minv - 1) if t == "integer" else float(minv - 1)))
            if maxv is not None:
                out.append(str(int(maxv) if t == "integer" else float(maxv)))
                out.append(str(int(maxv + 1) if t == "integer" else float(maxv + 1)))
            if minv is None and maxv is None:
                out.extend(["0", "1", "-1", "10"])
        elif t == "boolean":
            out.extend(["true", "false"])
        else:
            min_len = f.min_length
            max_len = f.max_length
            if sh:
                if sh.min_length is not None:
                    min_len = sh.min_length if min_len is None else max(min_len, sh.min_length)
                if sh.max_length is not None:
                    max_len = sh.max_length if max_len is None else min(max_len, sh.max_length)
                if sh.pattern:
                    out.append(sh.pattern)
            if f.pattern:
                out.append(f.pattern)

            if min_len is not None:
                out.append("a" * max(1, min_len))
            if max_len is not None and max_len > 0:
                out.append("b" * max_len)
                out.append("c" * (max_len + 1))
            if min_len is None and max_len is None and not out:
                out.extend(["fuzzstring", "sample"])

        if _looks_like_id_name(f.name):
            out.extend(_default_id_values(f.name))
        return _uniq([x for x in out if x != ""])

    def enhance_from_fields(self, fields: List[FieldHint]) -> None:
        for f in fields:
            name = f.name
            t = (f.type_name or "string").lower()
            sh = self.source_hints.get(_canonical_key(name))
            values = self._values_from_constraints(f, sh)
            is_deep = name.count(".") > 3
            for v in values:
                if not is_deep:
                    self._apply_field_value(name, t, v)
                # Also apply to short tail field key for nested names.
                tail = name.split(".")[-1]
                if tail:
                    self._apply_field_value(tail, t, v)

            # Format-specific fuzzable pools.
            fmt = (f.fmt or "").lower()
            if fmt == "uuid":
                for v in values:
                    self._add_list_value("restler_fuzzable_uuid4", v)
            elif fmt in ("date-time", "datetime"):
                for v in values:
                    self._add_list_value("restler_fuzzable_datetime", v)
            elif fmt == "date":
                for v in values:
                    self._add_list_value("restler_fuzzable_date", v)

    def enhance_multipart_defaults(self, multipart_eps: List[MultipartEndpoint]) -> None:
        self._add_payload_value("restler_custom_payload_header", "Content-Type", "multipart/form-data")
        self._add_payload_value("restler_custom_payload", "multipart_boundary", "------------------------smartfuzzboundary")
        for ep in multipart_eps:
            for fld in ep.fields:
                tail = fld.name.split(".")[-1]
                key = tail if tail else fld.name
                if fld.multipart_file:
                    self._add_payload_value("restler_custom_payload", f"{key}.filename", "fuzz.bin")
                    self._add_payload_value("restler_custom_payload", f"{key}.filename", "payload.txt")
                    self._add_payload_value("restler_custom_payload", f"{key}.contentType", "application/octet-stream")
                    self._add_payload_value("restler_custom_payload", f"{key}.contentType", "text/plain")
                    self._add_payload_value("restler_custom_payload", f"{key}.contentType", "image/png")
                    self._add_payload_value("restler_custom_payload", f"{key}.content", "A")
                    self._add_payload_value("restler_custom_payload", f"{key}.content", "{}")
                    self._add_payload_value("restler_custom_payload", f"{key}.content", "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")
                else:
                    vals = self._values_from_constraints(fld, self.source_hints.get(_canonical_key(fld.name)))
                    if not vals:
                        vals = ["value"]
                    for v in vals[:8]:
                        self._add_payload_value("restler_custom_payload", key, v)

    def finalize(self) -> Dict[str, Any]:
        for key, value in list(self.d.items()):
            if isinstance(value, list):
                self.d[key] = _uniq([_to_scalar(v) for v in value if _to_scalar(v) != ""])
            elif isinstance(value, dict):
                out_map: Dict[str, List[str]] = {}
                for sk, sv in value.items():
                    seq = sv if isinstance(sv, list) else [sv]
                    out_map[str(sk)] = _uniq([_to_scalar(v) for v in seq if _to_scalar(v) != ""])
                self.d[key] = out_map
        return self.d


# ---------------------------------------------------------------------------
# Grammar multipart seed injection
# ---------------------------------------------------------------------------

MULTIPART_MARKER_BEGIN = "# --- AUTO-GENERATED MULTIPART SEEDS (enhance-grammar.py) BEGIN ---"
MULTIPART_MARKER_END = "# --- AUTO-GENERATED MULTIPART SEEDS (enhance-grammar.py) END ---"


def _split_path_template(path: str) -> List[Tuple[str, str]]:
    """
    Return list of tuples:
    ("static", text) or ("param", name)
    """
    out: List[Tuple[str, str]] = []
    parts = re.split(r"(\{[^}]+\})", path)
    for p in parts:
        if p == "":
            continue
        if p.startswith("{") and p.endswith("}"):
            out.append(("param", p[1:-1].strip() or "id"))
        else:
            out.append(("static", p))
    return out


def _render_multipart_request_snippet(ep: MultipartEndpoint, idx: int) -> str:
    boundary = "------------------------smartfuzzboundary"
    path_parts = _split_path_template(ep.path)
    ctype_line = _py_string_literal(f"Content-Type: multipart/form-data; boundary={boundary}\r\n")
    boundary_line = _py_string_literal(f"--{boundary}\r\n")
    closing_boundary_line = _py_string_literal(f"--{boundary}--\r\n")

    lines: List[str] = []
    lines.append(f"# Multipart seed {idx}: {ep.method} {ep.path}")
    lines.append("request = requests.Request([")
    lines.append(f'    primitives.restler_static_string({_py_string_literal(ep.method + " ") }),')
    for kind, value in path_parts:
        if kind == "static":
            lines.append(f"    primitives.restler_static_string({_py_string_literal(value)}),")
        else:
            lines.append(f"    primitives.restler_custom_payload({_py_string_literal(value)}, quoted=False),")
    lines.append('    primitives.restler_static_string(" HTTP/1.1\\r\\n"),')
    lines.append('    primitives.restler_static_string("Accept: application/json\\r\\n"),')
    lines.append(f"    primitives.restler_static_string({ctype_line}),")
    lines.append('    primitives.restler_refreshable_authentication_token("authentication_token_tag"),')
    lines.append('    primitives.restler_static_string("\\r\\n"),')

    file_or_fields = ep.fields[:] if ep.fields else [FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True)]
    for fld in file_or_fields:
        key = fld.name.split(".")[-1] if "." in fld.name else fld.name
        key = key or "file"
        lines.append(f"    primitives.restler_static_string({boundary_line}),")
        if fld.multipart_file:
            disp_file_prefix = _py_string_literal(f"Content-Disposition: form-data; name=\"{key}\"; filename=\"")
            lines.append(
                f"    primitives.restler_static_string({disp_file_prefix}),"
            )
            lines.append(f"    primitives.restler_custom_payload({_py_string_literal(key + '.filename')}, quoted=False),")
            lines.append('    primitives.restler_static_string("\\"\\r\\n"),')
            lines.append('    primitives.restler_static_string("Content-Type: "),')
            lines.append(f"    primitives.restler_custom_payload({_py_string_literal(key + '.contentType')}, quoted=False),")
            lines.append('    primitives.restler_static_string("\\r\\n\\r\\n"),')
            lines.append(f"    primitives.restler_custom_payload({_py_string_literal(key + '.content')}, quoted=False),")
            lines.append('    primitives.restler_static_string("\\r\\n"),')
        else:
            disp_field = _py_string_literal(f"Content-Disposition: form-data; name=\"{key}\"\r\n\r\n")
            lines.append(
                f"    primitives.restler_static_string({disp_field}),"
            )
            lines.append(f"    primitives.restler_custom_payload({_py_string_literal(key)}),")
            lines.append('    primitives.restler_static_string("\\r\\n"),')

    lines.append(f"    primitives.restler_static_string({closing_boundary_line}),")
    lines.append("],")
    lines.append(f"requestId={_py_string_literal(ep.path)}")
    lines.append(")")
    lines.append("req_collection.add_request(request)")
    lines.append("")
    return "\n".join(lines)


def inject_multipart_seeds(grammar_path: Path, multipart_eps: List[MultipartEndpoint]) -> int:
    if not multipart_eps:
        return 0
    text = grammar_path.read_text(encoding="utf-8", errors="ignore")

    # Remove previous generated section if present.
    if MULTIPART_MARKER_BEGIN in text and MULTIPART_MARKER_END in text:
        beg = text.find(MULTIPART_MARKER_BEGIN)
        end = text.find(MULTIPART_MARKER_END, beg)
        if beg != -1 and end != -1:
            end += len(MULTIPART_MARKER_END)
            text = text[:beg].rstrip() + "\n\n"

    # Avoid duplicate operation tuples.
    seen_ops: Set[Tuple[str, str]] = set()
    deduped: List[MultipartEndpoint] = []
    for ep in multipart_eps:
        key = (ep.method.upper(), ep.path)
        if key in seen_ops:
            continue
        seen_ops.add(key)
        deduped.append(ep)

    if not deduped:
        grammar_path.write_text(text, encoding="utf-8")
        return 0

    snippets = [MULTIPART_MARKER_BEGIN, ""]
    for i, ep in enumerate(deduped, 1):
        snippets.append(_render_multipart_request_snippet(ep, i))
    snippets.append(MULTIPART_MARKER_END)
    snippets.append("")

    text = text.rstrip() + "\n\n" + "\n".join(snippets)
    grammar_path.write_text(text, encoding="utf-8")
    return len(deduped)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_external_dict(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(data, dict) and "dictionaries" in data and isinstance(data["dictionaries"], dict):
        return data["dictionaries"]
    if isinstance(data, dict):
        return data
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Enhance RESTler grammar/dict using swagger + source")
    parser.add_argument("--swagger", required=True, help="Path to OpenAPI/Swagger JSON")
    parser.add_argument("--grammar", required=True, help="Path to RESTler grammar.py")
    parser.add_argument("--dict", dest="dict_path", required=True, help="Path to RESTler dict.json")
    parser.add_argument("--src", help="Path to source directory with C# code (optional)")
    parser.add_argument("--external-dict", help="Additional dictionary JSON to merge (optional)")
    args = parser.parse_args()

    swagger_path = Path(args.swagger)
    grammar_path = Path(args.grammar)
    dict_path = Path(args.dict_path)
    src_path = Path(args.src) if args.src else None
    external_dict_path = Path(args.external_dict) if args.external_dict else None

    if not swagger_path.exists():
        print(f"[enhance] swagger file not found: {swagger_path}")
        return 1
    if not grammar_path.exists():
        print(f"[enhance] grammar file not found: {grammar_path}")
        return 1
    if not dict_path.exists():
        print(f"[enhance] dictionary file not found: {dict_path}")
        return 1

    try:
        spec = json.loads(swagger_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[enhance] failed to parse swagger JSON: {e}")
        return 1

    try:
        restler_dict = json.loads(dict_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[enhance] failed to parse dict JSON: {e}")
        return 1

    extractor = OpenAPIExtractor(spec)
    fields, multipart_eps = extractor.extract()

    src_hints = SourceExtractor(src_path).extract()

    enhancer = DictionaryEnhancer(restler_dict=restler_dict, source_hints=src_hints)
    enhancer.enhance_from_fields(fields)
    enhancer.enhance_multipart_defaults(multipart_eps)

    ext = _load_external_dict(external_dict_path)
    if ext:
        enhancer._merge_dict(ext)

    final_dict = enhancer.finalize()
    dict_path.write_text(json.dumps(final_dict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    injected = inject_multipart_seeds(grammar_path, multipart_eps)

    print(
        f"[enhance] fields={len(fields)} source_hints={len(src_hints)} "
        f"multipart_endpoints={len(multipart_eps)} injected={injected} "
        f"dict_values_added={enhancer.stats_added}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
