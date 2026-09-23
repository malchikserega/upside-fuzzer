"""OpenAPI 2.0 (Swagger) + 3.x parser -> typed IR.

Ports enhance-grammar.py::OpenAPIExtractor's $ref/allOf/oneOf/anyOf resolution and
v2+v3 field handling near-verbatim (it was already correct and generic — no need to
redesign it). Extends it to also retain each operation's *schema tree* (not just a
flattened FieldHint list), an operationId, and $ref component-schema names — this is
the raw material body_serializer.py (schema -> request-body segments) and
roslyn_merge.py (schema-name -> C# type matching) need, neither of which existed
before this pipeline (RESTler's own compiler did the schema serialization; nothing in
enhance-grammar.py ever had to).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .common import canonical_key, safe_float, safe_int, to_scalar, uniq


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
class ParamHint(FieldHint):
    location: str = "query"  # path | query | header


@dataclass
class MultipartEndpoint:
    method: str
    path: str
    fields: List[FieldHint] = field(default_factory=list)


@dataclass
class Operation:
    method: str
    path: str
    operation_id: str
    path_params: List[ParamHint] = field(default_factory=list)
    query_params: List[ParamHint] = field(default_factory=list)
    header_params: List[ParamHint] = field(default_factory=list)
    request_schema: Optional[Dict[str, Any]] = None
    request_schema_ref_name: Optional[str] = None
    request_content_type: Optional[str] = None
    is_multipart: bool = False
    multipart_fields: List[FieldHint] = field(default_factory=list)
    response_schema: Optional[Dict[str, Any]] = None
    response_schema_ref_name: Optional[str] = None
    # Every declared 2xx status's resolved schema (status code string -> schema),
    # unlike response_schema above (first-found only, kept as-is for existing
    # producer-field-inference callers). Feeds emit_templates.py's per-status
    # response_schemas export for the response-schema conformance oracle (Top-20+ #23).
    response_schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # x_state_transition (Top-20+ stateful architecture task's Tier 1 signal):
    # an operation-level x-state-transition vendor extension, when the spec
    # author declared one explicitly -- {"from": ..., "to": ..., "action": ...}.
    # Highest-trust source in the transition-source priority chain (explicit
    # spec declaration > source-code inference > runtime observation >
    # heuristic fallback -- see void/go/resource_scheduling.go's
    # deriveTransitionAction). Real-world specs essentially never declare
    # this today (it isn't a standardized OpenAPI extension), so this is
    # "support it when present," not something expected to fire often.
    x_state_transition: Optional[Dict[str, str]] = None


def parse_x_state_transition(raw: Any) -> Optional[Dict[str, str]]:
    """Parses an x-state-transition vendor extension value, supporting both a
    compact string shorthand ("from->action->to") and the explicit object
    form ({"from":..., "to":..., "action":...}). Returns None for anything
    that doesn't cleanly parse -- a malformed extension must never crash
    grammar compilation, just be silently ignored (falls through to the next
    tier in the priority chain)."""
    if isinstance(raw, dict):
        out = {k: str(v) for k, v in raw.items() if k in ("from", "to", "action") and v}
        return out or None
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split("->")]
        if len(parts) == 3 and all(parts):
            return {"from": parts[0], "action": parts[1], "to": parts[2]}
    return None


class OASParser:
    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec
        self.is_v2 = "swagger" in spec and "openapi" not in spec

    # ── $ref / combinator resolution (ported verbatim) ─────────────────────────

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

    def resolve_schema(self, schema: Any, seen: Optional[Set[str]] = None, depth: int = 0) -> Dict[str, Any]:
        if seen is None:
            seen = set()
        if depth > 12 or not isinstance(schema, dict):
            return {}
        ref = schema.get("$ref")
        if isinstance(ref, str):
            if ref in seen:
                return {}
            target = self._resolve_ref(ref)
            return self.resolve_schema(target, seen | {ref}, depth + 1)
        return schema

    @staticmethod
    def ref_name(schema: Any) -> Optional[str]:
        """Component schema short name for a direct $ref (e.g. 'CreateOrderRequest'
        from '#/components/schemas/CreateOrderRequest') -- the primary, robust match
        key for roslyn_merge.py, since Swashbuckle/NSwag-generated specs name schema
        components after the actual C# DTO type (verified against eShopOnWeb's own
        swagger.json during this migration)."""
        if not isinstance(schema, dict):
            return None
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            return ref.rsplit("/", 1)[-1]
        return None

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
        rs = self.resolve_schema(schema)
        if not rs:
            return out
        node_sig = (id(rs), prefix)
        if node_sig in seen_nodes:
            return out
        seen_nodes = set(seen_nodes)
        seen_nodes.add(node_sig)

        if required is None:
            required = set(rs.get("required", [])) if isinstance(rs.get("required"), list) else set()

        merged_props: Dict[str, Any] = {}
        merged_required: Set[str] = set(required)
        for key in ("allOf", "oneOf", "anyOf"):
            entries = rs.get(key)
            if isinstance(entries, list):
                for sub in entries:
                    sub_rs = self.resolve_schema(sub)
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
                p_rs = self.resolve_schema(prop_schema)
                if not p_rs:
                    continue
                full = f"{prefix}.{prop_name}" if prefix else prop_name
                p_type = str(p_rs.get("type", "string"))
                p_fmt = str(p_rs.get("format", ""))
                p_enum = [str(v) for v in p_rs.get("enum", [])] if isinstance(p_rs.get("enum"), list) else []
                examples: List[str] = []
                if "example" in p_rs:
                    examples.append(to_scalar(p_rs.get("example")))
                if "default" in p_rs:
                    examples.append(to_scalar(p_rs.get("default")))
                hint = FieldHint(
                    name=full, type_name=p_type, fmt=p_fmt,
                    enum_values=uniq([x for x in p_enum if x != ""]),
                    examples=uniq([x for x in examples if x != ""]),
                    min_length=safe_int(p_rs.get("minLength")), max_length=safe_int(p_rs.get("maxLength")),
                    minimum=safe_float(p_rs.get("minimum")), maximum=safe_float(p_rs.get("maximum")),
                    pattern=str(p_rs.get("pattern")) if p_rs.get("pattern") is not None else None,
                    required=prop_name in merged_required,
                    multipart_file=(p_type == "string" and p_fmt == "binary"),
                )
                out.append(hint)
                if p_type == "object" or "properties" in p_rs or "$ref" in p_rs:
                    out.extend(self._collect_schema_fields(p_rs, prefix=full, depth=depth + 1, seen_nodes=seen_nodes))
                elif p_type == "array":
                    items = p_rs.get("items")
                    if isinstance(items, dict):
                        out.extend(self._collect_schema_fields(items, prefix=full, depth=depth + 1, seen_nodes=seen_nodes))
            return out

        leaf_name = prefix if prefix else "value"
        p_type = str(rs.get("type", "string"))
        p_fmt = str(rs.get("format", ""))
        p_enum = [str(v) for v in rs.get("enum", [])] if isinstance(rs.get("enum"), list) else []
        examples_leaf: List[str] = []
        if "example" in rs:
            examples_leaf.append(to_scalar(rs.get("example")))
        if "default" in rs:
            examples_leaf.append(to_scalar(rs.get("default")))
        out.append(FieldHint(
            name=leaf_name, type_name=p_type, fmt=p_fmt,
            enum_values=uniq([x for x in p_enum if x != ""]),
            examples=uniq([x for x in examples_leaf if x != ""]),
            min_length=safe_int(rs.get("minLength")), max_length=safe_int(rs.get("maxLength")),
            minimum=safe_float(rs.get("minimum")), maximum=safe_float(rs.get("maximum")),
            pattern=str(rs.get("pattern")) if rs.get("pattern") is not None else None,
            multipart_file=(p_type == "string" and p_fmt == "binary"),
        ))
        return out

    def _iter_raw_operations(self) -> Iterable[Tuple[str, str, Dict[str, Any], Dict[str, Any]]]:
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return
        methods = ("get", "post", "put", "delete", "patch", "head", "options")
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in methods:
                op = path_item.get(method)
                if isinstance(op, dict):
                    yield method.upper(), str(path), op, path_item

    def _param_hint(self, p: Dict[str, Any]) -> Optional[ParamHint]:
        if "$ref" in p:
            p = self._resolve_ref(str(p.get("$ref")))
        if not isinstance(p, dict):
            return None
        pname = str(p.get("name", "param"))
        p_schema = p.get("schema") if isinstance(p.get("schema"), dict) else p
        p_rs = self.resolve_schema(p_schema)
        p_type = str(p_rs.get("type", "string"))
        p_fmt = str(p_rs.get("format", ""))
        p_enum = [str(v) for v in p_rs.get("enum", [])] if isinstance(p_rs.get("enum"), list) else []
        examples: List[str] = []
        for src in (p, p_rs):
            if "example" in src:
                examples.append(to_scalar(src.get("example")))
            if "default" in src:
                examples.append(to_scalar(src.get("default")))
        return ParamHint(
            name=pname, type_name=p_type, fmt=p_fmt,
            enum_values=uniq([x for x in p_enum if x != ""]),
            examples=uniq([x for x in examples if x != ""]),
            min_length=safe_int(p_rs.get("minLength")), max_length=safe_int(p_rs.get("maxLength")),
            minimum=safe_float(p_rs.get("minimum")), maximum=safe_float(p_rs.get("maximum")),
            pattern=str(p_rs.get("pattern")) if p_rs.get("pattern") is not None else None,
            required=bool(p.get("required", False)),
            multipart_file=(p_type == "file" or (p_type == "string" and p_fmt == "binary")),
            location=str(p.get("in", "query")).lower(),
        )

    def parse(self) -> List[Operation]:
        operations: List[Operation] = []
        global_consumes = self.spec.get("consumes", []) if isinstance(self.spec.get("consumes"), list) else []

        for method, path, op, path_item in self._iter_raw_operations():
            raw_params: List[Dict[str, Any]] = []
            for src in (path_item.get("parameters"), op.get("parameters")):
                if isinstance(src, list):
                    raw_params.extend(p for p in src if isinstance(p, dict))

            operation = Operation(method=method, path=path, operation_id=str(op.get("operationId") or f"{method}_{path}"))
            operation.x_state_transition = parse_x_state_transition(op.get("x-state-transition"))

            for raw in raw_params:
                hint = self._param_hint(raw)
                if hint is None:
                    continue
                if hint.location == "path":
                    operation.path_params.append(hint)
                elif hint.location == "header":
                    operation.header_params.append(hint)
                elif hint.location == "formdata":
                    consumes = op.get("consumes", global_consumes)
                    if isinstance(consumes, list) and any("multipart/form-data" in str(x).lower() for x in consumes):
                        operation.is_multipart = True
                        operation.multipart_fields.append(hint)
                    else:
                        operation.query_params.append(hint)
                elif hint.location == "body":
                    # Swagger 2.0's request-body convention: a single `in: body` param
                    # carrying the full (often $ref'd) object schema directly -- the v2
                    # analog of v3's `requestBody.content["application/json"].schema`,
                    # which IS handled below but only for v3 specs. Found missing while
                    # writing this session's grammarc test suite: any v2 spec's body
                    # parameter silently fell through to the `else` branch and got
                    # treated as a query parameter, leaving request_schema unset (and
                    # therefore never getting a JSON body serialized at all) for every
                    # v2 operation with a request body -- not a synthetic edge case,
                    # this is the *standard* way Swagger 2.0 specs declare bodies.
                    schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else None
                    if schema is not None:
                        operation.request_schema_ref_name = self.ref_name(schema)
                        operation.request_schema = self.resolve_schema(schema)
                        consumes = op.get("consumes", global_consumes)
                        operation.request_content_type = (
                            str(consumes[0]) if isinstance(consumes, list) and consumes else "application/json"
                        )
                else:
                    operation.query_params.append(hint)

            # v3 requestBody
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                if "$ref" in rb:
                    rb = self._resolve_ref(str(rb.get("$ref")))
                content = rb.get("content")
                if isinstance(content, dict) and content:
                    # Prefer application/json if present, else first declared content type.
                    ctype = "application/json" if "application/json" in content else next(iter(content))
                    media = content.get(ctype) or {}
                    schema = media.get("schema") if isinstance(media, dict) else None
                    if isinstance(schema, dict):
                        operation.request_schema_ref_name = self.ref_name(schema)
                        operation.request_schema = self.resolve_schema(schema)
                        operation.request_content_type = ctype
                    if "multipart/form-data" in str(ctype).lower():
                        operation.is_multipart = True
                        operation.multipart_fields.extend(self._collect_schema_fields(schema))

            # 2xx response schemas. response_schema/response_schema_ref_name keep their
            # original "first one found" semantics (existing producer-field-inference
            # callers depend on that); response_schemas additionally captures every
            # declared 2xx status, for the response-schema conformance oracle (#23) to
            # compare against the status actually observed at runtime rather than
            # assuming the first-declared one always applies.
            responses = op.get("responses")
            if isinstance(responses, dict):
                first_captured = False
                for status, resp in sorted(responses.items()):
                    if not (isinstance(status, str) and status.startswith("2")):
                        continue
                    if "$ref" in resp:
                        resp = self._resolve_ref(str(resp.get("$ref")))
                    content = resp.get("content") if isinstance(resp, dict) else None
                    if isinstance(content, dict):
                        media = content.get("application/json") or next(iter(content.values()), None)
                        schema = media.get("schema") if isinstance(media, dict) else None
                        if isinstance(schema, dict):
                            resolved = self.resolve_schema(schema)
                            if resolved:
                                operation.response_schemas[status] = resolved
                            if not first_captured:
                                operation.response_schema_ref_name = self.ref_name(schema)
                                operation.response_schema = resolved
                                first_captured = True

            operations.append(operation)
        return operations

    def multipart_endpoints(self, operations: List[Operation]) -> List[MultipartEndpoint]:
        out: List[MultipartEndpoint] = []
        for op in operations:
            if op.is_multipart and op.method in ("POST", "PUT", "PATCH"):
                seen: Set[str] = set()
                deduped: List[FieldHint] = []
                for f in op.multipart_fields:
                    ck = canonical_key(f.name)
                    if ck in seen:
                        continue
                    seen.add(ck)
                    deduped.append(f)
                out.append(MultipartEndpoint(method=op.method, path=op.path, fields=deduped))
        return out
