"""Builds a full, structure-preserving schema AST for a request body -- object,
array, scalar, required, nullable, constraints, properties, items, allOf/oneOf/anyOf,
and discriminator -- as a new, purely additive `body_schema` field alongside the
existing flat `segments[]` list `body_serializer.py` already emits.

Deliberately separate from body_serializer.py/oas.py: this module fixes a real bug
those two share (oneOf/anyOf are logically *exclusive* alternatives but
oas.py::_collect_schema_fields / body_serializer.py::_merge_object_props both blindly
`.update()` every variant's properties together, as if they were an allOf). The fix
lives only here -- body_serializer.py's flattening is untouched, so `segments[]`
output for every existing grammar stays byte-for-byte identical. See
void/src/void/internal/engine/body_schema.go for the Go-side mirror this feeds.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Optional

from .common import canonical_key, looks_like_id_name, safe_float, safe_int, to_scalar, uniq
from .dependencies import DependencyPlan
from .oas import OASParser

# Hard recursion-depth cutoff for schema trees that recurse without ever repeating a
# literal $ref (e.g. deeply inlined nested objects with no $ref at all) -- the
# per-path `seen` set below catches genuine $ref cycles; this catches everything else.
_MAX_SCHEMA_DEPTH = 8


def _node_type_and_resolved(schema: Any, parser: OASParser) -> tuple[str, Dict[str, Any]]:
    rs = parser.resolve_schema(schema)
    if not rs:
        return "scalar", {}
    if isinstance(rs.get("oneOf"), list) and rs["oneOf"]:
        return "oneOf", rs
    if isinstance(rs.get("anyOf"), list) and rs["anyOf"]:
        return "anyOf", rs
    if isinstance(rs.get("allOf"), list) and rs["allOf"]:
        return "object", rs  # allOf is a genuine (conjunctive) merge -- see _merged_allof_object
    raw_type = rs.get("type")
    if isinstance(raw_type, list):
        non_null = [t for t in raw_type if t != "null"]
        raw_type = non_null[0] if non_null else "string"
    if raw_type == "object" or (raw_type is None and isinstance(rs.get("properties"), dict)):
        return "object", rs
    if raw_type == "array":
        return "array", rs
    return "scalar", rs


def _is_nullable(rs: Dict[str, Any]) -> bool:
    if rs.get("nullable") is True:
        return True
    raw_type = rs.get("type")
    return isinstance(raw_type, list) and "null" in raw_type


def _merged_allof_object(rs: Dict[str, Any], parser: OASParser) -> tuple[Dict[str, Any], List[str]]:
    """Conjunctive allOf merge: combines every branch's properties/required into one
    object -- correct OpenAPI semantics for allOf (unlike oneOf/anyOf, which this
    module keeps as separate variants; see build_schema_node)."""
    merged_props: Dict[str, Any] = {}
    merged_required: List[str] = list(rs.get("required", []) if isinstance(rs.get("required"), list) else [])
    for sub in rs.get("allOf", []):
        sub_rs = parser.resolve_schema(sub)
        if not sub_rs:
            continue
        sub_props, sub_req = _merged_allof_object(sub_rs, parser) if isinstance(sub_rs.get("allOf"), list) else (
            sub_rs.get("properties") if isinstance(sub_rs.get("properties"), dict) else {},
            list(sub_rs.get("required", [])) if isinstance(sub_rs.get("required"), list) else [],
        )
        merged_props.update(sub_props)
        merged_required.extend(sub_req)
    own_props = rs.get("properties")
    if isinstance(own_props, dict):
        merged_props.update(own_props)
    return merged_props, uniq(merged_required)


def _discriminator_node(rs: Dict[str, Any], variants: List[Dict[str, Any]], variant_schemas: List[Any], parser: OASParser) -> Optional[Dict[str, Any]]:
    disc = rs.get("discriminator")
    if not isinstance(disc, dict):
        return None
    prop_name = str(disc.get("propertyName") or "").strip()
    if not prop_name:
        return None
    explicit_mapping = disc.get("mapping") if isinstance(disc.get("mapping"), dict) else None
    mapping: Dict[str, int] = {}
    if explicit_mapping:
        # OpenAPI discriminator.mapping value is a $ref (or bare schema name); resolve
        # it back to a variant index by matching ref_name against each variant's own.
        variant_ref_names = [OASParser.ref_name(s) for s in variant_schemas]
        for disc_value, ref_or_name in explicit_mapping.items():
            target_name = ref_or_name.rsplit("/", 1)[-1] if isinstance(ref_or_name, str) else None
            for idx, vname in enumerate(variant_ref_names):
                if vname and vname == target_name:
                    mapping[str(disc_value)] = idx
                    break
    else:
        # Implicit mapping (OpenAPI spec default): the discriminator value for each
        # variant is that variant's own component-schema name.
        for idx, s in enumerate(variant_schemas):
            vname = OASParser.ref_name(s)
            if vname:
                mapping[vname] = idx
    if not mapping:
        return None
    return {"property_name": prop_name, "mapping": mapping}


def build_schema_node(
    schema: Any,
    parser: OASParser,
    dep_plan: Optional[DependencyPlan] = None,
    op_index: Optional[int] = None,
    path_prefix: str = "",
    field_name: str = "",
    depth: int = 0,
    seen: FrozenSet[str] = frozenset(),
) -> Optional[Dict[str, Any]]:
    """Recursively builds the schema AST for `schema`. Returns None only when `schema`
    itself doesn't resolve to anything (e.g. an empty/absent request body) -- every
    resolvable schema, however deep or malformed, degrades to an inert scalar leaf
    rather than raising, matching this pipeline's existing "never crash grammar
    compilation" convention (see oas.py::parse_x_state_transition's docstring)."""
    if not isinstance(schema, dict):
        return None

    ref = schema.get("$ref") if isinstance(schema.get("$ref"), str) else None
    if ref is not None and ref in seen:
        # Genuine $ref cycle (e.g. Employee.manager -> Employee) -- degrade to an inert
        # leaf rather than recursing forever. Depth cap below catches non-$ref cycles
        # (deeply inlined self-similar objects with no $ref to detect).
        return {"node_type": "scalar", "path": path_prefix, "field_name": field_name, "scalar_type": "string"}
    if depth > _MAX_SCHEMA_DEPTH:
        return {"node_type": "scalar", "path": path_prefix, "field_name": field_name, "scalar_type": "string"}

    node_type, rs = _node_type_and_resolved(schema, parser)
    if not rs:
        return None
    next_seen = (seen | {ref}) if ref is not None else seen
    nullable = _is_nullable(rs)

    if node_type in ("oneOf", "anyOf"):
        variant_schemas = rs.get(node_type, [])
        variants = [
            build_schema_node(v, parser, dep_plan, op_index, path_prefix, field_name, depth + 1, next_seen)
            for v in variant_schemas
        ]
        variants = [v for v in variants if v is not None]
        node: Dict[str, Any] = {
            "node_type": node_type, "path": path_prefix, "field_name": field_name,
            "nullable": nullable, "variants": variants,
        }
        disc = _discriminator_node(rs, variants, variant_schemas, parser)
        if disc:
            node["discriminator"] = disc
        return node

    if node_type == "object":
        if isinstance(rs.get("allOf"), list) and rs["allOf"]:
            props, required = _merged_allof_object(rs, parser)
        else:
            props = rs.get("properties") if isinstance(rs.get("properties"), dict) else {}
            required = list(rs.get("required", [])) if isinstance(rs.get("required"), list) else []
        prop_order = list(props.keys())
        prop_nodes: Dict[str, Any] = {}
        for prop_name, prop_schema in props.items():
            full_path = f"{path_prefix}.{prop_name}" if path_prefix else prop_name
            child = build_schema_node(prop_schema, parser, dep_plan, op_index, full_path, prop_name, depth + 1, next_seen)
            if child is not None:
                prop_nodes[prop_name] = child
        node = {
            "node_type": "object", "path": path_prefix, "field_name": field_name,
            "nullable": nullable, "properties": prop_nodes, "property_order": prop_order,
            "required": [r for r in required if r in prop_nodes],
        }
        ap = rs.get("additionalProperties")
        if ap is False:
            node["allow_additional"] = False
        elif isinstance(ap, dict):
            ap_node = build_schema_node(ap, parser, dep_plan, op_index, path_prefix, field_name, depth + 1, next_seen)
            if ap_node is not None:
                node["additional_properties"] = ap_node
            node["allow_additional"] = True
        else:
            node["allow_additional"] = True
        return node

    if node_type == "array":
        items_schema = rs.get("items")
        items_node = None
        if isinstance(items_schema, dict):
            items_node = build_schema_node(items_schema, parser, dep_plan, op_index, path_prefix, field_name, depth + 1, next_seen)
        node = {
            "node_type": "array", "path": path_prefix, "field_name": field_name, "nullable": nullable,
            "items": items_node,
        }
        min_items = safe_int(rs.get("minItems"))
        max_items = safe_int(rs.get("maxItems"))
        if min_items is not None:
            node["min_items"] = min_items
        if max_items is not None:
            node["max_items"] = max_items
        if rs.get("uniqueItems") is True:
            node["unique_items"] = True
        return node

    # scalar
    raw_type = rs.get("type")
    if isinstance(raw_type, list):
        non_null = [t for t in raw_type if t != "null"]
        raw_type = non_null[0] if non_null else "string"
    scalar_type = str(raw_type or "string")
    node = {
        "node_type": "scalar", "path": path_prefix, "field_name": field_name, "nullable": nullable,
        "scalar_type": scalar_type,
    }
    fmt = rs.get("format")
    if fmt:
        node["format"] = str(fmt)
    enum_vals = rs.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        node["enum_values"] = uniq([to_scalar(v) for v in enum_vals if to_scalar(v) != ""])
    pattern = rs.get("pattern")
    if pattern:
        node["pattern"] = str(pattern)
    min_length = safe_int(rs.get("minLength"))
    if min_length is not None:
        node["min_length"] = min_length
    max_length = safe_int(rs.get("maxLength"))
    if max_length is not None:
        node["max_length"] = max_length
    minimum = safe_float(rs.get("minimum"))
    if minimum is not None:
        node["minimum"] = minimum
    maximum = safe_float(rs.get("maximum"))
    if maximum is not None:
        node["maximum"] = maximum

    payload_key = None
    if dep_plan is not None and op_index is not None and depth <= 1 and field_name:
        payload_key = dep_plan.payload_key.get(op_index, {}).get(field_name)
    if payload_key is None and field_name and looks_like_id_name(field_name):
        payload_key = canonical_key(field_name)
    if payload_key:
        node["payload_key"] = payload_key

    return node
