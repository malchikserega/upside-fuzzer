"""Merges tools/dotnet/analyzer/'s roslyn-constraints.json (real, type/property-scoped C# validation
constraints) into the OAS-derived FieldHints, with Roslyn winning per-field when a
scoped match exists.

Match strategy, in order:
1. **Schema-name match (primary, robust)**: OpenAPI request-body schemas produced by
   Swashbuckle/NSwag are named after the actual C# DTO type (`#/components/schemas/
   CreateCatalogItemRequest` <-> `class CreateCatalogItemRequest`) -- verified directly
   against eShopOnWeb's own swagger.json during this migration. This avoids the fragile
   problem of normalizing two independently-authored route-template syntaxes (OAS
   `{id}` vs ASP.NET `{id:int}` / minimal-API attribute routing).
2. **Route+method match (fallback)**: only used when there's no direct `$ref` (inline
   request schemas), via the analyzer's `endpoints[]` list and its per-endpoint
   `parameter_types`.

This is the direct, mechanical fix for docs/ARCHITECTURE_REVIEW.md subsystem-3 weakness #2
(the old regex extractor's global name-canonicalization collision): the lookup key here
is always a specific (type, property), never a bare property name.

Scope note: merge only applies at the top level of the matched request DTO (its direct
properties) -- nested object properties keep OAS-only constraints. Real-world DTOs
fuzzed by this project (eShopOnWeb, Bitwarden) are overwhelmingly flat; deep nested
constraint propagation is a disclosed limitation, not silently wrong.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace
from typing import Any, Dict, List, Optional

from .oas import FieldHint, Operation


def _normalize_route(route: str) -> str:
    route = re.sub(r"\{[^}:]+(:[^}]+)?\}", "{}", route or "")
    return route.strip("/").lower()


class RoslynIndex:
    def __init__(self, data: Dict[str, Any]):
        self.types: Dict[str, Any] = data.get("types", {}) if isinstance(data, dict) else {}
        self.endpoints: List[Dict[str, Any]] = data.get("endpoints", []) if isinstance(data, dict) else []
        self._by_short_name: Dict[str, List[str]] = defaultdict(list)
        for full in self.types:
            short = full.rsplit(".", 1)[-1]
            self._by_short_name[short].append(full)
        self._route_index: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for ep in self.endpoints:
            key = (str(ep.get("http_method", "")).upper(), _normalize_route(str(ep.get("route_template", ""))))
            self._route_index[key].append(ep)
        # Real .NET codebases commonly have multiple unrelated types sharing a short
        # name across namespaces (verified against eShopOnWeb: BlazorShared.Models.
        # CreateCatalogItemRequest -- a UI-layer model with real DataAnnotations -- vs.
        # Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints.CreateCatalogItemRequest --
        # the actual fuzzed API DTO with none). Picking `candidates[0]` arbitrarily
        # would silently apply the wrong type's constraints -- exactly the
        # cross-contamination bug this whole migration exists to fix, just moved from
        # "global property name" to "global short type name". The fix: an endpoint's
        # parameter type is written unqualified in C# (just "CreateCatalogItemRequest"),
        # so disambiguate by preferring the candidate whose *namespace* matches the
        # endpoint's own controller/handler namespace -- DTOs are overwhelmingly
        # declared alongside their endpoint (verified: CreateCatalogItemEndpoint and
        # CreateCatalogItemRequest share Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints).
        self._referenced_full_names: set = set()
        for ep in self.endpoints:
            controller = str(ep.get("controller") or "")
            controller_ns = controller.rsplit(".", 1)[0] if "." in controller else ""
            for ptype in ep.get("parameter_types", {}).values():
                short = str(ptype).split("<")[0].strip()
                candidates = self._by_short_name.get(short, [])
                if len(candidates) == 1:
                    self._referenced_full_names.add(candidates[0])
                elif len(candidates) > 1 and controller_ns:
                    same_ns = [c for c in candidates if self.types[c].get("namespace", "") == controller_ns]
                    if len(same_ns) == 1:
                        self._referenced_full_names.add(same_ns[0])

    def _resolve_type(self, schema_name: str) -> Optional[Dict[str, Any]]:
        candidates = self._by_short_name.get(schema_name, [])
        if not candidates:
            return None
        if len(candidates) > 1:
            referenced = [c for c in candidates if c in self._referenced_full_names]
            if len(referenced) == 1:
                return self.types[referenced[0]]
            # Still ambiguous (0 or >1 endpoint-referenced matches) -- best-effort,
            # documented: fall through to the first candidate rather than guess further.
        return self.types[candidates[0]]

    def type_for_operation(self, op: Operation) -> Optional[Dict[str, Any]]:
        if op.request_schema_ref_name:
            t = self._resolve_type(op.request_schema_ref_name)
            if t is not None:
                return t
        key = (op.method.upper(), _normalize_route(op.path))
        for ep in self._route_index.get(key, []):
            for ptype in ep.get("parameter_types", {}).values():
                t = self._resolve_type(str(ptype).split("<")[0].strip())
                if t is not None:
                    return t
        return None

    def endpoint_for_operation(self, op: Operation) -> Optional[Dict[str, Any]]:
        key = (op.method.upper(), _normalize_route(op.path))
        matches = self._route_index.get(key, [])
        return matches[0] if matches else None


def _merge_one(oas_hint: FieldHint, prop: Dict[str, Any]) -> FieldHint:
    merged = replace(oas_hint)
    if prop.get("min_length") is not None:
        merged.min_length = prop["min_length"] if merged.min_length is None else max(merged.min_length, prop["min_length"])
    if prop.get("max_length") is not None:
        merged.max_length = prop["max_length"] if merged.max_length is None else min(merged.max_length, prop["max_length"])
    if prop.get("minimum") is not None:
        merged.minimum = prop["minimum"] if merged.minimum is None else max(merged.minimum, prop["minimum"])
    if prop.get("maximum") is not None:
        merged.maximum = prop["maximum"] if merged.maximum is None else min(merged.maximum, prop["maximum"])
    if prop.get("pattern"):
        merged.pattern = prop["pattern"]  # Roslyn wins outright for pattern (OAS rarely has one for C#-validated fields)
    if prop.get("enum_values"):
        merged.enum_values = list(dict.fromkeys(list(merged.enum_values) + list(prop["enum_values"])))
    merged.required = bool(merged.required or prop.get("required"))
    # FieldHint has no separate email/url booleans (OAS already expresses these via
    # `format`) -- fold Roslyn's [EmailAddress]/[Url] detection into `fmt` the same way,
    # so boundary.py's single fmt-keyed branch handles both sources uniformly.
    if prop.get("email") and not merged.fmt:
        merged.fmt = "email"
    if prop.get("url") and not merged.fmt:
        merged.fmt = "uri"
    return merged


def merge_operation_fields(op: Operation, idx: Optional[RoslynIndex], top_level_fields: Dict[str, FieldHint]) -> Dict[str, FieldHint]:
    """top_level_fields: property-name (as it appears in the OAS schema, e.g. camelCase
    JSON key) -> FieldHint for the operation's direct request-body properties. Returns
    a new dict with Roslyn constraints merged in wherever a scoped match is found."""
    if idx is None:
        return top_level_fields
    roslyn_type = idx.type_for_operation(op)
    if not roslyn_type:
        return top_level_fields
    roslyn_props: Dict[str, Any] = roslyn_type.get("properties", {})
    # Case-insensitive lookup: JSON property names are typically camelCase while the
    # C# property is PascalCase (default System.Text.Json/Newtonsoft casing policy).
    by_lower = {k.lower(): v for k, v in roslyn_props.items()}

    out: Dict[str, FieldHint] = {}
    for name, hint in top_level_fields.items():
        prop = by_lower.get(name.lower())
        out[name] = _merge_one(hint, prop) if prop else hint
    return out
