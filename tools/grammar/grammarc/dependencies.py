"""Producer/consumer (dependency) inference -- the one piece of the pipeline with zero
prior first-party code to port, since RESTler's own compiler did this before.

De-risked by a key finding from reading void/go/sequence.go: the Go engine already
independently re-derives path-based producer/consumer relationships at runtime
(`inferResourceIDKeyFromPath`, `extractEntityIDs`, same-path-family fallback in
`findFollowups`) regardless of what the grammar's `reads`/`writes` say. So this module
mainly needs to make sure id-shaped fields that refer to the *same* logical resource
--whether they appear as a path parameter, a bare "id" body field, or a compound
"fooId" foreign-key body field -- all resolve to the *same* payload_key string, so
void/go/store.go's SequenceState/RuntimeStore correlation (keyed by payload_key) can
actually connect them. That correlation was previously impossible for `custom_payload`
segments regardless of this module's output, because of the payload_key/name JSON-key
bug fixed in emit_templates.py -- this module's job is just to pick good, consistent
keys once that channel actually works.

Algorithm (name/path-convention based, no response-schema inspection needed):
  1. Every operation's own "resource family" is the singularized, canonicalized form
     of the last *static* path segment before any `{param}` (e.g.
     "/api/catalog-items/{id}" -> "catalog-items" -> "catalogitem").
  2. A bare "id"-named path param or top-level body field is renamed to
     "<own-resource>id" -- e.g. PUT /api/catalog-items's body `"id"` field and
     GET/DELETE /api/catalog-items/{catalogItemId}'s path param both resolve to the
     same key "catalogitemid", because "catalogItemId" already canonicalizes to that
     string and the bare "id" gets the same resource-derived name. This is what makes
     eShopOnWeb's PUT->GET/DELETE chain (the concrete pipeline regression test) work
     without needing to inspect response bodies at all.
  3. A compound "fooId"-named field keeps its own canonical name as its key -- which,
     by construction, matches resource "foo"'s own bare-id key if "foo" is itself a
     fuzzed resource family, giving free cross-resource foreign-key correlation
     (e.g. catalog-items' "catalogBrandId" field naturally keys the same as
     catalog-brands' own resource id, IF catalog-brands is also in this spec).
  4. POST and PUT to a resource's *collection-root* path (no trailing `{id}` segment)
     are treated as producers (`writes`) of that resource's id; any operation with a
     path param or body field resolving to that key is a consumer (`reads`).

Residual, disclosed limitations: multi-word/irregular English pluralization, composite
keys, and HAL/JSON:API link conventions are not modeled -- same class of limitation
void/go/sequence.go's own runtime fallback already documents. A wrong or missing
inference here degrades gracefully to "no cross-request correlation for that field,"
never silence or a crash.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .common import canonical_key, singularize
from .oas import Operation


@dataclass
class DependencyPlan:
    # per-operation-index overrides: field/param name -> payload_key to actually emit
    payload_key: Dict[int, Dict[str, str]] = field(default_factory=lambda: defaultdict(dict))
    reads: Dict[int, List[str]] = field(default_factory=lambda: defaultdict(list))
    writes: Dict[int, List[str]] = field(default_factory=lambda: defaultdict(list))


def _own_resource_key(path: str) -> str:
    prefix = path.split("{", 1)[0]
    parts = [p for p in prefix.strip("/").split("/") if p]
    if not parts:
        return ""
    last = re.sub(r"[-_]", "", parts[-1])
    return canonical_key(singularize(last))


def _is_collection_root(path: str) -> bool:
    """True if the path's last segment is the static resource-collection name with no
    trailing {param} right after it (e.g. "/api/catalog-items", not
    "/api/catalog-items/{id}") -- the conventional create/replace-by-body-id shape."""
    trimmed = path.rstrip("/")
    last_segment = trimmed.rsplit("/", 1)[-1]
    return not (last_segment.startswith("{") and last_segment.endswith("}"))


def _is_plural_collection_segment(path: str) -> bool:
    """Requires the last static path segment to actually be a detected plural (i.e.
    singularize() changed it) before treating an endpoint as a resource producer --
    filters out singular action/RPC-style endpoints (`/api/authenticate`, `/login`,
    `/health`) that happen to sit at a path with no trailing {param}, which would
    otherwise be mistaken for a REST collection root."""
    prefix = path.split("{", 1)[0]
    parts = [p for p in prefix.strip("/").split("/") if p]
    if not parts:
        return False
    last = re.sub(r"[-_]", "", parts[-1])
    return singularize(last) != last


def infer(operations: List[Operation]) -> DependencyPlan:
    plan = DependencyPlan()

    resource_of_op: Dict[int, str] = {}
    for i, op in enumerate(operations):
        resource_of_op[i] = _own_resource_key(op.path)

    def key_for(op_index: int, field_name: str) -> str:
        canon = canonical_key(field_name)
        if canon == "id":
            resource = resource_of_op[op_index]
            return f"{resource}id" if resource else "id"
        return canon

    known_resource_ids: Set[str] = set()
    for i, op in enumerate(operations):
        resource = resource_of_op[i]
        if resource and op.method in ("POST", "PUT") and _is_collection_root(op.path) and _is_plural_collection_segment(op.path):
            rid_key = f"{resource}id"
            plan.writes[i].append(rid_key)
            known_resource_ids.add(rid_key)

    for i, op in enumerate(operations):
        for p in op.path_params:
            k = key_for(i, p.name)
            plan.payload_key[i][p.name] = k
            plan.reads[i].append(k)
        # Top-level body fields: only id-shaped properties (bare "id" or compound
        # "fooId") get a payload_key override. This is deliberately narrow -- setting
        # an override for *every* property (even "description"/"name"-style free-text
        # fields with no real constraint) would make body_serializer._leaf_segments()
        # treat "an override exists" as "this field is dictionary-worthy", forcing it
        # into a thin, mostly-static custom_payload pool instead of a freely-mutated
        # `fuzzable` segment -- a real loss of mutation diversity vs. the baseline
        # RESTler pipeline, not an improvement. Only id-shaped fields need a shared key
        # for cross-request correlation; everything else should fall through to
        # is_dictionary_worthy()'s own constraint-based judgment in body_serializer.py.
        if op.request_schema and isinstance(op.request_schema.get("properties"), dict):
            for prop_name in op.request_schema["properties"]:
                canon = canonical_key(prop_name)
                if canon == "id" or canon.endswith("id"):
                    k = key_for(i, prop_name)
                    plan.payload_key[i][prop_name] = k
                    if k in known_resource_ids or canon == "id":
                        plan.reads[i].append(k)

    return plan
