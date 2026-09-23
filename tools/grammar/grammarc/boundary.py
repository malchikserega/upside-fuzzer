"""Boundary-value synthesis -- ported near-verbatim from
enhance-grammar.py::DictionaryEnhancer._values_from_constraints (already correct and
target-agnostic; no redesign needed). Produces the candidate-value pool for a single
merged (OAS + Roslyn) FieldHint, used both for dict.json's per-key pools and directly
as `custom_payload` segment candidates.
"""

from __future__ import annotations

from typing import List

from .common import default_id_values, looks_like_id_name, to_scalar, uniq
from .oas import FieldHint


def values_from_constraints(f: FieldHint) -> List[str]:
    out: List[str] = []
    t = (f.type_name or "string").lower()
    fmt = (f.fmt or "").lower()

    out.extend([to_scalar(x) for x in f.examples if to_scalar(x) != ""])
    out.extend([to_scalar(x) for x in f.enum_values if to_scalar(x) != ""])

    if fmt == "uuid":
        out.extend(["566048da-ed19-4cd3-8e0a-b7e0e1ec4d72", "00000000-0000-0000-0000-000000000000"])
    elif fmt in ("date-time", "datetime"):
        out.extend(["2024-01-15T00:00:00Z", "2020-02-29T12:00:00Z"])
    elif fmt == "date":
        out.extend(["2024-01-15", "2020-02-29"])
    elif fmt == "email":
        out.extend(["fuzzer@example.com", "devnull@example.org"])
    elif fmt in ("uri", "url"):
        out.extend(["https://example.com", "http://localhost"])

    if t in ("integer", "number"):
        minv, maxv = f.minimum, f.maximum
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
        min_len, max_len = f.min_length, f.max_length
        if f.pattern:
            out.append(f.pattern)
        if min_len is not None:
            out.append("a" * max(1, min_len))
        if max_len is not None and max_len > 0:
            out.append("b" * max_len)
            out.append("c" * (max_len + 1))
        if min_len is None and max_len is None and not out:
            out.extend(["fuzzstring", "sample"])

    if looks_like_id_name(f.name):
        out.extend(default_id_values(f.name))
    return uniq([x for x in out if x != ""])


# Formats with a real, semantically-specific canned-value pool (uuid, dates, email,
# urls -- see values_from_constraints above). Deliberately excludes generic numeric
# precision hints ("int32", "int64", "double", "float") that Swashbuckle/NSwag attach
# to nearly every number/integer property -- treating those as "worthy" would push
# almost every numeric field into a thin custom_payload pool instead of a freely
# mutated `fuzzable` segment, which is a real loss of mutation diversity, not a gain.
_MEANINGFUL_FORMATS = {"uuid", "date-time", "datetime", "date", "email", "uri", "url"}


def is_dictionary_worthy(f: FieldHint) -> bool:
    """Whether this field's boundary pool is rich/specific enough to be worth routing
    through `custom_payload` (dict-backed, sequence/correlation-reachable) instead of a
    plain `fuzzable` segment. Deliberately permissive for genuinely constrained fields
    (enum/pattern/length/range/id-shaped/semantically-specific format): emitting *those*
    as custom_payload is a disclosed, intentional improvement over RESTler's behavior
    (see grammarc/body_serializer.py) -- pickCustomPayloadValue() (void/go/store.go)
    always falls back to the segment's own Default when no dict/sequence/correlation
    value is found, so there's no downside for genuinely constrained fields. Plain
    free-text/numeric fields with no real constraint are deliberately left `fuzzable`."""
    return bool(
        f.enum_values or f.pattern or f.min_length is not None or f.max_length is not None or
        f.minimum is not None or f.maximum is not None or (f.fmt or "").lower() in _MEANINGFUL_FORMATS or
        looks_like_id_name(f.name)
    )
