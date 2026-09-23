"""Small shared helpers, ported near-verbatim from enhance-grammar.py (stdlib-only,
matching the repo's existing zero-third-party-dependency convention for the grammar
pipeline)."""

from __future__ import annotations

import functools
import re
from typing import Any, Iterable, List, Optional, Set


@functools.lru_cache(maxsize=4096)
def canonical_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def uniq(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def to_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


def safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None


@functools.lru_cache(maxsize=2048)
def looks_like_id_name(name: str) -> bool:
    c = canonical_key(name)
    return c == "id" or c.endswith("id")


def default_id_values(name: str) -> List[str]:
    base = re.sub(r"Id$", "", str(name or ""), flags=re.IGNORECASE)
    base = re.sub(r"[^A-Za-z0-9]+", "", base)
    if not base:
        base = "ID"
    prefix = base[:3].upper() if len(base) >= 3 else base.upper()
    if not prefix:
        prefix = "ID"
    return [f"{prefix}-0001", f"{prefix}-0042", f"{prefix}-1234-0001", f"{prefix}-1234-5678-0001"]


def singularize(word: str) -> str:
    """Simple English singularization for resource-family name inference
    (dependencies.py). Deliberately conservative -- residual pluralization
    edge cases are a documented, disclosed limitation (see grammarc/dependencies.py)."""
    w = str(word or "")
    if w.endswith("ies") and len(w) > 3:
        return w[:-3] + "y"
    if w.endswith("ses") or w.endswith("xes") or w.endswith("zes") or w.endswith("ches") or w.endswith("shes"):
        return w[:-2]
    if w.endswith("s") and not w.endswith("ss") and len(w) > 1:
        return w[:-1]
    return w
