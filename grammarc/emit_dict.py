"""Writes dict.json in the flat format void/go/store.go's `loadDict`/`DictStore`
consults first and unconditionally (`d.arrays`, matched by field/payload key via
`candidatesForKey`). Note for accuracy: Go *also* separately special-cases exactly four
legacy nested container names (`restler_custom_payload`, `restler_custom_payload_
unquoted`, `restler_custom_payload_query`, `restler_custom_payload_header` --
store.go:90-108) if present as one-level-nested dicts, purely for backward compatibility
with hand-written RESTler-shaped dictionaries. grammarc never emits that nested shape --
it always writes flat top-level keys, which `candidatesForKey`'s first, unconditional
lookup path already matches -- so there is no dependency on those four names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .common import to_scalar, uniq


def merge_external_dict(pool: Dict[str, List[str]], external_path: Path) -> None:
    if not external_path.exists():
        return
    try:
        data = json.loads(external_path.read_text(encoding="utf-8"))
    except Exception:
        return
    if isinstance(data, dict) and isinstance(data.get("dictionaries"), dict):
        data = data["dictionaries"]
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if isinstance(value, list):
            pool.setdefault(key, []).extend(to_scalar(v) for v in value)
        elif isinstance(value, dict):
            # one-level-nested container (e.g. RESTler-shaped restler_custom_payload)
            # -- flatten it into top-level keys too, since Go's candidatesForKey only
            # ever indexes the top-level arrays map (see store.go:39-58: nested dict
            # values go into `containers`, which candidatesForKey does consult via a
            # fixed list of container names it does NOT include arbitrary external
            # ones). Flattening keeps any legacy external --dict still useful.
            for sk, sv in value.items():
                seq = sv if isinstance(sv, list) else [sv]
                pool.setdefault(sk, []).extend(to_scalar(v) for v in seq)
        else:
            pool.setdefault(key, []).append(to_scalar(value))


def write_dict(pool: Dict[str, List[str]], out_path: Path) -> None:
    final = {k: uniq([v for v in vs if v != ""]) for k, vs in pool.items()}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(final, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
