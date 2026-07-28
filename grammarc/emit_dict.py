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


def merge_external_dict(pool: Dict[str, List[str]], external_path: Path, warn_on_parse_error: bool = False) -> None:
    if not external_path.exists():
        return
    try:
        data = json.loads(external_path.read_text(encoding="utf-8"))
    except Exception as e:
        # warn_on_parse_error is False for the always-on dict.custom.json convention
        # merge (emit_dict.py's own scaffold_custom_dict_if_missing call below) --
        # that file may legitimately not exist yet or be mid-edit, and staying silent
        # there is by design. It's True for an explicit, user-supplied `--dict <path>`
        # (cli.py): a user who deliberately pointed at a dictionary file that fails to
        # parse deserves to know why their values never showed up, the same way every
        # other cli.py error path already prints a `[grammarc] WARNING: ...` line.
        if warn_on_parse_error:
            print(f"[grammarc] WARNING: could not parse --dict file {external_path}: {e}")
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


# ── Custom dictionary convention (add-your-own values, survives regeneration) ──
#
# dict.json (above) is fully regenerated -- and fully overwritten -- on every
# compile-grammar.sh run, so it is not a safe place to hand-edit values. This is
# the dedicated file for that: grammarc auto-creates a starter copy the first time
# it compiles a given --out directory, auto-merges it into every dict.json it
# writes from then on (see compile_grammar in cli.py), and never overwrites or
# deletes it once it exists -- edits made here persist across every regeneration,
# including ones triggered by the target's OpenAPI spec changing.
CUSTOM_DICT_FILENAME = "dict.custom.json"

_CUSTOM_DICT_SCAFFOLD: Dict[str, Any] = {
    "_readme": [
        "This file is yours. compile-grammar.sh reads and merges it into dict.json",
        "on every run, but NEVER overwrites or deletes it -- values you add here",
        "survive re-running compile-grammar.sh, including after the target's API changes.",
        "",
        "Format: flat map. Each key is a request field/payload name; each value is an",
        "array of candidate strings the fuzzer tries for that field, blended in",
        "alongside its own generic boundary-value mutations -- not a replacement for them.",
        "",
        "Key matching is case/separator-insensitive: userId, user_id, UserId, and",
        "user-id all resolve to the same pool (void/go/store.go::canonicalKey).",
        "",
        "To find real field names worth targeting, open dict.json in this same",
        "directory (fully regenerated every run, auto-discovered from this target's",
        "own OpenAPI spec + Roslyn constraints) and copy the keys you care about here",
        "with values you actually want tried: real tenant/org IDs, known-valid",
        "coupon/promo codes, staging API keys, currency/locale codes your domain",
        "actually uses, admin usernames, etc. -- anything the spec can't tell the",
        "fuzzer but you know from working with this system.",
        "",
        "Full docs: docs/INSTRUCTIONS.md section 10, 'Custom Dictionary Format'.",
    ],
    "exampleFieldName": [
        "REPLACE-ME -- not a real field in this target, delete this key once you've added your own",
    ],
}


def scaffold_custom_dict_if_missing(out_dir: Path) -> bool:
    """Write a starter dict.custom.json in out_dir if one doesn't exist yet.
    Never overwrites an existing file. Returns True if a new file was created."""
    path = out_dir / CUSTOM_DICT_FILENAME
    if path.exists():
        return False
    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_CUSTOM_DICT_SCAFFOLD, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True


def merge_custom_dict_convention(pool: Dict[str, List[str]], out_dir: Path) -> None:
    """Merge <out_dir>/dict.custom.json into pool if present -- the convention path,
    automatic on every compile, no --dict flag required. A separate, explicit --dict
    (merge_external_dict) can still be used for one-off/CI-supplied dictionaries and
    is merged independently; the two are not mutually exclusive."""
    merge_external_dict(pool, out_dir / CUSTOM_DICT_FILENAME)
