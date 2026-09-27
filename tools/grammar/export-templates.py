#!/usr/bin/env python3
"""
export-templates.py  —  DEPRECATED legacy fallback, not the primary path.

RESTler has been retired (ARCHITECTURE_REVIEW.md Top-20 #9/#10). The current
`bin/compile-grammar.sh` (tools/grammar/grammarc/ + tools/dotnet/analyzer/) writes `templates.export.json` directly —
it never produces or touches a `grammar.py` file, and never invokes this script.

This script is kept ONLY so grammar directories generated *before* the migration (which
have a `grammar.py` but no `templates.export.json`) keep working without manual
regeneration: void/go/template.go's `exportTemplates()` auto-invokes it at Void startup
in exactly that one case. If you're generating a grammar for the first time, or
regenerating an existing one, use `bin/compile-grammar.sh` instead — you will never need
this script.

Parses RESTler grammar.py and exports request templates to JSON
(TemplateExport format consumed by the Go fuzzer).

Supports RESTler old-style grammars:
    from engine import primitives
    from engine.core import requests
    req = requests.Request([...])   ← list of segment-producing primitives

Usage (legacy grammars only):
    python3 export-templates.py --grammar-dir <dir> --out <output.json>
    python3 export-templates.py --grammar-dir . --out templates.export.json
"""

import sys
import os
import json
import argparse
import importlib.util
import traceback
import types
from typing import Any


# ── Segment helpers ───────────────────────────────────────────────────────────

def seg_static(value: str) -> dict:
    return {"kind": "static", "value": value}

def seg_fuzzable(value_type: str, default: Any, quoted: bool = False) -> dict:
    return {"kind": "fuzzable", "value_type": value_type,
            "default": str(default) if default is not None else "",
            "quoted": quoted}

def seg_payload(name: str, quoted: bool = False) -> dict:
    return {"kind": "custom_payload", "name": str(name), "quoted": quoted}


# ── RESTler primitives (shared across both shim styles) ───────────────────────

def _make_prim_ns():
    """Return a SimpleNamespace with all restler_* callables."""

    def restler_static_string(s="", *a, **kw):
        # If arg is not a plain string/None (e.g. a _DepRef sentinel), pass it through
        # so _flatten/_extract_dep_refs can detect and classify it.
        if s is None or isinstance(s, str):
            return [seg_static(str(s) if s is not None else "")]
        return [s]  # _DepRef or other sentinel — _flatten handles it
    def restler_basepath(s="", *a, **kw):             return [seg_static(str(s) if s is not None else "")]
    def restler_fuzzable_string(d="fuzzstring", *a, quoted=False, examples=None, **kw): return [seg_fuzzable("string", d, quoted=quoted)]
    def restler_fuzzable_int(d=0, *a, quoted=False, examples=None, **kw):               return [seg_fuzzable("int", d, quoted=quoted)]
    def restler_fuzzable_number(d=0.0, *a, quoted=False, examples=None, **kw):          return [seg_fuzzable("number", d, quoted=quoted)]
    def restler_fuzzable_bool(d=True, *a, quoted=False, examples=None, **kw):           return [seg_fuzzable("bool", d, quoted=quoted)]
    def restler_fuzzable_datetime(d="2024-01-01T00:00:00Z", *a, quoted=False, examples=None, **kw): return [seg_fuzzable("datetime", d, quoted=quoted)]
    def restler_fuzzable_uuid4(d="00000000-0000-0000-0000-000000000000", *a, quoted=False, examples=None, **kw): return [seg_fuzzable("uuid", d, quoted=quoted)]
    def restler_fuzzable_object(d="{}", *a, quoted=False, examples=None, **kw):         return [seg_fuzzable("object", d, quoted=quoted)]
    def restler_fuzzable_group(name, values, *a, quoted=False, examples=None, **kw):   return [seg_fuzzable("string", values[0] if values else "", quoted=quoted)]
    def restler_custom_payload(name, *a, quoted=False, **kw):                           return [seg_payload(str(name), quoted=quoted)]
    def restler_custom_payload_unquoted(name, *a, **kw):                                return [seg_payload(str(name), quoted=False)]
    def restler_custom_payload_query(name, *a, **kw):                                   return [seg_payload(str(name), quoted=False)]
    def restler_custom_payload_header(name, *a, **kw):                                  return [seg_payload(str(name), quoted=False)]
    def restler_custom_payload_uuid4_suffix(name, *a, **kw):                            return [seg_fuzzable("uuid", "00000000-0000-0000-0000-000000000000")]
    def restler_refreshable_authentication_token(token="TOKEN", *a, **kw):              return [seg_static("Authorization: Bearer TOKEN\r\n")]
    def restler_multipart_formdata(*parts, **kw):                                       return [seg_fuzzable("string", "--boundary\r\n")]
    def Shadow(*a, **kw):                                                               return [seg_fuzzable("string", "1")]
    def restler_resource_start(name, *a, **kw):                                         return []
    def restler_resource_end(name, *a, **kw):                                           return []

    return types.SimpleNamespace(**{k: v for k, v in locals().items() if callable(v)})


# ── Grammar interpreter ───────────────────────────────────────────────────────

class GrammarInterpreter:
    def __init__(self, grammar_dir: str) -> None:
        self.grammar_dir = grammar_dir
        self.templates: list[dict] = []
        self.skipped = 0
        self._next_id = 0

    # ── Public ────────────────────────────────────────────────────────────────

    def load(self) -> None:
        grammar_path = os.path.join(self.grammar_dir, "grammar.py")
        if not os.path.isfile(grammar_path):
            raise FileNotFoundError(f"grammar.py not found in: {self.grammar_dir}")

        self._install_shims()

        spec = importlib.util.spec_from_file_location("_grammar_module", grammar_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot load grammar.py as a Python module")
        module = importlib.util.module_from_spec(spec)
        sys.modules["_grammar_module"] = module

        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except SystemExit:
            pass
        except Exception as exc:
            raise RuntimeError(f"Failed to execute grammar.py: {exc}") from exc

    def export(self) -> dict:
        return {"count": len(self.templates), "skipped": self.skipped,
                "templates": self.templates}

    # ── Shim installer ────────────────────────────────────────────────────────

    def _install_shims(self) -> None:
        interp = self
        prim = _make_prim_ns()

        # ── engine.errors ──────────────────────────────────────────────────────
        class ResponseParsingException(Exception): pass

        errors_mod = types.ModuleType("engine.errors")
        errors_mod.ResponseParsingException = ResponseParsingException  # type: ignore[attr-defined]

        # ── engine.dependencies ────────────────────────────────────────────────
        _dyn: dict = {}

        # Pattern: RESTler dep var names start with "_api_" or match _<method>_ convention.
        # We tag them via a sentinel wrapper so _flatten can classify reads vs writes.
        import re as _re
        _DEP_RE = _re.compile(r'^_[a-z]')

        class _DepRef:
            """Wraps a dependency variable name so _flatten can detect it."""
            __slots__ = ("name", "is_write")
            def __init__(self, name: str, is_write: bool = False):
                self.name = name
                self.is_write = is_write
            def __str__(self):
                return self.name

        class DynamicVariable:
            def __init__(self, name: str):
                self._name = name
                _dyn[name] = None
            def __repr__(self):
                return f"DynamicVariable({self._name!r})"
            def writer(self, *a, **kw):
                # Called inside post_send.dependencies — marks this template as a PRODUCER.
                return _DepRef(self._name, is_write=True)
            def reader(self, *a, **kw):
                # Called inside restler_static_string — marks this template as a CONSUMER.
                return _DepRef(self._name, is_write=False)

        deps_mod = types.ModuleType("engine.dependencies")
        deps_mod.DynamicVariable = DynamicVariable      # type: ignore[attr-defined]
        deps_mod.set_variable    = lambda n, v=None: _dyn.update({n: v})  # type: ignore[attr-defined]
        deps_mod.get_variable    = lambda n: _dyn.get(n)                  # type: ignore[attr-defined]
        deps_mod.writer          = lambda name, *a, **kw: _DepRef(name, True)   # type: ignore[attr-defined]
        deps_mod.reader          = lambda name, *a, **kw: _DepRef(name, False)  # type: ignore[attr-defined]

        # ── engine.core.requests ───────────────────────────────────────────────
        class _Request:
            def __init__(self, definition=None, *a, **kw):
                try:
                    reads, writes = interp._extract_dep_refs(definition or [])
                    segs = interp._flatten(definition or [])
                    interp.templates.append({
                        "id": interp._next_id,
                        "request_id": interp._extract_path(segs),
                        "segments": segs,
                        "reads":  list(reads),
                        "writes": list(writes),
                    })
                    interp._next_id += 1
                except Exception:
                    interp.skipped += 1

        class _RequestCollection:
            def __init__(self, reqs=None, *a, **kw):
                self.requests = list(reqs or [])
            def add_request(self, req, *a, **kw):
                self.requests.append(req)

        requests_ns = types.SimpleNamespace(Request=_Request,
                                            RequestCollection=_RequestCollection)

        core_mod           = types.ModuleType("engine.core")
        core_mod.requests  = requests_ns  # type: ignore[attr-defined]
        requests_mod       = types.ModuleType("engine.core.requests")
        requests_mod.Request           = _Request              # type: ignore[attr-defined]
        requests_mod.RequestCollection = _RequestCollection    # type: ignore[attr-defined]

        # ── engine (root) ──────────────────────────────────────────────────────
        engine_mod              = types.ModuleType("engine")
        engine_mod.primitives   = prim         # type: ignore[attr-defined]
        engine_mod.dependencies = deps_mod     # type: ignore[attr-defined]
        engine_mod.errors       = errors_mod   # type: ignore[attr-defined]
        engine_mod.core         = core_mod     # type: ignore[attr-defined]
        # Also expose ResponseParsingException at top of engine for convenience
        engine_mod.ResponseParsingException = ResponseParsingException  # type: ignore[attr-defined]

        # Copy all restler_* callables to engine root (some grammars use engine.restler_*)
        for attr, val in vars(prim).items():
            setattr(engine_mod, attr, val)

        # ── Register everything ────────────────────────────────────────────────
        sys.modules["engine"]                = engine_mod
        sys.modules["engine.primitives"]     = types.ModuleType("engine.primitives")
        # Make engine.primitives module behave like prim namespace
        for attr, val in vars(prim).items():
            setattr(sys.modules["engine.primitives"], attr, val)
        sys.modules["engine.dependencies"]   = deps_mod
        sys.modules["engine.errors"]         = errors_mod
        sys.modules["engine.core"]           = core_mod
        sys.modules["engine.core.requests"]  = requests_mod

        # Also expose ResponseParsingException at the errors module level so
        # `from engine.errors import ResponseParsingException` works
        sys.modules["engine.errors"].ResponseParsingException = ResponseParsingException  # type: ignore[attr-defined]

    # ── Dependency extraction ─────────────────────────────────────────────────

    def _extract_dep_refs(self, obj, reads=None, writes=None):
        """Walk raw definition recursively, collecting _DepRef objects."""
        if reads is None:
            reads = set()
            writes = set()
        if obj is None:
            return reads, writes
        # Check if obj is a _DepRef (identified by duck-typing — it has .is_write attr)
        if hasattr(obj, 'is_write') and hasattr(obj, 'name'):
            if obj.is_write:
                writes.add(obj.name)
            else:
                reads.add(obj.name)
            return reads, writes
        if isinstance(obj, (list, tuple)):
            for item in obj:
                self._extract_dep_refs(item, reads, writes)
        elif isinstance(obj, dict):
            for v in obj.values():
                self._extract_dep_refs(v, reads, writes)
        return reads, writes

    # ── Segment helpers ───────────────────────────────────────────────────────

    def _flatten(self, obj) -> list[dict]:
        if obj is None:
            return []
        # _DepRef (reader/writer sentinel): render as a static string with the dep name.
        if hasattr(obj, 'is_write') and hasattr(obj, 'name'):
            # Writer refs appear in post_send.dependencies — skip them from segments.
            if obj.is_write:
                return []
            # Reader refs appear inside restler_static_string — emit as custom_payload so they are fuzzed if missing.
            return [seg_payload(obj.name)]
        if isinstance(obj, dict):
            # Verify all values are JSON-safe primitives; skip bad ones
            clean = {k: v for k, v in obj.items()
                     if isinstance(v, (str, int, float, bool)) or v is None}
            if "kind" in clean:
                return [clean]
            return []
        if isinstance(obj, (list, tuple)):
            result = []
            for item in obj:
                result.extend(self._flatten(item))
            return result
        # Callable (e.g. writer/reader result as a string is ok, as function — skip)
        if callable(obj):
            return []
        if isinstance(obj, str):
            return [seg_static(obj)]
        # Skip anything else
        return []

    def _extract_path(self, segs: list[dict]) -> str:
        parts: list[str] = []
        for s in segs:
            if s.get("kind") != "static":
                break
            v = s.get("value", "")
            if v.endswith(" "):
                parts.append(v.rstrip())
                continue
            if v.startswith(" HTTP/"):
                break
            parts.append(v)
        return "".join(parts).strip()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export RESTler grammar.py to JSON templates for Void-Go"
    )
    parser.add_argument("--grammar-dir", required=True,
                        help="Directory containing grammar.py")
    parser.add_argument("--out", required=True,
                        help="Output JSON file path")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    grammar_dir = os.path.abspath(args.grammar_dir)
    out_path    = os.path.abspath(args.out)

    if args.verbose:
        print(f"[export-templates] grammar_dir={grammar_dir}", file=sys.stderr)

    try:
        interp = GrammarInterpreter(grammar_dir)
        interp.load()
        data = interp.export()
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return 1

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)

    print(f"[export-templates] Exported {data['count']} templates "
          f"({data['skipped']} skipped) → {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
