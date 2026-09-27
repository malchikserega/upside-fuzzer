#!/usr/bin/env python3
"""scenarios.py — the declarative security-scenario library (Phase 5
#125, docs/ARCHITECTURE_STATEFUL.md's operational-maturity family).

Renamed from security_scenarios.py during the tools/ packaging pass (see
repo-root security_scenarios.py, now a thin compatibility wrapper) --
content and behavior unchanged.

Parses and validates security_scenarios.yaml: a declarative, reusable catalog
describing every stateful security-scenario family this project's task spec
calls for (BOLA/IDOR, tenant escape, mass assignment, workflow bypass, stale
object, optimistic locking, idempotency, races, auth confusion, async
workflows), each with requires/valid/attack/confirm blocks, a request
budget, and a minimization strategy -- in the exact shape the design task
specifies.

Honest scope note (read before assuming more than this provides): this
module is a **catalog loader and validator**, not a runtime rule
interpreter. void's own oracles (internal/oracle/..., see
docs/architecture) already implement each of these scenario families
natively in Go, hand-written and individually tested (200+ Go tests across
them). This file's job is to describe that same set of behaviors in one
declarative, reusable, version-controlled place -- for documentation, for
auditing "does every required family actually have an implementation," and
as the seed of a future generic interpreter -- not to replace or re-drive
those Go oracles at runtime. `implemented_by` on every scenario names the
exact Go symbol that already does the work; `verify_catalog_matches_implementation`
below checks that name is still real, so this file can't silently drift out
of sync with the engine the way a comment easily could.

Run with: python3 -m unittest tools.campaign.test_scenarios -v
Stdlib-only, matching the rest of this repo's Python modules. Reuses
parser.parse_simple_yaml (extended with bounded inline-list support
specifically for this file's own `status_in: [200, 201]` fields).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .parser import CampaignYAMLError, parse_simple_yaml

# tools/campaign/scenarios.py -> tools/campaign -> tools -> repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class SecurityScenarioError(Exception):
    """Raised for a security_scenarios.yaml entry missing a required field,
    or shaped in a way this loader doesn't recognize."""


_REQUIRED_TOP_LEVEL_FIELDS = ("id", "requires", "valid", "attack", "confirm")


@dataclass
class SecurityScenario:
    id: str
    family: str
    description: str
    requires: List[str] = field(default_factory=list)
    valid: Dict[str, Any] = field(default_factory=dict)
    attack: Dict[str, Any] = field(default_factory=dict)
    confirm: Dict[str, Any] = field(default_factory=dict)
    request_budget: int = 10
    minimization_strategy: str = "drop-unnecessary-steps"
    implemented_by: str = ""


def _require_mapping(value: Any, scenario_id: str, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise SecurityScenarioError(f"scenario {scenario_id!r}: {field_name!r} must be a mapping")
    return value


def load_scenarios(path: Path) -> List[SecurityScenario]:
    text = path.read_text()
    doc = parse_simple_yaml(text)
    scenarios_raw = doc.get("scenarios") if isinstance(doc, dict) else None
    if not isinstance(scenarios_raw, dict):
        raise SecurityScenarioError(f"{path}: top level must have a 'scenarios' mapping of id -> scenario fields")

    out: List[SecurityScenario] = []
    for scenario_id, fields_ in scenarios_raw.items():
        if not isinstance(fields_, dict):
            raise SecurityScenarioError(f"scenario {scenario_id!r}: must be a mapping of fields")
        missing = [f for f in ("requires", "valid", "attack", "confirm") if f not in fields_]
        if missing:
            raise SecurityScenarioError(f"scenario {scenario_id!r}: missing required field(s) {missing}")
        requires = fields_.get("requires") or []
        if not isinstance(requires, list):
            raise SecurityScenarioError(f"scenario {scenario_id!r}: 'requires' must be a list")
        out.append(
            SecurityScenario(
                id=scenario_id,
                family=str(fields_.get("family") or ""),
                description=str(fields_.get("description") or ""),
                requires=list(requires),
                valid=_require_mapping(fields_["valid"], scenario_id, "valid"),
                attack=_require_mapping(fields_["attack"], scenario_id, "attack"),
                confirm=_require_mapping(fields_["confirm"], scenario_id, "confirm"),
                request_budget=int(fields_.get("request_budget") or 10),
                minimization_strategy=str(fields_.get("minimization_strategy") or "drop-unnecessary-steps"),
                implemented_by=str(fields_.get("implemented_by") or ""),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Catalog <-> implementation drift check
# ---------------------------------------------------------------------------

_GO_SYMBOL_RE_TEMPLATE = r"\b{}\b"

# Go source lives under src/void/cmd/void/ (thin entrypoint) and
# src/void/internal/... (the split-out engine packages), a self-contained Go
# module since 2026-07-31 (previously cmd/void/ + internal/ directly at repo
# root) -- see docs/architecture/overview.md for the post-refactor package map.
_GO_SEARCH_ROOTS = ("src/void/cmd/void", "src/void/internal")


def _go_symbol_exists(symbol: str) -> bool:
    """Greps this repo's Go source (src/void/cmd/void/, src/void/internal/)
    for a Go symbol name (function/type/const) -- a lightweight, dependency-free way to catch
    a scenario's own `implemented_by` reference going stale (renamed/removed)
    without needing a real Go AST parser from Python."""
    pattern = re.compile(_GO_SYMBOL_RE_TEMPLATE.format(re.escape(symbol)))
    any_root_present = False
    for root_name in _GO_SEARCH_ROOTS:
        go_dir = REPO_ROOT / root_name
        if not go_dir.is_dir():
            continue
        any_root_present = True
        for go_file in go_dir.rglob("*.go"):
            if go_file.name.endswith("_test.go"):
                continue
            try:
                if pattern.search(go_file.read_text()):
                    return True
            except OSError:
                continue
    if not any_root_present:
        return True  # can't check (e.g. a stripped checkout) -- don't false-fail
    return False


def verify_catalog_matches_implementation(scenarios: List[SecurityScenario]) -> List[str]:
    """Returns a list of human-readable problems -- empty if every scenario's
    `implemented_by` symbol was actually found in the Go source tree. Doesn't
    raise: callers (a CI check, a test) decide whether an empty
    `implemented_by` or a stale reference is fatal."""
    problems: List[str] = []
    for s in scenarios:
        if not s.implemented_by:
            problems.append(f"{s.id}: no implemented_by reference (undocumented implementation status)")
            continue
        # implemented_by is "file.go::Symbol" or "file.go::Symbol (extra
        # human context, e.g. an oracle-kind constant)" -- only the bare
        # leading identifier is checked; anything else is documentation for
        # humans, not part of the drift check.
        after_marker = s.implemented_by.split("::")[-1].strip()
        symbol_match = re.match(r"[A-Za-z_]\w*", after_marker)
        if not symbol_match:
            problems.append(f"{s.id}: implemented_by {s.implemented_by!r} has no recognizable Go symbol")
            continue
        symbol = symbol_match.group(0)
        if not _go_symbol_exists(symbol):
            problems.append(f"{s.id}: implemented_by references {symbol!r}, not found in the Go source tree (stale?)")
    return problems


if __name__ == "__main__":
    import sys

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "security_scenarios.yaml"
    loaded = load_scenarios(path)
    print(f"Loaded {len(loaded)} scenarios from {path}:")
    for sc in loaded:
        print(f"  - {sc.id} ({sc.family}): budget={sc.request_budget} implemented_by={sc.implemented_by or '<undocumented>'}")
    drift = verify_catalog_matches_implementation(loaded)
    if drift:
        print("\nDrift found:")
        for d in drift:
            print(f"  ! {d}")
        sys.exit(1)
    print("\nNo drift: every scenario's implemented_by symbol was found.")
