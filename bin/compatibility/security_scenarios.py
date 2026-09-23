#!/usr/bin/env python3
"""security_scenarios.py - compatibility wrapper.

The actual implementation moved to tools/campaign/scenarios.py during the
repo-architecture refactor (renamed from security_scenarios.py to scenarios.py
now that it lives inside the tools/campaign package, alongside campaign.py).
This file exists so every existing invocation (`python3
bin/compatibility/security_scenarios.py security_scenarios.yaml`, `from
security_scenarios import load_scenarios`, docs, CI) keeps working unchanged.
Moved from the repo root to bin/compatibility/ in the self-contained-module
refactor (2026-07-31) -- the sys.path insert below climbs to the actual repo
root explicitly now, since this file's own directory is no longer it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.campaign.scenarios import (  # noqa: E402  (path insert must come first)
    REPO_ROOT,
    SecurityScenario,
    SecurityScenarioError,
    load_scenarios,
    verify_catalog_matches_implementation,
)

__all__ = [
    "REPO_ROOT",
    "SecurityScenario",
    "SecurityScenarioError",
    "load_scenarios",
    "verify_catalog_matches_implementation",
]

if __name__ == "__main__":
    loaded = load_scenarios(
        Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "tools" / "campaign" / "security_scenarios.yaml"
    )
    print(f"Loaded {len(loaded)} scenarios:")
    for sc in loaded:
        print(f"  - {sc.id} ({sc.family}): budget={sc.request_budget} implemented_by={sc.implemented_by or '<undocumented>'}")
    drift = verify_catalog_matches_implementation(loaded)
    if drift:
        print("\nDrift found:")
        for d in drift:
            print(f"  ! {d}")
        sys.exit(1)
    print("\nNo drift: every scenario's implemented_by symbol was found.")
