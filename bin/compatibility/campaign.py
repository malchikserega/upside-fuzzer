#!/usr/bin/env python3
"""campaign.py - compatibility wrapper.

The actual implementation moved to tools/campaign/ (campaign.py + parser.py)
during the repo-architecture refactor. This file exists so every existing
invocation (`python3 bin/compatibility/campaign.py run campaign.yaml`,
`from campaign import Campaign`, docs, CI) keeps working unchanged. Moved
from the repo root to bin/compatibility/ in the self-contained-module
refactor (2026-07-31) -- the sys.path insert below climbs to the actual repo
root explicitly now, since this file's own directory is no longer it.

Imported via the "tools.campaign.campaign" dotted path (not a bare "import
campaign") deliberately: this wrapper module is itself importable as
top-level "campaign", so importing its implementation under that same bare
name would self-collide (Python resolves an already-registered sys.modules
entry before ever consulting sys.path) -- "tools.campaign.campaign" is a
distinct name with no such collision, requiring only repo root on sys.path.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.campaign.campaign import (  # noqa: E402  (path insert must come first)
    Campaign,
    CampaignYAMLError,
    load_campaign,
    main,
    parse_simple_yaml,
    run_state_command,
    to_void_args,
    to_void_env,
    unknown_scenarios,
    wait_for_readiness,
)

__all__ = [
    "Campaign",
    "CampaignYAMLError",
    "load_campaign",
    "main",
    "parse_simple_yaml",
    "run_state_command",
    "to_void_args",
    "to_void_env",
    "unknown_scenarios",
    "wait_for_readiness",
]

if __name__ == "__main__":
    sys.exit(main())
