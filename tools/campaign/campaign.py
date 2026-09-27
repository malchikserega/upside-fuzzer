#!/usr/bin/env python3
"""campaign.py — the campaign.yaml contract (Phase 5 #124,
docs/ARCHITECTURE_STATEFUL.md's operational-maturity family).

Instead of a hand-assembled bag of CLI flags re-typed (and re-drifted) per
run, campaign.yaml declares a fuzzing campaign as one reusable, versionable
file: target/readiness, state reset/seed/cleanup commands, which identities
file to use, coarse safety policy, and which security-scenario families to
enable. This module parses that file and translates it into the environment
variables and `void` CLI flags the engine already understands (see
void/README.md for TARGET_HOST/SHM_HOST, and main.go for every -flag
referenced below) -- it does not invent new engine behavior, it composes
existing, already-tested flags from one declarative source.

Stdlib-only, matching this repo's own established convention for
grammarc/fuzzprep ("stdlib-only, no pip install needed" -- see those
modules' own test-file docstrings): PyYAML is not a dependency of this
project, so campaign.yaml is parsed by parser.parse_simple_yaml, a
deliberately bounded block-style YAML SUBSET parser -- see that module's own
docstring for exactly what it supports and what it explicitly rejects rather
than silently misparsing. The parser moved into its own module (parser.py)
during the tools/ packaging pass so scenarios.py can share it without
importing this file's CLI/orchestration code -- no parsing behavior changed.

Run with: python3 -m tools.campaign.campaign run campaign.yaml (or via the
repo-root campaign.py compatibility wrapper: python3 campaign.py run ...)
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .parser import CampaignYAMLError, parse_simple_yaml

__all__ = [
    "CampaignYAMLError",
    "parse_simple_yaml",
    "Campaign",
    "load_campaign",
    "unknown_scenarios",
    "to_void_env",
    "to_void_args",
    "wait_for_readiness",
    "run_state_command",
    "main",
]

# ---------------------------------------------------------------------------
# Campaign: the parsed, validated contract
# ---------------------------------------------------------------------------


@dataclass
class Campaign:
    base_url: str
    swagger_url: str = ""
    readiness: List[str] = field(default_factory=list)
    state_reset: str = ""
    state_seed: str = ""
    state_cleanup: str = ""
    identities_file: str = ""
    required_roles: List[str] = field(default_factory=list)
    max_rps: Optional[float] = None
    destructive_operations: str = "allow"  # allow | isolated | deny
    workflow_depth: int = 6
    scenarios: List[str] = field(default_factory=lambda: ["baseline"])


def load_campaign(path: Path) -> Campaign:
    text = path.read_text()
    doc = parse_simple_yaml(text)
    if not isinstance(doc, dict):
        raise CampaignYAMLError(f"{path}: top level must be a mapping (target/state/identities/policy/scenarios)")

    target = doc.get("target") or {}
    if not isinstance(target, dict) or not target.get("base_url"):
        raise CampaignYAMLError(f"{path}: target.base_url is required")
    state = doc.get("state") or {}
    identities = doc.get("identities") or {}
    policy = doc.get("policy") or {}
    scenarios = doc.get("scenarios")
    if scenarios is not None and not isinstance(scenarios, list):
        raise CampaignYAMLError(f"{path}: scenarios must be a list")

    return Campaign(
        base_url=str(target.get("base_url")),
        swagger_url=str(target.get("swagger_url") or ""),
        readiness=list(target.get("readiness") or []),
        state_reset=str(state.get("reset") or ""),
        state_seed=str(state.get("seed") or ""),
        state_cleanup=str(state.get("cleanup") or ""),
        identities_file=str(identities.get("file") or ""),
        required_roles=list(identities.get("required_roles") or []),
        max_rps=float(policy["max_rps"]) if policy.get("max_rps") is not None else None,
        destructive_operations=str(policy.get("destructive_operations") or "allow"),
        workflow_depth=int(policy.get("workflow_depth") or 6),
        scenarios=list(scenarios) if scenarios else ["baseline"],
    )


# ---------------------------------------------------------------------------
# Scenario -> void flag translation
# ---------------------------------------------------------------------------

# Each named scenario turns on a coherent bundle of already-existing void
# flags (docs/ARCHITECTURE_STATEFUL.md's security-scenario families) --
# additive: multiple scenarios in one campaign just union their flag sets.
# Deliberately a fixed, small vocabulary for this pass, not the fully
# declarative per-scenario precondition/confirm rule engine
# (security_scenarios.yaml, Phase 5 #125) -- that's a separate, larger
# contract layered on TOP of this one, not yet built.
SCENARIO_FLAGS: Dict[str, List[str]] = {
    "baseline": [],
    "bola": ["-access-probe", "-probe-bola=true", "-probe-auth-bypass=true"],
    "mass-assignment": ["-access-probe", "-probe-mass-assign=true"],
    "differential": ["-access-probe", "-probe-differential=true"],
    "lifecycle": [
        "-resource-graph=true",
        "-probe-stale-object=true",
        "-probe-stale-etag=true",
        "-probe-workflow-bypass=true",
    ],
    "idempotency": ["-access-probe", "-probe-idempotency=true"],
    "concurrency": ["-race-mode=true", "-probe-race-outcome=true"],
    "injection": ["-injection-oracle=true"],
    "schema": ["-schema-conformance=true"],
}


def unknown_scenarios(campaign: Campaign) -> List[str]:
    return [s for s in campaign.scenarios if s not in SCENARIO_FLAGS]


def to_void_env(campaign: Campaign) -> Dict[str, str]:
    """TARGET_HOST/SHM_HOST are void's own env-var-configured target
    (void/README.md) -- SHM_HOST defaults to the same host as TARGET_HOST
    unless a target ever needs them split, which campaign.yaml's schema
    doesn't currently expose (no real target in this repo's own runbooks
    has needed it split from base_url)."""
    base = campaign.base_url.rstrip("/")
    return {"TARGET_HOST": base, "SHM_HOST": base}


def to_void_args(campaign: Campaign) -> List[str]:
    """Translates policy + scenarios into void CLI flags. destructive_operations
    has no direct engine equivalent yet (void has no "isolate destructive
    calls" mode) -- 'deny' is the one case mapped today (turns off the
    mutation categories most likely to actually destroy state), 'isolated'
    is accepted but only documented as operator guidance (see
    docs/CAMPAIGN.md), not enforced by a flag, so this doesn't silently
    claim a safety guarantee the engine doesn't provide."""
    args: List[str] = ["-sequence-max-depth", str(campaign.workflow_depth)]
    if campaign.identities_file:
        args += ["-auth-file", campaign.identities_file, "-multi-identity=true"]
    if campaign.destructive_operations == "deny":
        args += ["-race-mode=false"]
    seen = set()
    for scenario in campaign.scenarios:
        for flag in SCENARIO_FLAGS.get(scenario, []):
            if flag not in seen:
                args.append(flag)
                seen.add(flag)
    return args


# ---------------------------------------------------------------------------
# Orchestration: readiness wait + state reset/seed/cleanup
# ---------------------------------------------------------------------------


def wait_for_readiness(campaign: Campaign, timeout_sec: float = 120.0, poll_interval_sec: float = 2.0) -> None:
    """Polls every campaign.target.readiness path (resolved against base_url)
    until each returns any HTTP status < 500, or raises TimeoutError. A
    no-op if readiness is empty (some targets have no health endpoint at
    all -- not requiring one keeps this from being a hard blocker for
    those)."""
    deadline = time.monotonic() + timeout_sec
    base = campaign.base_url.rstrip("/")
    for path in campaign.readiness:
        url = base + (path if path.startswith("/") else "/" + path)
        while True:
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    if resp.status < 500:
                        break
            except urllib.error.HTTPError as e:
                if e.code < 500:
                    break
            except (urllib.error.URLError, OSError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError(f"readiness check timed out waiting for {url}")
            time.sleep(poll_interval_sec)


def run_state_command(command: str, *, check: bool) -> None:
    """Runs a state.reset/seed/cleanup shell command. check=True propagates a
    non-zero exit as a CalledProcessError (reset/seed failing should stop
    the campaign before it fuzzes against unknown state); check=False is
    used for cleanup, which runs best-effort even after a failure upstream."""
    if not command.strip():
        return
    subprocess.run(command, shell=True, check=check)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_plan(campaign: Campaign) -> None:
    print(f"Campaign target: {campaign.base_url}")
    if campaign.readiness:
        print(f"Readiness checks: {', '.join(campaign.readiness)}")
    if campaign.state_reset:
        print(f"State reset: {campaign.state_reset}")
    if campaign.state_seed:
        print(f"State seed: {campaign.state_seed}")
    if campaign.identities_file:
        print(f"Identities: {campaign.identities_file} (required_roles={campaign.required_roles})")
    print(f"Scenarios: {', '.join(campaign.scenarios)}")
    unknown = unknown_scenarios(campaign)
    if unknown:
        print(f"WARNING: unrecognized scenario name(s), no flags applied: {', '.join(unknown)}")
    print(f"void env: {to_void_env(campaign)}")
    print(f"void args: {' '.join(to_void_args(campaign))}")


def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2 or argv[0] not in ("run", "plan"):
        print("usage: campaign.py <run|plan> <campaign.yaml>", file=sys.stderr)
        return 2
    action, path_str = argv[0], argv[1]
    campaign = load_campaign(Path(path_str))

    if action == "plan":
        _print_plan(campaign)
        return 0

    # action == "run"
    _print_plan(campaign)
    if campaign.state_reset:
        run_state_command(campaign.state_reset, check=True)
    if campaign.readiness:
        wait_for_readiness(campaign)
    if campaign.state_seed:
        run_state_command(campaign.state_seed, check=True)

    env_str = " ".join(f"{k}={v}" for k, v in to_void_env(campaign).items())
    args_str = " ".join(to_void_args(campaign))
    print(f"\nRun the fuzzer with:\n  {env_str} ./void {args_str}\n")
    print("(campaign.py composes the environment/flags -- it does not itself launch the void binary;")
    print(" see docs/CAMPAIGN.md for wiring this into `upsidefuzz.py run` directly.)")

    if campaign.state_cleanup:
        run_state_command(campaign.state_cleanup, check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
