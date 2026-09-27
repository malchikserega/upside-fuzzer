"""Tests for campaign.py -- the campaign.yaml contract (Phase 5 #124),
including its bounded, stdlib-only YAML-subset parser (parse_simple_yaml).

Run with: cd tools && python3 -m unittest campaign.test_campaign -v
(same pattern as grammarc's own tests: cd to the package's parent dir, then
`-m unittest <package>.<test_module>`.) Stdlib-only, matching the rest of
this repo's Python test suites.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from .campaign import (
    Campaign,
    CampaignYAMLError,
    load_campaign,
    parse_simple_yaml,
    to_void_args,
    to_void_env,
    unknown_scenarios,
)

EXAMPLE_YAML = """
target:
  base_url: http://localhost:8080
  swagger_url: http://localhost:8080/swagger/v1/swagger.json
  readiness:
    - /health
    - /shm/health

state:
  reset: docker compose down -v && docker compose up -d
  seed: ./populate-test-data.sh
  cleanup: ./cleanup-test-data.sh

identities:
  file: auth.identities.json
  required_roles:
    - tenant_a_admin
    - tenant_b_user

policy:
  max_rps: 40
  destructive_operations: isolated
  workflow_depth: 6

scenarios:
  - baseline
  - bola
  - lifecycle
  - concurrency
"""


class ParseSimpleYamlTests(unittest.TestCase):
    def test_flat_mapping(self):
        self.assertEqual(parse_simple_yaml("a: 1\nb: two\n"), {"a": 1, "b": "two"})

    def test_nested_mapping(self):
        got = parse_simple_yaml("target:\n  base_url: http://x\n  port: 8080\n")
        self.assertEqual(got, {"target": {"base_url": "http://x", "port": 8080}})

    def test_scalar_types(self):
        got = parse_simple_yaml("a: true\nb: false\nc: null\nd: 3.5\ne: 7\nf: plain\n")
        self.assertEqual(got, {"a": True, "b": False, "c": None, "d": 3.5, "e": 7, "f": "plain"})

    def test_quoted_strings(self):
        got = parse_simple_yaml('a: "hello world"\nb: \'single # not a comment\'\n')
        self.assertEqual(got, {"a": "hello world", "b": "single # not a comment"})

    def test_comments_and_blank_lines_ignored(self):
        text = "# a top comment\na: 1\n\n# another\nb: 2  # trailing comment\n"
        self.assertEqual(parse_simple_yaml(text), {"a": 1, "b": 2})

    def test_list_of_scalars(self):
        got = parse_simple_yaml("items:\n  - a\n  - b\n  - c\n")
        self.assertEqual(got, {"items": ["a", "b", "c"]})

    def test_full_example_document(self):
        got = parse_simple_yaml(EXAMPLE_YAML)
        self.assertEqual(got["target"]["base_url"], "http://localhost:8080")
        self.assertEqual(got["target"]["readiness"], ["/health", "/shm/health"])
        self.assertEqual(got["state"]["reset"], "docker compose down -v && docker compose up -d")
        self.assertEqual(got["identities"]["required_roles"], ["tenant_a_admin", "tenant_b_user"])
        self.assertEqual(got["policy"]["max_rps"], 40)
        self.assertEqual(got["policy"]["workflow_depth"], 6)
        self.assertEqual(got["scenarios"], ["baseline", "bola", "lifecycle", "concurrency"])

    def test_inline_scalar_list_is_supported(self):
        self.assertEqual(parse_simple_yaml("a: [1, 2, 3]\n"), {"a": [1, 2, 3]})
        self.assertEqual(parse_simple_yaml('a: [200, "abc", true]\n'), {"a": [200, "abc", True]})
        self.assertEqual(parse_simple_yaml("a: []\n"), {"a": []})

    def test_rejects_flow_mapping(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("a: {b: 1}\n")

    def test_rejects_nested_flow_list(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("a: [[1, 2]]\n")

    def test_rejects_bare_flow_list_without_key(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("[1, 2, 3]\n")

    def test_rejects_anchors(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("a: &anchor 1\nb: *anchor\n")

    def test_rejects_multi_document(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("a: 1\n---\nb: 2\n")

    def test_rejects_tab_indentation(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("a:\n\tb: 1\n")

    def test_rejects_sequence_of_mappings(self):
        with self.assertRaises(CampaignYAMLError):
            parse_simple_yaml("items:\n  - key: value\n")

    def test_empty_document_returns_empty_mapping(self):
        self.assertEqual(parse_simple_yaml(""), {})
        self.assertEqual(parse_simple_yaml("# just a comment\n"), {})


class LoadCampaignTests(unittest.TestCase):
    def _load(self, text: str) -> Campaign:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "campaign.yaml"
            path.write_text(text)
            return load_campaign(path)

    def test_full_example_loads_correctly(self):
        c = self._load(EXAMPLE_YAML)
        self.assertEqual(c.base_url, "http://localhost:8080")
        self.assertEqual(c.swagger_url, "http://localhost:8080/swagger/v1/swagger.json")
        self.assertEqual(c.readiness, ["/health", "/shm/health"])
        self.assertEqual(c.state_reset, "docker compose down -v && docker compose up -d")
        self.assertEqual(c.state_seed, "./populate-test-data.sh")
        self.assertEqual(c.state_cleanup, "./cleanup-test-data.sh")
        self.assertEqual(c.identities_file, "auth.identities.json")
        self.assertEqual(c.required_roles, ["tenant_a_admin", "tenant_b_user"])
        self.assertEqual(c.max_rps, 40.0)
        self.assertEqual(c.destructive_operations, "isolated")
        self.assertEqual(c.workflow_depth, 6)
        self.assertEqual(c.scenarios, ["baseline", "bola", "lifecycle", "concurrency"])

    def test_missing_base_url_raises(self):
        with self.assertRaises(CampaignYAMLError):
            self._load("target:\n  swagger_url: http://x\n")

    def test_minimal_campaign_uses_defaults(self):
        c = self._load("target:\n  base_url: http://localhost:9000\n")
        self.assertEqual(c.base_url, "http://localhost:9000")
        self.assertEqual(c.readiness, [])
        self.assertEqual(c.workflow_depth, 6)
        self.assertEqual(c.scenarios, ["baseline"])
        self.assertIsNone(c.max_rps)
        self.assertEqual(c.destructive_operations, "allow")


class ScenarioTranslationTests(unittest.TestCase):
    def test_to_void_env(self):
        c = Campaign(base_url="http://localhost:8080/")
        self.assertEqual(to_void_env(c), {"TARGET_HOST": "http://localhost:8080", "SHM_HOST": "http://localhost:8080"})

    def test_to_void_args_includes_workflow_depth(self):
        c = Campaign(base_url="http://x", workflow_depth=9)
        args = to_void_args(c)
        self.assertIn("-sequence-max-depth", args)
        self.assertEqual(args[args.index("-sequence-max-depth") + 1], "9")

    def test_to_void_args_includes_auth_file_when_set(self):
        c = Campaign(base_url="http://x", identities_file="auth.json")
        args = to_void_args(c)
        self.assertIn("-auth-file", args)
        self.assertEqual(args[args.index("-auth-file") + 1], "auth.json")
        self.assertIn("-multi-identity=true", args)

    def test_to_void_args_omits_auth_file_when_unset(self):
        c = Campaign(base_url="http://x")
        self.assertNotIn("-auth-file", to_void_args(c))

    def test_scenario_flags_are_unioned_and_deduped(self):
        c = Campaign(base_url="http://x", scenarios=["bola", "bola", "lifecycle"])
        args = to_void_args(c)
        self.assertEqual(args.count("-access-probe"), 1)
        self.assertIn("-probe-bola=true", args)
        self.assertIn("-resource-graph=true", args)
        self.assertIn("-probe-workflow-bypass=true", args)

    def test_destructive_operations_deny_disables_race_mode(self):
        c = Campaign(base_url="http://x", destructive_operations="deny")
        self.assertIn("-race-mode=false", to_void_args(c))

    def test_destructive_operations_allow_does_not_touch_race_mode(self):
        c = Campaign(base_url="http://x", destructive_operations="allow")
        self.assertNotIn("-race-mode=false", to_void_args(c))

    def test_unknown_scenarios_reported_not_silently_dropped(self):
        c = Campaign(base_url="http://x", scenarios=["bola", "not-a-real-scenario"])
        self.assertEqual(unknown_scenarios(c), ["not-a-real-scenario"])
        # The known scenario's flags must still apply.
        self.assertIn("-probe-bola=true", to_void_args(c))

    def test_baseline_scenario_adds_no_extra_flags(self):
        c = Campaign(base_url="http://x", scenarios=["baseline"])
        args = to_void_args(c)
        self.assertEqual(args, ["-sequence-max-depth", "6"])


if __name__ == "__main__":
    unittest.main()
