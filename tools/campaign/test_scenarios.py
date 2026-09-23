"""Tests for scenarios.py -- the declarative security-scenario library
(Phase 5 #125). Renamed from test_security_scenarios.py during the tools/
packaging pass, alongside its module (security_scenarios.py -> scenarios.py).

Run with: cd tools && python3 -m unittest campaign.test_scenarios -v
Stdlib-only, matching the rest of this repo's Python test suites.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from .scenarios import (
    REPO_ROOT,
    SecurityScenario,
    SecurityScenarioError,
    _go_symbol_exists,
    load_scenarios,
    verify_catalog_matches_implementation,
)

MINIMAL_DOC = """
scenarios:
  cross_tenant_read:
    family: bola
    description: Identity B reads a resource identity A created in a different tenant
    requires:
      - resource.owner_identity
      - second_identity
    valid:
      identity: owner
      operation: read
    attack:
      identity: other
      operation: same
    confirm:
      status_in: [200, 201, 204]
      response_contains_resource_identity: true
    request_budget: 2
    minimization_strategy: drop-unnecessary-headers-then-fields
    implemented_by: "oracle.go::maybeEnqueueAccessProbes"
"""


class LoadScenariosTests(unittest.TestCase):
    def _load(self, text: str):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "security_scenarios.yaml"
            path.write_text(text)
            return load_scenarios(path)

    def test_loads_a_well_formed_scenario(self):
        scenarios = self._load(MINIMAL_DOC)
        self.assertEqual(len(scenarios), 1)
        s = scenarios[0]
        self.assertEqual(s.id, "cross_tenant_read")
        self.assertEqual(s.family, "bola")
        self.assertEqual(s.requires, ["resource.owner_identity", "second_identity"])
        self.assertEqual(s.valid, {"identity": "owner", "operation": "read"})
        self.assertEqual(s.attack, {"identity": "other", "operation": "same"})
        self.assertEqual(s.confirm["status_in"], [200, 201, 204])
        self.assertEqual(s.confirm["response_contains_resource_identity"], True)
        self.assertEqual(s.request_budget, 2)
        self.assertEqual(s.minimization_strategy, "drop-unnecessary-headers-then-fields")
        self.assertEqual(s.implemented_by, "oracle.go::maybeEnqueueAccessProbes")

    def test_missing_top_level_scenarios_key_raises(self):
        with self.assertRaises(SecurityScenarioError):
            self._load("not_scenarios:\n  x: 1\n")

    def test_scenario_missing_required_field_raises(self):
        text = """
scenarios:
  broken_one:
    family: bola
    requires:
      - a
    valid:
      identity: owner
    attack:
      identity: other
    # missing 'confirm'
"""
        with self.assertRaises(SecurityScenarioError):
            self._load(text)

    def test_defaults_applied_for_optional_fields(self):
        text = """
scenarios:
  minimal:
    requires: []
    valid:
      identity: owner
    attack:
      identity: other
    confirm:
      status_in: [200]
"""
        scenarios = self._load(text)
        s = scenarios[0]
        self.assertEqual(s.request_budget, 10)
        self.assertEqual(s.minimization_strategy, "drop-unnecessary-steps")
        self.assertEqual(s.implemented_by, "")
        self.assertEqual(s.family, "")
        self.assertEqual(s.description, "")

    def test_requires_must_be_a_list(self):
        text = """
scenarios:
  broken:
    requires: not-a-list
    valid:
      identity: owner
    attack:
      identity: other
    confirm:
      status_in: [200]
"""
        with self.assertRaises(SecurityScenarioError):
            self._load(text)

    def test_multiple_scenarios_all_loaded(self):
        text = MINIMAL_DOC + """
  second_one:
    requires: []
    valid:
      identity: owner
    attack:
      identity: other
    confirm:
      status_in: [200]
"""
        scenarios = self._load(text)
        self.assertEqual({s.id for s in scenarios}, {"cross_tenant_read", "second_one"})


class GoSymbolExistsTests(unittest.TestCase):
    def test_finds_a_real_symbol(self):
        # maybeEnqueueMassAssignProbe is a real function in oracle.go, added
        # and tested earlier in this same session (Phase 3 #113-117).
        self.assertTrue(_go_symbol_exists("maybeEnqueueMassAssignProbe"))

    def test_does_not_find_a_fabricated_symbol(self):
        self.assertFalse(_go_symbol_exists("thisFunctionDefinitelyDoesNotExistAnywhere12345"))


class VerifyCatalogMatchesImplementationTests(unittest.TestCase):
    def test_real_symbol_reports_no_drift(self):
        s = SecurityScenario(
            id="x", family="bola", description="", requires=[], valid={}, attack={}, confirm={},
            implemented_by="oracle.go::maybeEnqueueMassAssignProbe",
        )
        self.assertEqual(verify_catalog_matches_implementation([s]), [])

    def test_stale_symbol_reports_drift(self):
        s = SecurityScenario(
            id="x", family="bola", description="", requires=[], valid={}, attack={}, confirm={},
            implemented_by="oracle.go::thisFunctionDefinitelyDoesNotExistAnywhere12345",
        )
        problems = verify_catalog_matches_implementation([s])
        self.assertEqual(len(problems), 1)
        self.assertIn("x", problems[0])

    def test_empty_implemented_by_reports_undocumented(self):
        s = SecurityScenario(id="x", family="", description="", requires=[], valid={}, attack={}, confirm={})
        problems = verify_catalog_matches_implementation([s])
        self.assertEqual(len(problems), 1)
        self.assertIn("undocumented", problems[0])

    def test_annotated_implemented_by_still_extracts_bare_symbol(self):
        s = SecurityScenario(
            id="x", family="bola", description="", requires=[], valid={}, attack={}, confirm={},
            implemented_by="oracle.go::maybeEnqueueAccessProbes (oracleKindBOLA)",
        )
        self.assertEqual(verify_catalog_matches_implementation([s]), [])


class RealCatalogFileTests(unittest.TestCase):
    """Exercises the actual security_scenarios.yaml shipped in this repo --
    the single most valuable check here: this file (and the Go symbols it
    references) must never silently drift apart."""

    def test_real_catalog_loads_and_has_no_drift(self):
        path = Path(__file__).resolve().parent / "security_scenarios.yaml"
        if not path.exists():
            self.skipTest("security_scenarios.yaml not present in this checkout")
        scenarios = load_scenarios(path)
        self.assertGreater(len(scenarios), 0)
        problems = verify_catalog_matches_implementation(scenarios)
        self.assertEqual(problems, [], f"security_scenarios.yaml has drifted from the Go implementation: {problems}")

    def test_real_catalog_covers_every_required_family(self):
        path = Path(__file__).resolve().parent / "security_scenarios.yaml"
        if not path.exists():
            self.skipTest("security_scenarios.yaml not present in this checkout")
        scenarios = load_scenarios(path)
        families = {s.family for s in scenarios}
        required = {
            "bola", "tenant_escape", "mass_assignment", "workflow_bypass",
            "stale_object", "optimistic_locking", "idempotency", "races",
            "auth_confusion", "async_workflows",
        }
        missing = required - families
        self.assertEqual(missing, set(), f"security_scenarios.yaml is missing required families: {missing}")


if __name__ == "__main__":
    unittest.main()
