"""Tests for the transition-source priority chain's grammar-side passthrough
(docs/ARCHITECTURE_STATEFUL.md §2.3): an operation's x-state-transition
extension and a Roslyn-discovered controller action name, both surfaced onto
the compiled template so void/go/resource_scheduling.go's
deriveTransitionActionForTemplate can consult them ahead of its own
path/method heuristic.

Run with: python3 -m unittest grammarc.test_transition_hints -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .emit_templates import build_template
from .oas import OASParser
from .roslyn_merge import RoslynIndex


def _op_for(spec):
    parser = OASParser(spec)
    return parser.parse()[0], parser


class XStateTransitionEmissionTests(unittest.TestCase):
    def test_x_state_transition_is_passed_through_to_the_template(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/orders/{id}/approve": {
                    "post": {
                        "operationId": "approveOrder",
                        "x-state-transition": {"from": "pending", "to": "approved", "action": "approve"},
                    }
                }
            },
        }
        op, parser = _op_for(spec)
        template = build_template(op, 0, parser, None, None)
        self.assertEqual(
            template["x_state_transition"],
            {"from": "pending", "to": "approved", "action": "approve"},
        )

    def test_absent_extension_omits_the_key_entirely(self):
        spec = {"openapi": "3.0.0", "paths": {"/orders": {"get": {"operationId": "listOrders"}}}}
        op, parser = _op_for(spec)
        template = build_template(op, 0, parser, None, None)
        self.assertNotIn("x_state_transition", template)


class RoslynActionEmissionTests(unittest.TestCase):
    def test_roslyn_action_is_resolved_and_passed_through(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/orders/{id}/approve": {
                    "post": {"operationId": "approveOrder"},
                }
            },
        }
        op, parser = _op_for(spec)
        idx = RoslynIndex({
            "types": {},
            "endpoints": [
                {
                    "controller": "Api.OrdersController",
                    "action": "ApproveOrder",
                    "http_method": "POST",
                    "route_template": "/orders/{id}/approve",
                }
            ],
        })
        template = build_template(op, 0, parser, idx, None)
        self.assertEqual(template["roslyn_action"], "ApproveOrder")

    def test_no_matching_endpoint_omits_the_key(self):
        spec = {"openapi": "3.0.0", "paths": {"/orders": {"get": {"operationId": "listOrders"}}}}
        op, parser = _op_for(spec)
        idx = RoslynIndex({"types": {}, "endpoints": []})
        template = build_template(op, 0, parser, idx, None)
        self.assertNotIn("roslyn_action", template)

    def test_none_roslyn_index_omits_the_key(self):
        spec = {"openapi": "3.0.0", "paths": {"/orders": {"get": {"operationId": "listOrders"}}}}
        op, parser = _op_for(spec)
        template = build_template(op, 0, parser, None, None)
        self.assertNotIn("roslyn_action", template)

    def test_blank_action_name_omits_the_key(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/orders": {"get": {"operationId": "listOrders"}}},
        }
        op, parser = _op_for(spec)
        idx = RoslynIndex({
            "types": {},
            "endpoints": [
                {"controller": "Api.OrdersController", "action": "", "http_method": "GET", "route_template": "/orders"}
            ],
        })
        template = build_template(op, 0, parser, idx, None)
        self.assertNotIn("roslyn_action", template)


if __name__ == "__main__":
    unittest.main()
