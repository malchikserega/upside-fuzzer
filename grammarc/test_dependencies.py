"""Tests for producer/consumer dependency inference (dependencies.py).

Run with: python3 -m unittest grammarc.test_dependencies -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .dependencies import infer
from .oas import Operation, ParamHint


class InferDependenciesTests(unittest.TestCase):
    def test_post_to_collection_root_is_a_producer(self):
        ops = [
            Operation(
                method="POST", path="/api/catalog-items", operation_id="create",
                request_schema={"type": "object", "properties": {"name": {"type": "string"}}},
            ),
        ]
        plan = infer(ops)
        self.assertIn("catalogitemid", plan.writes[0])

    def test_action_endpoint_at_collection_shaped_path_is_not_a_false_producer(self):
        # /api/authenticate has no trailing {param} (same shape as a collection root)
        # but "authenticate" doesn't singularize to something different -- it's an
        # RPC-style action endpoint, not a REST collection, and must not be
        # mistaken for one (this is exactly what _is_plural_collection_segment guards).
        ops = [
            Operation(method="POST", path="/api/authenticate", operation_id="auth"),
        ]
        plan = infer(ops)
        self.assertEqual(plan.writes[0], [])

    def test_path_param_and_bare_id_body_field_resolve_to_same_payload_key(self):
        # The concrete pipeline regression this module exists for: PUT's body "id"
        # field and GET/DELETE's path param "catalogItemId" must both resolve to the
        # identical payload_key "catalogitemid" so void/go/store.go's runtime
        # correlation can actually connect them across requests.
        ops = [
            Operation(
                method="PUT", path="/api/catalog-items/{catalogItemId}", operation_id="update",
                path_params=[ParamHint(name="catalogItemId", type_name="integer", location="path")],
                request_schema={"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}},
            ),
            Operation(
                method="GET", path="/api/catalog-items/{catalogItemId}", operation_id="get",
                path_params=[ParamHint(name="catalogItemId", type_name="integer", location="path")],
            ),
        ]
        plan = infer(ops)
        put_body_key = plan.payload_key[0]["id"]
        put_path_key = plan.payload_key[0]["catalogItemId"]
        get_path_key = plan.payload_key[1]["catalogItemId"]
        self.assertEqual(put_body_key, "catalogitemid")
        self.assertEqual(put_path_key, "catalogitemid")
        self.assertEqual(get_path_key, "catalogitemid")

    def test_path_params_are_always_reads(self):
        ops = [
            Operation(
                method="DELETE", path="/api/orders/{orderId}", operation_id="delete",
                path_params=[ParamHint(name="orderId", type_name="integer", location="path")],
            ),
        ]
        plan = infer(ops)
        self.assertIn("orderid", plan.reads[0])

    def test_compound_foreign_key_field_correlates_with_its_own_resources_producer(self):
        # catalog-items' "catalogBrandId" body field must key the same as
        # catalog-brands' own bare-id producer key, giving free cross-resource
        # foreign-key correlation.
        ops = [
            Operation(
                method="POST", path="/api/catalog-brands", operation_id="createBrand",
                request_schema={"type": "object", "properties": {"name": {"type": "string"}}},
            ),
            Operation(
                method="POST", path="/api/catalog-items", operation_id="createItem",
                request_schema={"type": "object", "properties": {"catalogBrandId": {"type": "integer"}}},
            ),
        ]
        plan = infer(ops)
        self.assertIn("catalogbrandid", plan.writes[0])
        self.assertEqual(plan.payload_key[1]["catalogBrandId"], "catalogbrandid")
        self.assertIn("catalogbrandid", plan.reads[1])

    def test_non_id_body_fields_get_no_payload_key_override(self):
        # Only id-shaped fields get an override -- free-text fields must fall through
        # to body_serializer.py's own is_dictionary_worthy() judgment, not be forced
        # into a thin custom_payload pool just because *some* override map exists.
        ops = [
            Operation(
                method="POST", path="/api/catalog-items", operation_id="create",
                request_schema={"type": "object", "properties": {"description": {"type": "string"}}},
            ),
        ]
        plan = infer(ops)
        self.assertNotIn("description", plan.payload_key[0])


if __name__ == "__main__":
    unittest.main()
