"""Integration test for typed structural mutation (Stage 8): proves
build_template() emits the new body_schema field and the legacy segments[]
list TOGETHER, from one real build_template() call against a single spec
exercising every schema shape requirement #10 names -- nested object,
array-of-objects, oneOf+discriminator, and an id-shaped field -- not two
independently hand-authored halves.

Run with: python3 -m unittest grammarc.test_typed_body_integration -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .emit_templates import build_template
from .oas import OASParser


def _order_spec():
    return {
        "openapi": "3.0.3",
        "paths": {
            "/orgs/{orgId}/orders": {
                "post": {
                    "operationId": "createOrder",
                    "parameters": [
                        {"name": "orgId", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/OrderCreate"},
                            }
                        },
                    },
                    "responses": {"201": {"description": "created"}},
                }
            }
        },
        "components": {
            "schemas": {
                "OrderCreate": {
                    "type": "object",
                    "required": ["customerId", "items", "payment"],
                    "properties": {
                        "customerId": {"type": "string"},
                        "shipping": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                        },
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "properties": {"sku": {"type": "string"}},
                            },
                        },
                        "payment": {
                            "oneOf": [
                                {"$ref": "#/components/schemas/CardPayment"},
                                {"$ref": "#/components/schemas/WalletPayment"},
                            ],
                            "discriminator": {
                                "propertyName": "type",
                                "mapping": {
                                    "card": "#/components/schemas/CardPayment",
                                    "wallet": "#/components/schemas/WalletPayment",
                                },
                            },
                        },
                    },
                },
                "CardPayment": {
                    "type": "object",
                    "required": ["type"],
                    "properties": {"type": {"type": "string", "enum": ["card"]}, "cardNumber": {"type": "string"}},
                },
                "WalletPayment": {
                    "type": "object",
                    "required": ["type"],
                    "properties": {"type": {"type": "string", "enum": ["wallet"]}, "walletId": {"type": "string"}},
                },
            }
        },
    }


class TypedBodyIntegrationTests(unittest.TestCase):
    def setUp(self):
        parser = OASParser(_order_spec())
        self.op = parser.parse()[0]
        self.template = build_template(self.op, 0, parser, None, None)

    def test_legacy_segments_are_still_emitted_unconditionally(self):
        # Backward compatibility, concretely: the new body_schema field must be
        # ADDITIVE, never a replacement -- a renderer that only knows about
        # segments[] (every renderer before this feature) must see exactly
        # what it always has.
        self.assertIn("segments", self.template)
        self.assertTrue(len(self.template["segments"]) > 0)
        kinds = {seg.get("kind") for seg in self.template["segments"]}
        self.assertTrue(kinds & {"static", "fuzzable", "custom_payload"})

    def test_body_schema_is_present_alongside_segments(self):
        self.assertIn("body_schema", self.template)
        schema = self.template["body_schema"]
        self.assertEqual(schema["node_type"], "object")
        self.assertEqual(set(schema["properties"]), {"customerId", "shipping", "items", "payment"})

    def test_id_shaped_field_gets_a_payload_key(self):
        schema = self.template["body_schema"]
        self.assertEqual(schema["properties"]["customerId"]["payload_key"], "customerid")

    def test_nested_object_field_has_dotted_path(self):
        schema = self.template["body_schema"]
        shipping = schema["properties"]["shipping"]
        self.assertEqual(shipping["node_type"], "object")
        self.assertEqual(shipping["properties"]["city"]["path"], "shipping.city")

    def test_array_of_objects_field_shape(self):
        schema = self.template["body_schema"]
        items = schema["properties"]["items"]
        self.assertEqual(items["node_type"], "array")
        self.assertEqual(items["min_items"], 1)
        self.assertEqual(items["items"]["node_type"], "object")
        self.assertIn("sku", items["items"]["properties"])

    def test_oneof_discriminator_keeps_variants_independent(self):
        schema = self.template["body_schema"]
        payment = schema["properties"]["payment"]
        self.assertEqual(payment["node_type"], "oneOf")
        self.assertEqual(len(payment["variants"]), 2)
        # The bug this fixes (schema_ast.py's own docstring): the legacy
        # flat path blindly .update()s oneOf alternatives together, but here
        # each variant keeps ONLY its own declared properties.
        variant_props = [set(v["properties"]) for v in payment["variants"]]
        self.assertIn({"type", "cardNumber"}, variant_props)
        self.assertIn({"type", "walletId"}, variant_props)
        self.assertEqual(payment["discriminator"]["property_name"], "type")
        self.assertEqual(len(payment["discriminator"]["mapping"]), 2)

    def test_required_list_matches_declared_required(self):
        schema = self.template["body_schema"]
        self.assertEqual(set(schema["required"]), {"customerId", "items", "payment"})


if __name__ == "__main__":
    unittest.main()
