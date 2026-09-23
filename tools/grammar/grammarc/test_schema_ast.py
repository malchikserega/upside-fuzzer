"""Tests for the request-body schema AST (schema_ast.py::build_schema_node) --
object/array/scalar/required/nullable/constraints/allOf/oneOf/anyOf/discriminator/
additionalProperties/cycle-safety/property-order fidelity.

Run with: python3 -m unittest grammarc.test_schema_ast -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .dependencies import DependencyPlan
from .oas import OASParser
from .schema_ast import build_schema_node


def _parser(components=None):
    spec = {"openapi": "3.0.0", "paths": {}}
    if components:
        spec["components"] = {"schemas": components}
    return OASParser(spec)


class ScalarNodeTests(unittest.TestCase):
    def test_basic_string_scalar(self):
        node = build_schema_node({"type": "string"}, _parser())
        self.assertEqual(node["node_type"], "scalar")
        self.assertEqual(node["scalar_type"], "string")
        self.assertFalse(node["nullable"])

    def test_constraints_are_carried(self):
        node = build_schema_node(
            {"type": "string", "minLength": 3, "maxLength": 10, "pattern": "^[a-z]+$",
             "enum": ["a", "b", "c"]},
            _parser(),
        )
        self.assertEqual(node["min_length"], 3)
        self.assertEqual(node["max_length"], 10)
        self.assertEqual(node["pattern"], "^[a-z]+$")
        self.assertEqual(node["enum_values"], ["a", "b", "c"])

    def test_numeric_constraints(self):
        node = build_schema_node({"type": "integer", "minimum": 1, "maximum": 100}, _parser())
        self.assertEqual(node["minimum"], 1.0)
        self.assertEqual(node["maximum"], 100.0)

    def test_format_is_carried(self):
        node = build_schema_node({"type": "string", "format": "uuid"}, _parser())
        self.assertEqual(node["format"], "uuid")

    def test_nullable_oas30_style(self):
        node = build_schema_node({"type": "string", "nullable": True}, _parser())
        self.assertTrue(node["nullable"])

    def test_nullable_oas31_type_array_style(self):
        node = build_schema_node({"type": ["string", "null"]}, _parser())
        self.assertTrue(node["nullable"])
        self.assertEqual(node["scalar_type"], "string")

    def test_not_nullable_by_default(self):
        node = build_schema_node({"type": "string"}, _parser())
        self.assertFalse(node["nullable"])

    def test_id_shaped_field_name_gets_payload_key(self):
        node = build_schema_node({"type": "string"}, _parser(), field_name="orderId", depth=1)
        self.assertEqual(node["payload_key"], "orderid")

    def test_non_id_field_name_gets_no_payload_key(self):
        node = build_schema_node({"type": "string"}, _parser(), field_name="description", depth=1)
        self.assertNotIn("payload_key", node)

    def test_dep_plan_override_wins_at_top_level(self):
        dep_plan = DependencyPlan()
        dep_plan.payload_key[0]["fooId"] = "explicit_override_key"
        node = build_schema_node({"type": "string"}, _parser(), dep_plan=dep_plan, op_index=0,
                                  field_name="fooId", depth=1)
        self.assertEqual(node["payload_key"], "explicit_override_key")


class ObjectNodeTests(unittest.TestCase):
    def test_basic_object_with_properties(self):
        schema = {
            "type": "object",
            "properties": {"city": {"type": "string"}, "zip": {"type": "string"}},
            "required": ["city"],
        }
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["node_type"], "object")
        self.assertEqual(set(node["properties"].keys()), {"city", "zip"})
        self.assertEqual(node["required"], ["city"])
        self.assertTrue(node["allow_additional"])

    def test_property_order_is_preserved(self):
        schema = {
            "type": "object",
            "properties": {"zeta": {"type": "string"}, "alpha": {"type": "string"}, "mid": {"type": "string"}},
        }
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["property_order"], ["zeta", "alpha", "mid"])

    def test_nested_object_dotted_path(self):
        schema = {
            "type": "object",
            "properties": {
                "owner": {"type": "object", "properties": {"address": {
                    "type": "object", "properties": {"city": {"type": "string"}},
                }}},
            },
        }
        node = build_schema_node(schema, _parser())
        owner = node["properties"]["owner"]
        address = owner["properties"]["address"]
        city = address["properties"]["city"]
        self.assertEqual(owner["path"], "owner")
        self.assertEqual(address["path"], "owner.address")
        self.assertEqual(city["path"], "owner.address.city")

    def test_required_excludes_names_not_in_properties(self):
        # A "required" entry with no matching property is dropped, not carried as a
        # dangling reference the Go side would have to defensively guard against.
        schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a", "ghost"]}
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["required"], ["a"])

    def test_additional_properties_false(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}
        node = build_schema_node(schema, _parser())
        self.assertFalse(node["allow_additional"])
        self.assertNotIn("additional_properties", node)

    def test_additional_properties_schema(self):
        schema = {
            "type": "object", "properties": {"a": {"type": "string"}},
            "additionalProperties": {"type": "integer"},
        }
        node = build_schema_node(schema, _parser())
        self.assertTrue(node["allow_additional"])
        self.assertEqual(node["additional_properties"]["scalar_type"], "integer")

    def test_additional_properties_default_true(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}}}
        node = build_schema_node(schema, _parser())
        self.assertTrue(node["allow_additional"])
        self.assertNotIn("additional_properties", node)

    def test_implicit_object_type_from_properties_alone(self):
        # No explicit "type": "object" -- properties alone imply it (real specs
        # sometimes omit "type" for objects; oas.py's own flattening handles this too).
        node = build_schema_node({"properties": {"a": {"type": "string"}}}, _parser())
        self.assertEqual(node["node_type"], "object")


class ArrayNodeTests(unittest.TestCase):
    def test_array_of_scalars(self):
        node = build_schema_node({"type": "array", "items": {"type": "string"}}, _parser())
        self.assertEqual(node["node_type"], "array")
        self.assertEqual(node["items"]["node_type"], "scalar")

    def test_array_of_objects(self):
        schema = {"type": "array", "items": {
            "type": "object", "properties": {"sku": {"type": "string"}, "qty": {"type": "integer"}},
        }}
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["items"]["node_type"], "object")
        self.assertEqual(set(node["items"]["properties"].keys()), {"sku", "qty"})

    def test_min_max_items(self):
        node = build_schema_node({"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 5}, _parser())
        self.assertEqual(node["min_items"], 1)
        self.assertEqual(node["max_items"], 5)

    def test_unique_items(self):
        node = build_schema_node({"type": "array", "items": {"type": "string"}, "uniqueItems": True}, _parser())
        self.assertTrue(node["unique_items"])

    def test_array_with_no_items_schema_has_none_items_node(self):
        node = build_schema_node({"type": "array"}, _parser())
        self.assertIsNone(node["items"])


class AllOfMergeTests(unittest.TestCase):
    def test_allof_merges_into_one_object(self):
        schema = {"allOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]},
            {"type": "object", "properties": {"b": {"type": "integer"}}, "required": ["b"]},
        ]}
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["node_type"], "object")
        self.assertEqual(set(node["properties"].keys()), {"a", "b"})
        self.assertEqual(set(node["required"]), {"a", "b"})

    def test_allof_with_ref_components(self):
        components = {
            "Base": {"type": "object", "properties": {"id": {"type": "string"}}},
            "Extra": {"type": "object", "properties": {"name": {"type": "string"}}},
        }
        schema = {"allOf": [{"$ref": "#/components/schemas/Base"}, {"$ref": "#/components/schemas/Extra"}]}
        node = build_schema_node(schema, _parser(components))
        self.assertEqual(set(node["properties"].keys()), {"id", "name"})


class OneOfAnyOfTests(unittest.TestCase):
    def test_oneof_keeps_variants_independent_not_merged(self):
        # The bug this module fixes: oneOf variants must stay separate subtrees, not
        # get blindly combined into one object the way body_serializer.py's flat path
        # (left untouched) still does.
        schema = {"oneOf": [
            {"type": "object", "properties": {"cardNumber": {"type": "string"}}},
            {"type": "object", "properties": {"walletId": {"type": "string"}}},
        ]}
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["node_type"], "oneOf")
        self.assertEqual(len(node["variants"]), 2)
        self.assertEqual(set(node["variants"][0]["properties"].keys()), {"cardNumber"})
        self.assertEqual(set(node["variants"][1]["properties"].keys()), {"walletId"})

    def test_anyof_produces_anyof_node_type(self):
        schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        node = build_schema_node(schema, _parser())
        self.assertEqual(node["node_type"], "anyOf")
        self.assertEqual(len(node["variants"]), 2)

    def test_oneof_with_explicit_discriminator_mapping(self):
        components = {
            "CardPayment": {"type": "object", "properties": {"cardNumber": {"type": "string"}}},
            "WalletPayment": {"type": "object", "properties": {"walletId": {"type": "string"}}},
        }
        schema = {
            "oneOf": [
                {"$ref": "#/components/schemas/CardPayment"},
                {"$ref": "#/components/schemas/WalletPayment"},
            ],
            "discriminator": {
                "propertyName": "type",
                "mapping": {"card": "#/components/schemas/CardPayment", "wallet": "#/components/schemas/WalletPayment"},
            },
        }
        node = build_schema_node(schema, _parser(components))
        self.assertEqual(node["discriminator"]["property_name"], "type")
        self.assertEqual(node["discriminator"]["mapping"], {"card": 0, "wallet": 1})

    def test_oneof_with_implicit_discriminator_mapping(self):
        components = {
            "CardPayment": {"type": "object", "properties": {"cardNumber": {"type": "string"}}},
            "WalletPayment": {"type": "object", "properties": {"walletId": {"type": "string"}}},
        }
        schema = {
            "oneOf": [
                {"$ref": "#/components/schemas/CardPayment"},
                {"$ref": "#/components/schemas/WalletPayment"},
            ],
            "discriminator": {"propertyName": "type"},
        }
        node = build_schema_node(schema, _parser(components))
        self.assertEqual(node["discriminator"]["property_name"], "type")
        self.assertEqual(node["discriminator"]["mapping"], {"CardPayment": 0, "WalletPayment": 1})

    def test_no_discriminator_key_when_schema_declares_none(self):
        schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
        node = build_schema_node(schema, _parser())
        self.assertNotIn("discriminator", node)


class CycleAndDepthSafetyTests(unittest.TestCase):
    def test_self_referential_ref_degrades_to_scalar_leaf_not_infinite_recursion(self):
        components = {
            "Employee": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "manager": {"$ref": "#/components/schemas/Employee"},
                },
            },
        }
        schema = {"$ref": "#/components/schemas/Employee"}
        node = build_schema_node(schema, _parser(components))
        self.assertEqual(node["node_type"], "object")
        manager = node["properties"]["manager"]
        self.assertEqual(manager["node_type"], "scalar")

    def test_deeply_inlined_non_ref_recursion_hits_depth_cap_not_recursion_error(self):
        # Build a schema nested deeper than _MAX_SCHEMA_DEPTH with no $ref anywhere,
        # so only the raw depth cap (not the $ref-cycle guard) can stop it.
        node_schema = {"type": "string"}
        for _ in range(20):
            node_schema = {"type": "object", "properties": {"next": node_schema}}
        node = build_schema_node(node_schema, _parser())  # must not raise RecursionError
        self.assertEqual(node["node_type"], "object")


class MissingBodyTests(unittest.TestCase):
    def test_non_dict_schema_returns_none(self):
        self.assertIsNone(build_schema_node(None, _parser()))
        self.assertIsNone(build_schema_node("not a schema", _parser()))

    def test_unresolvable_ref_returns_none(self):
        node = build_schema_node({"$ref": "#/components/schemas/DoesNotExist"}, _parser())
        self.assertIsNone(node)


if __name__ == "__main__":
    unittest.main()
