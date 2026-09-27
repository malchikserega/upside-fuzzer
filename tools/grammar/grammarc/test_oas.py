"""Tests for OASParser's core schema resolution and operation parsing (oas.py) --
$ref resolution, allOf/oneOf merging, and Swagger 2.0 vs OpenAPI 3.x parameter
handling. response_schemas coverage (added this session, Top-20+ #23) lives in
test_response_schemas.py; this file covers the rest of the parser.

Run with: python3 -m unittest grammarc.test_oas -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .oas import OASParser, parse_x_state_transition


class ResolveSchemaTests(unittest.TestCase):
    def test_resolves_a_direct_ref(self):
        spec = {
            "openapi": "3.0.0",
            "components": {"schemas": {"Order": {"type": "object", "properties": {"id": {"type": "integer"}}}}},
        }
        parser = OASParser(spec)
        resolved = parser.resolve_schema({"$ref": "#/components/schemas/Order"})
        self.assertEqual(resolved["type"], "object")
        self.assertIn("id", resolved["properties"])

    def test_cyclic_ref_does_not_infinite_loop(self):
        spec = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "Node": {
                        "type": "object",
                        "properties": {"child": {"$ref": "#/components/schemas/Node"}},
                    }
                }
            },
        }
        parser = OASParser(spec)
        # Must terminate (the `seen` set guards against infinite $ref recursion).
        resolved = parser.resolve_schema({"$ref": "#/components/schemas/Node"})
        self.assertEqual(resolved["type"], "object")

    def test_ref_name_extracts_component_short_name(self):
        parser = OASParser({"openapi": "3.0.0"})
        name = parser.ref_name({"$ref": "#/components/schemas/CreateOrderRequest"})
        self.assertEqual(name, "CreateOrderRequest")

    def test_ref_name_none_for_non_ref_schema(self):
        parser = OASParser({"openapi": "3.0.0"})
        self.assertIsNone(parser.ref_name({"type": "string"}))


class CollectSchemaFieldsAllOfTests(unittest.TestCase):
    def test_allof_merges_properties_from_all_branches(self):
        spec = {"openapi": "3.0.0"}
        parser = OASParser(spec)
        schema = {
            "allOf": [
                {"type": "object", "properties": {"id": {"type": "integer"}}},
                {"type": "object", "properties": {"name": {"type": "string"}}},
            ]
        }
        fields = parser._collect_schema_fields(schema)
        names = {f.name for f in fields}
        self.assertEqual(names, {"id", "name"})

    def test_allof_merges_required_from_all_branches(self):
        spec = {"openapi": "3.0.0"}
        parser = OASParser(spec)
        schema = {
            "allOf": [
                {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
                {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
            ]
        }
        fields = parser._collect_schema_fields(schema)
        required = {f.name for f in fields if f.required}
        self.assertEqual(required, {"id", "name"})

    def test_nested_object_property_produces_dotted_path(self):
        spec = {"openapi": "3.0.0"}
        parser = OASParser(spec)
        schema = {
            "type": "object",
            "properties": {
                "shipping": {"type": "object", "properties": {"city": {"type": "string"}}},
            },
        }
        fields = parser._collect_schema_fields(schema)
        names = {f.name for f in fields}
        self.assertIn("shipping", names)
        self.assertIn("shipping.city", names)


class ParseOperationsTests(unittest.TestCase):
    def test_openapi3_path_and_query_params(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/items/{id}": {
                    "get": {
                        "operationId": "getItem",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                            {"name": "expand", "in": "query", "schema": {"type": "boolean"}},
                        ],
                    }
                }
            },
        }
        ops = OASParser(spec).parse()
        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.method, "GET")
        self.assertEqual([p.name for p in op.path_params], ["id"])
        self.assertEqual([p.name for p in op.query_params], ["expand"])

    def test_swagger2_body_parameter_becomes_request_schema(self):
        spec = {
            "swagger": "2.0",
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "parameters": [
                            {
                                "name": "body",
                                "in": "body",
                                "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                            }
                        ],
                    }
                }
            },
        }
        ops = OASParser(spec).parse()
        op = next(o for o in ops if o.operation_id == "createItem")
        self.assertIsNotNone(op.request_schema)
        self.assertIn("name", op.request_schema["properties"])

    def test_openapi3_request_body_prefers_application_json(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "content": {
                                "application/xml": {"schema": {"type": "object"}},
                                "application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}},
                            }
                        },
                    }
                }
            },
        }
        ops = OASParser(spec).parse()
        op = ops[0]
        self.assertEqual(op.request_content_type, "application/json")
        self.assertIn("name", op.request_schema["properties"])

    def test_multipart_form_data_marks_operation_and_collects_fields(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/upload": {
                    "post": {
                        "operationId": "upload",
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"file": {"type": "string", "format": "binary"}},
                                    }
                                }
                            }
                        },
                    }
                }
            },
        }
        ops = OASParser(spec).parse()
        op = ops[0]
        self.assertTrue(op.is_multipart)
        self.assertTrue(any(f.name == "file" for f in op.multipart_fields))

    def test_non_http_method_keys_are_ignored(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/items": {"parameters": [{"name": "x", "in": "query"}], "get": {"operationId": "list"}}},
        }
        ops = OASParser(spec).parse()
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0].operation_id, "list")

    def test_x_state_transition_extension_object_form_is_parsed(self):
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
        op = OASParser(spec).parse()[0]
        self.assertEqual(op.x_state_transition, {"from": "pending", "to": "approved", "action": "approve"})

    def test_x_state_transition_extension_absent_by_default(self):
        spec = {"openapi": "3.0.0", "paths": {"/orders": {"get": {"operationId": "listOrders"}}}}
        op = OASParser(spec).parse()[0]
        self.assertIsNone(op.x_state_transition)


class ParseXStateTransitionTests(unittest.TestCase):
    def test_object_form(self):
        self.assertEqual(
            parse_x_state_transition({"from": "draft", "action": "publish", "to": "published"}),
            {"from": "draft", "action": "publish", "to": "published"},
        )

    def test_string_shorthand(self):
        self.assertEqual(
            parse_x_state_transition("sent->pay->paid"),
            {"from": "sent", "action": "pay", "to": "paid"},
        )

    def test_string_shorthand_with_whitespace(self):
        self.assertEqual(
            parse_x_state_transition(" sent -> pay -> paid "),
            {"from": "sent", "action": "pay", "to": "paid"},
        )

    def test_malformed_string_returns_none(self):
        self.assertIsNone(parse_x_state_transition("not-a-valid-transition"))
        self.assertIsNone(parse_x_state_transition("a->b"))
        self.assertIsNone(parse_x_state_transition("a->->c"))

    def test_none_and_other_types_return_none(self):
        self.assertIsNone(parse_x_state_transition(None))
        self.assertIsNone(parse_x_state_transition(42))
        self.assertIsNone(parse_x_state_transition([]))

    def test_empty_dict_returns_none(self):
        self.assertIsNone(parse_x_state_transition({}))
        self.assertIsNone(parse_x_state_transition({"unrelated_key": "value"}))


if __name__ == "__main__":
    unittest.main()
