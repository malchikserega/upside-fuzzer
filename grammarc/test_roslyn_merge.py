"""Tests for roslyn_merge.py -- merging dotnet/analyzer/'s real, type/property-scoped C#
validation constraints into OAS-derived FieldHints, with Roslyn winning per-field.

Run with: python3 -m unittest grammarc.test_roslyn_merge -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .oas import FieldHint, Operation
from .roslyn_merge import RoslynIndex, merge_operation_fields


class MergeOperationFieldsTests(unittest.TestCase):
    def test_no_index_returns_fields_unchanged(self):
        fields = {"name": FieldHint(name="name", type_name="string")}
        out = merge_operation_fields(Operation(method="POST", path="/items", operation_id="x"), None, fields)
        self.assertIs(out, fields)

    def test_no_matching_roslyn_type_returns_fields_unchanged(self):
        idx = RoslynIndex({"types": {}, "endpoints": []})
        fields = {"name": FieldHint(name="name", type_name="string")}
        op = Operation(method="POST", path="/items", operation_id="x")
        out = merge_operation_fields(op, idx, fields)
        self.assertEqual(out, fields)

    def test_length_bounds_take_the_tighter_of_both_sources(self):
        idx = RoslynIndex({
            "types": {
                "MyApp.CreateItemRequest": {
                    "namespace": "MyApp", "name": "CreateItemRequest",
                    "properties": {"Name": {"min_length": 3, "max_length": 20}},
                }
            },
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "CreateItemRequest"
        # OAS says [1, 50]; Roslyn says [3, 20] -- merged must be the TIGHTER bound on
        # each side: max(1,3)=3, min(50,20)=20.
        fields = {"name": FieldHint(name="name", type_name="string", min_length=1, max_length=50)}
        out = merge_operation_fields(op, idx, fields)
        self.assertEqual(out["name"].min_length, 3)
        self.assertEqual(out["name"].max_length, 20)

    def test_roslyn_pattern_overrides_oas_pattern_outright(self):
        idx = RoslynIndex({
            "types": {"MyApp.Dto": {"namespace": "MyApp", "name": "Dto", "properties": {"Code": {"pattern": r"^[A-Z]{3}$"}}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "Dto"
        fields = {"code": FieldHint(name="code", type_name="string", pattern="oas-pattern")}
        out = merge_operation_fields(op, idx, fields)
        self.assertEqual(out["code"].pattern, r"^[A-Z]{3}$")

    def test_enum_values_are_unioned_and_deduped(self):
        idx = RoslynIndex({
            "types": {"MyApp.Dto": {"namespace": "MyApp", "name": "Dto", "properties": {"Status": {"enum_values": ["B", "C"]}}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "Dto"
        fields = {"status": FieldHint(name="status", type_name="string", enum_values=["A", "B"])}
        out = merge_operation_fields(op, idx, fields)
        self.assertEqual(list(dict.fromkeys(out["status"].enum_values)), ["A", "B", "C"])

    def test_required_is_ored_not_overwritten(self):
        idx = RoslynIndex({
            "types": {"MyApp.Dto": {"namespace": "MyApp", "name": "Dto", "properties": {"Name": {"required": True}}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "Dto"
        fields = {"name": FieldHint(name="name", type_name="string", required=False)}
        out = merge_operation_fields(op, idx, fields)
        self.assertTrue(out["name"].required)

    def test_property_matching_is_case_insensitive(self):
        # JSON key "name" (camelCase) must match C# property "Name" (PascalCase).
        idx = RoslynIndex({
            "types": {"MyApp.Dto": {"namespace": "MyApp", "name": "Dto", "properties": {"Name": {"max_length": 10}}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "Dto"
        fields = {"name": FieldHint(name="name", type_name="string")}
        out = merge_operation_fields(op, idx, fields)
        self.assertEqual(out["name"].max_length, 10)

    def test_field_with_no_roslyn_counterpart_is_left_untouched(self):
        idx = RoslynIndex({
            "types": {"MyApp.Dto": {"namespace": "MyApp", "name": "Dto", "properties": {"Name": {"max_length": 10}}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/items", operation_id="create")
        op.request_schema_ref_name = "Dto"
        fields = {"description": FieldHint(name="description", type_name="string")}
        out = merge_operation_fields(op, idx, fields)
        self.assertIsNone(out["description"].max_length)


class RoslynIndexTypeResolutionTests(unittest.TestCase):
    def test_schema_name_match_is_the_primary_strategy(self):
        idx = RoslynIndex({
            "types": {"Microsoft.eShopWeb.PublicApi.CreateCatalogItemRequest": {"namespace": "Microsoft.eShopWeb.PublicApi", "name": "CreateCatalogItemRequest", "properties": {}}},
            "endpoints": [],
        })
        op = Operation(method="POST", path="/api/catalog-items", operation_id="create")
        op.request_schema_ref_name = "CreateCatalogItemRequest"
        t = idx.type_for_operation(op)
        self.assertIsNotNone(t)
        self.assertEqual(t["name"], "CreateCatalogItemRequest")

    def test_ambiguous_short_name_disambiguated_by_endpoint_referencing_namespace(self):
        # Two unrelated types share the short name "CreateCatalogItemRequest" across
        # namespaces (the exact eShopOnWeb scenario this module's own docstring
        # describes) -- must resolve to the one actually referenced by an endpoint
        # whose controller namespace matches, not an arbitrary first candidate.
        idx = RoslynIndex({
            "types": {
                "BlazorShared.Models.CreateCatalogItemRequest": {
                    "namespace": "BlazorShared.Models", "name": "CreateCatalogItemRequest", "properties": {"Name": {"max_length": 5}},
                },
                "Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints.CreateCatalogItemRequest": {
                    "namespace": "Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints", "name": "CreateCatalogItemRequest", "properties": {"Name": {"max_length": 99}},
                },
            },
            "endpoints": [
                {
                    "http_method": "POST", "route_template": "api/catalog-items",
                    "controller": "Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints.CreateCatalogItemEndpoint",
                    "parameter_types": {"request": "CreateCatalogItemRequest"},
                }
            ],
        })
        op = Operation(method="POST", path="/api/catalog-items", operation_id="create")
        # No direct $ref name -- forces the route+method fallback match path.
        t = idx.type_for_operation(op)
        self.assertIsNotNone(t)
        self.assertEqual(t["namespace"], "Microsoft.eShopWeb.PublicApi.CatalogItemEndpoints")
        self.assertEqual(t["properties"]["Name"]["max_length"], 99)

    def test_route_normalization_ignores_parameter_names_and_type_constraints(self):
        # OAS "{id}" vs ASP.NET "{id:int}" must normalize to the same route key.
        idx = RoslynIndex({
            "types": {},
            "endpoints": [{"http_method": "GET", "route_template": "api/items/{id:int}", "parameter_types": {}}],
        })
        op = Operation(method="GET", path="/api/items/{id}", operation_id="get")
        ep = idx.endpoint_for_operation(op)
        self.assertIsNotNone(ep)


if __name__ == "__main__":
    unittest.main()
