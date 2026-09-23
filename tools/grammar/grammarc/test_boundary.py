"""Tests for boundary-value synthesis (boundary.py) -- the same boundary-value
candidate logic void/go/mutation_engine.go's mutateInt/mutateStringCategorized mirror
on the Go side (Top-20 #14). A divergence here would silently desync the dict-based
candidate pool from the direct-mutation boundary candidates.

Run with: python3 -m unittest grammarc.test_boundary -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .boundary import is_dictionary_worthy, values_from_constraints
from .oas import FieldHint


class ValuesFromConstraintsTests(unittest.TestCase):
    def test_integer_with_range_emits_boundary_values(self):
        f = FieldHint(name="quantity", type_name="integer", minimum=1, maximum=100)
        values = values_from_constraints(f)
        self.assertIn("0", values)   # minimum - 1
        self.assertIn("1", values)   # minimum
        self.assertIn("100", values)  # maximum
        self.assertIn("101", values)  # maximum + 1

    def test_integer_with_no_range_falls_back_to_generic_candidates(self):
        f = FieldHint(name="count", type_name="integer")
        values = values_from_constraints(f)
        for expected in ("0", "1", "-1", "10"):
            self.assertIn(expected, values)

    def test_string_with_length_constraints_emits_boundary_lengths(self):
        f = FieldHint(name="name", type_name="string", min_length=2, max_length=5)
        values = values_from_constraints(f)
        self.assertIn("aa", values)      # min_length repeated
        self.assertIn("bbbbb", values)   # max_length repeated
        self.assertIn("cccccc", values)  # max_length + 1

    def test_string_pattern_included_as_a_candidate(self):
        f = FieldHint(name="code", type_name="string", pattern=r"^[A-Z]{3}\d{3}$")
        values = values_from_constraints(f)
        self.assertIn(r"^[A-Z]{3}\d{3}$", values)

    def test_boolean_emits_true_and_false(self):
        f = FieldHint(name="active", type_name="boolean")
        values = values_from_constraints(f)
        self.assertEqual(set(values), {"true", "false"})

    def test_uuid_format_emits_real_and_nil_uuid(self):
        f = FieldHint(name="id", type_name="string", fmt="uuid")
        values = values_from_constraints(f)
        self.assertIn("00000000-0000-0000-0000-000000000000", values)

    def test_email_format_emits_canned_addresses(self):
        f = FieldHint(name="contact", type_name="string", fmt="email")
        values = values_from_constraints(f)
        self.assertTrue(any("@" in v for v in values))

    def test_id_shaped_name_adds_default_id_values(self):
        f = FieldHint(name="userId", type_name="integer")
        values = values_from_constraints(f)
        # looks_like_id_name("userId") should be True, contributing default_id_values.
        self.assertGreater(len(values), 4)  # more than just the generic 0/1/-1/10 set

    def test_enum_values_are_always_included(self):
        f = FieldHint(name="status", type_name="string", enum_values=["Active", "Inactive"])
        values = values_from_constraints(f)
        self.assertIn("Active", values)
        self.assertIn("Inactive", values)

    def test_output_has_no_duplicates_or_empty_strings(self):
        f = FieldHint(name="quantity", type_name="integer", minimum=1, maximum=1)
        values = values_from_constraints(f)
        self.assertEqual(len(values), len(set(values)))
        self.assertNotIn("", values)


class IsDictionaryWorthyTests(unittest.TestCase):
    def test_plain_unconstrained_field_is_not_worthy(self):
        f = FieldHint(name="notes", type_name="string")
        self.assertFalse(is_dictionary_worthy(f))

    def test_enum_field_is_worthy(self):
        f = FieldHint(name="status", type_name="string", enum_values=["A", "B"])
        self.assertTrue(is_dictionary_worthy(f))

    def test_length_constrained_field_is_worthy(self):
        f = FieldHint(name="name", type_name="string", max_length=50)
        self.assertTrue(is_dictionary_worthy(f))

    def test_id_shaped_name_is_worthy(self):
        f = FieldHint(name="orderId", type_name="integer")
        self.assertTrue(is_dictionary_worthy(f))

    def test_generic_numeric_precision_format_is_not_worthy(self):
        # int32/int64/double/float are deliberately excluded -- routing nearly every
        # numeric field into a thin custom_payload pool would be a real loss of
        # mutation diversity, not a gain (see the function's own docstring).
        f = FieldHint(name="amount", type_name="number", fmt="double")
        self.assertFalse(is_dictionary_worthy(f))

    def test_meaningful_format_is_worthy(self):
        f = FieldHint(name="createdAt", type_name="string", fmt="date-time")
        self.assertTrue(is_dictionary_worthy(f))


if __name__ == "__main__":
    unittest.main()
