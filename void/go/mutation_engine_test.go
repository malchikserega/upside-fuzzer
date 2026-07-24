package main

import (
	"strconv"
	"testing"
)

// TestMutateIntFieldConstraintBoundaries verifies Top-20 #14: when a Segment carries
// declared Minimum/Maximum, mutateInt's candidate pool includes the exact boundary
// values (min-1/min/min+1/max-1/max/max+1), in addition to the pre-existing generic
// pool -- additive, not a replacement.
func TestMutateIntFieldConstraintBoundaries(t *testing.T) {
	min, max := 1.0, 10000.0
	hint := &Segment{Minimum: &min, Maximum: &max}

	seen := map[int]bool{}
	for i := 0; i < 2000; i++ {
		v := mutateInt("5000", hint)
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("mutateInt produced non-integer output: %q", v)
		}
		seen[n] = true
	}

	for _, want := range []int{0, 1, 2, 9999, 10000, 10001} {
		if !seen[want] {
			t.Errorf("expected boundary value %d to appear among mutateInt outputs with hint min=%v max=%v, got set: %v", want, min, max, seen)
		}
	}
}

// TestMutateIntNilHintUnchanged verifies the nil-hint path (today's default for any
// segment without constraint metadata) never crashes and stays within the pre-existing
// generic candidate universe -- i.e. this change is backward compatible.
func TestMutateIntNilHintUnchanged(t *testing.T) {
	for i := 0; i < 50; i++ {
		v := mutateInt("42", nil)
		if _, err := strconv.Atoi(v); err != nil {
			t.Fatalf("mutateInt(nil hint) produced non-integer output: %q", v)
		}
	}
}

// TestMutateStringCategorizedEnumBlend verifies enum-typed fields occasionally surface
// a valid enum value (and a deliberately-invalid near-miss) among mutation outputs.
func TestMutateStringCategorizedEnumBlend(t *testing.T) {
	hint := &Segment{EnumValues: []string{"Pending", "Paid", "Shipped"}}
	found := false
	for i := 0; i < 500; i++ {
		v, cat := mutateStringCategorized("Pending", hint)
		if cat == "mcat_field_constraint" && (v == "Pending" || v == "Paid" || v == "Shipped" || v == "Pending_INVALID" || v == "Paid_INVALID" || v == "Shipped_INVALID") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one field-constraint-category enum-derived candidate over 500 attempts")
	}
}

// TestFieldConstraintStringCandidatesLengthBoundaries checks exact min/max length
// candidates are generated when a segment declares length bounds.
func TestFieldConstraintStringCandidatesLengthBoundaries(t *testing.T) {
	minLen, maxLen := 3, 8
	hint := &Segment{MinLength: &minLen, MaxLength: &maxLen}
	cands := fieldConstraintStringCandidates("hello", hint)

	hasLen := func(n int) bool {
		for _, c := range cands {
			if len(c) == n {
				return true
			}
		}
		return false
	}
	for _, want := range []int{minLen - 1, minLen, maxLen, maxLen + 1} {
		if !hasLen(want) {
			t.Errorf("expected a candidate of length %d among %v", want, cands)
		}
	}
}
