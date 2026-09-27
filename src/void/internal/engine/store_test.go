package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"void/internal/config"
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

func TestDictStoreAllIDLikeValues(t *testing.T) {
	d := &DictStore{
		arrays: map[string][]string{"orderId": {"o-1"}, "email": {"a@example.com"}},
		containers: map[string]map[string][]string{
			"restler_custom_payload": {"userId": {"u-1"}},
		},
	}
	got := d.allIDLikeValues()
	want := map[string]bool{"o-1": true, "u-1": true}
	if len(got) != 2 {
		t.Fatalf("expected 2 id-like values, got %v", got)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected value %q in %v", v, got)
		}
	}
}

func TestDictStoreAllIDLikeValuesNilStoreIsSafe(t *testing.T) {
	var d *DictStore
	if got := d.allIDLikeValues(); got != nil {
		t.Errorf("expected nil from a nil *DictStore, got %v", got)
	}
}

func TestPairKey(t *testing.T) {
	pk, asc, lo, hi := pairKey("orderId", "userId")
	if pk == "" {
		t.Fatal("expected a non-empty pair key")
	}
	if lo >= hi {
		t.Errorf("expected lo < hi lexicographically, got lo=%q hi=%q", lo, hi)
	}
	pkRev, ascRev, loRev, hiRev := pairKey("userId", "orderId")
	if pk != pkRev || lo != loRev || hi != hiRev {
		t.Errorf("expected pairKey to be order-independent, got (%q,%q,%q) vs (%q,%q,%q)", pk, lo, hi, pkRev, loRev, hiRev)
	}
	if asc == ascRev {
		t.Error("expected asc to flip when arguments are swapped")
	}

	if pk, _, _, _ := pairKey("orderId", "orderId"); pk != "" {
		t.Errorf("expected empty pair key for identical canonical keys, got %q", pk)
	}
	if pk, _, _, _ := pairKey("", "userId"); pk != "" {
		t.Errorf("expected empty pair key when one side is empty, got %q", pk)
	}
}

func TestRuntimeStoreAddRelationDedupsAndCaps(t *testing.T) {
	r := newRuntimeStore()
	if !r.addRelation("orderId", "1", "userId", "u1") {
		t.Fatal("expected first relation add to succeed")
	}
	if r.addRelation("orderId", "1", "userId", "u1") {
		t.Error("expected an identical relation to be rejected as a duplicate")
	}
	if r.addRelation("orderId", "null", "userId", "u2") {
		t.Error("expected a non-useful value to be rejected")
	}

	for i := 0; i < maxRuntimeRelationsPerKV+5; i++ {
		r.addRelation("orderId", "v"+strconv.Itoa(i), "userId", "u"+strconv.Itoa(i))
	}
	pk, _, _, _ := pairKey("orderId", "userId")
	if len(r.relations[pk]) > maxRuntimeRelationsPerKV {
		t.Errorf("expected relations capped at %d, got %d", maxRuntimeRelationsPerKV, len(r.relations[pk]))
	}
}

func TestRuntimeStoreAddDepValueAndGetDepValue(t *testing.T) {
	r := newRuntimeStore()
	if got := r.getDepValue("orderId"); got != "" {
		t.Errorf("expected empty string for an unknown dep, got %q", got)
	}
	r.addDepValue("orderId", "abc-123")
	if got := r.getDepValue("orderId"); got != "abc-123" {
		t.Errorf("expected the single stored value back, got %q", got)
	}
	// A non-useful value must not be stored.
	r.addDepValue("orderId2", "")
	if got := r.getDepValue("orderId2"); got != "" {
		t.Errorf("expected empty-string value to be rejected, got %q", got)
	}
}

func TestRuntimeStoreAllIDLikeValues(t *testing.T) {
	r := newRuntimeStore()
	r.addValue("orderId", "o-1")
	r.addValue("email", "a@example.com")
	got := r.allIDLikeValues()
	if len(got) != 1 || got[0] != "o-1" {
		t.Errorf("expected only the id-suffixed key's values, got %v", got)
	}
}

func TestRuntimeStorePickCorrelated(t *testing.T) {
	r := newRuntimeStore()
	if got := r.pickCorrelated([]string{"onlyOneKey"}); got != nil {
		t.Errorf("expected nil with fewer than 2 keys, got %v", got)
	}
	if got := r.pickCorrelated([]string{"orderId", "userId"}); got != nil {
		t.Errorf("expected nil with no recorded relation, got %v", got)
	}
	r.addRelation("orderId", "o-1", "userId", "u-1")
	got := r.pickCorrelated([]string{"orderId", "userId"})
	if got["orderId"] != "o-1" || got["userId"] != "u-1" {
		t.Errorf("expected correlated pair {orderId:o-1, userId:u-1}, got %v", got)
	}
}

func TestRuntimeStoreCustomPayloadCandidates(t *testing.T) {
	r := newRuntimeStore()
	r.addValue("couponCode", "RUNTIME1")
	dict := &DictStore{arrays: map[string][]string{"couponCode": {"DICT1"}}, containers: map[string]map[string][]string{}}
	got := r.customPayloadCandidates("couponCode", dict)
	hasRuntime, hasDict := false, false
	for _, v := range got {
		if v == "RUNTIME1" {
			hasRuntime = true
		}
		if v == "DICT1" {
			hasDict = true
		}
	}
	if !hasRuntime || !hasDict {
		t.Errorf("expected both runtime and dict candidates present, got %v", got)
	}

	r.addValue("orderId", "o-42")
	idCands := r.customPayloadCandidates("orderId", &DictStore{})
	found := false
	for _, v := range idCands {
		if v == "o-42" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the id-suffixed key to pull in allIDLikeValues, got %v", idCands)
	}
}

func TestRuntimeStorePickCustomPayloadValueFallsBackToFuzzedString(t *testing.T) {
	r := newRuntimeStore()
	dict := &DictStore{}
	if got := r.pickCustomPayloadValue("unknownField", dict, ""); got == "" {
		t.Error("expected a non-empty fuzzed fallback value")
	}
	if got := r.pickCustomPayloadValue("unknownField", dict, "literalFallback"); got != "literalFallback" {
		t.Errorf("expected the literal fallback to be used when no candidates exist, got %q", got)
	}
	if got := r.pickCustomPayloadValue("unknownField", dict, "CUSTOM_PAYLOAD"); got == "CUSTOM_PAYLOAD" {
		t.Error("expected the literal placeholder 'CUSTOM_PAYLOAD' to never be returned as-is")
	}
}

func TestRuntimeStorePickCustomPayloadValueUsesCandidate(t *testing.T) {
	r := newRuntimeStore()
	r.addValue("couponCode", "ONLYCAND")
	if got := r.pickCustomPayloadValue("couponCode", &DictStore{}, "fallback"); got != "ONLYCAND" {
		t.Errorf("expected the single candidate to be picked, got %q", got)
	}
}

func TestRuntimeStorePickDynamic(t *testing.T) {
	r := newRuntimeStore()
	r.addDepValue("orderId", "known-dep-value")
	if v, src := r.pickDynamic("orderId", &DictStore{}); v != "known-dep-value" || src != "dep_known" {
		t.Errorf("expected the known dep value to win, got (%q,%q)", v, src)
	}

	r2 := newRuntimeStore()
	r2.addValue("orderId", "inferred-value")
	v, src := r2.pickDynamic("orderId", &DictStore{})
	if v == "" {
		t.Error("expected a non-empty inferred-key candidate")
	}
	if src == "dep_known" || src == "dep_default" {
		t.Errorf("expected an inferred-key source label, got %q", src)
	}

	r3 := newRuntimeStore()
	if v, src := r3.pickDynamic("totallyUnknownDep", &DictStore{}); v != "1" || src != "dep_default" {
		t.Errorf("expected the hardcoded default fallback, got (%q,%q)", v, src)
	}
}

func TestGraphBiasedPayloadCandidates_DisabledGraphIsBasePoolOnly(t *testing.T) {
	f := &Fuzzer{
		runtime: newRuntimeStore(),
		dict:    &DictStore{},
		cfg:     config.Config{ResourceGraphEnabled: false},
	}
	f.runtime.addValue("couponCode", "BASECAND")
	got := f.graphBiasedPayloadCandidates("couponCode")
	if len(got) != 1 || got[0] != "BASECAND" {
		t.Errorf("expected only the base candidate pool when the resource graph is disabled, got %v", got)
	}
}

func TestPickCustomPayloadValueGraphBiased_FallsBackToFuzzedString(t *testing.T) {
	f := &Fuzzer{
		runtime: newRuntimeStore(),
		dict:    &DictStore{},
		cfg:     config.Config{ResourceGraphEnabled: false},
	}
	if got := f.pickCustomPayloadValueGraphBiased("unknownField", ""); got == "" {
		t.Error("expected a non-empty fuzzed fallback value")
	}
}
