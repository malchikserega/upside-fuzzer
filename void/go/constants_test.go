package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConstantsPoolSample verifies sample{String,Int} report ok=false on an empty pool
// and return a loaded value once populated.
func TestConstantsPoolSample(t *testing.T) {
	p := newConstantsPool()
	if _, ok := p.sampleString(); ok {
		t.Error("expected sampleString on empty pool to report ok=false")
	}
	if _, ok := p.sampleInt(); ok {
		t.Error("expected sampleInt on empty pool to report ok=false")
	}
	p.load([]string{"UPSIDEFUZZ_MAGIC"}, []int64{424242})
	if v, ok := p.sampleString(); !ok || v != "UPSIDEFUZZ_MAGIC" {
		t.Errorf("expected sampleString to return %q, got %q ok=%v", "UPSIDEFUZZ_MAGIC", v, ok)
	}
	if v, ok := p.sampleInt(); !ok || v != 424242 {
		t.Errorf("expected sampleInt to return 424242, got %d ok=%v", v, ok)
	}
	strs, ints := p.size()
	if strs != 1 || ints != 1 {
		t.Errorf("expected pool size (1,1), got (%d,%d)", strs, ints)
	}
}

// TestConstantsPoolLoadReplacesNotAppends verifies a second load() call replaces the
// pool contents rather than accumulating -- fetchConstants is a one-shot startup
// fetch, not a repeated poll like CmpLog, so there is no accumulation semantics here.
func TestConstantsPoolLoadReplacesNotAppends(t *testing.T) {
	p := newConstantsPool()
	p.load([]string{"a", "b"}, []int64{1, 2})
	p.load([]string{"c"}, []int64{3})
	strs, ints := p.size()
	if strs != 1 || ints != 1 {
		t.Errorf("expected second load() to replace, not accumulate: got (%d,%d)", strs, ints)
	}
}

// TestFetchConstantsParsesAndCaps verifies fetchConstants decodes the /shm/constants
// JSON shape (strings + decimal-string ints), skips unparseable ints, and enforces
// the max-string-length bound.
func TestFetchConstantsParsesAndCaps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shm/constants" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(constantsResponse{
			Strings: []string{"SUMMER2026", strings.Repeat("x", maxConstantsStrLen+1), ""},
			Ints:    []string{"424242", "not-a-number", "-77"},
		})
	}))
	defer srv.Close()

	pool := newConstantsPool()
	strs, ints, err := fetchConstants(srv.Client(), srv.URL, pool)
	if err != nil {
		t.Fatalf("fetchConstants returned error: %v", err)
	}
	// Oversized and empty strings rejected -> only "SUMMER2026" survives.
	if strs != 1 {
		t.Errorf("expected 1 accepted string, got %d", strs)
	}
	// "not-a-number" skipped, not an error -> 2 valid ints.
	if ints != 2 {
		t.Errorf("expected 2 accepted ints, got %d", ints)
	}
	if v, ok := pool.sampleString(); !ok || v != "SUMMER2026" {
		t.Errorf("expected sampleString %q, got %q ok=%v", "SUMMER2026", v, ok)
	}
}

// TestFetchConstants404IsNotAnError verifies a 404 (target built before this feature
// existed) is treated as "nothing available", not a hard failure.
func TestFetchConstants404IsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pool := newConstantsPool()
	strs, ints, err := fetchConstants(srv.Client(), srv.URL, pool)
	if err != nil {
		t.Fatalf("expected no error on 404, got %v", err)
	}
	if strs != 0 || ints != 0 {
		t.Errorf("expected (0,0) on 404, got (%d,%d)", strs, ints)
	}
}

// TestMutateStringCategorizedUsesConstantsPool verifies a value loaded into the
// global constantsPool can surface through mutateStringCategorized's "mcat_constants"
// category.
func TestMutateStringCategorizedUsesConstantsPool(t *testing.T) {
	constantsPool.resetForTest()
	defer constantsPool.resetForTest()
	constantsPool.load([]string{"HARVESTED_CONST_VALUE"}, nil)

	found := false
	for i := 0; i < 2000; i++ {
		v, cat := mutateStringCategorized("whatever", nil)
		if cat == "mcat_constants" {
			if v != "HARVESTED_CONST_VALUE" {
				t.Fatalf("mcat_constants produced unexpected value %q", v)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mutateStringCategorized to surface a constants-sourced candidate at least once over 2000 attempts")
	}
}

// TestMutateIntUsesConstantsPool verifies a value loaded into the global
// constantsPool is blended into mutateInt's candidate union.
func TestMutateIntUsesConstantsPool(t *testing.T) {
	constantsPool.resetForTest()
	defer constantsPool.resetForTest()
	constantsPool.load(nil, []int64{424242})

	seen := map[string]bool{}
	for i := 0; i < 3000; i++ {
		seen[mutateInt("1", nil)] = true
	}
	if !seen["424242"] {
		t.Errorf("expected mutateInt to surface the constants-harvested value 424242 among outputs, got: %v", seen)
	}
}
