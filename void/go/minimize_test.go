package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestMinimizeQueryPartDropsOnlyNonEssentialParams verifies the greedy field-removal
// loop keeps a param removed only when the crash (simulated via trySet) still
// reproduces without it, and restores/keeps essential params.
func TestMinimizeQueryPartDropsOnlyNonEssentialParams(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{Path: "/items?a=1&b=2&c=3"}

	// Crash only reproduces while b=2 is present -- a and c are noise.
	trySet := func(cand WorkItem) bool {
		u, err := url.Parse(cand.Path)
		if err != nil {
			return false
		}
		return u.Query().Get("b") == "2"
	}

	got := f.minimizeQueryPart(item, trySet)

	u, err := url.Parse(got.Path)
	if err != nil {
		t.Fatalf("minimized path did not parse: %v", err)
	}
	q := u.Query()
	if q.Get("b") != "2" {
		t.Errorf("expected essential param b=2 to survive minimization, got path %q", got.Path)
	}
	if q.Has("a") || q.Has("c") {
		t.Errorf("expected non-essential params a/c to be stripped, got path %q", got.Path)
	}
}

func TestMinimizeQueryPartNoQueryStringIsANoOp(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{Path: "/items"}
	called := false
	got := f.minimizeQueryPart(item, func(WorkItem) bool { called = true; return true })
	if called {
		t.Error("expected trySet never called when the path has no query string")
	}
	if got.Path != "/items" {
		t.Errorf("expected path unchanged, got %q", got.Path)
	}
}

func TestMinimizeFormBodyDropsOnlyNonEssentialFields(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    "a=1&b=2&c=3",
	}
	trySet := func(cand WorkItem) bool {
		vals, err := url.ParseQuery(cand.Body)
		if err != nil {
			return false
		}
		return vals.Get("b") == "2"
	}

	got := f.minimizeFormBody(item, trySet)

	vals, err := url.ParseQuery(got.Body)
	if err != nil {
		t.Fatalf("minimized body did not parse: %v", err)
	}
	if vals.Get("b") != "2" {
		t.Errorf("expected essential field b=2 to survive, got body %q", got.Body)
	}
	if vals.Has("a") || vals.Has("c") {
		t.Errorf("expected non-essential fields a/c to be stripped, got body %q", got.Body)
	}
}

func TestMinimizeFormBodyIgnoresNonFormContentType(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"a":1}`,
	}
	called := false
	got := f.minimizeFormBody(item, func(WorkItem) bool { called = true; return true })
	if called {
		t.Error("expected trySet never called for a non-form-urlencoded content type")
	}
	if got.Body != `{"a":1}` {
		t.Errorf("expected body unchanged, got %q", got.Body)
	}
}

func TestMinimizeJSONBodyDropsOnlyNonEssentialKeys(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"a":1,"b":2,"c":3}`,
	}
	trySet := func(cand WorkItem) bool {
		var obj map[string]any
		if err := json.Unmarshal([]byte(cand.Body), &obj); err != nil {
			return false
		}
		v, ok := obj["b"]
		return ok && v == float64(2)
	}

	got := f.minimizeJSONBody(item, trySet)

	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	if len(obj) != 1 {
		t.Errorf("expected exactly the essential key to remain, got %v", obj)
	}
	if v, ok := obj["b"]; !ok || v != float64(2) {
		t.Errorf("expected essential key b=2 to survive minimization, got %v", obj)
	}
}

func TestMinimizePathSegmentsReplacesOnlyDynamicSegmentsAndKeepsEssentialValue(t *testing.T) {
	f := &Fuzzer{}
	// "12345" (index 1) is non-essential noise; "67890" (index 3) is essential --
	// the crash only reproduces while it's present.
	item := WorkItem{Path: "/items/12345/orders/67890"}
	trySet := func(cand WorkItem) bool {
		return strings.Contains(cand.Path, "67890")
	}

	got := f.minimizePathSegments(item, trySet)

	if !strings.Contains(got.Path, "67890") {
		t.Errorf("expected the essential segment 67890 to survive minimization, got %q", got.Path)
	}
	if strings.Contains(got.Path, "12345") {
		t.Errorf("expected the non-essential segment 12345 to be replaced, got %q", got.Path)
	}
}

// TestReproCheckCrashComputesStabilityAgainstARealServer exercises reproCheckCrash's
// actual HTTP round-trip (unlike the minimizeXxx tests above, this cannot be
// verified with a fake predicate alone -- it owns the request-sending itself).
func TestReproCheckCrashComputesStabilityAgainstARealServer(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		// Reproduces (500) on every other request -- 50% stability.
		if hits%2 == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg: Config{
			ReproRuns:       4,
			ReproTimeoutSec: 5,
			ReproTargetPct:  100, // require full reproducibility so "stable_reproducible" is provably false here
		},
		client: srv.Client(),
		target: srv.URL,
	}
	item := WorkItem{Method: "GET", Path: "/crash"}

	result := f.reproCheckCrash(item, 500)

	if result["runs"] != 4 {
		t.Errorf("expected runs=4, got %v", result["runs"])
	}
	if result["hits"] != 2 {
		t.Errorf("expected 2 of 4 probes to hit 5xx, got %v", result["hits"])
	}
	if result["stability_pct"] != "50.0" {
		t.Errorf("expected stability_pct=50.0, got %v", result["stability_pct"])
	}
	if result["stable_reproducible"] != false {
		t.Errorf("expected stable_reproducible=false at a 100%% target with only 50%% actual, got %v", result["stable_reproducible"])
	}
}

func TestReproCheckCrashZeroRunsIsANoOp(t *testing.T) {
	f := &Fuzzer{cfg: Config{ReproRuns: 0}}
	result := f.reproCheckCrash(WorkItem{}, 500)
	if len(result) != 0 {
		t.Errorf("expected an empty map when ReproRuns is 0, got %v", result)
	}
}
