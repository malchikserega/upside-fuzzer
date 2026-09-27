package engine

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"void/internal/config"
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

// ---- minimizeBodyTree (typed structural mutation Stage 7) ----

func objField(key, val string) BodyField {
	return BodyField{Key: key, Value: newStringValue(nil, key, val)}
}

func TestMinimizeBodyTreeDropsOnlyNonEssentialTopLevelFields(t *testing.T) {
	f := &Fuzzer{}
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{objField("a", "1"), objField("b", "2"), objField("c", "3")}
	item := WorkItem{BodyTree: tree, Body: tree.ToJSON()}

	trySet := func(cand WorkItem) bool {
		var obj map[string]any
		if err := json.Unmarshal([]byte(cand.Body), &obj); err != nil {
			return false
		}
		v, ok := obj["b"]
		return ok && v == "2"
	}

	got := f.minimizeBodyTree(item, trySet)

	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	if len(obj) != 1 {
		t.Errorf("expected exactly the essential key to remain, got %v", obj)
	}
	if v, ok := obj["b"]; !ok || v != "2" {
		t.Errorf("expected essential key b=2 to survive minimization, got %v", obj)
	}
	// The candidate.Body must stay in sync with candidate.BodyTree at every
	// accepted step, or trySet's no-op guard (minimizeCrashCandidate) would
	// silently swallow every further real change.
	if got.BodyTree.ToJSON() != got.Body {
		t.Errorf("BodyTree/Body desync after minimization: tree=%q body=%q", got.BodyTree.ToJSON(), got.Body)
	}
}

func TestMinimizeBodyTreeRecursesIntoNestedObjects(t *testing.T) {
	f := &Fuzzer{}
	inner := newObjectValue(nil, "owner")
	inner.Fields = []BodyField{objField("name", "alice"), objField("noise", "x")}
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{{Key: "owner", Value: inner}}
	item := WorkItem{BodyTree: tree, Body: tree.ToJSON()}

	// Only reproduces while owner.name == "alice" is present; owner.noise is not needed.
	trySet := func(cand WorkItem) bool {
		var obj map[string]any
		if err := json.Unmarshal([]byte(cand.Body), &obj); err != nil {
			return false
		}
		owner, ok := obj["owner"].(map[string]any)
		return ok && owner["name"] == "alice"
	}

	got := f.minimizeBodyTree(item, trySet)

	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	owner, ok := obj["owner"].(map[string]any)
	if !ok {
		t.Fatalf("expected owner object to survive, got %v", obj)
	}
	if len(owner) != 1 || owner["name"] != "alice" {
		t.Errorf("expected only owner.name=alice to survive nested minimization, got %v", owner)
	}
}

func TestMinimizeBodyTreeShrinksArraysElementByElement(t *testing.T) {
	f := &Fuzzer{}
	arr := newArrayValue(nil, "tags")
	arr.Items = []*BodyValue{
		newStringValue(nil, "tags", "keep"),
		newStringValue(nil, "tags", "drop-1"),
		newStringValue(nil, "tags", "drop-2"),
	}
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{{Key: "tags", Value: arr}}
	item := WorkItem{BodyTree: tree, Body: tree.ToJSON()}

	trySet := func(cand WorkItem) bool {
		var obj map[string]any
		if err := json.Unmarshal([]byte(cand.Body), &obj); err != nil {
			return false
		}
		tags, ok := obj["tags"].([]any)
		if !ok {
			return false
		}
		for _, v := range tags {
			if v == "keep" {
				return true
			}
		}
		return false
	}

	got := f.minimizeBodyTree(item, trySet)

	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	tags, ok := obj["tags"].([]any)
	if !ok || len(tags) != 1 || tags[0] != "keep" {
		t.Errorf("expected tags shrunk to exactly [\"keep\"], got %v", obj["tags"])
	}
}

func TestMinimizeBodyTreeNilBodyTreeIsANoOp(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{Body: `{"a":1}`}
	called := false
	got := f.minimizeBodyTree(item, func(WorkItem) bool { called = true; return true })
	if called {
		t.Error("expected trySet never called when item.BodyTree is nil")
	}
	if got.Body != `{"a":1}` {
		t.Errorf("expected body unchanged, got %q", got.Body)
	}
}

func TestMinimizeBodyTreeNeverMutatesTheOriginalTree(t *testing.T) {
	f := &Fuzzer{}
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{objField("a", "1"), objField("b", "2")}
	original := tree.ToJSON()
	item := WorkItem{BodyTree: tree, Body: original}

	// Every attempt "succeeds" -- the most aggressive possible minimization --
	// yet the caller's own tree pointer (item.BodyTree passed in) must be
	// left completely untouched: minimizeBodyTree clones before mutating,
	// specifically so a crash record captured from the same shared pointer
	// elsewhere in the crash-recording path can't be corrupted by this.
	_ = f.minimizeBodyTree(item, func(WorkItem) bool { return true })

	if got := tree.ToJSON(); got != original {
		t.Errorf("original tree was mutated: before=%q after=%q", original, got)
	}
}

func TestMinimizeCrashCandidateUsesBodyTreePathWhenPresentInsteadOfFlatJSONBody(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{MinimizeMaxProbes: 100}}
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{objField("a", "1"), objField("b", "2")}
	item := WorkItem{Method: "POST", Path: "/x", BodyTree: tree, Body: tree.ToJSON()}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		var obj map[string]any
		if json.Unmarshal(buf, &obj) == nil {
			if v, ok := obj["b"]; ok && v == "2" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f.target = srv.URL
	f.client = srv.Client()

	got, changed, probes := f.minimizeCrashCandidate(item, http.StatusInternalServerError)
	if probes == 0 {
		t.Fatal("expected at least one probe")
	}
	if !changed {
		t.Fatal("expected minimization to find a smaller reproducing body")
	}
	if got.BodyTree == nil {
		t.Fatal("expected the minimized item to still carry a BodyTree")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	if len(obj) != 1 || obj["b"] != "2" {
		t.Errorf("expected only the essential field b=2 to survive, got %v", obj)
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
		cfg: config.Config{
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
	f := &Fuzzer{cfg: config.Config{ReproRuns: 0}}
	result := f.reproCheckCrash(WorkItem{}, 500)
	if len(result) != 0 {
		t.Errorf("expected an empty map when ReproRuns is 0, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// minimizeChainCandidate (Phase 5 #126)
// ---------------------------------------------------------------------------

func TestMinimizeChainCandidateNilSeqStateIsANoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{MinimizeMaxProbes: 100}}
	history, changed, probes := f.minimizeChainCandidate(WorkItem{})
	if history != nil || changed || probes != 0 {
		t.Errorf("expected a no-op (nil, false, 0) for a nil SeqState, got (%v, %v, %v)", history, changed, probes)
	}
}

func TestMinimizeChainCandidateSingleStepHistoryIsANoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{MinimizeMaxProbes: 100}}
	item := WorkItem{SeqState: &SequenceState{History: []SequenceStep{
		{Method: "GET", Path: "/crash"},
	}}}
	history, changed, probes := f.minimizeChainCandidate(item)
	if history != nil || changed || probes != 0 {
		t.Errorf("expected a no-op (nil, false, 0) for a single-step chain, got (%v, %v, %v)", history, changed, probes)
	}
}

func TestMinimizeChainCandidateZeroMaxProbesIsANoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{MinimizeMaxProbes: 0}}
	item := WorkItem{SeqState: &SequenceState{History: []SequenceStep{
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/crash"},
	}}}
	history, changed, probes := f.minimizeChainCandidate(item)
	if changed || probes != 0 {
		t.Errorf("expected no probing when MinimizeMaxProbes is 0, got (changed=%v, probes=%v)", changed, probes)
	}
	if len(history) != 2 {
		t.Errorf("expected the original 2-step history returned unchanged, got %v", history)
	}
}

// TestMinimizeChainCandidateDropsGenuinelyNonEssentialStep sets up a 3-step
// chain where only the FINAL step's status matters for "still crashes" -- the
// middle step (/noise) is unrelated setup that should be dropped, while the
// first step (/setup) stays because the fake server only returns 500 on the
// final step when it has already seen a request to /setup earlier in the
// same probe sequence.
func TestMinimizeChainCandidateDropsGenuinelyNonEssentialStep(t *testing.T) {
	// lastWasSetup is consumed (reset) the instant /crash checks it, so it
	// only reflects whether /setup was hit earlier in THIS SAME candidate
	// replay -- not leaked truthiness from an earlier, separate probe attempt.
	var lastWasSetup bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/setup":
			lastWasSetup = true
			w.WriteHeader(http.StatusOK)
		case "/noise":
			w.WriteHeader(http.StatusOK)
		case "/crash":
			if lastWasSetup {
				lastWasSetup = false
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg:    config.Config{MinimizeMaxProbes: 100},
		client: srv.Client(),
		target: srv.URL,
	}
	item := WorkItem{SeqState: &SequenceState{History: []SequenceStep{
		{Method: "GET", Path: "/setup"},
		{Method: "GET", Path: "/noise"},
		{Method: "GET", Path: "/crash"},
	}}}

	history, changed, probes := f.minimizeChainCandidate(item)

	if !changed {
		t.Fatal("expected the chain to be shrunk")
	}
	if probes == 0 {
		t.Error("expected at least one probe to have been sent")
	}
	if len(history) != 2 {
		t.Fatalf("expected the noise step dropped leaving a 2-step chain, got %d steps: %v", len(history), history)
	}
	if history[0].Path != "/setup" || history[len(history)-1].Path != "/crash" {
		t.Errorf("expected /setup to survive and /crash to remain last, got %v", history)
	}
	for _, step := range history {
		if step.Path == "/noise" {
			t.Errorf("expected /noise to be dropped, got %v", history)
		}
	}
}

// TestMinimizeChainCandidateRefusesToDropAnEssentialStep mirrors the above but
// with only ONE prior step, which is essential -- dropping it must be
// rejected since the final step then stops crashing.
func TestMinimizeChainCandidateRefusesToDropAnEssentialStep(t *testing.T) {
	var lastWasSetup bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/setup":
			lastWasSetup = true
			w.WriteHeader(http.StatusOK)
		case "/crash":
			if lastWasSetup {
				lastWasSetup = false
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg:    config.Config{MinimizeMaxProbes: 100},
		client: srv.Client(),
		target: srv.URL,
	}
	item := WorkItem{SeqState: &SequenceState{History: []SequenceStep{
		{Method: "GET", Path: "/setup"},
		{Method: "GET", Path: "/crash"},
	}}}

	history, changed, probes := f.minimizeChainCandidate(item)

	if changed {
		t.Errorf("expected no drop since /setup is essential, got history %v", history)
	}
	if probes == 0 {
		t.Error("expected the drop to have been attempted (and rejected)")
	}
	if len(history) != 2 || history[0].Path != "/setup" || history[1].Path != "/crash" {
		t.Errorf("expected the original 2-step history unchanged, got %v", history)
	}
}

// TestMinimizeChainCandidateStopsAtProbeBudget verifies a small budget caps
// the number of HTTP round-trips sent, even when more steps remain to try.
func TestMinimizeChainCandidateStopsAtProbeBudget(t *testing.T) {
	var probeCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg:    config.Config{MinimizeMaxProbes: 1},
		client: srv.Client(),
		target: srv.URL,
	}
	item := WorkItem{SeqState: &SequenceState{History: []SequenceStep{
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/b"},
		{Method: "GET", Path: "/crash"},
	}}}

	_, _, probes := f.minimizeChainCandidate(item)

	if probes > 1 {
		t.Errorf("expected probing to stop at the MinimizeMaxProbes budget (1), got %d probes sent", probes)
	}
	if probeCount > 1 {
		t.Errorf("expected at most 1 real HTTP request sent, server saw %d", probeCount)
	}
}
