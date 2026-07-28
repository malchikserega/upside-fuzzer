package main

import (
	"sort"
	"testing"
)

// resource_bench_test.go — reproducible old-vs-new comparison for
// docs/resource-state-graph-report.md. Per the design task's own instruction,
// this measures extraction *count and correctness* (the interesting number
// here) rather than raw ns/op for extraction, plus a genuine ns/op overhead
// benchmark for the new coverage-directed scheduler vs the old static sort
// (to confirm the new path doesn't regress the sequence engine's own
// throughput).

// representativeResponseBodies mirrors the corpus described in
// docs/resource-state-graph-plan.md §13: plain id, GUID, slug, HAL,
// JSON:API, and a nested composite key.
var representativeResponseBodies = []struct {
	name string
	body string
}{
	{"plain_id", `{"id": "42", "status": "active"}`},
	{"guid_reference", `{"reference": "550e8400-e29b-41d4-a716-446655440000", "status": "confirmed"}`},
	{"slug", `{"slug": "my-cool-project", "visibility": "public"}`},
	{"hal_links", `{"_links": {"self": {"href": "/orders/123"}, "customer": {"href": "/customers/456"}}}`},
	{"jsonapi", `{"data": {"type": "orders", "id": "123", "relationships": {"customer": {"data": {"type": "customers", "id": "456"}}}}}`},
	{"nested_composite", `{"assignedTo": {"employeeId": "E-9981", "name": "Alex"}}`},
	{"domain_specific_no_id_substring", `{"resourceRef": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}`},
}

// TestExtractionComparison_OldVsNew is written as a Test (not a Benchmark)
// because the number that matters is candidate *count*, reported once, not a
// timing loop -- but it's the actual comparison table for
// docs/resource-state-graph-report.md, run via:
//
//	go test -run TestExtractionComparison_OldVsNew -v ./...
func TestExtractionComparison_OldVsNew(t *testing.T) {
	f := newTestFuzzerForExtraction()
	oldTotal, newTotal := 0, 0
	for _, c := range representativeResponseBodies {
		old := extractEntityIDs(c.body, nil)
		newC := f.extractResourceCandidates(c.body, nil, "GET /x/1")
		t.Logf("%-32s old=%d new=%d", c.name, len(old), len(newC))
		oldTotal += len(old)
		newTotal += len(newC)
	}
	t.Logf("TOTAL across %d representative bodies: old=%d new=%d", len(representativeResponseBodies), oldTotal, newTotal)
	if newTotal <= oldTotal {
		t.Fatalf("expected the new pipeline to find strictly more candidates across this representative corpus (old=%d, new=%d)", oldTotal, newTotal)
	}
}

// BenchmarkExtractResourceCandidates measures the new pipeline's own
// steady-state cost per response, across the representative corpus -- useful
// to confirm extraction itself isn't a hot-path regression risk (it runs once
// per sequence-engine step, not once per request).
func BenchmarkExtractResourceCandidates(b *testing.B) {
	f := newTestFuzzerForExtraction()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, c := range representativeResponseBodies {
			_ = f.extractResourceCandidates(c.body, nil, "GET /x/1")
		}
	}
}

// BenchmarkFollowupRanking_OldStaticVsNewCoverageDirected compares the
// per-call overhead of the old static-priority sort against the new
// coverage-directed ranking, at a realistic candidate-list size, to confirm
// the new scheduling path does not measurably regress sequence-engine
// throughput.
func BenchmarkFollowupRanking_OldStaticSort(b *testing.B) {
	f := newTestFuzzerForScheduling()
	candidates := make([]int, 12)
	for i := range candidates {
		tid := i + 1
		candidates[i] = tid
		f.meta[tid] = TemplateMeta{Method: "GET", Norm: "/resource" + string(rune('a'+i)) + "/{param}"}
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out := make([]int, len(candidates))
		copy(out, candidates)
		sortByStaticPriority(out, f, "POST", "/resource")
	}
}

func BenchmarkFollowupRanking_NewCoverageDirected(b *testing.B) {
	f := newTestFuzzerForScheduling()
	candidates := make([]int, 12)
	for i := range candidates {
		tid := i + 1
		candidates[i] = tid
		f.meta[tid] = TemplateMeta{Method: "GET", Norm: "/resource" + string(rune('a'+i)) + "/{param}"}
		f.tmplEPKey[tid] = f.meta[tid].Method + " " + f.meta[tid].Norm
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out := make([]int, len(candidates))
		copy(out, candidates)
		_ = f.rankConsumersCoverageDirected(out, "POST", "/resource")
	}
}

// sortByStaticPriority isolates the OLD sort.SliceStable(...followupPriority...)
// call from findFollowups for a clean, apples-to-apples benchmark comparison
// against rankConsumersCoverageDirected (findFollowups itself does candidate
// *gathering* too, which both old and new paths share and isn't the part that
// changed).
func sortByStaticPriority(out []int, f *Fuzzer, sourceMethod, sourceNorm string) {
	sort.SliceStable(out, func(i, j int) bool {
		a := f.meta[out[i]]
		b := f.meta[out[j]]
		return followupPriority(sourceMethod, sourceNorm, a.Method, a.Norm) < followupPriority(sourceMethod, sourceNorm, b.Method, b.Norm)
	})
}
