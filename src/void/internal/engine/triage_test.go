package engine

import (
	"os"
	"path/filepath"
	"testing"

	"void/internal/config"
)

func TestTemplateSourcePriorityWeight(t *testing.T) {
	f := &Fuzzer{templatePriority: map[int]float64{1: 2.5}}
	if got := f.templateSourcePriorityWeight(1); got != 2.5 {
		t.Errorf("expected the stored weight 2.5, got %v", got)
	}
	if got := f.templateSourcePriorityWeight(99); got != 1.0 {
		t.Errorf("expected the default weight 1.0 for an unknown template, got %v", got)
	}
	f2 := &Fuzzer{templatePriority: map[int]float64{1: 0}}
	if got := f2.templateSourcePriorityWeight(1); got != 1.0 {
		t.Errorf("expected the default weight 1.0 for a non-positive stored weight, got %v", got)
	}
}

func TestSensitivePathScore(t *testing.T) {
	base := sensitivePathScore("GET", "/api/products")
	billing := sensitivePathScore("GET", "/api/billing/invoices")
	if billing <= base {
		t.Errorf("expected a sensitive-keyword path to score higher than a neutral one: billing=%v base=%v", billing, base)
	}
	writeBilling := sensitivePathScore("POST", "/api/billing/invoices")
	if writeBilling <= billing {
		t.Errorf("expected a write method to score higher than a read on the same sensitive path: write=%v read=%v", writeBilling, billing)
	}
	// Score must stay within the documented clamp range.
	multi := sensitivePathScore("POST", "/api/admin/billing/payment/checkout/tenant")
	if multi < 0.8 || multi > 6.0 {
		t.Errorf("expected the score to stay clamped to [0.8,6.0], got %v", multi)
	}
}

func TestScanSourceRouteScores(t *testing.T) {
	dir := t.TempDir()
	// A .cs file with a route attribute and a billing-related keyword.
	src := `
using Microsoft.AspNetCore.Mvc;
namespace Demo.Controllers {
	[ApiController]
	[Route("api/billing/invoices/{id}")]
	public class BillingController : ControllerBase {
		[HttpGet]
		public IActionResult Get(int id) => Ok();
	}
}`
	if err := os.WriteFile(filepath.Join(dir, "BillingController.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-.cs file must be ignored.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("Route(\"api/billing\")"), 0o644)
	// A bin/ directory must be skipped entirely.
	binDir := filepath.Join(dir, "bin")
	os.MkdirAll(binDir, 0o755)
	os.WriteFile(filepath.Join(binDir, "Ignored.cs"), []byte(`[Route("api/should-not-appear")]`), 0o644)

	scores := scanSourceRouteScores(dir)
	if len(scores) == 0 {
		t.Fatal("expected at least one scored route pattern")
	}
	found := false
	for k, v := range scores {
		if v < 1.0 || v > 4.0 {
			t.Errorf("expected score for %q to stay clamped to [1.0,4.0], got %v", k, v)
		}
		if k == "/api/billing/invoices/{param}" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the billing route pattern normalized with {param}, got %v", scores)
	}
	if _, ok := scores["/api/should-not-appear"]; ok {
		t.Error("expected files under bin/ to be skipped")
	}
}

func TestScanSourceRouteScores_EmptyDirReturnsEmptyMap(t *testing.T) {
	if got := scanSourceRouteScores(""); len(got) != 0 {
		t.Errorf("expected an empty map for an empty srcDir, got %v", got)
	}
	if got := scanSourceRouteScores(t.TempDir()); len(got) != 0 {
		t.Errorf("expected an empty map for a directory with no .cs files, got %v", got)
	}
}

func TestNormalizeRoutePattern(t *testing.T) {
	cases := map[string]string{
		"api/orders/{orderId}": "/api/orders/{param}",
		"/api/orders/*":        "/api/orders/{param}",
		"api/orders/:id":       "/api/orders/{param}",
		"":                     "",
		"/":                    "/",
		"api\\orders\\{id}":    "/api/orders/{param}",
	}
	for in, want := range cases {
		if got := normalizeRoutePattern(in); got != want {
			t.Errorf("normalizeRoutePattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadSourceAwarePriority(t *testing.T) {
	dir := t.TempDir()
	src := `[Route("api/billing/{id}")]`
	os.WriteFile(filepath.Join(dir, "Billing.cs"), []byte(src), 0o644)

	f := &Fuzzer{
		cfg:       config.Config{SourceDir: dir},
		activeIDs: []int{1, 2},
		meta: map[int]TemplateMeta{
			1: {Method: "POST", Norm: "/api/billing/1"},
			2: {Method: "GET", Norm: "/api/widgets"},
		},
	}
	boosted := f.loadSourceAwarePriority()
	if boosted == 0 {
		t.Error("expected at least one template boosted above the neutral weight")
	}
	if f.templatePriority[1] <= f.templatePriority[2] {
		t.Errorf("expected the sensitive/source-matched billing endpoint to outweigh the plain one: billing=%v widgets=%v", f.templatePriority[1], f.templatePriority[2])
	}
}

func TestLoadSourceAwarePriority_NoSourceDirStillScoresBySensitivity(t *testing.T) {
	f := &Fuzzer{
		cfg:       config.Config{},
		activeIDs: []int{1},
		meta:      map[int]TemplateMeta{1: {Method: "GET", Norm: "/api/widgets"}},
	}
	f.loadSourceAwarePriority()
	if _, ok := f.templatePriority[1]; !ok {
		t.Error("expected a priority weight computed even without a configured SourceDir")
	}
}
