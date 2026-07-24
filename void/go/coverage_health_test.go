package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchCoverageHealthParsesFields covers the /shm/health JSON contract
// emitted by fuzz-prep-multi.py's generated C# coverage runtime (Top-20 #4).
// The endpoint reports facts only (no verdict) — see coverage.go's
// CoverageHealth doc comment for why per-assembly "linked" status can't be
// computed on the .NET side.
func TestFetchCoverageHealthParsesFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shm_bound":true,"mode":"file-backed-mmap","total_classes":3,` +
			`"linked_assemblies":1,"app_assemblies":["PlantedBugApi"]}`))
	}))
	defer srv.Close()

	health, err := fetchCoverageHealth(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchCoverageHealth failed: %v", err)
	}
	if !health.ShmBound || health.TotalClasses != 3 {
		t.Errorf("unexpected health: %+v", health)
	}
	if len(health.AppAssemblies) != 1 || health.AppAssemblies[0] != "PlantedBugApi" {
		t.Errorf("expected app_assemblies=[PlantedBugApi], got %v", health.AppAssemblies)
	}
}

// TestCheckCoverageHealthFailsClosedOnUnbound verifies the engine refuses to
// start when shm_bound=false (the coverage pointer never bound at all) and
// -allow-degraded-coverage was not passed, but continues when it was.
func TestCheckCoverageHealthFailsClosedOnUnbound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shm_bound":false,"mode":"heap","total_classes":0,"linked_assemblies":0,"app_assemblies":[]}`))
	}))
	defer srv.Close()

	f := &Fuzzer{cfg: Config{}, target: srv.URL, client: srv.Client()}
	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected checkCoverageHealth to fail closed when shm_bound=false, got nil error")
	}

	f2 := &Fuzzer{cfg: Config{AllowDegradedCoverage: true}, target: srv.URL, client: srv.Client()}
	if err := f2.checkCoverageHealth(); err != nil {
		t.Fatalf("expected checkCoverageHealth to continue with -allow-degraded-coverage, got error: %v", err)
	}
}

// TestCheckCoverageHealthNoTemplatesFallsBackToShmBound verifies that when no
// templates are loaded yet (activeIDs empty), the check can't run its warm-up
// probe and falls back to the shm_bound-only signal instead of panicking.
func TestCheckCoverageHealthNoTemplatesFallsBackToShmBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shm_bound":true,"mode":"file-backed-mmap","total_classes":0,"linked_assemblies":1,"app_assemblies":["Api"]}`))
	}))
	defer srv.Close()

	f := &Fuzzer{cfg: Config{}, target: srv.URL, client: srv.Client()}
	if err := f.checkCoverageHealth(); err != nil {
		t.Fatalf("expected fallback pass with no templates loaded, got error: %v", err)
	}
}

// TestCheckCoverageHealthUnreachableFailsClosed verifies a network/decode
// failure against /shm/health is also treated as fail-closed by default.
func TestCheckCoverageHealthUnreachableFailsClosed(t *testing.T) {
	f := &Fuzzer{cfg: Config{}, target: "http://127.0.0.1:1", client: http.DefaultClient}
	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected checkCoverageHealth to fail closed when /shm/health is unreachable")
	}

	f2 := &Fuzzer{cfg: Config{AllowDegradedCoverage: true}, target: "http://127.0.0.1:1", client: http.DefaultClient}
	if err := f2.checkCoverageHealth(); err != nil {
		t.Fatalf("expected -allow-degraded-coverage to override an unreachable health check, got error: %v", err)
	}
}
