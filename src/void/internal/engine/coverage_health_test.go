package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"void/internal/config"
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

	f := &Fuzzer{cfg: config.Config{}, target: srv.URL, client: srv.Client()}
	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected checkCoverageHealth to fail closed when shm_bound=false, got nil error")
	}

	f2 := &Fuzzer{cfg: config.Config{AllowDegradedCoverage: true}, target: srv.URL, client: srv.Client()}
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

	f := &Fuzzer{cfg: config.Config{}, target: srv.URL, client: srv.Client()}
	if err := f.checkCoverageHealth(); err != nil {
		t.Fatalf("expected fallback pass with no templates loaded, got error: %v", err)
	}
}

// TestCheckCoverageHealthUnreachableFailsClosed verifies a network/decode
// failure against /shm/health is also treated as fail-closed by default.
func TestCheckCoverageHealthUnreachableFailsClosed(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{}, target: "http://127.0.0.1:1", client: http.DefaultClient}
	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected checkCoverageHealth to fail closed when /shm/health is unreachable")
	}

	f2 := &Fuzzer{cfg: config.Config{AllowDegradedCoverage: true}, target: "http://127.0.0.1:1", client: http.DefaultClient}
	if err := f2.checkCoverageHealth(); err != nil {
		t.Fatalf("expected -allow-degraded-coverage to override an unreachable health check, got error: %v", err)
	}
}

// TestFetchCoverageHealthParsesInstrumentedTypes verifies the Top-20 #17
// instrumented_types field (real build-time instrumented-type count, used to
// auto-size the SHM bitmap) round-trips through the /shm/health JSON contract,
// and that its absence (a build predating this field) decodes to 0 rather than
// erroring -- old and new coverage runtimes must both be readable.
func TestFetchCoverageHealthParsesInstrumentedTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shm_bound":true,"mode":"file-backed-mmap","total_classes":3,` +
			`"linked_assemblies":1,"instrumented_types":42,"app_assemblies":["PlantedBugApi"]}`))
	}))
	defer srv.Close()

	health, err := fetchCoverageHealth(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchCoverageHealth failed: %v", err)
	}
	if health.InstrumentedTypes != 42 {
		t.Errorf("expected instrumented_types=42, got %d", health.InstrumentedTypes)
	}

	srvOld := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shm_bound":true,"mode":"heap","total_classes":0,"linked_assemblies":0,"app_assemblies":[]}`))
	}))
	defer srvOld.Close()
	healthOld, err := fetchCoverageHealth(srvOld.Client(), srvOld.URL)
	if err != nil {
		t.Fatalf("fetchCoverageHealth failed on a pre-#17 payload: %v", err)
	}
	if healthOld.InstrumentedTypes != 0 {
		t.Errorf("expected instrumented_types=0 when the field is absent, got %d", healthOld.InstrumentedTypes)
	}
}

// TestShouldResetCoverageBitmap verifies the Top-20 #17 reset gating: a reset
// now requires BOTH high saturation AND genuine stagnation (no new edge
// recently), not saturation alone -- so a bitmap reset never discards progress
// mid-productive-run purely because a byte-percentage threshold was crossed.
func TestShouldResetCoverageBitmap(t *testing.T) {
	now := time.Now()

	// Saturated but still actively finding edges (lastEdgeEvent just now) -> no reset.
	if shouldResetCoverageBitmap(90.0, 65536, now, time.Time{}, now) {
		t.Errorf("must not reset while still actively finding edges, even at high saturation")
	}

	// Saturated AND stagnant (last edge 60s ago) AND never reset before -> reset.
	if !shouldResetCoverageBitmap(90.0, 65536, now.Add(-60*time.Second), time.Time{}, now) {
		t.Errorf("expected reset when saturated and stagnant")
	}

	// Stagnant but NOT saturated -> no reset (nothing to gain from wiping a map that isn't full).
	if shouldResetCoverageBitmap(50.0, 65536, now.Add(-60*time.Second), time.Time{}, now) {
		t.Errorf("must not reset when saturation is low, regardless of stagnation")
	}

	// Saturated and stagnant, but reset only 10s ago -> too soon, no reset (avoids tight loops).
	if shouldResetCoverageBitmap(90.0, 65536, now.Add(-60*time.Second), now.Add(-10*time.Second), now) {
		t.Errorf("must not reset again within the cooldown window")
	}

	// No bitmap capacity known yet -> never reset (capacity<=0 guard).
	if shouldResetCoverageBitmap(90.0, 0, now.Add(-60*time.Second), time.Time{}, now) {
		t.Errorf("must not reset when coverageCapacity is unknown (0)")
	}
}
