package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
)

func writeSHMFile(t *testing.T, size int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "coverage.bin")
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSHMCoverageReader_FullLifecycle(t *testing.T) {
	path := writeSHMFile(t, minSHMBitmapSize)
	s := &SHMCoverageReader{path: path, mode: "file"}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Close()

	if s.Capacity() != minSHMBitmapSize {
		t.Errorf("Capacity() = %d, want %d", s.Capacity(), minSHMBitmapSize)
	}
	if s.ActiveMode() != "file" {
		t.Errorf("expected file mode on a non-linux/non-mmap-requested reader, got %q", s.ActiveMode())
	}

	edges, err := s.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 0 {
		t.Errorf("expected 0 edges for an all-zero bitmap, got %d", edges)
	}

	// Simulate the .NET side writing some coverage directly to the file.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{1, 5, 0, 0, 0, 0, 0, 0, 200}, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()

	edges2, err := s.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges after write: %v", err)
	}
	if edges2 <= 0 {
		t.Error("expected new edges after the bitmap gained non-zero bytes")
	}

	// A repeat read with unchanged bucket state must not double-count.
	edges3, err := s.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges repeat: %v", err)
	}
	if edges3 != edges2 {
		t.Errorf("expected edge count to stay stable on a repeat read (%d), got %d", edges2, edges3)
	}

	if err := s.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	edges4, err := s.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges after Reset: %v", err)
	}
	if edges4 != 0 {
		t.Errorf("expected 0 edges after Reset zeroed the bitmap and virgin map, got %d", edges4)
	}
}

func TestSHMCoverageReader_GetEdgesBeforeInitErrors(t *testing.T) {
	s := &SHMCoverageReader{}
	if _, err := s.GetEdges(); err == nil {
		t.Error("expected an error calling GetEdges before Init")
	}
}

func TestSHMCoverageReader_ResetBeforeInitErrors(t *testing.T) {
	s := &SHMCoverageReader{}
	if err := s.Reset(); err == nil {
		t.Error("expected an error calling Reset before Init")
	}
}

func TestSHMCoverageReader_CloseWithoutInitIsSafe(t *testing.T) {
	s := &SHMCoverageReader{}
	if err := s.Close(); err != nil {
		t.Errorf("expected Close on an uninitialized reader to be a safe no-op, got %v", err)
	}
}

func TestSHMCoverageReader_ShouldUseMmap(t *testing.T) {
	s := &SHMCoverageReader{mode: "disabled"}
	if s.shouldUseMmap() {
		t.Error("expected false for an unrecognized/disabled mode")
	}
	s2 := &SHMCoverageReader{mode: "auto"}
	os.Unsetenv("SMART_FUZZER_SHM_MMAP")
	if s2.shouldUseMmap() && goruntime.GOOS != "linux" {
		t.Error("expected false for auto mode on a non-linux OS")
	}

	s3 := &SHMCoverageReader{mode: "mmap"}
	if s3.shouldUseMmap() != (goruntime.GOOS == "linux") {
		t.Errorf("expected shouldUseMmap for mode=mmap to equal GOOS==linux, got %v on %s", s3.shouldUseMmap(), goruntime.GOOS)
	}
}

func TestSHMCoverageReader_ActiveModeDefaultsToFile(t *testing.T) {
	s := &SHMCoverageReader{}
	if s.ActiveMode() != "file" {
		t.Errorf("expected default ActiveMode 'file' before Init, got %q", s.ActiveMode())
	}
}

func newTestHTTPCoverageReader(host string) *HTTPCoverageReader {
	return &HTTPCoverageReader{client: http.DefaultClient, shmHost: host}
}

func TestHTTPCoverageReader_FullLifecycle(t *testing.T) {
	edgeCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/shm/create", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"size": 65536})
	})
	mux.HandleFunc("/shm/coverage", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"edges": edgeCount, "size": 65536})
	})
	mux.HandleFunc("/shm/reset", func(w http.ResponseWriter, r *http.Request) {
		edgeCount = 0
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := newTestHTTPCoverageReader(srv.URL)
	if err := h.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if h.Capacity() != 65536 {
		t.Errorf("Capacity() = %d, want 65536", h.Capacity())
	}

	edgeCount = 42
	got, err := h.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if got != 42 {
		t.Errorf("GetEdges() = %d, want 42", got)
	}

	if err := h.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got2, err := h.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges after reset: %v", err)
	}
	if got2 != 0 {
		t.Errorf("expected edges reset to 0, got %d", got2)
	}

	if err := h.Close(); err != nil {
		t.Errorf("expected Close to always succeed, got %v", err)
	}
}

func TestHTTPCoverageReader_InitNonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := newTestHTTPCoverageReader(srv.URL)
	if err := h.Init(); err == nil {
		t.Error("expected an error for a non-200 /shm/create response")
	}
}

func TestHTTPCoverageReader_GetEdgesNonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	h := newTestHTTPCoverageReader(srv.URL)
	if _, err := h.GetEdges(); err == nil {
		t.Error("expected an error for a non-200 /shm/coverage response")
	}
}

func TestHTTPCoverageReader_ResetNonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	h := newTestHTTPCoverageReader(srv.URL)
	if err := h.Reset(); err == nil {
		t.Error("expected an error for a non-200 /shm/reset response")
	}
}

func TestFetchCoverageHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CoverageHealth{ShmBound: true, Mode: "hook", TotalClasses: 10})
	}))
	defer srv.Close()

	health, err := fetchCoverageHealth(http.DefaultClient, srv.URL)
	if err != nil {
		t.Fatalf("fetchCoverageHealth: %v", err)
	}
	if !health.ShmBound || health.Mode != "hook" {
		t.Errorf("unexpected health payload: %+v", health)
	}
}

func TestFetchCoverageHealth_NonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := fetchCoverageHealth(http.DefaultClient, srv.URL); err == nil {
		t.Error("expected an error for a non-200 /shm/health response")
	}
}

func TestCheckCoverageHealth_HealthyProbeSucceeds(t *testing.T) {
	edges := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/shm/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CoverageHealth{ShmBound: true, Mode: "hook"})
	})
	mux.HandleFunc("/shm/create", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"size": 65536})
	})
	mux.HandleFunc("/shm/coverage", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"edges": edges, "size": 65536})
	})
	mux.HandleFunc("/widgets", func(w http.ResponseWriter, r *http.Request) {
		edges++ // simulate a real coverage gain per warm-up request
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("TARGET_HOST", srv.URL)
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()
	if err := f.coverage.Init(); err != nil {
		t.Fatalf("coverage.Init: %v", err)
	}

	if err := f.checkCoverageHealth(); err != nil {
		t.Fatalf("expected the health check to pass when edges increase after warm-up, got %v", err)
	}
}

func TestCheckCoverageHealth_ShmNotBoundFailsClosed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/shm/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CoverageHealth{ShmBound: false})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("TARGET_HOST", srv.URL)
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected a fail-closed error when shm_bound=false")
	}
}

func TestCheckCoverageHealth_ShmNotBoundWarnsWhenAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/shm/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CoverageHealth{ShmBound: false})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("TARGET_HOST", srv.URL)
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/widgets")})
	cfg.AllowDegradedCoverage = true
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	if err := f.checkCoverageHealth(); err != nil {
		t.Errorf("expected no error with -allow-degraded-coverage, got %v", err)
	}
}

func TestCheckCoverageHealth_UnreachableTargetFailsClosed(t *testing.T) {
	t.Setenv("TARGET_HOST", "http://127.0.0.1:1")
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected an error when the health endpoint is unreachable")
	}
}

func TestCheckCoverageHealth_NoEdgeGainFailsClosed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/shm/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(CoverageHealth{ShmBound: true})
	})
	mux.HandleFunc("/shm/create", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"size": 65536})
	})
	mux.HandleFunc("/shm/coverage", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"edges": 0, "size": 65536}) // never gains edges
	})
	mux.HandleFunc("/widgets", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("TARGET_HOST", srv.URL)
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()
	if err := f.coverage.Init(); err != nil {
		t.Fatalf("coverage.Init: %v", err)
	}

	if err := f.checkCoverageHealth(); err == nil {
		t.Fatal("expected a fail-closed error when the warm-up probe gains no new edges")
	}
}

func TestFailOrWarnDegraded(t *testing.T) {
	fStrict := &Fuzzer{}
	if err := fStrict.failOrWarnDegraded("boom"); err == nil {
		t.Error("expected an error by default (fail-closed)")
	}

	fLenient := &Fuzzer{}
	fLenient.cfg.AllowDegradedCoverage = true
	if err := fLenient.failOrWarnDegraded("boom"); err != nil {
		t.Errorf("expected no error with AllowDegradedCoverage=true, got %v", err)
	}
}
