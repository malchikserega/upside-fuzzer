package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// coverage.go — CoverageReader interface, HTTPCoverageReader (via /shm/ endpoints),
// SHMCoverageReader (direct file-backed SHM for Docker sidecar mode).
//
// Coverage novelty uses AFL-style hit-count buckets. Each edge's raw 8-bit hit
// count is classified into a log-scale bucket (1, 2, 3, 4-7, 8-15, 16-31,
// 32-127, 128+). A bucket bit never seen before for that edge counts as new
// coverage — so an edge executed once is distinguished from the same edge
// executed 50 or 5000 times, which is what lets the fuzzer drive deeper into
// loops, retries, pagination and state machines instead of plateauing the
// moment every edge has been touched at least once. `seen[i]` holds the OR of
// all bucket bits observed for edge i (the bucketed "virgin map").

// countClass maps a raw hit count (0..255) to its AFL-style bucket bit.
var countClass = buildCountClass()

func buildCountClass() [256]byte {
	var t [256]byte
	for i := 0; i < 256; i++ {
		c := byte(i)
		switch {
		case c == 0:
			t[i] = 0
		case c == 1:
			t[i] = 1
		case c == 2:
			t[i] = 2
		case c == 3:
			t[i] = 4
		case c <= 7:
			t[i] = 8
		case c <= 15:
			t[i] = 16
		case c <= 31:
			t[i] = 32
		case c <= 127:
			t[i] = 64
		default:
			t[i] = 128
		}
	}
	return t
}

type CoverageReader interface {
	Init() error
	GetEdges() (int, error)
	Reset() error
	Capacity() int
	Close() error
}

type HTTPCoverageReader struct {
	client   *http.Client
	shmHost  string
	capacity int
}

func (h *HTTPCoverageReader) Init() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/create", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("/shm/create status=%d body=%s", resp.StatusCode, string(b))
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err == nil {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return nil
}

func (h *HTTPCoverageReader) GetEdges() (int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(h.shmHost, "/")+"/shm/coverage", nil)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("/shm/coverage status=%d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return 0, err
	}
	if h.capacity <= 0 {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return toInt(payload["edges"]), nil
}

func (h *HTTPCoverageReader) Reset() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/reset", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/shm/reset status=%d", resp.StatusCode)
	}
	return nil
}

func (h *HTTPCoverageReader) Capacity() int { return h.capacity }

func (h *HTTPCoverageReader) Close() error { return nil }

// CoverageHealth mirrors the /shm/health JSON emitted by the generated C#
// coverage runtime (fuzz-prep-multi.py, both hook and source inject modes).
// It reports facts only, not a verdict: SharpFuzz's Trace type lives in
// SharpFuzz.Common.dll, never in the app's own IL-rewritten assemblies, so
// per-assembly "linked" status can't be measured by type reflection on the
// .NET side. The fail-closed ok/degraded decision (Top-20 #4) is made here,
// engine-side, via checkCoverageHealth's warm-up probe.
type CoverageHealth struct {
	ShmBound         bool     `json:"shm_bound"`
	Mode             string   `json:"mode"`
	TotalClasses     int      `json:"total_classes"`
	LinkedAssemblies int      `json:"linked_assemblies"`
	AppAssemblies    []string `json:"app_assemblies"`
	// InstrumentedTypes is the real instrumented-type count captured at build time
	// by instrumentor/Program.cs (Top-20 #17), used by the .NET side to auto-size
	// the SHM bitmap instead of a fixed 256KB guess. 0 on a build predating this
	// field or when the meta file couldn't be written -- callers must treat 0 as
	// "unknown", not "zero types instrumented".
	InstrumentedTypes int `json:"instrumented_types"`
}

// fetchCoverageHealth queries the target's /shm/health control endpoint. It
// works regardless of coverage-read mode (HTTP polling or direct-shm) because
// the .NET app always serves this endpoint over its normal HTTP listener —
// direct-shm mode only changes how the Go engine *reads* the bitmap file, not
// how the .NET side reports link status.
func fetchCoverageHealth(client *http.Client, host string) (*CoverageHealth, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(host, "/")+"/shm/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("/shm/health status=%d body=%s", resp.StatusCode, string(b))
	}
	var health CoverageHealth
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&health); err != nil {
		return nil, fmt.Errorf("/shm/health decode failed: %w", err)
	}
	return &health, nil
}

// checkCoverageHealth verifies instrumentation is actually producing coverage
// before the real fuzzing run starts, and by default fails closed (refuses to
// start) if it isn't. Top-20 #4 — self-verifying, fail-closed instrumentation.
//
// /shm/health alone can't answer this: SharpFuzz uses one flat shared bitmap
// with hashed offsets and no per-assembly attribution, so there is no honest
// way to ask "did assembly X specifically get instrumented" from the .NET
// side. The only architecturally sound signal is empirical: send a few real,
// unmutated requests and check whether the shared bitmap actually gains new
// edges. A target that is reachable, has shm_bound=true, and even reports app
// assemblies loaded can still be completely uninstrumented (wrong image,
// wrong --src, a namespace excluded by --exclude-namespaces) — in which case
// every request would return 200/404/whatever normally, and a fuzzing run
// would silently burn its whole time budget without a single real edge. This
// check is what would have caught that: it fails closed on exactly that case.
func (f *Fuzzer) checkCoverageHealth() error {
	health, err := fetchCoverageHealth(f.client, f.target)
	if err != nil {
		msg := fmt.Sprintf("coverage health check failed: %v", err)
		return f.failOrWarnDegraded(msg)
	}
	fmt.Printf("Coverage health: shm_bound=%v mode=%s instrumented_types=%d app_assemblies=%v\n", health.ShmBound, health.Mode, health.InstrumentedTypes, health.AppAssemblies)
	if !health.ShmBound {
		return f.failOrWarnDegraded("coverage instrumentation degraded: shared coverage bitmap is not bound (shm_bound=false)")
	}

	if len(f.activeIDs) == 0 {
		// Templates aren't loaded yet at this call site in some configurations;
		// nothing to probe with, so fall back to the shm_bound-only signal above.
		return nil
	}

	before, _ := f.coverage.GetEdges()
	probed := 0
	for _, tid := range f.activeIDs {
		if probed >= 3 {
			break
		}
		item, err := f.renderTemplate(tid, "none", 0, -1)
		if err != nil {
			continue
		}
		f.sendOne(item)
		probed++
	}
	if probed == 0 {
		return f.failOrWarnDegraded("coverage instrumentation degraded: could not render any warm-up request from the loaded templates to verify coverage")
	}
	after, err := f.coverage.GetEdges()
	if err != nil {
		return f.failOrWarnDegraded(fmt.Sprintf("coverage health check failed: could not read coverage after warm-up probe: %v", err))
	}
	f.currentEdges = after
	if after <= before {
		msg := fmt.Sprintf(
			"coverage instrumentation degraded: sent %d real warm-up request(s) but the coverage bitmap gained no new edges "+
				"(before=%d after=%d). App assemblies seen by the runtime: %v. This usually means the IL rewrite never reached "+
				"the target's own assemblies (wrong image, wrong --src, or a namespace excluded by --exclude-namespaces)",
			probed, before, after, health.AppAssemblies)
		return f.failOrWarnDegraded(msg)
	}
	fmt.Printf("Coverage health OK: warm-up probe (%d request(s)) produced %d new edge(s)\n", probed, after-before)
	return nil
}

// failOrWarnDegraded is the shared fail-closed/override policy: by default it
// refuses to start (returns an error); with -allow-degraded-coverage it warns
// and continues instead.
func (f *Fuzzer) failOrWarnDegraded(msg string) error {
	if f.cfg.AllowDegradedCoverage {
		fmt.Printf("Coverage health WARNING (continuing due to -allow-degraded-coverage): %s\n", msg)
		return nil
	}
	return errors.New(msg + " — refusing to start a possibly-blind fuzzing run. Pass -allow-degraded-coverage to override (not recommended).")
}

type SHMCoverageReader struct {
	path       string
	size       int
	mode       string
	f          *os.File
	mapSize    int
	mem        []byte
	readBuf    []byte
	activeMode string
	seen       []byte
	zeroBuf    []byte // pre-allocated for Reset() to avoid per-reset allocation
	edges      int
}

func (s *SHMCoverageReader) Init() error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		fi, err := os.Stat(s.path)
		if err == nil && fi.Size() >= minSHMBitmapSize {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("shm file not ready: %s", s.path)
		}
		time.Sleep(500 * time.Millisecond)
	}
	f, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	// Top-20 #17: trust the actual on-disk file size, not the (possibly stale)
	// -coverage-bitmap-size flag. The .NET side now sizes this file dynamically
	// from the real instrumented-type count (fuzz-prep-multi.py::ResolveShmSize),
	// so it can legitimately be larger than any size the Go side was told to
	// expect. Previously this clamped mapSize down to the flag's value whenever
	// the real file was bigger, silently reading only the first N bytes of the
	// bitmap and dropping real coverage from the untruncated remainder -- a
	// footgun now that the two sides can disagree on size by design.
	mapSize := int(fi.Size())
	if mapSize < minSHMBitmapSize {
		_ = f.Close()
		return fmt.Errorf("shm file too small: %d bytes (need at least %d)", mapSize, minSHMBitmapSize)
	}
	if desired := s.size; desired > 0 && desired != mapSize {
		// Purely diagnostic: the .NET side now sizes this file itself (from the real
		// instrumented-type count when SHM_SIZE isn't pinned -- Top-20 #17), so a
		// mismatch here is expected whenever -coverage-bitmap-size wasn't also passed
		// as the SHM_SIZE env var on the target container. Not an error.
		fmt.Printf("Coverage bitmap: actual SHM file size %d bytes differs from -coverage-bitmap-size %d (using actual size)\n", mapSize, desired)
	}
	s.f = f
	s.mapSize = mapSize
	s.activeMode = "file"
	if s.shouldUseMmap() {
		mem, err := syscall.Mmap(int(f.Fd()), 0, mapSize, syscall.PROT_READ, syscall.MAP_SHARED)
		if err == nil {
			s.mem = mem
			s.activeMode = "mmap"
		}
	}
	if len(s.mem) == 0 {
		s.readBuf = make([]byte, mapSize)
	}
	s.seen = make([]byte, mapSize)
	s.zeroBuf = make([]byte, mapSize)
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) GetEdges() (int, error) {
	if s.f == nil || s.mapSize <= 0 {
		return 0, errors.New("shm not initialized")
	}
	buf := s.mem
	if len(buf) == 0 {
		if len(s.readBuf) != s.mapSize {
			s.readBuf = make([]byte, s.mapSize)
		}
		n, err := s.f.ReadAt(s.readBuf, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if n <= 0 {
			return s.edges, nil
		}
		buf = s.readBuf[:n]
	}
	if len(s.seen) != len(buf) {
		s.seen = make([]byte, len(buf))
		s.zeroBuf = make([]byte, len(buf))
		s.edges = 0
	}
	// Bucketed virgin-map scan: classify each edge's raw hit count into an
	// AFL-style bucket bit; a bucket not yet recorded for that edge is new
	// coverage. Skip all-zero 8-byte words (sparse-bitmap fast path — an all-zero
	// word can only yield bucket 0, i.e. no novelty).
	n := len(buf)
	i := 0
	for ; i+8 <= n; i += 8 {
		if binary.LittleEndian.Uint64(buf[i:]) == 0 {
			continue
		}
		for j := 0; j < 8; j++ {
			c := buf[i+j]
			if c == 0 {
				continue
			}
			bucket := countClass[c]
			if s.seen[i+j]&bucket == 0 {
				s.seen[i+j] |= bucket
				s.edges++
			}
		}
	}
	// Handle tail bytes.
	for ; i < n; i++ {
		c := buf[i]
		if c == 0 {
			continue
		}
		bucket := countClass[c]
		if s.seen[i]&bucket == 0 {
			s.seen[i] |= bucket
			s.edges++
		}
	}
	return s.edges, nil
}

func (s *SHMCoverageReader) Reset() error {
	if s.f == nil {
		return errors.New("shm not initialized")
	}
	// Zero the actual SHM file so the .NET side starts fresh too.
	if _, err := s.f.WriteAt(s.zeroBuf, 0); err != nil {
		return fmt.Errorf("shm file zero failed: %w", err)
	}
	_ = s.f.Sync()
	if len(s.seen) > 0 {
		for i := range s.seen {
			s.seen[i] = 0
		}
	}
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) Capacity() int { return s.mapSize }

func (s *SHMCoverageReader) Close() error {
	if len(s.mem) > 0 {
		_ = syscall.Munmap(s.mem)
	}
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

func (s *SHMCoverageReader) shouldUseMmap() bool {
	mode := strings.ToLower(strings.TrimSpace(s.mode))
	switch mode {
	case "mmap":
		return runtime.GOOS == "linux"
	case "auto":
		// Keep auto conservative: mmap only when explicitly allowed.
		return runtime.GOOS == "linux" && strings.TrimSpace(os.Getenv("SMART_FUZZER_SHM_MMAP")) == "1"
	default:
		return false
	}
}

func (s *SHMCoverageReader) ActiveMode() string {
	if strings.TrimSpace(s.activeMode) == "" {
		return "file"
	}
	return s.activeMode
}
