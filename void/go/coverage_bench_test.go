package main

import (
	"math/rand"
	"os"
	"testing"
)

// coverage_bench_test.go — correctness + benchmark coverage for
// SHMCoverageReader.GetEdges(), the direct-SHM bitmap scan that turns raw
// per-edge hit counts into the bucketed novelty count everything else in the
// engine (seed energy, mutation-category weights, epoch rebalancing) learns
// from. Before this file, GetEdges/Init/Reset/Close had zero automated test
// coverage at all, despite docs/ARCHITECTURE.md and docs/WHITEPAPER.md both
// describing this exact scan as the foundation the rest of the scheduler's
// signal quality depends on.

// newTestSHMReader builds an SHMCoverageReader whose scan loop runs entirely
// against an in-memory buffer (s.mem populated directly -- the same code path
// direct-shm/mmap mode uses), so both the benchmark and the correctness tests
// exercise the real GetEdges() scan logic without needing a real SHM-backed
// file's bytes to be read. GetEdges still requires a non-nil s.f (only to
// confirm the reader was "initialized" -- it's never actually read from when
// s.mem is already populated), so tb supplies a throwaway temp file for that.
func newTestSHMReader(tb testing.TB, size int) *SHMCoverageReader {
	tb.Helper()
	f, err := os.CreateTemp(tb.TempDir(), "shm-bench-*")
	if err != nil {
		tb.Fatalf("CreateTemp: %v", err)
	}
	tb.Cleanup(func() { f.Close() })
	return &SHMCoverageReader{
		f:       f,
		mem:     make([]byte, size),
		mapSize: size,
	}
}

func TestSHMCoverageReader_BucketedNovelty(t *testing.T) {
	r := newTestSHMReader(t, 64)

	// First observation of edge 0 at hit-count 1 (bucket "1"): novel.
	r.mem[0] = 1
	edges, err := r.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 1 {
		t.Fatalf("expected 1 novel edge after first hit, got %d", edges)
	}

	// Same raw hit count again (no change to the bitmap): must NOT recount --
	// this is the "seen" virgin-map behavior the whole novelty signal depends on.
	edges, err = r.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 1 {
		t.Fatalf("expected edge count to stay at 1 for an already-seen bucket, got %d", edges)
	}

	// Same edge, hit count climbs into a materially different bucket (1 -> 5,
	// which is bucket "4-7" per the AFL-style table): this MUST count as novel
	// again -- this is the entire point of bucketing hit counts instead of a
	// binary present/absent bitmap (see docs/WHITEPAPER.md §8).
	r.mem[0] = 5
	edges, err = r.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 2 {
		t.Fatalf("expected a new bucket transition (1->5) to count as novel (total 2), got %d", edges)
	}

	// A second, previously-untouched edge lighting up for the first time: novel.
	r.mem[63] = 200
	edges, err = r.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 3 {
		t.Fatalf("expected a second distinct edge to add one more novel bucket (total 3), got %d", edges)
	}
}

func TestSHMCoverageReader_AllZeroBitmapIsNotNovel(t *testing.T) {
	r := newTestSHMReader(t, 4096)
	edges, err := r.GetEdges()
	if err != nil {
		t.Fatalf("GetEdges: %v", err)
	}
	if edges != 0 {
		t.Fatalf("an all-zero bitmap must report 0 edges, got %d", edges)
	}
}

// BenchmarkSHMCoverageReader_GetEdges_SteadyState models the common runtime
// case: the virgin map is already warm (most edges already seen at their
// current bucket) and a scan finds few-to-no new buckets, which is what the
// all-zero-word fast path and "seen" check are optimized for.
func BenchmarkSHMCoverageReader_GetEdges_SteadyState(b *testing.B) {
	const size = 262144 // default SHM bitmap size (defaultSHMBitmapSize)
	r := newTestSHMReader(b, size)

	// Populate ~15% of the bitmap with varied hit counts (roughly representative
	// of a real target's edge density) and warm the virgin map with one scan.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < size/7; i++ {
		idx := rng.Intn(size)
		r.mem[idx] = byte(1 + rng.Intn(254))
	}
	if _, err := r.GetEdges(); err != nil {
		b.Fatalf("warm-up GetEdges: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := r.GetEdges(); err != nil {
			b.Fatalf("GetEdges: %v", err)
		}
	}
}

// BenchmarkSHMCoverageReader_GetEdges_ColdStart models the first scan against
// a freshly-populated bitmap, where every touched edge is genuinely novel
// (worst case for the "seen" bookkeeping, since every hit takes the
// bucket-update branch instead of being skipped).
func BenchmarkSHMCoverageReader_GetEdges_ColdStart(b *testing.B) {
	const size = 262144
	rng := rand.New(rand.NewSource(1))
	// One shared temp file for the whole benchmark -- GetEdges only checks that
	// s.f is non-nil, it never actually reads from it while s.mem is populated,
	// so there's no need to re-create it (and pay real file-I/O cost) every
	// b.N iteration just to satisfy that check.
	f, err := os.CreateTemp(b.TempDir(), "shm-bench-*")
	if err != nil {
		b.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		r := &SHMCoverageReader{f: f, mem: make([]byte, size), mapSize: size}
		for j := 0; j < size/7; j++ {
			idx := rng.Intn(size)
			r.mem[idx] = byte(1 + rng.Intn(254))
		}
		b.StartTimer()
		if _, err := r.GetEdges(); err != nil {
			b.Fatalf("GetEdges: %v", err)
		}
	}
}
