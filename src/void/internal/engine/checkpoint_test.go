package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"void/internal/config"
)

func newTestFuzzerForCheckpoint() *Fuzzer {
	return &Fuzzer{
		resourceGraph: newResourceGraph(ResourceGraphLimits{}),
		seedSampler:   NewFenwickSampler(),
		cfg:           config.Config{},
	}
}

func TestSaveCheckpoint_EmptyPathIsNoOp(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	if err := f.SaveCheckpoint(""); err != nil {
		t.Fatalf("expected no error for an empty path, got %v", err)
	}
}

func TestSaveCheckpoint_WritesReadableJSON(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	f.corpus = []Seed{{TemplateID: 1, Payload: "GET /widgets HTTP/1.1\r\n\r\n", Energy: 3.5, MutationName: "seed"}}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"POST /widgets", "seq-1", LifecycleCreated, 0.9,
	)

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := f.SaveCheckpoint(path); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected checkpoint file to exist: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected the .tmp file to be renamed away, not left behind")
	}
}

func TestSaveCheckpoint_CreatesParentDirectory(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	path := filepath.Join(t.TempDir(), "nested", "dir", "checkpoint.json")
	if err := f.SaveCheckpoint(path); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected checkpoint file to exist under a freshly-created nested dir: %v", err)
	}
}

func TestLoadCheckpoint_EmptyPathIsNoOp(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	loaded, err := f.LoadCheckpoint("")
	if err != nil || loaded {
		t.Fatalf("expected loaded=false err=nil for an empty path, got loaded=%v err=%v", loaded, err)
	}
}

func TestLoadCheckpoint_MissingFileReturnsNotLoadedNoError(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	loaded, err := f.LoadCheckpoint(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("expected no error for a missing checkpoint file (first -resume run), got %v", err)
	}
	if loaded {
		t.Fatal("expected loaded=false for a missing checkpoint file")
	}
}

func TestSaveThenLoadCheckpoint_RoundTripsCorpusAndResourceGraph(t *testing.T) {
	f1 := newTestFuzzerForCheckpoint()
	f1.corpus = []Seed{
		{TemplateID: 1, Payload: "GET /widgets HTTP/1.1\r\n\r\n", Energy: 3.5, MutationName: "seed"},
		{TemplateID: 2, Payload: "POST /orders HTTP/1.1\r\n\r\n", Energy: 12.0, MutationName: "mutate_body"},
	}
	f1.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"POST /widgets", "seq-1", LifecycleCreated, 0.9,
	)
	f1.resourceGraph.recordTransition(ResourceTransition{
		From: LifecycleUnknown, To: LifecycleCreated, Action: "create",
		ConsumerOp: "POST /widgets", SequenceID: "seq-1", StatusCode: 201, Result: "valid",
	})

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := f1.SaveCheckpoint(path); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	f2 := newTestFuzzerForCheckpoint()
	loaded, err := f2.LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if !loaded {
		t.Fatal("expected loaded=true")
	}

	if len(f2.corpus) != 2 {
		t.Fatalf("expected 2 restored corpus seeds, got %d", len(f2.corpus))
	}
	if f2.corpus[1].Payload != "POST /orders HTTP/1.1\r\n\r\n" || f2.corpus[1].Energy != 12.0 {
		t.Fatalf("expected corpus seed contents to round-trip exactly, got %+v", f2.corpus[1])
	}

	widget := f2.resourceGraph.getInstance(ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1")})
	if widget == nil {
		t.Fatal("expected the widget instance to survive the round trip")
	}
	if widget.Lifecycle != LifecycleCreated {
		t.Fatalf("expected restored lifecycle CREATED, got %s", widget.Lifecycle)
	}

	// A transition with the SAME signature as the one saved must now be
	// recognized as NOT novel -- proving seenTransition was actually
	// rebuilt from the restored transitions, not left empty.
	novel := f2.resourceGraph.recordTransition(ResourceTransition{
		From: LifecycleUnknown, To: LifecycleCreated, Action: "create",
		ConsumerOp: "POST /widgets", SequenceID: "seq-2", StatusCode: 201, Result: "valid",
	})
	if novel {
		t.Fatal("expected the restored transition's signature to already be known (not novel) after resume")
	}
}

func TestSaveThenLoadCheckpoint_SeedSamplerRebuiltFromRestoredCorpus(t *testing.T) {
	f1 := newTestFuzzerForCheckpoint()
	f1.corpus = []Seed{
		{TemplateID: 1, Energy: 1.0},
		{TemplateID: 2, Energy: 99.0},
	}
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := f1.SaveCheckpoint(path); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	f2 := newTestFuzzerForCheckpoint()
	if _, err := f2.LoadCheckpoint(path); err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if f2.seedSampler == nil {
		t.Fatal("expected a rebuilt seedSampler after resume")
	}
	// The high-energy seed (idx 1) should dominate weighted selection --
	// sample many times and confirm it's picked overwhelmingly more often.
	counts := map[int]int{}
	for i := 0; i < 200; i++ {
		idx := f2.seedSampler.Pick()
		counts[idx]++
	}
	if counts[1] <= counts[0] {
		t.Fatalf("expected the high-energy seed (idx=1, energy=99) to dominate sampling, got counts=%v", counts)
	}
}

func TestMaybeSaveCheckpoint_NoOpWithoutPath(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	f.maybeSaveCheckpoint() // must not panic, must not touch lastCheckpointSave
	if !f.lastCheckpointSave.IsZero() {
		t.Fatal("expected lastCheckpointSave to stay zero when CheckpointPath is unset")
	}
}

func TestMaybeSaveCheckpoint_ThrottlesByInterval(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	f.cfg.CheckpointPath = filepath.Join(t.TempDir(), "checkpoint.json")
	f.cfg.CheckpointIntervalSec = 3600 // effectively "don't save again this test"

	f.maybeSaveCheckpoint()
	first := f.lastCheckpointSave
	if first.IsZero() {
		t.Fatal("expected the first call to save immediately")
	}

	f.maybeSaveCheckpoint()
	if !f.lastCheckpointSave.Equal(first) {
		t.Fatal("expected a second call within the interval to be throttled (no re-save)")
	}
}

func TestMaybeSaveCheckpoint_SavesAgainAfterIntervalElapses(t *testing.T) {
	f := newTestFuzzerForCheckpoint()
	f.cfg.CheckpointPath = filepath.Join(t.TempDir(), "checkpoint.json")
	f.cfg.CheckpointIntervalSec = 0.01 // 10ms

	f.maybeSaveCheckpoint()
	first := f.lastCheckpointSave
	time.Sleep(30 * time.Millisecond)
	f.maybeSaveCheckpoint()
	if !f.lastCheckpointSave.After(first) {
		t.Fatal("expected a second call after the interval elapsed to save again")
	}
}
