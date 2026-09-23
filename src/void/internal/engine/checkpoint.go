package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// checkpoint.go — corpus + resource-graph checkpoint/resume
// (docs/ARCHITECTURE_STATEFUL.md §2.7): periodically snapshots the mutation
// corpus and the typed resource graph to a single JSON file, so a long
// campaign against the same target can survive a restart (crash, deliberate
// stop, machine reboot) without rebuilding valid producer->consumer chains
// from scratch. Entirely opt-in (-checkpoint-path unset writes nothing,
// -resume unset never reads one back) -- zero behavior change for any
// existing invocation.
//
// Deliberately NOT included: f.seenStateSigs/f.persistedWorkflowExemplars/
// endpoint stats/coverage bitmap state. The corpus (what to mutate next) and
// the resource graph (what real IDs/lifecycle state exist) are the two
// pieces of state whose loss actually costs a fresh run meaningful search
// progress; the rest either rebuilds cheaply from the corpus itself (a
// re-sent seed re-discovers its own coverage) or is deliberately run-scoped
// (endpoint stall/throttle counters SHOULD reset on a fresh process).

// Checkpoint is the on-disk shape saved/loaded by SaveCheckpoint/LoadCheckpoint.
type Checkpoint struct {
	SavedAt             string               `json:"saved_at"`
	Corpus              []Seed               `json:"corpus"`
	ResourceInstances   []*ResourceInstance  `json:"resource_instances,omitempty"`
	ResourceTransitions []ResourceTransition `json:"resource_transitions,omitempty"`
}

// SaveCheckpoint writes the current corpus and resource graph to path as
// JSON, atomically (write to a temp file, then rename) so a crash or
// concurrent read mid-write never observes a truncated/corrupt checkpoint.
func (f *Fuzzer) SaveCheckpoint(path string) error {
	if path == "" {
		return nil
	}
	cp := Checkpoint{
		SavedAt: time.Now().UTC().Format(time.RFC3339),
		Corpus:  f.corpus,
	}
	if f.resourceGraph != nil {
		cp.ResourceInstances, cp.ResourceTransitions = f.resourceGraph.exportAll()
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint marshal: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("checkpoint mkdir: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("checkpoint write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("checkpoint rename: %w", err)
	}
	return nil
}

// LoadCheckpoint reads path and restores the corpus + resource graph into f.
// Returns (loaded=false, nil) if path doesn't exist -- not an error, since
// "no checkpoint yet" is the expected state for a first run with -resume set.
func (f *Fuzzer) LoadCheckpoint(path string) (loaded bool, err error) {
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("checkpoint read: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return false, fmt.Errorf("checkpoint unmarshal: %w", err)
	}

	f.corpus = cp.Corpus
	f.seedSampler = NewFenwickSampler()
	for _, s := range f.corpus {
		f.seedSampler.Append(s.Energy)
	}

	if f.resourceGraph != nil && (len(cp.ResourceInstances) > 0 || len(cp.ResourceTransitions) > 0) {
		f.resourceGraph.importAll(cp.ResourceInstances, cp.ResourceTransitions)
	}
	return true, nil
}

// maybeSaveCheckpoint is the periodic, self-throttling save called from the
// main loop's own tick (worker.go) -- a no-op unless CheckpointPath is set
// and at least CheckpointIntervalSec has elapsed since the last save. Errors
// are logged, not fatal: a failed checkpoint write must never take down an
// otherwise-healthy fuzzing run.
func (f *Fuzzer) maybeSaveCheckpoint() {
	if f.cfg.CheckpointPath == "" {
		return
	}
	interval := f.cfg.CheckpointIntervalSec
	if interval <= 0 {
		interval = 60
	}
	if !f.lastCheckpointSave.IsZero() && time.Since(f.lastCheckpointSave) < time.Duration(interval*float64(time.Second)) {
		return
	}
	f.lastCheckpointSave = time.Now()
	if err := f.SaveCheckpoint(f.cfg.CheckpointPath); err != nil {
		fmt.Printf("Checkpoint save warning: %v\n", err)
	}
}
