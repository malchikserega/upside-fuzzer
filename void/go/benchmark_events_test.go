package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLogRequestEventNilWriterIsNoop verifies logRequestEvent doesn't panic
// or write anything when -event-log wasn't passed (eventLogWriter == nil),
// which is the default/most common case.
func TestLogRequestEventNilWriterIsNoop(t *testing.T) {
	f := &Fuzzer{}
	f.logRequestEvent(SendResult{Item: WorkItem{Method: "GET", Path: "/x"}, Status: 200}, 1)
	f.logEpochEvent("Baseline", "Havoc", "")
	f.logSequenceEvent(&SequenceState{ID: "seq-1", History: []SequenceStep{{Method: "GET", Path: "/x", Status: 200}}}, true)
	// No panic == pass.
}

// TestLogRequestEventWritesExpectedFields verifies the benchmark event
// stream (BENCHMARK_PLAN.md §12 request_event.jsonl) actually reaches disk
// with the fields the analysis pipeline depends on.
func TestLogRequestEventWritesExpectedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request_event.jsonl")
	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	f := &Fuzzer{eventLogWriter: w, cfg: Config{RunID: "run-abc"}, totalDone: 42}
	res := SendResult{
		Item: WorkItem{
			Method: "POST", Path: "/orders/123", Identity: "alice",
			EpochName: "Havoc", MutationName: "havoc", MutationLabel: "havoc+mcat_sqli",
			SeedIdx: 7, SeqDepth: 2, SeqState: &SequenceState{ID: "seq-xyz"},
		},
		Status: 201,
	}
	f.logRequestEvent(res, 5)
	_ = w.Close()

	rows := readJSONLLines(t, path)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row["run_id"] != "run-abc" {
		t.Errorf("run_id = %v, want run-abc", row["run_id"])
	}
	if row["endpoint_template"] != "/orders/{param}" && row["endpoint_template"] != "/orders/{id}" {
		// normalizeEndpointPath collapses the numeric id -- exact placeholder name
		// isn't the point here, just that it's collapsed, not the literal "123".
		if row["endpoint_template"] == "/orders/123" {
			t.Errorf("endpoint_template should collapse the numeric id, got %v", row["endpoint_template"])
		}
	}
	if row["sequence_id"] != "seq-xyz" {
		t.Errorf("sequence_id = %v, want seq-xyz", row["sequence_id"])
	}
	if row["coverage_delta"].(float64) != 5 {
		t.Errorf("coverage_delta = %v, want 5", row["coverage_delta"])
	}
	if row["state_change_flag"] != true {
		t.Errorf("state_change_flag should be true for a 201 POST, got %v", row["state_change_flag"])
	}
	if row["valid_flag"] != true {
		t.Errorf("valid_flag should be true for a 201, got %v", row["valid_flag"])
	}
}

// TestLogSequenceEventWritesExpectedFields verifies sequence_event.jsonl rows
// carry the shape signature and success flag the analysis pipeline needs.
func TestLogSequenceEventWritesExpectedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sequence_event.jsonl")
	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	f := &Fuzzer{sequenceEventWriter: w, cfg: Config{RunID: "run-abc"}}
	state := &SequenceState{
		ID:     "seq-1",
		Depth:  2,
		Energy: 12.5,
		History: []SequenceStep{
			{Method: "POST", Path: "/widgets", Status: 201},
			{Method: "GET", Path: "/widgets/1", Status: 200},
		},
	}
	f.logSequenceEvent(state, true)
	_ = w.Close()

	rows := readJSONLLines(t, path)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row["sequence_id"] != "seq-1" {
		t.Errorf("sequence_id = %v, want seq-1", row["sequence_id"])
	}
	if row["success_flag"] != true {
		t.Errorf("success_flag = %v, want true", row["success_flag"])
	}
	if row["new_coverage"].(float64) != 12.5 {
		t.Errorf("new_coverage = %v, want 12.5", row["new_coverage"])
	}
	steps, ok := row["steps"].([]any)
	if !ok || len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %v", row["steps"])
	}
}

func readJSONLLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var rows []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			break
		}
		rows = append(rows, row)
	}
	return rows
}
