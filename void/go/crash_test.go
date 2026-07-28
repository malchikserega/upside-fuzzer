package main

import (
	"path/filepath"
	"testing"
	"time"
)

func newCrashTestFuzzer(t *testing.T) *Fuzzer {
	t.Helper()
	dir := t.TempDir()
	crashW, err := NewJSONLWriter(filepath.Join(dir, "crashes.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter(crashes): %v", err)
	}
	uniqW, err := NewJSONLWriter(filepath.Join(dir, "unique.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter(unique): %v", err)
	}
	return &Fuzzer{
		cfg: Config{
			// Disable every expensive/file-writing side path so recordCrash's dedup
			// logic (the thing under test) is exercised without needing an HTTP
			// server, minimize/repro machinery, or PoC/timeline output dirs.
			CrashTriage:      false,
			MinimizeCrash:    false,
			ReproRuns:        0,
			CrashReplayCount: 0,
			PocDir:           "",
			TimelineDir:      "",
		},
		crashWriter:     crashW,
		uniqueWriter:    uniqW,
		uniqueCrashKeys: map[string]struct{}{},
		crashBoost:      map[string]int{},
		crashBoostCount: map[string]int{},
		startTime:       time.Now(),
	}
}

func mkCrashResult(method, path string, status int, exceptionType, body string) SendResult {
	return SendResult{
		Item: WorkItem{
			TemplateID:    1,
			Method:        method,
			Path:          path,
			MutationLabel: "mcat_boundary",
			MutationName:  "mutate_int",
		},
		Status:        status,
		Body:          body,
		ExceptionType: exceptionType,
	}
}

func TestRecordCrashDedupsIdenticalCrashes(t *testing.T) {
	f := newCrashTestFuzzer(t)
	res := mkCrashResult("GET", "/items/1", 500, "NullReferenceException", "boom")

	first := f.recordCrash(res)
	second := f.recordCrash(res)

	if !first {
		t.Error("expected the first occurrence of a crash to be reported as unique")
	}
	if second {
		t.Error("expected an identical repeat crash to be reported as a duplicate")
	}
	if f.uniqueCrashes != 1 {
		t.Errorf("expected 1 unique crash recorded, got %d", f.uniqueCrashes)
	}
	if f.totalCrashes != 2 {
		t.Errorf("expected totalCrashes to count both occurrences (2), got %d", f.totalCrashes)
	}
	if len(f.findings) != 1 {
		t.Errorf("expected exactly 1 finding (dedup must not double-append), got %d", len(f.findings))
	}
}

func TestRecordCrashDistinctExceptionsAreDistinctCrashes(t *testing.T) {
	f := newCrashTestFuzzer(t)
	a := mkCrashResult("GET", "/items/1", 500, "NullReferenceException", "boom")
	b := mkCrashResult("GET", "/items/1", 500, "ArgumentOutOfRangeException", "boom")

	if !f.recordCrash(a) {
		t.Error("expected first crash to be unique")
	}
	if !f.recordCrash(b) {
		t.Error("expected a crash with a different exception type to also be reported as unique")
	}
	if f.uniqueCrashes != 2 {
		t.Errorf("expected 2 distinct unique crashes, got %d", f.uniqueCrashes)
	}
}

func TestRecordCrashDistinctRoutesAreDistinctCrashes(t *testing.T) {
	f := newCrashTestFuzzer(t)
	a := mkCrashResult("GET", "/items/1", 500, "NullReferenceException", "boom")
	b := mkCrashResult("GET", "/orders/1", 500, "NullReferenceException", "boom")

	f.recordCrash(a)
	if !f.recordCrash(b) {
		t.Error("expected a crash on a different route to be reported as unique even with the same exception")
	}
	if f.uniqueCrashes != 2 {
		t.Errorf("expected 2 distinct unique crashes, got %d", f.uniqueCrashes)
	}
}

func TestCrashSignatureSameInputsProduceSameSignature(t *testing.T) {
	f := &Fuzzer{}
	sig1 := f.crashSignature("GET", "/items/1", 500, "mcat_boundary", "NullReferenceException", "boom")
	sig2 := f.crashSignature("GET", "/items/2", 500, "mcat_havoc", "NullReferenceException", "different body")
	// Different concrete resource ID (normalized away) and different mutation/body
	// (CrashSigMutation defaults false, and exception type dominates the response
	// fingerprint branch) -- same underlying bug must produce the same signature.
	if sig1 != sig2 {
		t.Errorf("expected the same root-cause signature across cosmetic differences, got %q vs %q", sig1, sig2)
	}
}

func TestCrashSignatureDiffersOnException(t *testing.T) {
	f := &Fuzzer{}
	sig1 := f.crashSignature("GET", "/items/1", 500, "mcat_boundary", "NullReferenceException", "boom")
	sig2 := f.crashSignature("GET", "/items/1", 500, "mcat_boundary", "ArgumentOutOfRangeException", "boom")
	if sig1 == sig2 {
		t.Error("expected a different exception type to produce a different signature")
	}
}

func TestCrashSignatureDiffersOnRoute(t *testing.T) {
	f := &Fuzzer{}
	sig1 := f.crashSignature("GET", "/items/1", 500, "mcat_boundary", "NullReferenceException", "boom")
	sig2 := f.crashSignature("GET", "/orders/1", 500, "mcat_boundary", "NullReferenceException", "boom")
	if sig1 == sig2 {
		t.Error("expected a different route to produce a different signature")
	}
}

func TestCrashSignatureDiffersOnStatus(t *testing.T) {
	f := &Fuzzer{}
	sig1 := f.crashSignature("GET", "/items/1", 500, "mcat_boundary", "", "boom")
	sig2 := f.crashSignature("GET", "/items/1", 502, "mcat_boundary", "", "boom")
	if sig1 == sig2 {
		t.Error("expected a different status code to produce a different signature")
	}
}

func TestNormalizeCrashPathSignatureCollapsesDynamicSegments(t *testing.T) {
	numeric := normalizeCrashPathSignature("/items/12345", false)
	uuid := normalizeCrashPathSignature("/items/550e8400-e29b-41d4-a716-446655440000", false)
	if numeric != "/items/{int}" {
		t.Errorf("expected numeric id collapsed to {int}, got %q", numeric)
	}
	if uuid != "/items/{uuid}" {
		t.Errorf("expected UUID collapsed to {uuid}, got %q", uuid)
	}
}

func TestNormalizeCrashPathSignatureEmptyBecomesRoot(t *testing.T) {
	if got := normalizeCrashPathSignature("", false); got != "/" {
		t.Errorf("expected empty path to normalize to \"/\", got %q", got)
	}
}

func TestNormalizeCrashMutationLabelCategorizes(t *testing.T) {
	cases := map[string]string{
		"mcat_boundary":            "mcat_boundary",
		"mutate_int":               "mutate_int",
		"crash_replay_1":           "crash_replay",
		"mcat_boundary+mutate_int": "mcat_boundary+mutate_int",
		"":                         "",
		// The label is split on "+" BEFORE category matching, including inside
		// havoc(...)'s own parens (a plain string split, not paren-aware) -- so
		// "havoc(mcat_a+mcat_b)" becomes two pieces, "havoc(mcat_a" (matches the
		// "havoc(" prefix check) and "mcat_b)" (matches the "mcat_" prefix check,
		// trailing paren kept as-is). Documented via this test rather than assumed.
		"havoc(mcat_a+mcat_b)":         "havoc+mcat_b)",
		"totally_unrecognized_label_x": "totally_unrecognized_label_x", // falls back to truncated raw text
	}
	for input, want := range cases {
		got := normalizeCrashMutationLabel(input)
		if got != want {
			t.Errorf("normalizeCrashMutationLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestExtractExceptionTypeParsesDotNetExceptionNames(t *testing.T) {
	cases := map[string]string{
		"System.ArgumentException: Value cannot be null": "ArgumentException",
		"Nop.Core.NopException: something broke":         "NopException",
		"no exception marker here at all":                "",
		"":                                               "",
	}
	for body, want := range cases {
		got := extractExceptionType(body)
		if got != want {
			t.Errorf("extractExceptionType(%q) = %q, want %q", body, got, want)
		}
	}
}
