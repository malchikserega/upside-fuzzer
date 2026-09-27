package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"void/internal/config"
)

// writeTestGrammar writes a minimal but real templates.export.json (and,
// optionally, a dict.json) into a fresh temp directory and returns a Config
// pointed at it, with every required output-file path also inside that temp
// dir -- everything NewFuzzer needs to succeed for real, no mocking.
func writeTestGrammar(t *testing.T, templates []Template) config.Config {
	t.Helper()
	dir := t.TempDir()
	exp := TemplateExport{Count: len(templates), Templates: templates}
	buf, err := json.Marshal(exp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "templates.export.json"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return config.Config{
		GrammarDir:                  dir,
		RequestTimeoutSec:           5,
		CrashFile:                   filepath.Join(dir, "crashes.jsonl"),
		UniqueCrashFile:             filepath.Join(dir, "unique-crashes.jsonl"),
		SummaryFile:                 filepath.Join(dir, "summary.json"),
		ReportFile:                  filepath.Join(dir, "report.json"),
		Concurrency:                 1,
		MinConcurrency:              1,
		MaxConcurrency:              4,
		ResourceGraphMaxPerType:     10,
		ResourceGraphMaxAliases:     4,
		ResourceGraphMaxTransitions: 10,
	}
}

func staticGETTemplate(id int, path string) Template {
	return Template{
		ID:        id,
		RequestID: path,
		Segments: []Segment{
			{Kind: "static", Value: "GET " + path + " HTTP/1.1\r\nHost: example.test\r\n\r\n"},
		},
	}
}

func TestNewFuzzer_SuccessLoadsTemplatesAndInitializesState(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{
		staticGETTemplate(1, "/api/widgets"),
		staticGETTemplate(2, "/api/health"),
	})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	if len(f.templates) != 2 {
		t.Fatalf("expected 2 templates loaded, got %d", len(f.templates))
	}
	if f.tmplByID[1] == nil || f.tmplByID[2] == nil {
		t.Fatal("expected tmplByID populated for both templates")
	}
	if f.target == "" {
		t.Error("expected a default target host")
	}
	if f.resourceGraph == nil {
		t.Error("expected resourceGraph initialized")
	}
	if f.seedSampler == nil {
		t.Error("expected seedSampler initialized")
	}
}

func TestNewFuzzer_NoTemplatesFileErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		GrammarDir:        dir,
		RequestTimeoutSec: 5,
		CrashFile:         filepath.Join(dir, "crashes.jsonl"),
		UniqueCrashFile:   filepath.Join(dir, "unique-crashes.jsonl"),
		SummaryFile:       filepath.Join(dir, "summary.json"),
		ReportFile:        filepath.Join(dir, "report.json"),
	}
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when templates.export.json does not exist and RefreshTemplates is false")
	}
}

func TestNewFuzzer_EmptyTemplateListErrors(t *testing.T) {
	cfg := writeTestGrammar(t, nil)
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error for a templates.export.json with zero templates")
	}
}

func TestFuzzerClose_DoesNotPanicAndClosesWriters(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	f.Close()
	// Closing twice must also be safe (defer + explicit call is a common pattern).
	f.Close()
}

func TestBuildTemplateMetaAndDependencies_PopulatesActiveIDsAndMeta(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{
		staticGETTemplate(1, "/api/widgets"),
		staticGETTemplate(2, "/api/health"),
	})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	f.buildTemplateMetaAndDependencies()

	if len(f.activeIDs) != 2 {
		t.Fatalf("expected 2 active template ids, got %d: %v", len(f.activeIDs), f.activeIDs)
	}
	m, ok := f.meta[1]
	if !ok {
		t.Fatal("expected meta populated for template 1")
	}
	if m.Method != "GET" {
		t.Errorf("expected method GET, got %q", m.Method)
	}
	if m.Norm != "/api/widgets" {
		t.Errorf("expected normalized path /api/widgets, got %q", m.Norm)
	}
}

func TestBuildTemplateMetaAndDependencies_SkipsSHMEndpoints(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{
		staticGETTemplate(1, "/shm/coverage"),
		staticGETTemplate(2, "/api/widgets"),
	})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	f.buildTemplateMetaAndDependencies()

	for _, id := range f.activeIDs {
		if id == 1 {
			t.Error("expected the /shm/ endpoint to be excluded from activeIDs")
		}
	}
}

func TestSeedBaselineCorpus_OneSeedPerActiveTemplate(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{
		staticGETTemplate(1, "/api/widgets"),
		staticGETTemplate(2, "/api/health"),
	})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	f.buildTemplateMetaAndDependencies()
	f.seedBaselineCorpus()

	if len(f.corpus) != len(f.activeIDs) {
		t.Fatalf("expected one seed per active template, got %d seeds for %d active ids", len(f.corpus), len(f.activeIDs))
	}
	for _, s := range f.corpus {
		if s.MutationName != "seed" || s.Energy != 1.0 {
			t.Errorf("expected a baseline seed record, got %+v", s)
		}
	}
}

func TestNewFuzzer_EmptyCrashFileErrors(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.CrashFile = ""
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when CrashFile is empty (NewJSONLWriter rejects an empty path)")
	}
}

func TestNewFuzzer_EmptyUniqueCrashFileErrors(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.UniqueCrashFile = ""
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when UniqueCrashFile is empty")
	}
}

func TestNewFuzzer_EmptySummaryFileErrors(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.SummaryFile = ""
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when SummaryFile is empty (ensureFileExists rejects an empty path)")
	}
}

func TestNewFuzzer_EmptyReportFileErrors(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.ReportFile = ""
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when ReportFile is empty")
	}
}

func TestNewFuzzer_InvalidDictJSONErrors(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	badDict := filepath.Join(cfg.GrammarDir, "dict.json")
	if err := os.WriteFile(badDict, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.DictPath = badDict
	if _, err := NewFuzzer(cfg); err == nil {
		t.Fatal("expected an error when the dictionary file has invalid JSON")
	}
}

func TestNewFuzzer_EventLogOpensSiblingWriters(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.EventLog = filepath.Join(cfg.GrammarDir, "events", "event_log.jsonl")
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	if f.eventLogWriter == nil || f.epochEventWriter == nil || f.sequenceEventWriter == nil {
		t.Error("expected all three event-log writers to be opened when -event-log is set")
	}
	for _, fname := range []string{"event_log.jsonl", "epoch_event.jsonl", "sequence_event.jsonl"} {
		if _, err := os.Stat(filepath.Join(cfg.GrammarDir, "events", fname)); err != nil {
			t.Errorf("expected %s to exist: %v", fname, err)
		}
	}
}

func TestBuildTemplateMetaAndDependencies_AdaptiveContentTypePrefersForm(t *testing.T) {
	jsonTemplate := Template{
		ID: 1, RequestID: "/widgets",
		Segments: []Segment{{Kind: "static", Value: "POST /widgets HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{}"}},
	}
	formTemplate := Template{
		ID: 2, RequestID: "/widgets",
		Segments: []Segment{{Kind: "static", Value: "POST /widgets HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=b"}},
	}
	cfg := writeTestGrammar(t, []Template{jsonTemplate, formTemplate})
	cfg.AdaptiveContentType = true
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	f.buildTemplateMetaAndDependencies()

	epKey := endpointKey("POST", normalizePath("/widgets"))
	if _, ok := f.forceFormEndpoints[epKey]; !ok {
		t.Error("expected the mixed JSON+form endpoint to be marked force-form under AdaptiveContentType")
	}
}

func TestBuildTemplateMetaAndDependencies_BuildsDependencyGraphFromReadsWrites(t *testing.T) {
	producer := Template{
		ID: 1, RequestID: "/api/orders",
		Segments: []Segment{{Kind: "static", Value: "POST /api/orders HTTP/1.1\r\nHost: x\r\n\r\n"}},
		Writes:   []string{"orderId"},
	}
	consumer := Template{
		ID: 2, RequestID: "/api/orders/{orderId}",
		Segments: []Segment{{Kind: "static", Value: "GET /api/orders/1 HTTP/1.1\r\nHost: x\r\n\r\n"}},
		Reads:    []string{"orderId"},
	}
	cfg := writeTestGrammar(t, []Template{producer, consumer})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()

	f.buildTemplateMetaAndDependencies()

	info1 := f.depIndex[1]
	if len(info1.Writes) == 0 {
		t.Error("expected template 1's DepInfo.Writes to be populated from t.Writes")
	}
	info2 := f.depIndex[2]
	if len(info2.Reads) == 0 {
		t.Error("expected template 2's DepInfo.Reads to be populated from t.Reads")
	}
	if len(f.depConsumers["orderId"]) == 0 {
		t.Error("expected depConsumers[\"orderId\"] to list the consuming template")
	}
}

func TestShouldRefreshTemplates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "templates.export.json")

	// Missing file always triggers a refresh.
	if !shouldRefreshTemplates(config.Config{}, p) {
		t.Error("expected refresh=true when the templates file doesn't exist")
	}

	os.WriteFile(p, []byte(`{"templates":[]}`), 0o644)

	// Existing file + RefreshTemplates=false -> no refresh needed.
	if shouldRefreshTemplates(config.Config{RefreshTemplates: false}, p) {
		t.Error("expected refresh=false for an existing file with RefreshTemplates unset")
	}

	// Existing file + RefreshTemplates=true -> always refresh.
	if !shouldRefreshTemplates(config.Config{RefreshTemplates: true}, p) {
		t.Error("expected refresh=true when RefreshTemplates is explicitly set")
	}
}
