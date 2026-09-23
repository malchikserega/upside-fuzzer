package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"void/internal/config"
)

func TestUseDashboardUI(t *testing.T) {
	if (&Fuzzer{cfg: config.Config{NoUI: true}}).useDashboardUI() {
		t.Error("expected false when NoUI is set")
	}
	if (&Fuzzer{cfg: config.Config{PlainUI: true}}).useDashboardUI() {
		t.Error("expected false when PlainUI is set")
	}
	if (&Fuzzer{cfg: config.Config{ForceUI: true}}).useDashboardUI() != true {
		t.Error("expected true when ForceUI is set")
	}
	if (&Fuzzer{uiInline: true}).useDashboardUI() != true {
		t.Error("expected true when uiInline is set")
	}
	if (&Fuzzer{}).useDashboardUI() {
		t.Error("expected false by default with nothing configured")
	}
}

func TestDashboardWidth(t *testing.T) {
	t.Setenv("SMART_FUZZER_UI_WIDTH", "")
	t.Setenv("COLUMNS", "")
	f := &Fuzzer{cfg: config.Config{UIWidth: 150}}
	if got := f.dashboardWidth(); got != 150 {
		t.Errorf("expected the configured width 150, got %d", got)
	}
	// Locked after first call, even if cfg changes.
	f.cfg.UIWidth = 90
	if got := f.dashboardWidth(); got != 150 {
		t.Errorf("expected the width to stay locked at 150, got %d", got)
	}
}

func TestDashboardWidth_ClampsToRange(t *testing.T) {
	t.Setenv("SMART_FUZZER_UI_WIDTH", "")
	t.Setenv("COLUMNS", "")
	f := &Fuzzer{cfg: config.Config{UIWidth: 5}}
	if got := f.dashboardWidth(); got != 80 {
		t.Errorf("expected clamp to the 80 floor, got %d", got)
	}
	f2 := &Fuzzer{cfg: config.Config{UIWidth: 999}}
	if got := f2.dashboardWidth(); got != 200 {
		t.Errorf("expected clamp to the 200 ceiling, got %d", got)
	}
}

func TestDashboardWidth_FallsBackToDefault(t *testing.T) {
	t.Setenv("SMART_FUZZER_UI_WIDTH", "")
	t.Setenv("COLUMNS", "")
	f := &Fuzzer{}
	if got := f.dashboardWidth(); got != 120 {
		t.Errorf("expected the default width 120 with nothing configured, got %d", got)
	}
}

func TestDashboardHeightHint(t *testing.T) {
	t.Setenv("LINES", "")
	f := &Fuzzer{}
	if got := f.dashboardHeightHint(); got != 44 {
		t.Errorf("expected the default height hint 44, got %d", got)
	}
	t.Setenv("LINES", "60")
	if got := f.dashboardHeightHint(); got != 60 {
		t.Errorf("expected the LINES env value 60, got %d", got)
	}
	t.Setenv("LINES", "5")
	if got := f.dashboardHeightHint(); got != 20 {
		t.Errorf("expected clamp to the 20 floor, got %d", got)
	}
}

func TestDashProgressBar(t *testing.T) {
	if got := dashProgressBar(0.5, 10, true); got != "#####-----" {
		t.Errorf("dashProgressBar(0.5,10,ascii) = %q", got)
	}
	if got := dashProgressBar(-1, 10, true); got != "----------" {
		t.Errorf("expected a negative fraction clamped to 0, got %q", got)
	}
	if got := dashProgressBar(2, 4, true); got != "####" {
		t.Errorf("expected a >1 fraction clamped to 1, got %q", got)
	}
	unicode := dashProgressBar(1.0, 3, false)
	if unicode != "███" {
		t.Errorf("dashProgressBar(1.0,3,unicode) = %q", unicode)
	}
}

func TestDashTruncate(t *testing.T) {
	if got := dashTruncate("hello", 0); got != "" {
		t.Errorf("expected empty string for maxLen<=0, got %q", got)
	}
	if got := dashTruncate("hi", 10); got != "hi" {
		t.Errorf("expected short strings to pass through unchanged, got %q", got)
	}
	if got := dashTruncate("hello world", 7); got != "hello.." {
		t.Errorf("dashTruncate truncation = %q, want %q", got, "hello..")
	}
	if got := dashTruncate("hello world", 2); got != "he" {
		t.Errorf("expected a maxLen<=2 to hard-truncate with no ellipsis, got %q", got)
	}
}

func TestDashBorders(t *testing.T) {
	if got := dashTopBorder(5, true); got != "+---+" {
		t.Errorf("dashTopBorder ascii = %q", got)
	}
	if got := dashBottomBorder(5, true); got != "+---+" {
		t.Errorf("dashBottomBorder ascii = %q", got)
	}
	if got := dashHLine(5, true); got != "+---+" {
		t.Errorf("dashHLine ascii = %q", got)
	}
	if got := dashTopBorder(5, false); got != "┌───┐" {
		t.Errorf("dashTopBorder unicode = %q", got)
	}
	if got := dashBottomBorder(5, false); got != "└───┘" {
		t.Errorf("dashBottomBorder unicode = %q", got)
	}
	if got := dashHLine(5, false); got != "├───┤" {
		t.Errorf("dashHLine unicode = %q", got)
	}
}

func TestDashRow(t *testing.T) {
	got := dashRow("hi", 10, true)
	if got != "| hi     |" {
		t.Errorf("dashRow ascii = %q", got)
	}
	if len([]rune(got)) != 10 {
		t.Errorf("expected dashRow output to be exactly `width` runes wide, got %d: %q", len([]rune(got)), got)
	}
	long := dashRow("this is a very long string that will not fit", 10, true)
	if len([]rune(long)) != 10 {
		t.Errorf("expected dashRow to always produce exactly `width` runes, got %d: %q", len([]rune(long)), long)
	}
}

func TestFormatMMSS(t *testing.T) {
	cases := map[float64]string{
		0:    "00:00",
		59:   "00:59",
		60:   "01:00",
		125:  "02:05",
		3661: "01:01:01",
		-5:   "00:00",
	}
	for in, want := range cases {
		if got := formatMMSS(in); got != want {
			t.Errorf("formatMMSS(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestSortEndpointsForUI(t *testing.T) {
	eps := []*EndpointStats{
		{Method: "GET", Path: "/a", Reqs: 5, NewEdges: 1, LastSeen: 1, S500: 0},
		{Method: "GET", Path: "/b", Reqs: 10, NewEdges: 0, LastSeen: 5, S500: 2},
		{Method: "GET", Path: "/c", Reqs: 2, NewEdges: 3, LastSeen: 3, S500: 0},
	}

	byReqs := append([]*EndpointStats{}, eps...)
	sortEndpointsForUI(byReqs, "requests")
	if byReqs[0].Path != "/b" {
		t.Errorf("expected /b (10 reqs) first when sorting by requests, got %s", byReqs[0].Path)
	}

	byEdges := append([]*EndpointStats{}, eps...)
	sortEndpointsForUI(byEdges, "edges")
	if byEdges[0].Path != "/c" {
		t.Errorf("expected /c (3 new edges) first when sorting by edges, got %s", byEdges[0].Path)
	}

	byRecent := append([]*EndpointStats{}, eps...)
	sortEndpointsForUI(byRecent, "recent")
	if byRecent[0].Path != "/b" {
		t.Errorf("expected /b (LastSeen=5) first when sorting by recent, got %s", byRecent[0].Path)
	}

	byAlpha := append([]*EndpointStats{}, eps...)
	sortEndpointsForUI(byAlpha, "alpha")
	if byAlpha[0].Path != "/a" || byAlpha[1].Path != "/b" || byAlpha[2].Path != "/c" {
		t.Errorf("expected alphabetical order by endpoint key, got %v", []string{byAlpha[0].Path, byAlpha[1].Path, byAlpha[2].Path})
	}

	byHot := append([]*EndpointStats{}, eps...)
	sortEndpointsForUI(byHot, "hot")
	if byHot[0].Path != "/b" {
		t.Errorf("expected /b (S500=2) first for the default 'hot' mode, got %s", byHot[0].Path)
	}
}

func TestWriteJSONReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "report.json")
	writeJSONReport(path, "test", map[string]any{"ok": true})

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected the report file to exist: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf, &got); err != nil {
		t.Fatalf("expected valid JSON, got error: %v, content: %s", err, buf)
	}
	if got["ok"] != true {
		t.Errorf("unexpected decoded content: %v", got)
	}
}

func TestWriteJSONReport_UnmarshalableValueWarnsWithoutPanicking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	// A channel can't be marshaled to JSON; writeJSONReport must warn and
	// return instead of panicking, and must not create the file.
	writeJSONReport(path, "test", map[string]any{"bad": make(chan int)})
	if _, err := os.Stat(path); err == nil {
		t.Error("expected no file written when marshaling fails")
	}
}
