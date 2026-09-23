package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"void/internal/config"
)

func TestCurrentEpoch(t *testing.T) {
	epochs := []Epoch{
		{Name: "Baseline", Fraction: 0.05},
		{Name: "Deterministic", Fraction: 0.30},
		{Name: "Havoc", Fraction: 0.50},
		{Name: "Splicing", Fraction: 0.15},
	}
	total := 100 * time.Second

	cases := []struct {
		elapsed  time.Duration
		wantName string
	}{
		{0, "Baseline"},
		{4 * time.Second, "Baseline"},
		{10 * time.Second, "Deterministic"},
		{50 * time.Second, "Havoc"},
		{95 * time.Second, "Splicing"},
		{999 * time.Second, "Splicing"}, // past the end -> last epoch
	}
	for _, tc := range cases {
		_, ep := currentEpoch(epochs, tc.elapsed, total)
		if ep.Name != tc.wantName {
			t.Errorf("currentEpoch(elapsed=%v) = %q, want %q", tc.elapsed, ep.Name, tc.wantName)
		}
	}
}

func TestCurrentEpoch_ZeroTotalReturnsLastEpoch(t *testing.T) {
	epochs := []Epoch{{Name: "A", Fraction: 0.5}, {Name: "B", Fraction: 0.5}}
	_, ep := currentEpoch(epochs, 0, 0)
	if ep.Name != "B" {
		t.Errorf("expected the last epoch when total=0, got %q", ep.Name)
	}
}

func TestExtractPathParamNames(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/api/orgs/{orgId}/projects/{projectId}", []string{"orgId", "projectId"}},
		{"/api/widgets", nil},
		{"/api/widgets/{id}/{id}", []string{"id"}}, // deduplicated
	}
	for _, tc := range cases {
		got := extractPathParamNames(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("extractPathParamNames(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("extractPathParamNames(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestParseRawRequest_ValidRequest(t *testing.T) {
	raw := "POST /api/widgets HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	method, path, headers, body, err := parseRawRequest(raw)
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if method != "POST" {
		t.Errorf("method = %q, want POST", method)
	}
	if path != "/api/widgets" {
		t.Errorf("path = %q, want /api/widgets", path)
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header parsed, got %v", headers)
	}
	if body != `{"a":1}` {
		t.Errorf("body = %q, want %q", body, `{"a":1}`)
	}
}

func TestParseRawRequest_LFOnlySeparatorAlsoWorks(t *testing.T) {
	raw := "GET /health HTTP/1.1\nHost: x\n\n"
	method, path, _, _, err := parseRawRequest(raw)
	if err != nil {
		t.Fatalf("parseRawRequest: %v", err)
	}
	if method != "GET" || path != "/health" {
		t.Errorf("got method=%q path=%q", method, path)
	}
}

func TestParseRawRequest_MissingSeparatorErrors(t *testing.T) {
	if _, _, _, _, err := parseRawRequest("GET /x HTTP/1.1\r\nHost: y"); err == nil {
		t.Error("expected an error for a raw request with no header/body separator")
	}
}

func TestParseRawRequest_InvalidRequestLineErrors(t *testing.T) {
	if _, _, _, _, err := parseRawRequest("justoneword\r\n\r\n"); err == nil {
		t.Error("expected an error for a request line with fewer than 2 fields")
	}
}

func TestRemoveActiveTemplate(t *testing.T) {
	f := &Fuzzer{activeIDs: []int{1, 2, 3}}
	f.removeActiveTemplate(2)
	if len(f.activeIDs) != 2 {
		t.Fatalf("expected 2 remaining ids, got %v", f.activeIDs)
	}
	for _, id := range f.activeIDs {
		if id == 2 {
			t.Error("expected id 2 removed")
		}
	}
}

func TestBlockEndpointByTemplateID(t *testing.T) {
	f := &Fuzzer{
		activeIDs:        []int{1, 2, 3},
		meta:             map[int]TemplateMeta{1: {Method: "GET", Norm: "/api/x"}, 2: {Method: "GET", Norm: "/api/x"}, 3: {Method: "GET", Norm: "/api/y"}},
		tmplEPKey:        map[int]string{},
		blockedEndpoints: map[string]struct{}{},
	}
	removed := f.blockEndpointByTemplateID(1)
	if removed != 2 {
		t.Fatalf("expected 2 templates removed (both sharing /api/x), got %d", removed)
	}
	if len(f.activeIDs) != 1 || f.activeIDs[0] != 3 {
		t.Errorf("expected only template 3 (/api/y) left active, got %v", f.activeIDs)
	}
	// Calling again for the same now-blocked endpoint is a no-op.
	if removed2 := f.blockEndpointByTemplateID(2); removed2 != 0 {
		t.Errorf("expected re-blocking an already-blocked endpoint to remove 0, got %d", removed2)
	}
}

func TestShouldForceForm(t *testing.T) {
	f := &Fuzzer{
		cfg:                config.Config{AdaptiveContentType: true},
		forceFormEndpoints: map[string]struct{}{endpointKey("POST", normalizeEndpointPath("/api/widgets")): {}},
	}
	if !f.shouldForceForm("POST", "/api/widgets") {
		t.Error("expected true for a POST to a marked endpoint")
	}
	if f.shouldForceForm("GET", "/api/widgets") {
		t.Error("expected false for a non-write method even if marked")
	}
	if f.shouldForceForm("POST", "/api/other") {
		t.Error("expected false for an unmarked endpoint")
	}

	fDisabled := &Fuzzer{cfg: config.Config{AdaptiveContentType: false}, forceFormEndpoints: f.forceFormEndpoints}
	if fDisabled.shouldForceForm("POST", "/api/widgets") {
		t.Error("expected false when AdaptiveContentType is disabled, regardless of the marked set")
	}
}

func TestAdaptPathParamsFromRuntime_NoPlaceholderIsNoOp(t *testing.T) {
	f := &Fuzzer{}
	tmpl := &Template{RequestID: "/api/widgets"}
	got, labels := f.adaptPathParamsFromRuntime(tmpl, "/api/widgets")
	if got != "/api/widgets" || labels != nil {
		t.Errorf("expected no-op for a template with no path placeholders, got (%q, %v)", got, labels)
	}
}

func TestAdaptPathParamsFromRuntime_NilTemplateIsNoOp(t *testing.T) {
	f := &Fuzzer{}
	got, labels := f.adaptPathParamsFromRuntime(nil, "/api/widgets/1")
	if got != "/api/widgets/1" || labels != nil {
		t.Errorf("expected no-op for a nil template, got (%q, %v)", got, labels)
	}
}

func TestHavocDepth(t *testing.T) {
	f := &Fuzzer{}
	if got := f.havocDepth("mutate"); got != 1 {
		t.Errorf("expected non-havoc mode to always return depth 1, got %d", got)
	}
	if got := f.havocDepth("havoc"); got != 1 {
		t.Errorf("expected depth 1 with stallCounter=0, got %d", got)
	}
	f.stallCounter = 40
	if got := f.havocDepth("havoc"); got != 4 {
		t.Errorf("expected depth clamped to 4 with a high stall counter, got %d", got)
	}
}

func TestResolveDictionaryPath(t *testing.T) {
	dir := t.TempDir()
	dictPath := filepath.Join(dir, "dict.json")
	os.WriteFile(dictPath, []byte("{}"), 0o644)

	if got := resolveDictionaryPath(dictPath, ""); got == "" {
		t.Error("expected explicit --dict path to resolve")
	}
	if got := resolveDictionaryPath("", dir); got == "" {
		t.Error("expected grammar-dir/dict.json to resolve when it exists")
	}
	if got := resolveDictionaryPath("", t.TempDir()); got != "" {
		t.Errorf("expected empty string when no dict.json exists anywhere, got %q", got)
	}
}

func TestResolveExporterPath_ExplicitExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "export-templates.py")
	os.WriteFile(p, []byte("# stub"), 0o644)
	if got := resolveExporterPath(p); got != p {
		t.Errorf("expected an existing absolute path returned as-is, got %q", got)
	}
}

func TestResolveExporterPath_NonexistentFallsBackToInputUnchanged(t *testing.T) {
	got := resolveExporterPath("/definitely/does/not/exist/export-templates.py")
	if got != "/definitely/does/not/exist/export-templates.py" {
		t.Errorf("expected the original path returned when no candidate exists, got %q", got)
	}
}

func TestLoadTemplates_RealFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "templates.export.json")
	os.WriteFile(p, []byte(`{"count":2,"templates":[{"id":1,"request_id":"/a"},{"id":2,"request_id":"/b"}]}`), 0o644)

	got, err := loadTemplates(p)
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(got))
	}
}

func TestLoadTemplates_DedupsByID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "templates.export.json")
	os.WriteFile(p, []byte(`{"templates":[{"id":1,"request_id":"/a"},{"id":1,"request_id":"/a-dup"}]}`), 0o644)

	got, err := loadTemplates(p)
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected duplicate template ids collapsed to 1, got %d", len(got))
	}
}

func TestLoadTemplates_MissingFileErrors(t *testing.T) {
	if _, err := loadTemplates(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected an error for a missing templates file")
	}
}

func TestLoadTemplates_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "templates.export.json")
	os.WriteFile(p, []byte("not json"), 0o644)
	if _, err := loadTemplates(p); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func TestExportTemplates_MissingExporterErrors(t *testing.T) {
	err := exportTemplates("/definitely/does/not/exist.py", t.TempDir(), filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected an error when the exporter script doesn't exist")
	}
}

func TestTemplateEndpointKey(t *testing.T) {
	f := &Fuzzer{
		tmplEPKey: map[int]string{1: "GET /cached"},
		meta:      map[int]TemplateMeta{2: {Method: "POST", Norm: "/computed"}},
	}
	if got := f.templateEndpointKey(1); got != "GET /cached" {
		t.Errorf("expected the cached key, got %q", got)
	}
	if got := f.templateEndpointKey(2); got != endpointKey("POST", "/computed") {
		t.Errorf("expected the computed key from meta, got %q", got)
	}
	if got := f.templateEndpointKey(99); got != "" {
		t.Errorf("expected an empty key for an unknown template, got %q", got)
	}
}

func TestIsTemplateBlocked(t *testing.T) {
	f := &Fuzzer{
		tmplEPKey:        map[int]string{1: "GET /x"},
		blockedEndpoints: map[string]struct{}{"GET /x": {}},
	}
	if !f.isTemplateBlocked(1) {
		t.Error("expected template 1 to be reported blocked")
	}
	if f.isTemplateBlocked(2) {
		t.Error("expected an unknown template to be reported not-blocked")
	}
}

func richFuzzableTemplate(id int) Template {
	return Template{
		ID:        id,
		RequestID: "/api/widgets/{widgetId}",
		Segments: []Segment{
			{Kind: "static", Value: "PUT /api/widgets/1 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"name\":\""},
			{Kind: "fuzzable", ValueType: "string", Default: "hello", Name: "name"},
			{Kind: "static", Value: "\",\"count\":"},
			{Kind: "fuzzable", ValueType: "int", Default: "3", Name: "count"},
			{Kind: "static", Value: ",\"couponCode\":\""},
			{Kind: "custom_payload", PayloadKey: "couponCode", Default: "CUSTOM_PAYLOAD"},
			{Kind: "static", Value: "\",\"ownerId\":\""},
			{Kind: "dynamic", Name: "ownerId"},
			{Kind: "static", Value: "\"}"},
		},
	}
}

func TestRenderTemplateContext_MutateModeProducesValidRequest(t *testing.T) {
	f := &Fuzzer{
		tmplByID: map[int]*Template{1: ptrTemplate(richFuzzableTemplate(1))},
		runtime:  newRuntimeStore(),
		dict:     &DictStore{},
	}
	for i := 0; i < 50; i++ {
		item, err := f.renderTemplateContext(1, "mutate", 1, -1, nil)
		if err != nil {
			t.Fatalf("renderTemplateContext(mutate): %v", err)
		}
		if item.Method != "PUT" {
			t.Errorf("expected method PUT, got %q", item.Method)
		}
		if item.MutationLabel == "" {
			t.Error("expected a non-empty mutation label")
		}
	}
}

func TestRenderTemplateContext_HavocModeProducesValidRequest(t *testing.T) {
	f := &Fuzzer{
		tmplByID:     map[int]*Template{1: ptrTemplate(richFuzzableTemplate(1))},
		runtime:      newRuntimeStore(),
		dict:         &DictStore{},
		stallCounter: 40,
	}
	for i := 0; i < 30; i++ {
		item, err := f.renderTemplateContext(1, "havoc", f.havocDepth("havoc"), -1, nil)
		if err != nil {
			t.Fatalf("renderTemplateContext(havoc): %v", err)
		}
		if item.Method != "PUT" {
			t.Errorf("expected method PUT, got %q", item.Method)
		}
	}
}

func TestRenderTemplateContext_SequenceContextOverridesCustomAndDynamicValues(t *testing.T) {
	f := &Fuzzer{
		tmplByID: map[int]*Template{1: ptrTemplate(richFuzzableTemplate(1))},
		runtime:  newRuntimeStore(),
		dict:     &DictStore{},
	}
	seqState := &SequenceState{Values: map[string]string{"couponCode": "SEQ-COUPON", "ownerId": "seq-owner-1"}}
	item, err := f.renderTemplateContext(1, "none", 1, -1, &WorkItem{SeqState: seqState})
	if err != nil {
		t.Fatalf("renderTemplateContext: %v", err)
	}
	if !strings.Contains(item.Body, "SEQ-COUPON") {
		t.Errorf("expected the sequence-context couponCode value substituted, got body=%q", item.Body)
	}
	if !strings.Contains(item.Body, "seq-owner-1") {
		t.Errorf("expected the sequence-context ownerId value substituted, got body=%q", item.Body)
	}
}

func TestRenderTemplateContext_UnknownTemplateErrors(t *testing.T) {
	f := &Fuzzer{tmplByID: map[int]*Template{}}
	if _, err := f.renderTemplateContext(99, "none", 1, -1, nil); err == nil {
		t.Error("expected an error for an unregistered template id")
	}
}

func TestAdaptPathParamsFromRuntime_SubstitutesFromDict(t *testing.T) {
	f := &Fuzzer{
		runtime: newRuntimeStore(),
		dict:    &DictStore{arrays: map[string][]string{"widgetId": {"real-widget-42"}}},
	}
	tmpl := &Template{RequestID: "/api/widgets/{widgetId}"}
	// adaptPathParamsFromRuntime only replaces segments that are STILL
	// placeholder-shaped (empty/"fuzz*"/"custom_payload*") in the rendered
	// path -- a real concrete id like "1" is left alone (see
	// isPathPlaceholderValue, utils.go).
	got, labels := f.adaptPathParamsFromRuntime(tmpl, "/api/widgets/fuzzstring")
	if got == "/api/widgets/fuzzstring" {
		t.Error("expected the still-placeholder-shaped segment to be substituted from the dict-backed candidate pool")
	}
	if len(labels) == 0 || labels[0] != "path_widgetId" {
		t.Errorf("expected a path_widgetId label, got %v", labels)
	}
}

func TestPrepareItemForSend_InjectsAntiForgeryTokenIntoFormBody(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryHeader: "X-CSRF-Token", AntiForgeryField: "__RequestVerificationToken"})
	f.registerAntiForgeryToken("live-token", time.Now())
	item := WorkItem{
		Method:  "POST",
		Path:    "/checkout",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    "amount=10",
	}
	got := f.prepareItemForSend(item)
	if getHeaderCI(got.Headers, "X-CSRF-Token") != "live-token" {
		t.Errorf("expected the anti-forgery header set, got headers=%v", got.Headers)
	}
	if !strings.Contains(got.Body, "live-token") {
		t.Errorf("expected the anti-forgery field appended to the form body, got %q", got.Body)
	}
}

func TestPrepareItemForSend_DisabledOrNonFormIsNoOp(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{})
	f.cfg.AutoAntiForgery = false
	item := WorkItem{Method: "POST", Path: "/checkout", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: "a=b"}
	got := f.prepareItemForSend(item)
	if got.Body != "a=b" {
		t.Errorf("expected a no-op when AutoAntiForgery is disabled, got body=%q", got.Body)
	}

	f2 := newAntiForgeryTestFuzzer(config.Config{})
	item2 := WorkItem{Method: "POST", Path: "/api/checkout", Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"a":1}`}
	got2 := f2.prepareItemForSend(item2)
	if got2.Body != `{"a":1}` {
		t.Errorf("expected a no-op for a JSON API request, got body=%q", got2.Body)
	}
}

func ptrTemplate(t Template) *Template { return &t }

func TestBuildWorkItem_DrainsReplayQueueFirst(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.CrashReplayProb = 1.0
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()

	f.replayQueue = append(f.replayQueue, WorkItem{TemplateID: 1, Method: "GET", Path: "/api/widgets"})
	item, ok := f.buildWorkItem(0, Epoch{Name: "Replay", Mode: "none"})
	if !ok {
		t.Fatal("expected a work item drained from the replay queue")
	}
	if item.TemplateID != 1 {
		t.Errorf("expected the queued replay item's template id, got %d", item.TemplateID)
	}
	if len(f.replayQueue) != 0 {
		t.Errorf("expected the replay queue drained, got %d remaining", len(f.replayQueue))
	}
}

func TestBuildWorkItem_DrainsRaceQueue(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()

	f.raceQueue = append(f.raceQueue, WorkItem{TemplateID: 1, Method: "GET", Path: "/api/widgets"})
	item, ok := f.buildWorkItem(0, Epoch{Name: "Race", Mode: "none"})
	if !ok || item.TemplateID != 1 {
		t.Fatalf("expected a work item drained from the race queue, got ok=%v item=%+v", ok, item)
	}
}

func TestBuildWorkItem_DrainsOracleQueueEagerly(t *testing.T) {
	f := &Fuzzer{oracleQueue: []WorkItem{{TemplateID: 5, Method: "GET", Path: "/api/probe"}}}
	item, ok := f.buildWorkItem(0, Epoch{Name: "Oracle", Mode: "none"})
	if !ok || item.TemplateID != 5 {
		t.Fatalf("expected the oracle queue item returned as-is, got ok=%v item=%+v", ok, item)
	}
	if len(item.Trace) == 0 {
		t.Error("expected a trace to be attached when the oracle item didn't already have one")
	}
}

func TestBuildWorkItem_DrainsSequenceQueue(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets")})
	cfg.SequenceProb = 1.0
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()

	f.sequenceQueue = append(f.sequenceQueue, WorkItem{TemplateID: 1, Method: "GET", Path: "/api/widgets"})
	item, ok := f.buildWorkItem(0, Epoch{Name: "Sequence", Mode: "none"})
	if !ok || item.TemplateID != 1 {
		t.Fatalf("expected a work item drained from the sequence queue, got ok=%v item=%+v", ok, item)
	}
}

func TestBuildWorkItem_NoActiveTemplatesReturnsFalse(t *testing.T) {
	f := &Fuzzer{}
	if _, ok := f.buildWorkItem(0, Epoch{Name: "Baseline", Mode: "none"}); ok {
		t.Error("expected false when there are no active templates and every queue is empty")
	}
}

func TestBuildWorkItem_WeightedPickPath(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{staticGETTemplate(1, "/api/widgets"), staticGETTemplate(2, "/api/health")})
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()

	item, ok := f.buildWorkItem(0, Epoch{Name: "Baseline", Mode: "none"})
	if !ok {
		t.Fatal("expected a rendered work item via the weighted-template pick path")
	}
	if item.TemplateID != 1 && item.TemplateID != 2 {
		t.Errorf("expected one of the active templates picked, got %d", item.TemplateID)
	}
}

func TestBuildWorkItem_SeedMutatePath(t *testing.T) {
	cfg := writeTestGrammar(t, []Template{richFuzzableTemplate(1)})
	cfg.SequenceProb = 0
	f, err := NewFuzzer(cfg)
	if err != nil {
		t.Fatalf("NewFuzzer: %v", err)
	}
	defer f.Close()
	f.buildTemplateMetaAndDependencies()
	f.seedBaselineCorpus()

	item, ok := f.buildWorkItem(0, Epoch{Name: "Deterministic", Mode: "mutate"})
	if !ok {
		t.Fatal("expected a rendered work item via the seed-mutate path")
	}
	if item.TemplateID != 1 {
		t.Errorf("expected template 1 picked from the single-seed corpus, got %d", item.TemplateID)
	}
}
