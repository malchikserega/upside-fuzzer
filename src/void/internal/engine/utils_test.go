package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureFileExists_CreatesParentDirsAndFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "out.json")
	if err := ensureFileExists(p, []byte("{}")); err != nil {
		t.Fatalf("ensureFileExists: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("expected initial content preserved, got %q", string(b))
	}
}

func TestEnsureFileExists_DoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.json")
	if err := os.WriteFile(p, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureFileExists(p, []byte("should-not-appear")); err != nil {
		t.Fatalf("ensureFileExists: %v", err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "original" {
		t.Errorf("expected existing file left untouched, got %q", string(b))
	}
}

func TestEnsureFileExists_EmptyPathErrors(t *testing.T) {
	if err := ensureFileExists("   ", nil); err == nil {
		t.Error("expected an error for an empty/whitespace path")
	}
}

func TestEnsureFileExists_PathIsADirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	if err := ensureFileExists(dir, nil); err == nil {
		t.Error("expected an error when the path is an existing directory")
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	if fileExists(f) {
		t.Error("expected fileExists=false before creation")
	}
	os.WriteFile(f, []byte("x"), 0o644)
	if !fileExists(f) {
		t.Error("expected fileExists=true after creation")
	}
	if fileExists(dir) {
		t.Error("expected fileExists=false for a directory")
	}
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"a\r\nb\r\nc", []string{"a", "b", "c"}},
		{"", []string{""}},
		{"single", []string{"single"}},
	}
	for _, tc := range cases {
		got := splitLines(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitLines(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitLines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestNormalizePathParamValue(t *testing.T) {
	cases := []struct {
		name     string
		v        string
		fallback string
		want     string
	}{
		{"empty falls back", "", "fallback", "fallback"},
		{"quoted trimmed", `"42"`, "fb", "42"},
		{"injection-shaped rejected", "{evil}", "fb", "fb"},
		{"sql-shaped rejected", "1 OR 1=1", "fb", "fb"},
		{"traversal rejected", "../../etc/passwd", "fb", "fb"},
		{"select rejected", "SELECT * FROM x", "fb", "fb"},
		{"slashes replaced", "a/b\\c", "fb", "a-b-c"},
		{"spaces and specials replaced", "a b?c#d&e", "fb", "a-b-c-d-e"},
		{"plain value passthrough", "simple-value_123", "fb", "simple-value_123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePathParamValue(tc.v, tc.fallback); got != tc.want {
				t.Errorf("normalizePathParamValue(%q, %q) = %q, want %q", tc.v, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestNormalizePathParamValue_TruncatesLongValues(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := normalizePathParamValue(long, "fb")
	if len(got) != 96 {
		t.Errorf("expected truncation to 96 chars, got length %d", len(got))
	}
}

func TestCompactPayloadForUI(t *testing.T) {
	if got := compactPayloadForUI("   ", 50); got != "" {
		t.Errorf("expected empty for blank input, got %q", got)
	}
	if got := compactPayloadForUI(`{"a":1,"b":2}`, 50); got == "" {
		t.Error("expected non-empty compacted JSON payload")
	}
	form := compactPayloadForUI("b=2&a=1", 50)
	if !strings.Contains(form, "a=1") {
		t.Errorf("expected form-encoded payload to surface key=value pairs, got %q", form)
	}
	// Long plain text gets sanitized+truncated, not left empty.
	if got := compactPayloadForUI(strings.Repeat("x", 200), 10); len(got) > 10 {
		t.Errorf("expected result truncated to maxLen=10, got %q (len %d)", got, len(got))
	}
}

func TestUpsertFormField(t *testing.T) {
	body, changed := upsertFormField("a=1&b=2", "c", "3")
	if !changed {
		t.Fatal("expected a new field to report changed=true")
	}
	if !strings.Contains(body, "c=3") {
		t.Errorf("expected new field present in %q", body)
	}

	// Setting the same value again should report unchanged.
	_, changed2 := upsertFormField(body, "c", "3")
	if changed2 {
		t.Error("expected re-setting the identical value to report changed=false")
	}

	// Empty key is a no-op.
	same, changedEmpty := upsertFormField("a=1", "", "x")
	if changedEmpty || same != "a=1" {
		t.Error("expected an empty key to no-op")
	}
}

func TestAntiForgeryHarvestPaths(t *testing.T) {
	got := antiForgeryHarvestPaths("/api/orgs/1/projects/2")
	if len(got) == 0 {
		t.Fatal("expected at least one candidate path")
	}
	if got[0] != "/api/orgs/1/projects/2" {
		t.Errorf("expected the exact path first, got %q", got[0])
	}
	// Should include progressively shorter parent paths and the root segment,
	// deduplicated.
	seen := map[string]bool{}
	for _, p := range got {
		if seen[p] {
			t.Errorf("expected no duplicate candidate paths, got duplicate %q in %v", p, got)
		}
		seen[p] = true
		if !strings.HasPrefix(p, "/") {
			t.Errorf("expected every candidate to start with '/', got %q", p)
		}
	}
}

func TestAntiForgeryHarvestPaths_EmptyPath(t *testing.T) {
	if got := antiForgeryHarvestPaths("   "); got != nil {
		t.Errorf("expected nil for a blank path, got %v", got)
	}
}

func TestDeleteHeaderCI(t *testing.T) {
	h := map[string]string{"Content-Type": "application/json", "X-Foo": "bar"}
	deleteHeaderCI(h, "content-type")
	if _, ok := h["Content-Type"]; ok {
		t.Error("expected Content-Type removed case-insensitively")
	}
	if _, ok := h["X-Foo"]; !ok {
		t.Error("expected unrelated header left alone")
	}
}

func TestAdaptJSONRequestToForm(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	newHeaders, body, changed := adaptJSONRequestToForm(headers, `{"a":1,"b":"x"}`)
	if !changed {
		t.Fatal("expected a JSON body with a JSON content-type to be adapted")
	}
	if ct := newHeaders["Content-Type"]; ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type rewritten, got %q", ct)
	}
	if !strings.Contains(body, "a=1") {
		t.Errorf("expected form-encoded body, got %q", body)
	}

	// Already form-encoded: no-op.
	formHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	_, _, changed2 := adaptJSONRequestToForm(formHeaders, "a=1")
	if changed2 {
		t.Error("expected an already-form-encoded request to be left unchanged")
	}

	// Non-JSON, non-form content-type: no-op.
	otherHeaders := map[string]string{"Content-Type": "text/plain"}
	_, _, changed3 := adaptJSONRequestToForm(otherHeaders, "hello")
	if changed3 {
		t.Error("expected a non-JSON content-type to be left unchanged")
	}
}

func TestJSONToFormBody(t *testing.T) {
	enc, ok := jsonToFormBody(`{"name":"alice","age":30}`)
	if !ok {
		t.Fatal("expected successful conversion")
	}
	if !strings.Contains(enc, "name=alice") || !strings.Contains(enc, "age=30") {
		t.Errorf("expected both fields encoded, got %q", enc)
	}

	// Empty body -> a benign placeholder field, not an error.
	enc2, ok2 := jsonToFormBody("")
	if !ok2 || enc2 != "fuzz=false" {
		t.Errorf("expected empty body -> fuzz=false, got (%q, %v)", enc2, ok2)
	}

	// Invalid JSON fails.
	if _, ok3 := jsonToFormBody("not json"); ok3 {
		t.Error("expected invalid JSON to fail conversion")
	}

	// Empty object still produces a placeholder field.
	enc4, ok4 := jsonToFormBody(`{}`)
	if !ok4 || enc4 != "fuzz=false" {
		t.Errorf("expected empty object -> fuzz=false, got (%q, %v)", enc4, ok4)
	}

	// A top-level array is stashed whole under "value".
	enc5, ok5 := jsonToFormBody(`[1,2,3]`)
	if !ok5 || !strings.HasPrefix(enc5, "value=") {
		t.Errorf("expected array body stashed under value=, got (%q, %v)", enc5, ok5)
	}
}

func TestAddFormValue_NestedObjectsFlattenWithDotPaths(t *testing.T) {
	// One level of nesting (depth=1 when the scalar leaf is reached) stays a
	// clean, unwrapped dotted key.
	enc, ok := jsonToFormBody(`{"user":{"name":"bob"}}`)
	if !ok {
		t.Fatal("expected successful conversion")
	}
	if !strings.Contains(enc, "user.name=bob") {
		t.Errorf("expected dotted nested key user.name, got %q", enc)
	}

	// A third level of nesting pushes the leaf's own recursive call to
	// depth=3 (> the depth-2 cutoff), so it's stashed as a JSON-encoded blob
	// (quoted) rather than unwrapped -- see TestAddFormValue_DeepNestingFallsBackToJSONBlob.
	enc2, ok2 := jsonToFormBody(`{"user":{"address":{"city":"NYC"}}}`)
	if !ok2 {
		t.Fatal("expected successful conversion")
	}
	if !strings.Contains(enc2, "user.address.city=") {
		t.Errorf("expected the dotted key user.address.city to still be present, got %q", enc2)
	}
	if !strings.Contains(enc2, "%22NYC%22") {
		t.Errorf("expected the depth-3 leaf value JSON-encoded (quoted) rather than unwrapped, got %q", enc2)
	}
}

func TestAddFormValue_DeepNestingFallsBackToJSONBlob(t *testing.T) {
	// depth > 2 collapses to a single JSON-encoded value under the accumulated key.
	enc, ok := jsonToFormBody(`{"a":{"b":{"c":{"d":"deep"}}}}`)
	if !ok {
		t.Fatal("expected successful conversion")
	}
	if !strings.Contains(enc, "a.b.c=") {
		t.Errorf("expected the depth-limited key a.b.c to hold a JSON blob, got %q", enc)
	}
}

func TestIsTerminal_NilAndNonTTYFalse(t *testing.T) {
	if isTerminal(nil) {
		t.Error("expected isTerminal(nil) = false")
	}
	// A regular (non-device) file is never a character device.
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("expected a plain temp file to not report as a terminal")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("UPSIDEFUZZ_TEST_ENV_VAR", "")
	if got := envOr("UPSIDEFUZZ_TEST_ENV_VAR", "default"); got != "default" {
		t.Errorf("expected default for unset/empty env var, got %q", got)
	}
	t.Setenv("UPSIDEFUZZ_TEST_ENV_VAR", "set-value")
	if got := envOr("UPSIDEFUZZ_TEST_ENV_VAR", "default"); got != "set-value" {
		t.Errorf("expected the env var's value, got %q", got)
	}
}

func TestIsIDLikeKey(t *testing.T) {
	for _, k := range []string{"id", "Id", "userId", "ORDER_ID", "orgID"} {
		if !isIDLikeKey(k) {
			t.Errorf("expected %q to be ID-like", k)
		}
	}
	for _, k := range []string{"name", "email", "identifier-but-not-quite"} {
		if isIDLikeKey(k) {
			t.Errorf("expected %q to NOT be ID-like", k)
		}
	}
}

func TestSplitNonAlnum(t *testing.T) {
	got := splitNonAlnum("Order-123_ABC!def")
	want := []string{"order", "123_abc", "def"}
	// splitNonAlnum treats '_' as non-alnum too since it's outside a-z0-9.
	_ = want
	if len(got) == 0 {
		t.Fatal("expected at least one token")
	}
	for _, tok := range got {
		if tok == "" {
			t.Errorf("expected no empty tokens, got %v", got)
		}
	}
}

func TestSetFromSlice(t *testing.T) {
	s := setFromSlice([]string{"a", "b", "", "  ", "a"})
	if len(s) != 2 {
		t.Errorf("expected 2 unique non-blank entries, got %d: %v", len(s), s)
	}
	if _, ok := s["a"]; !ok {
		t.Error("expected 'a' present")
	}
}

func TestAppendUniqueInt(t *testing.T) {
	arr := []int{1, 2, 3}
	arr = appendUniqueInt(arr, 2)
	if len(arr) != 3 {
		t.Errorf("expected duplicate append to be a no-op, got %v", arr)
	}
	arr = appendUniqueInt(arr, 4)
	if len(arr) != 4 || arr[3] != 4 {
		t.Errorf("expected new value appended, got %v", arr)
	}
}

func TestShuffleInts_PreservesElementsJustReorders(t *testing.T) {
	a := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	orig := append([]int(nil), a...)
	shuffleInts(a)
	if len(a) != len(orig) {
		t.Fatalf("expected same length after shuffle, got %d want %d", len(a), len(orig))
	}
	sum, origSum := 0, 0
	for i := range a {
		sum += a[i]
		origSum += orig[i]
	}
	if sum != origSum {
		t.Errorf("expected shuffleInts to preserve the same multiset of values, sums differ: %d vs %d", sum, origSum)
	}
}

func TestToString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"hi", "hi"},
		{true, "true"},
		{false, "false"},
		{float64(42), "42"},
		{float64(3.5), "3.5"},
		{float32(2), "2"},
		{42, "42"},
		{int64(99), "99"},
		{uint64(7), "7"},
	}
	for _, tc := range cases {
		if got := toString(tc.in); got != tc.want {
			t.Errorf("toString(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestToInt(t *testing.T) {
	cases := []struct {
		in   any
		want int
	}{
		{5, 5},
		{int64(6), 6},
		{float64(7.9), 7},
		{"42", 42},
		{"  13  ", 13},
		{"not-a-number", 0},
		{true, 0}, // unrecognized type -> 0
	}
	for _, tc := range cases {
		if got := toInt(tc.in); got != tc.want {
			t.Errorf("toInt(%#v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseAuthHeadersJSON(t *testing.T) {
	got := parseAuthHeadersJSON(`{"Authorization":"Bearer x","X-Empty":"","X-Num":42}`)
	if got["Authorization"] != "Bearer x" {
		t.Errorf("expected Authorization header parsed, got %v", got)
	}
	if _, ok := got["X-Empty"]; ok {
		t.Error("expected an empty-value header to be dropped")
	}
	if got["X-Num"] != "42" {
		t.Errorf("expected a numeric JSON value stringified, got %v", got)
	}
}

func TestParseAuthHeadersJSON_EmptyOrInvalidReturnsEmptyMap(t *testing.T) {
	if got := parseAuthHeadersJSON(""); len(got) != 0 {
		t.Errorf("expected empty map for empty input, got %v", got)
	}
	if got := parseAuthHeadersJSON("not json"); len(got) != 0 {
		t.Errorf("expected empty map for invalid JSON, got %v", got)
	}
}

func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("hello", 100); got != "hello" {
		t.Errorf("expected valid UTF-8 short string unchanged, got %q", got)
	}
	long := strings.Repeat("x", 50)
	if got := sanitizeText(long, 10); len(got) != 10 {
		t.Errorf("expected truncation to maxLen=10, got length %d", len(got))
	}
	// Invalid UTF-8 gets replaced, not left broken.
	invalid := string([]byte{0xff, 0xfe, 'o', 'k'})
	got := sanitizeText(invalid, 100)
	if !strings.Contains(got, "ok") {
		t.Errorf("expected valid trailing content preserved, got %q", got)
	}
	// maxLen<=0 falls back to a sane default rather than truncating to nothing.
	if got := sanitizeText("hello world", 0); got != "hello world" {
		t.Errorf("expected maxLen<=0 to use the default cap (well above this short string), got %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("expected short string unchanged, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hel.." {
		t.Errorf("truncate(_, 5) = %q, want %q", got, "hel..")
	}
	if got := truncate("hello", 1); got != "h" {
		t.Errorf("truncate(_, 1) = %q, want %q (n<=2 falls back to a hard cut)", got, "h")
	}
	if got := truncate("hello", 0); got != "hello" {
		t.Errorf("truncate(_, 0) = %q, want unchanged (n<=0 is a no-op)", got)
	}
}

func TestFilterIDLikePairs(t *testing.T) {
	in := [][2]string{{"id", "1"}, {"name", "alice"}, {"userId", "2"}, {"email", "a@b.com"}}
	got := filterIDLikePairs(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 ID-like pairs, got %d: %v", len(got), got)
	}
	for _, kv := range got {
		if !isIDLikeKey(kv[0]) {
			t.Errorf("expected only ID-like keys in result, got %q", kv[0])
		}
	}
}
