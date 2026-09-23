package engine

import (
	"strings"
	"testing"
	"void/internal/config"
)

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

func TestExtractPaginationCursorValue_RecognizesCommonFieldNames(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"camelCase", `{"items":[1,2],"nextCursor":"abc123"}`, "abc123"},
		{"snake_case", `{"items":[1,2],"next_cursor":"xyz"}`, "xyz"},
		{"pageToken", `{"items":[],"nextPageToken":"tok-1"}`, "tok-1"},
		{"bare cursor", `{"items":[],"cursor":"c-1"}`, "c-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractPaginationCursorValue(c.body)
			if !ok || got != c.want {
				t.Fatalf("extractPaginationCursorValue(%q) = (%q, %v), want (%q, true)", c.body, got, ok, c.want)
			}
		})
	}
}

func TestExtractPaginationCursorValue_NoneFound(t *testing.T) {
	if _, ok := extractPaginationCursorValue(`{"items":[1,2,3]}`); ok {
		t.Fatal("expected no cursor found in a response with no pagination field")
	}
	if _, ok := extractPaginationCursorValue(`not json`); ok {
		t.Fatal("expected no cursor found in a non-JSON body")
	}
	if _, ok := extractPaginationCursorValue(`[1,2,3]`); ok {
		t.Fatal("expected no cursor found in a top-level JSON array")
	}
	if _, ok := extractPaginationCursorValue(`{"nextCursor":""}`); ok {
		t.Fatal("expected an empty cursor value to not count")
	}
	if _, ok := extractPaginationCursorValue(`{"nextCursor":null}`); ok {
		t.Fatal("expected a null cursor value to not count")
	}
}

func TestExtractPaginationNextLink(t *testing.T) {
	headers := map[string]string{"Link": `</items?cursor=abc>; rel="next", </items?cursor=xyz>; rel="prev"`}
	got, ok := extractPaginationNextLink(headers)
	if !ok || got != "/items?cursor=abc" {
		t.Fatalf("expected the rel=\"next\" link, got (%q, %v)", got, ok)
	}
	if _, ok := extractPaginationNextLink(map[string]string{"Link": `</items?cursor=xyz>; rel="prev"`}); ok {
		t.Fatal("expected no next link when only rel=\"prev\" is present")
	}
	if _, ok := extractPaginationNextLink(nil); ok {
		t.Fatal("expected no next link with no Link header at all")
	}
}

func TestRequestPaginationParamName(t *testing.T) {
	cases := []struct {
		path     string
		wantName string
		wantOK   bool
	}{
		{"/items?cursor=abc", "cursor", true},
		{"/items?page_token=abc&limit=20", "page_token", true},
		{"/items?after=abc", "after", true},
		{"/items?limit=20", "", false},
		{"/items", "", false},
	}
	for _, c := range cases {
		name, ok := requestPaginationParamName(c.path)
		if ok != c.wantOK || (ok && name != c.wantName) {
			t.Errorf("requestPaginationParamName(%q) = (%q, %v), want (%q, %v)", c.path, name, ok, c.wantName, c.wantOK)
		}
	}
}

func TestReplaceQueryParam(t *testing.T) {
	got := replaceQueryParam("/items?cursor=old&limit=20", "cursor", "new")
	gotName, ok := requestPaginationParamName(got)
	if !ok || gotName != "cursor" {
		t.Fatalf("expected the pagination param to survive replacement, got %q", got)
	}
	if !strings.Contains(got, "cursor=new") {
		t.Fatalf("expected cursor updated to 'new', got %q", got)
	}
	if !strings.Contains(got, "limit=20") {
		t.Fatalf("expected the OTHER query param (limit) preserved, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// maybeEnqueuePaginationFollowup
// ---------------------------------------------------------------------------

func TestMaybeEnqueuePaginationFollowup_ContinuesWithCursor(t *testing.T) {
	f := &Fuzzer{sequenceQueue: make([]WorkItem, 0, 8)}
	source := WorkItem{Method: "GET", Path: "/items?cursor=page1"}
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2],"nextCursor":"page2"}`}
	state := &SequenceState{ID: "seq-1", Depth: 1}

	ok := f.maybeEnqueuePaginationFollowup(source, res, state)
	if !ok {
		t.Fatal("expected a pagination follow-up to be queued")
	}
	if len(f.sequenceQueue) != 1 {
		t.Fatalf("expected 1 queued item, got %d", len(f.sequenceQueue))
	}
	item := f.sequenceQueue[0]
	if !strings.Contains(item.Path, "cursor=page2") {
		t.Fatalf("expected the follow-up's cursor updated to page2, got %q", item.Path)
	}
	if item.MutationName != "pagination" {
		t.Fatalf("expected MutationName=pagination, got %q", item.MutationName)
	}
}

func TestMaybeEnqueuePaginationFollowup_UsesLinkHeaderWhenPresent(t *testing.T) {
	f := &Fuzzer{sequenceQueue: make([]WorkItem, 0, 8)}
	source := WorkItem{Method: "GET", Path: "/items?cursor=page1"}
	res := SendResult{
		Item: source, Status: 200, Body: `{"items":[1,2]}`,
		Headers: map[string]string{"Link": `</items?cursor=page2-from-link>; rel="next"`},
	}
	state := &SequenceState{ID: "seq-1", Depth: 1}

	ok := f.maybeEnqueuePaginationFollowup(source, res, state)
	if !ok {
		t.Fatal("expected a pagination follow-up to be queued from the Link header")
	}
	if f.sequenceQueue[0].Path != "/items?cursor=page2-from-link" {
		t.Fatalf("expected the Link header's own next URI used verbatim, got %q", f.sequenceQueue[0].Path)
	}
}

func TestMaybeEnqueuePaginationFollowup_NoOpWithoutExistingPaginationParam(t *testing.T) {
	f := &Fuzzer{sequenceQueue: make([]WorkItem, 0, 8)}
	// The response DOES carry a cursor field, but the ORIGINAL request never
	// had a recognized pagination param -- must not fire (this mechanism only
	// ever continues an already-paginated chain).
	source := WorkItem{Method: "GET", Path: "/items"}
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2],"nextCursor":"page2"}`}
	state := &SequenceState{ID: "seq-1", Depth: 1}

	if f.maybeEnqueuePaginationFollowup(source, res, state) {
		t.Fatal("expected no follow-up when the source request wasn't already paginated")
	}
	if len(f.sequenceQueue) != 0 {
		t.Fatalf("expected nothing queued, got %d", len(f.sequenceQueue))
	}
}

func TestMaybeEnqueuePaginationFollowup_OnlyGET(t *testing.T) {
	f := &Fuzzer{sequenceQueue: make([]WorkItem, 0, 8)}
	source := WorkItem{Method: "POST", Path: "/items?cursor=page1"}
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2],"nextCursor":"page2"}`}
	state := &SequenceState{ID: "seq-1", Depth: 1}

	if f.maybeEnqueuePaginationFollowup(source, res, state) {
		t.Fatal("expected POST to never trigger pagination chaining")
	}
}

func TestMaybeEnqueuePaginationFollowup_NoOpWhenNoNextCursorInResponse(t *testing.T) {
	f := &Fuzzer{sequenceQueue: make([]WorkItem, 0, 8)}
	source := WorkItem{Method: "GET", Path: "/items?cursor=page1"}
	// Last page: no nextCursor field at all.
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2]}`}
	state := &SequenceState{ID: "seq-1", Depth: 1}

	if f.maybeEnqueuePaginationFollowup(source, res, state) {
		t.Fatal("expected no follow-up on the last page (no next cursor)")
	}
}

// ---------------------------------------------------------------------------
// Integration: enqueueSequenceFollowups actually reaches the pagination path
// ---------------------------------------------------------------------------

func TestEnqueueSequenceFollowups_PaginationDoesNotMisfireSeqStopNoProducedValue(t *testing.T) {
	f := &Fuzzer{
		depIndex:                   map[int]DepInfo{},
		meta:                       map[int]TemplateMeta{1: {Method: "GET", Norm: "/items"}},
		tmplEPKey:                  map[int]string{},
		endpointStats:              map[string]*EndpointStats{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		sequenceQueue:              make([]WorkItem, 0, 8),
		cfg:                        config.Config{SequenceMaxDepth: 3, PaginationChaining: true, ResourceGraphEnabled: false},
	}
	state := &SequenceState{ID: "seq-1", Values: map[string]string{}, Provenance: map[string]string{}}
	source := WorkItem{TemplateID: 1, Method: "GET", Path: "/items?cursor=page1", SeqState: state}
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2],"nextCursor":"page2"}`}

	n := f.enqueueSequenceFollowups(res)

	if n != 1 {
		t.Fatalf("expected enqueueSequenceFollowups to report 1 enqueued (the pagination follow-up), got %d", n)
	}
	if f.seqStopNoProducedValue != 0 {
		t.Fatalf("expected the pagination follow-up to prevent the seqStopNoProducedValue early return, got %d", f.seqStopNoProducedValue)
	}
	if len(f.sequenceQueue) != 1 {
		t.Fatalf("expected 1 queued pagination follow-up, got %d", len(f.sequenceQueue))
	}
}

func TestEnqueueSequenceFollowups_PaginationDisabledByFlag(t *testing.T) {
	f := &Fuzzer{
		depIndex:                   map[int]DepInfo{},
		meta:                       map[int]TemplateMeta{1: {Method: "GET", Norm: "/items"}},
		tmplEPKey:                  map[int]string{},
		endpointStats:              map[string]*EndpointStats{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		sequenceQueue:              make([]WorkItem, 0, 8),
		cfg:                        config.Config{SequenceMaxDepth: 3, PaginationChaining: false, ResourceGraphEnabled: false},
	}
	state := &SequenceState{ID: "seq-1", Values: map[string]string{}, Provenance: map[string]string{}}
	source := WorkItem{TemplateID: 1, Method: "GET", Path: "/items?cursor=page1", SeqState: state}
	res := SendResult{Item: source, Status: 200, Body: `{"items":[1,2],"nextCursor":"page2"}`}

	f.enqueueSequenceFollowups(res)

	if len(f.sequenceQueue) != 0 {
		t.Fatalf("expected -pagination-chaining=false to suppress the follow-up entirely, got %d", len(f.sequenceQueue))
	}
	if f.seqStopNoProducedValue != 1 {
		t.Fatalf("expected the ordinary seqStopNoProducedValue path to fire when pagination is disabled, got %d", f.seqStopNoProducedValue)
	}
}
