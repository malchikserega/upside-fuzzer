package engine

import (
	"encoding/json"
	"net/url"
	"strings"
)

// pagination.go — pagination/cursor-aware chaining (Phase 4 #121). List
// endpoints returning a next-page cursor/token are a chaining shape
// findFollowups (sequence.go) structurally can't produce: its same-family
// fallback explicitly excludes a template from following up on its OWN
// exact method+path (`if m.Method == sourceMethod && m.Norm == sourceNorm {
// continue }`), which is exactly what pagination needs -- "call this same
// endpoint again with an updated cursor." Handled here as its own small,
// direct mechanism rather than teaching the general dependency-based
// follow-up logic about self-reference.

// paginationCursorFieldNames are common JSON field names carrying a
// next-page cursor/token in a list response body.
var paginationCursorFieldNames = []string{
	"nextCursor", "next_cursor", "nextPageToken", "next_page_token",
	"nextPage", "next_page", "continuationToken", "continuation_token",
	"pageToken", "page_token", "cursor",
}

// paginationQueryParamNames are the query parameter names this mechanism
// recognizes as "this request is already paginated" -- a pagination
// follow-up only ever fires for a request that ALREADY carries one of these,
// so it can never misfire on an ordinary non-paginated GET.
var paginationQueryParamNames = []string{"cursor", "page_token", "pagetoken", "after", "continuation_token", "next"}

// extractPaginationCursorValue looks for a recognizable next-page cursor
// value in a list response body -- a top-level JSON string field matching a
// common pagination convention. Returns ok=false for the overwhelming
// majority of responses, which don't have one.
func extractPaginationCursorValue(body string) (value string, ok bool) {
	if !reJSONStartAny.MatchString(body) {
		return "", false
	}
	var js any
	if err := json.Unmarshal([]byte(body), &js); err != nil {
		return "", false
	}
	m, isObj := js.(map[string]any)
	if !isObj {
		return "", false
	}
	for _, name := range paginationCursorFieldNames {
		for k, v := range m {
			if !strings.EqualFold(k, name) {
				continue
			}
			if s, isStr := v.(string); isStr && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// extractPaginationNextLink looks for a Link response header with
// rel="next" -- when present it names the ENTIRE next-page URI directly
// (not just a cursor value), so it takes priority over a body-field cursor
// when both happen to be present.
func extractPaginationNextLink(headers map[string]string) (uri string, ok bool) {
	link := getHeaderCI(headers, "Link")
	if link == "" {
		return "", false
	}
	for _, m := range reLinkHeaderEntry.FindAllStringSubmatch(link, -1) {
		if len(m) == 3 && strings.EqualFold(m[2], "next") && m[1] != "" {
			return m[1], true
		}
	}
	return "", false
}

// requestPaginationParamName reports which recognized pagination query
// parameter name (if any) is already present on path.
func requestPaginationParamName(path string) (name string, ok bool) {
	i := strings.IndexByte(path, '?')
	if i < 0 {
		return "", false
	}
	q, err := url.ParseQuery(path[i+1:])
	if err != nil {
		return "", false
	}
	for _, candidate := range paginationQueryParamNames {
		for k := range q {
			if strings.EqualFold(k, candidate) {
				return k, true
			}
		}
	}
	return "", false
}

// replaceQueryParam sets name's value in path's query string, preserving the
// original key's exact casing when it's already present.
func replaceQueryParam(path, name, value string) string {
	i := strings.IndexByte(path, '?')
	base, rawQuery := path, ""
	if i >= 0 {
		base, rawQuery = path[:i], path[i+1:]
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		q = url.Values{}
	}
	for k := range q {
		if strings.EqualFold(k, name) {
			q.Set(k, value)
			return base + "?" + q.Encode()
		}
	}
	q.Set(name, value)
	return base + "?" + q.Encode()
}

// maybeEnqueuePaginationFollowup builds and queues exactly one follow-up
// request continuing a paginated list -- the SAME request repeated
// verbatim, with its pagination query parameter updated to the next-page
// cursor extracted from this response (or, when a Link rel="next" header
// names the entire next URI, that URI's own path+query used directly).
// No-op unless the SOURCE request already carried a recognized pagination
// parameter -- this only ever continues an ALREADY-paginated chain, never
// invents one. Returns whether a follow-up was actually queued.
func (f *Fuzzer) maybeEnqueuePaginationFollowup(source WorkItem, res SendResult, nextState *SequenceState) bool {
	if source.Method != "GET" {
		return false
	}
	if nextURI, ok := extractPaginationNextLink(res.Headers); ok {
		item := source
		item.Path = nextURI
		f.queuePaginationFollowup(item, nextState)
		return true
	}
	paramName, ok := requestPaginationParamName(source.Path)
	if !ok {
		return false
	}
	cursor, ok := extractPaginationCursorValue(res.Body)
	if !ok {
		return false
	}
	item := source
	item.Path = replaceQueryParam(source.Path, paramName, cursor)
	f.queuePaginationFollowup(item, nextState)
	return true
}

func (f *Fuzzer) queuePaginationFollowup(item WorkItem, nextState *SequenceState) {
	item.SeqDepth = nextState.Depth
	item.SeqState = nextState
	item.EpochName = "Sequence"
	item.MutationLabel = "pagination_next"
	item.MutationName = "pagination"
	item.Trace = f.extendTrace(item.Trace, item)
	if len(f.sequenceQueue) >= sequenceQueueMax {
		f.sequenceQueue = f.sequenceQueue[1:]
	}
	f.sequenceQueue = append(f.sequenceQueue, item)
}
