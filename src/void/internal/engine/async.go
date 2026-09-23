package engine

import "strings"

// async.go — async-operation lifecycle model (Phase 4 #120,
// docs/ARCHITECTURE_STATEFUL.md's "async workflows: submit -> poll ->
// consume/cancel/retry" security-scenario family). Deliberately small:
// extraction already generically captures a 202's Location header and any
// embedded job/operation id (resource_extraction.go, including the query-
// param extraction added for exactly this in Phase 1 #103), and follow-up
// scheduling already biases toward resource-graph-known, available instances
// (resource_scheduling.go). What was missing is explicitly recognizing a 202
// submission as a distinct phase, so the planner keeps preferring to RE-POLL
// a still-pending operation through to a terminal state instead of wandering
// off to unrelated endpoints -- see sequence.go::recordResourceGraphStep
// (tags Attributes["async_submitted"]) and scoreConsumer's use of
// isAsyncOperationPending below.

// asyncTerminalStatusWords are common status-field values signaling an async
// operation has reached a terminal state (succeeded or failed) -- not an
// exhaustive taxonomy (there is no single standard here), a practical
// heuristic covering the common REST convention.
var asyncTerminalStatusWords = map[string]struct{}{
	"completed": {}, "complete": {}, "succeeded": {}, "success": {},
	"done": {}, "finished": {}, "failed": {}, "failure": {}, "error": {},
	"errored": {}, "cancelled": {}, "canceled": {}, "aborted": {}, "timeout": {},
}

// isAsyncSubmission reports whether a response looks like it kicked off an
// async operation rather than completing synchronously: the standard 202
// Accepted status, or any other 2xx response carrying a Retry-After header
// (RFC 7231 -- used on both 202 and 3xx redirects to a status-polling
// location).
func isAsyncSubmission(status int, headers map[string]string) bool {
	if status == 202 {
		return true
	}
	if status >= 200 && status < 300 {
		if strings.TrimSpace(getHeaderCI(headers, "Retry-After")) != "" {
			return true
		}
	}
	return false
}

// isAsyncTerminalStatusValue reports whether a resource's own observed
// status-like attribute value (ResourceInstance.Attributes["status"]) names a
// terminal state for an async operation.
func isAsyncTerminalStatusValue(status string) bool {
	_, terminal := asyncTerminalStatusWords[strings.ToLower(strings.TrimSpace(status))]
	return terminal
}

// isAsyncOperationPending reports whether inst is a known in-flight async
// submission (Attributes["async_submitted"] set by recordResourceGraphStep)
// that hasn't yet reported a terminal status -- scoreConsumer's poll-bias
// signal.
func isAsyncOperationPending(inst *ResourceInstance) bool {
	if inst == nil || inst.Attributes == nil {
		return false
	}
	submitted, _ := inst.Attributes["async_submitted"].(bool)
	if !submitted {
		return false
	}
	if statusVal, ok := inst.Attributes["status"].(string); ok && isAsyncTerminalStatusValue(statusVal) {
		return false
	}
	return true
}

// asyncPollBonus is scoreConsumer's (resource_scheduling.go) scoring bonus
// for a GET candidate whose resource type has at least one known,
// still-pending async instance -- comparable in weight to the unreached-
// consumer bonus, since "finish polling this operation" is exactly the kind
// of exploration this engine should prioritize over a cold, unrelated
// endpoint once an async chain is already in flight.
const asyncPollBonus = 12.0
