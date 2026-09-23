package engine

// webhook.go — webhook/event callback lifecycle modeling (Phase 4 #123,
// docs/ARCHITECTURE_STATEFUL.md's "webhook/event callback lifecycle"
// security-scenario family).
//
// Honest scope note: this engine sends HTTP requests; it does not run an
// inbound listener to receive webhook callbacks. Genuinely observing "did
// the target actually fire a callback to a URL we control" would need a
// listener component -- port binding, accepting arbitrary inbound payloads
// -- a materially different and riskier feature than anything else added
// this session, and out of scope for this pass. SSRF-style probing of a
// webhook URL FIELD itself (does the registration handler make its own
// server-side fetch) is already covered by the existing SSRF payload set
// (mutations.go) and exploitationSignals' ssrf_metadata_reflected marker
// (identity.go) -- neither needed anything new here.
//
// What's implemented instead: recognizing a webhook/subscription's own soft-
// disabled lifecycle state, a gap #114's DELETE-only stale-object oracle
// can't see -- many webhook/subscription APIs turn a callback off via
// PATCH {"active": false} / {"enabled": false} rather than deleting it
// outright, and a subsequent trigger/test/fire call succeeding anyway is the
// same class of bug as a stale-object violation, just reached through a
// different (non-DELETE) lifecycle path.

// disabledStateFieldNames are common boolean field names signaling a
// resource has been explicitly turned off without being deleted -- the
// convention webhook/subscription endpoints most often use.
var disabledStateFieldNames = []string{"active", "enabled", "isactive", "isenabled", "is_enabled"}

// isSoftDisabledAttributes reports whether a resource's own last-known
// Attributes snapshot shows it explicitly disabled (a false-valued field
// matching disabledStateFieldNames), independent of DELETE ever happening.
func isSoftDisabledAttributes(attrs map[string]any) bool {
	for k, v := range attrs {
		for _, name := range disabledStateFieldNames {
			if !equalFoldASCII(k, name) {
				continue
			}
			if b, isBool := v.(bool); isBool && !b {
				return true
			}
		}
	}
	return false
}

// equalFoldASCII avoids importing strings just for this one case-insensitive
// compare in a hot-ish per-candidate path (called once per resource-graph
// candidate); disabledStateFieldNames is small and ASCII-only, so a byte
// loop is both sufficient and avoids the (negligible, but free to avoid)
// allocation strings.EqualFold's Unicode case-folding path can take.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// webhookTriggerActionVerbs are action verbs (deriveTransitionActionForTemplate)
// that cause a webhook/subscription to actually DO something -- the ones
// where "this still works despite being disabled" is the interesting
// finding, as opposed to e.g. a harmless GET of its own settings.
var webhookTriggerActionVerbs = map[string]struct{}{
	"trigger": {}, "test": {}, "fire": {}, "execute": {}, "invoke": {},
	"notify": {}, "send": {}, "resend": {}, "run": {},
}

// recordDisabledResourceStillActiveFinding is called from
// recordResourceGraphStep (sequence.go) when a trigger-shaped action
// succeeds against a resource whose own last-known attributes showed it
// explicitly disabled.
func (f *Fuzzer) recordDisabledResourceStillActiveFinding(source WorkItem, res SendResult, resourceType string) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeWorkflowBypass {
		return // same master + workflow-bypass toggles gate this -- same "lifecycle rule violated" family
	}
	f.recordAdversarialFinding(source, res, "disabled_resource_still_active", "likely_vuln_high", 8, []string{
		"disabled_resource_still_active",
		resourceType + "_explicitly_disabled_but_action_succeeded",
	})
}
