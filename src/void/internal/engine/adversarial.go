package engine

import (
	"fmt"
	"strings"
	"time"
)

// adversarial.go — the adversarial branch planner
// (docs/ARCHITECTURE_STATEFUL.md §2.4/§3, task spec's "adversarial branch
// generator"). oracle.go's existing BOLA/mass-assignment/differential probes
// all share one shape: replay the CURRENT successful request under a
// different identity/no-auth/parser-confusion variant. These three oracles
// start from a different place -- a resource the resource graph has ALREADY
// confirmed is real (created and tracked through a valid chain) -- and check
// whether the server correctly rejects exactly one controlled violation of
// it:
//
//   - stale object:      an operation succeeds against a resource already
//     observed as deleted (direct detection -- the
//     resource graph's own lifecycle classification
//     already knows this happened, no replay needed).
//   - stale ETag:        a write is accepted despite carrying a
//     deliberately wrong If-Match (active probe replay).
//   - workflow bypass:   an action endpoint succeeds against a resource
//     whose known state doesn't satisfy the endpoint's
//     own declared predecessor state (direct detection,
//     x-state-transition-gated -- see below).
//
// Each is intentionally narrow and low-noise rather than a general-purpose
// "try everything" fuzzer: every one of them requires the resource graph to
// already have concrete, confirmed evidence before firing, which is what
// keeps false-positive volume down (the same design principle BOLA's
// "identical response" tiering already uses).

const (
	oracleKindStaleETag = "stale_etag"
)

// staleETagFabricatedValue is the deliberately-wrong If-Match value used by
// maybeEnqueueStaleETagProbe -- constant and recognizable (rather than
// derived from the real ETag) so it's obviously a probe artifact if it ever
// shows up in a target's own logs during investigation.
const staleETagFabricatedValue = `"void-stale-etag-probe-0000000000000000"`

// maybeEnqueueStaleETagProbe replays a just-succeeded mutating write against
// a resource the graph already has a known Version (ETag) for, but with a
// deliberately wrong If-Match header -- if the server accepts it anyway
// (2xx) instead of rejecting it (409/412/428), optimistic locking isn't
// actually enforced: a lost-update / TOCTOU write can silently clobber a
// concurrent change.
func (f *Fuzzer) maybeEnqueueStaleETagProbe(res SendResult) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeStaleETag || res.Item.OracleKind != "" {
		return
	}
	if !f.cfg.ResourceGraphEnabled || f.resourceGraph == nil {
		return
	}
	if res.Status < 200 || res.Status >= 300 {
		return
	}
	switch res.Item.Method {
	case "PUT", "PATCH", "DELETE":
	default:
		return
	}
	inst := f.lookupInstanceForRequestPath(res.Item.Path)
	if inst == nil || inst.Version == "" || inst.Version == staleETagFabricatedValue {
		return
	}
	epKey := endpointKey(res.Item.Method, normalizeEndpointPath(res.Item.Path))
	if f.adversarialProbeCount[epKey] >= f.cfg.AccessProbeMaxPerEndpoint {
		return
	}

	p := res.Item
	p.OracleKind = oracleKindStaleETag
	p.OracleOriginIdentity = res.Item.Identity
	p.OracleOriginStatus = res.Status
	p.OracleOriginFP = inst.Version // the REAL, current ETag -- for the finding's own log
	p.SeedIdx = -1
	p.Trace = nil
	p.Headers = cloneStringMap(p.Headers)
	setHeaderCI(p.Headers, "If-Match", staleETagFabricatedValue)
	p.MutationName = "adv_" + oracleKindStaleETag
	p.MutationLabel = "adversarial_probe(" + oracleKindStaleETag + ")"

	f.oracleEnqueue(p)
	f.adversarialProbeCount[epKey]++
}

// lookupInstanceForRequestPath resolves path's own concrete resource
// instance (if any) via route-template matching against the request's OWN
// path -- the same mechanism recordResourceGraphStep already uses for a
// DELETE's empty-body response, reused here so both stale-ETag and
// workflow-bypass detection share one lookup instead of re-deriving it.
// Prefers the LAST (deepest, i.e. this endpoint's own) matched candidate
// over any parent segment.
func (f *Fuzzer) lookupInstanceForRequestPath(path string) *ResourceInstance {
	rt := resourceTypeFromEndpointPath(normalizePath(path))
	if rt == "" {
		return nil
	}
	candidates := f.matchRouteTemplateCandidates(path, "", "request_path", confRouteTemplateOnly)
	var best *ExtractedCandidate
	for i := range candidates {
		if candidates[i].ResourceType == rt {
			best = &candidates[i]
		}
	}
	if best == nil {
		return nil
	}
	return f.resourceGraph.getInstance(best.toIdentity())
}

// requestPathHasConfirmedContext reports whether path's typed segments
// include at least one resource the resource graph already knows is real --
// used to valid-chain-gate the mass-assignment oracle (oracle.go's
// maybeEnqueueMassAssignProbe, Phase 3 item #117): a PUT/PATCH's own
// resource, or a nested POST's parent, should be a genuine already-created
// resource, not an arbitrary/guessed path. Deliberately permissive when
// there's nothing TO confirm -- disabled resource graph, or a flat path with
// no typed segments at all (e.g. a plain top-level "POST /widgets" collection
// create has no parent/self context to check) both pass through unchanged,
// so this only ever narrows firing, never silently disables the oracle for
// targets/endpoints the resource graph can't say anything about.
func (f *Fuzzer) requestPathHasConfirmedContext(path string) bool {
	if !f.cfg.ResourceGraphEnabled || f.resourceGraph == nil {
		return true
	}
	candidates := f.matchRouteTemplateCandidates(path, "", "request_path", confRouteTemplateOnly)
	if len(candidates) == 0 {
		return true
	}
	for _, c := range candidates {
		if f.resourceGraph.getInstance(c.toIdentity()) != nil {
			return true
		}
	}
	return false
}

// recordStaleObjectFinding is called directly from recordResourceGraphStep
// (sequence.go) -- unlike the probe-based oracles above, no replay is
// needed: the resource graph's own lifecycle classification
// (deriveLifecycleTransition) has ALREADY determined that this exact
// request succeeded against a resource it knows was deleted. kind names
// which specific violation shape (stale read / update-after-delete /
// repeated deletion) for the finding's own reasons.
func (f *Fuzzer) recordStaleObjectFinding(source WorkItem, res SendResult, resourceType, violation string) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeStaleObject {
		return
	}
	class, severity := "likely_vuln", 6
	if violation == "update_after_delete" {
		// A write that "succeeded" on a deleted resource is a stronger signal
		// than a stale read -- it implies actual state was mutated/created
		// where none should exist.
		class, severity = "likely_vuln_high", 8
	}
	f.recordAdversarialFinding(WorkItem{
		Method: source.Method, Path: source.Path, Body: source.Body,
		Identity: source.Identity, Headers: source.Headers,
	}, res, "stale_object", class, severity,
		[]string{"stale_object_" + violation, resourceType + "_already_deleted_this_run"})
}

// recordAdversarialFinding is the shared sink for all three oracles in this
// file -- mirrors oracle.go's recordAccessControlFinding (same dedup ->
// unique-crash-JSONL -> f.findings pipeline) but keyed by resource/violation
// shape rather than by identity pair, since these oracles aren't
// identity-comparison-based.
func (f *Fuzzer) recordAdversarialFinding(item WorkItem, res SendResult, kind, class string, severity int, reasons []string) {
	normPath := normalizeEndpointPath(item.Path)
	dedupKey := "adv|" + kind + "|" + item.Method + "|" + normPath + "|" + strings.Join(reasons, ",")
	if _, ok := f.adversarialSeen[dedupKey]; ok {
		return
	}
	f.adversarialSeen[dedupKey] = struct{}{}
	f.adversarialFindings++

	sig := hashWithFNV(dedupKey)
	triage := map[string]any{
		"classification": class,
		"severity_score": severity,
		"impact_hint":    "stateful_security",
		"crash_layer":    "business_logic",
		"oracle":         kind,
		"identity":       item.Identity,
		"status":         res.Status,
		"reasons":        dedupStrings(reasons),
	}
	f.addEvent(fmt.Sprintf("ADVERSARIAL %s  %s %s  (%d)  %s", strings.ToUpper(kind),
		item.Method, truncate(normalizePath(item.Path), 48), res.Status, strings.Join(reasons, ",")))

	uniq := map[string]any{
		"signature":     sig,
		"ts":            time.Now().Format(time.RFC3339),
		"elapsed_secs":  fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		"status_code":   res.Status,
		"method":        item.Method,
		"path":          sanitizeText(item.Path, 1024),
		"identity":      item.Identity,
		"mutation":      "adv_" + kind,
		"payload":       truncate(sanitizeText(item.Body, 4000), 4000),
		"response_body": truncate(sanitizeText(res.Body, 4000), 4000),
		"triage":        triage,
		"adversarial":   true,
	}
	_ = f.uniqueWriter.Write(uniq)

	f.findings = append(f.findings, CrashFinding{
		Signature:  sig,
		ClusterKey: sig,
		TS:         time.Now().Format(time.RFC3339),
		ElapsedSec: fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		Method:     item.Method,
		Path:       strings.ToValidUTF8(item.Path, "?"),
		Status:     res.Status,
		Identity:   item.Identity,
		Mutation:   "adv_" + kind,
		Payload:    strings.ToValidUTF8(item.Body, "?"),
		Response:   strings.ToValidUTF8(res.Body, "?"),
		Triage:     triage,
	})
}

// recordWorkflowBypassFinding is called directly from enqueueSequenceFollowups
// (sequence.go) when an x-state-transition-declared action endpoint succeeds
// against a resource whose own recorded Attributes["status"] does not match
// the endpoint's declared predecessor state. Precise but narrow by
// construction: only fires on specs that actually declare x-state-transition
// (Tier 1 of the transition-source priority chain, resource_scheduling.go),
// which real-world OpenAPI specs rarely do -- see
// docs/ARCHITECTURE_STATEFUL.md §2.5 for the honest scope note. A
// general-purpose version that infers the required predecessor without an
// explicit annotation is future work.
func (f *Fuzzer) recordWorkflowBypassFinding(source WorkItem, res SendResult, expectedFrom, actualStatus string) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeWorkflowBypass {
		return
	}
	f.recordAdversarialFinding(source, res, "workflow_bypass", "likely_vuln_high", 8,
		[]string{
			"workflow_bypass_missing_predecessor_state",
			"expected_from:" + expectedFrom,
			"actual_state:" + actualStatus,
		})
}
