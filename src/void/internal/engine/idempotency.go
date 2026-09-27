package engine

import (
	"math/rand"
)

// idempotency.go — idempotency-replay oracle (Phase 4 #118,
// docs/ARCHITECTURE_STATEFUL.md's security-scenario family "idempotency:
// replay create/payment/refund"). After a successful create-shaped POST,
// replays the EXACT same request (same body/headers, including any client-
// supplied idempotency key) a second time. A correctly idempotent endpoint
// either returns the SAME resource id again or rejects the replay outright;
// one that creates a SECOND, DIFFERENT resource from an identical request is
// vulnerable to duplicate processing -- most dangerous on payment/refund/
// redeem/withdraw-shaped endpoints, where it means a double charge/payout,
// not just a duplicate row.

const oracleKindIdempotency = "idempotency_replay"

// idempotencySensitiveActions are action verbs (deriveTransitionActionForTemplate)
// where duplicate processing has real financial/business consequences -- these
// get flagged at higher severity than an ordinary duplicate create.
var idempotencySensitiveActions = map[string]struct{}{
	"pay": {}, "refund": {}, "redeem": {}, "withdraw": {}, "transfer": {},
	"charge": {}, "purchase": {}, "checkout": {},
}

// maybeEnqueueIdempotencyReplayProbe replays a just-succeeded create-shaped
// POST verbatim -- same method, path, headers (including any idempotency-key
// header the client itself supplied), and body -- to test whether the server
// treats an identical request as idempotent.
func (f *Fuzzer) maybeEnqueueIdempotencyReplayProbe(res SendResult) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeIdempotency || res.Item.OracleKind != "" {
		return
	}
	if res.Item.Method != "POST" {
		return
	}
	if res.Status < 200 || res.Status >= 300 {
		return
	}
	originIDs := extractEntityIDs(res.Body, res.Headers)
	if len(originIDs) == 0 {
		return // nothing to compare a replay's own created id against
	}
	epKey := endpointKey(res.Item.Method, normalizeEndpointPath(res.Item.Path)) + "|idem"
	if f.adversarialProbeCount[epKey] >= f.cfg.AccessProbeMaxPerEndpoint {
		return
	}
	if rand.Float64() > clampFloat(f.cfg.AccessProbeProb, 0.0, 1.0) {
		return
	}

	p := res.Item
	p.OracleKind = oracleKindIdempotency
	p.OracleOriginIdentity = res.Item.Identity
	p.OracleOriginStatus = res.Status
	p.OracleOriginFP = originIDs[0] // the FIRST request's own created id
	p.SeedIdx = -1
	p.Trace = nil
	p.MutationName = "adv_" + oracleKindIdempotency
	p.MutationLabel = "adversarial_probe(" + oracleKindIdempotency + ")"
	// Deliberately NOT re-mutated -- replaying the exact same body/headers a
	// second time IS the test; a different body would just be an ordinary
	// duplicate create, not an idempotency question.

	f.oracleEnqueue(p)
	f.adversarialProbeCount[epKey]++
}

// handleIdempotencyReplayResult evaluates a returned idempotency-replay probe
// -- called from handleOracleResult (oracle.go) before its generic BOLA-shaped
// body-emptiness/trivial-body guards, which exist to filter a different
// oracle's false-positive profile and would wrongly suppress a legitimate
// idempotency finding on an endpoint whose create response is minimal (e.g.
// {"id":"124"}).
func (f *Fuzzer) handleIdempotencyReplayResult(res SendResult) {
	if res.Status < 200 || res.Status >= 300 {
		return // correctly rejected/no-op replay -- not a finding
	}
	replayIDs := extractEntityIDs(res.Body, res.Headers)
	if len(replayIDs) == 0 || replayIDs[0] == res.Item.OracleOriginFP {
		return // idempotent (same id, or nothing extractable to compare)
	}
	class, severity := "likely_vuln", 6
	action := deriveTransitionActionForTemplate(f.meta[res.Item.TemplateID], res.Item.Method, res.Item.Path)
	if _, sensitive := idempotencySensitiveActions[action]; sensitive {
		class, severity = "likely_vuln_high", 9
	}
	f.recordAdversarialFinding(res.Item, res, oracleKindIdempotency, class, severity, []string{
		"idempotency_not_enforced",
		"original_id:" + res.Item.OracleOriginFP,
		"replay_created_new_id:" + replayIDs[0],
	})
}
