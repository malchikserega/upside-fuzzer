package engine

import (
	"math/rand"
	"sort"
	"strings"
)

// resource_scheduling.go — lifecycle-transition derivation and coverage-directed
// consumer scheduling, replacing findFollowups' purely-static followupPriority
// sort with a scored model that blends real coverage signals already tracked
// elsewhere in the engine (f.endpointStats' NewEdges) with resource-graph-derived
// novelty/reachedness/failure signals. See docs/resource-state-graph-plan.md §8.4.

// deriveLifecycleTransition classifies a step's effect on a resource's lifecycle
// from a *combination* of signals -- the request method, the response status
// class, and the resource's *prior* recorded lifecycle state (never method
// alone, per the design constraint). result is "valid" (an unsurprising, correct
// transition), "invalid" (a transition that succeeded/failed in a way that's
// itself interesting -- e.g. a successful update on a deleted resource, or a
// repeated deletion), or "unknown" (not enough signal to classify confidently).
func deriveLifecycleTransition(method string, status int, prior LifecycleState) (to LifecycleState, result string) {
	m := strings.ToUpper(strings.TrimSpace(method))
	success := status >= 200 && status < 300 || status >= 300 && status < 400
	notFoundLike := status == 404 || status == 410 || status == 409

	switch m {
	case "POST":
		if success {
			return LifecycleCreated, "valid"
		}
		return LifecycleFailedCreation, "invalid"

	case "GET", "HEAD":
		if success {
			if prior == LifecycleDeleted || prior == LifecycleInvalidated {
				// A successful read of a resource this run itself deleted --
				// interesting regardless of oracle.go's own separate BOLA/leak
				// checks; here it's simply a "stale-read succeeded" lifecycle fact.
				return LifecycleStale, "invalid"
			}
			return LifecycleReadable, "valid"
		}
		if notFoundLike && (prior == LifecycleDeleted || prior == LifecycleInvalidated) {
			return prior, "valid" // correctly confirms the deletion
		}
		if notFoundLike {
			return LifecycleUnknown, "unknown"
		}
		return prior, "unknown"

	case "PUT", "PATCH":
		if success {
			if prior == LifecycleDeleted || prior == LifecycleInvalidated {
				return LifecycleInvalidated, "invalid" // update-after-delete "worked" -- worth flagging
			}
			return LifecycleModified, "valid"
		}
		if notFoundLike && (prior == LifecycleDeleted || prior == LifecycleInvalidated) {
			return prior, "valid" // correctly rejected
		}
		return LifecycleFailedModification, "invalid"

	case "DELETE":
		if success {
			if prior == LifecycleDeleted {
				return LifecycleDeleted, "invalid" // repeated-deletion transition
			}
			return LifecycleDeleted, "valid"
		}
		if notFoundLike && prior == LifecycleDeleted {
			return prior, "valid" // correctly rejected double-delete
		}
		return LifecycleFailedDeletion, "invalid"

	default:
		return prior, "unknown"
	}
}

// knownTransitionActionVerbs is a heuristic vocabulary of REST action-suffix
// path segments (POST /resource/{id}/<verb>) that name a specific business
// transition distinctly from a generic CRUD verb -- e.g. "approve" and
// "refund" are both POST but represent completely different transitions, a
// distinction the design task explicitly calls out (HTTP method alone is a
// weak signal). Not exhaustive by design -- a full NLP verb classifier is out
// of scope -- covers the common REST action-suffix convention plus this
// project's own demo_app bug-catalog verbs (approve/restore/redeem/withdraw/
// revoke/...). Falls back to a generic method-derived action
// (create/read/update/delete) for anything outside it, per
// deriveTransitionAction below.
var knownTransitionActionVerbs = map[string]struct{}{
	"approve": {}, "reject": {}, "refund": {}, "pay": {}, "cancel": {},
	"restore": {}, "archive": {}, "unarchive": {}, "publish": {}, "unpublish": {},
	"revoke": {}, "accept": {}, "decline": {}, "invite": {}, "submit": {},
	"confirm": {}, "activate": {}, "deactivate": {}, "lock": {}, "unlock": {},
	"send": {}, "resend": {}, "complete": {}, "close": {}, "reopen": {},
	"retry": {}, "verify": {}, "reset": {}, "redeem": {}, "withdraw": {},
	"transfer": {}, "suspend": {}, "ban": {}, "unban": {}, "promote": {},
	"demote": {}, "renew": {}, "extend": {}, "duplicate": {}, "clone": {},
	"import": {}, "export": {}, "download": {}, "upload": {}, "poll": {},
	// Phase 4 #122: multipart upload -> process -> download chain verbs.
	"process": {}, "scan": {}, "convert": {}, "transcode": {}, "validate": {},
	// Phase 4 #123: webhook/event callback trigger verbs.
	"trigger": {}, "fire": {}, "execute": {}, "invoke": {}, "notify": {}, "test": {}, "run": {},
}

// deriveTransitionAction names the specific business action a step performed
// (ResourceTransition.Action) -- prefers path's own trailing action-suffix
// segment (POST /orders/{id}/approve -> "approve") when it matches the known
// verb vocabulary above; falls back to a generic method-derived action for
// conventional CRUD endpoints with no such suffix (e.g. plain
// POST /orders -> "create").
func deriveTransitionAction(method, path string) string {
	segs := splitPathTokensRaw(normalizePath(path))
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		if !isRouteTemplatePlaceholder(last) {
			verb := strings.ToLower(last)
			if _, known := knownTransitionActionVerbs[verb]; known {
				return verb
			}
		}
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST":
		return "create"
	case "GET", "HEAD":
		return "read"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return strings.ToLower(strings.TrimSpace(method))
	}
}

// genericRoslynActionNames are C# controller action method names that are
// generic ASP.NET boilerplate (Get/Post/Index/Create/...), carrying no more
// information than the path/method heuristic already provides -- used to
// decide whether RoslynAction (Tier 2 of the transition-source priority
// chain) is actually worth preferring over the fallback.
var genericRoslynActionNames = map[string]struct{}{
	"get": {}, "getall": {}, "getbyid": {}, "getone": {}, "post": {}, "put": {},
	"patch": {}, "delete": {}, "index": {}, "create": {}, "update": {},
	"remove": {}, "list": {}, "add": {}, "edit": {}, "save": {}, "find": {},
	"fetch": {}, "handle": {}, "handleasync": {}, "execute": {}, "run": {},
}

func isGenericRoslynActionName(name string) bool {
	_, generic := genericRoslynActionNames[strings.ToLower(strings.TrimSpace(name))]
	return generic
}

// deriveTransitionActionForTemplate resolves ResourceTransition.Action via
// the full transition-source priority chain (docs/ARCHITECTURE_STATEFUL.md
// §2.3): an explicit OpenAPI x-state-transition extension (Tier 1,
// TemplateMeta.XStateTransition, grammarc/oas.py) > a non-generic
// Roslyn-discovered C# controller action method name (Tier 2,
// TemplateMeta.RoslynAction, grammarc/roslyn_merge.py) > the path/method
// heuristic (deriveTransitionAction) applied to the live request. There is
// no separate "historical runtime observation" tier beyond that heuristic --
// this engine has no store of previously-inferred action names to consult
// first, so the design's Tier 3 and Tier 4 collapse into one concrete
// mechanism here. meta may be the zero value (no grammar-sourced hints
// available, e.g. -resource-graph tests); every tier degrades gracefully.
func deriveTransitionActionForTemplate(meta TemplateMeta, method, path string) string {
	if meta.XStateTransition != nil && meta.XStateTransition.Action != "" {
		return meta.XStateTransition.Action
	}
	if meta.RoslynAction != "" && !isGenericRoslynActionName(meta.RoslynAction) {
		return meta.RoslynAction
	}
	return deriveTransitionAction(method, path)
}

// scoreConsumer computes a coverage-directed priority score for candidate
// template tid as the next follow-up after (sourceMethod, sourceNorm). Higher
// is better. Blends:
//   - the existing static verb-affinity table (followupPriority) as ONE input,
//     not the only one -- inverted (lower raw priority number = better fit = more
//     score) and down-weighted relative to the coverage-driven terms below;
//   - a large bonus if this consumer has never once been reached via a sequence
//     follow-up (unreached_operation_weight);
//   - the consumer's own endpoint's historical coverage yield
//     (f.endpointStats[...].NewEdges -- already tracked for an unrelated purpose,
//     reused here rather than duplicating tracking);
//   - a penalty scaled by how many times this consumer has recently failed when
//     used as a sequence consumer (repeated_failure_penalty);
//   - the valid-workflow planner's two remaining scoring terms
//     (docs/ARCHITECTURE_STATEFUL.md §2.4): the consumer's own historical 2xx
//     rate (success-probability term, f.endpointStats' S2xx/Reqs), and whether
//     a resource instance of its expected type is actually available right
//     now, tenant-scoped (lifecycle-state-satisfiable term) -- a candidate
//     that structurally cannot succeed (no live resource to operate on)
//     shouldn't outrank one that can, even if their static/coverage signals
//     otherwise tie.
func (f *Fuzzer) scoreConsumer(tid int, sourceMethod, sourceNorm, tenantKey string) float64 {
	m := f.meta[tid]
	staticFit := float64(100 - followupPriority(sourceMethod, sourceNorm, m.Method, m.Norm))
	score := staticFit * 0.5 // one input among several, not the dominant term

	if f.resourceGraph.consumerReachedCount(tid) == 0 {
		score += f.cfg.ResourceGraphUnreachedWeight
	}

	if epKey := f.tmplEPKey[tid]; epKey != "" {
		if stats := f.endpointStats[epKey]; stats != nil {
			score += float64(stats.NewEdges) * f.cfg.ResourceGraphYieldWeight
			if stats.Reqs > 0 {
				successRate := float64(stats.S2xx) / float64(stats.Reqs)
				score += successRate * f.cfg.ResourceGraphSuccessProbWeight
			}
		}
	}

	if fails := f.resourceGraph.consumerFailureCount(tid); fails > 0 {
		score -= float64(fails) * f.cfg.ResourceGraphFailurePenalty
	}

	if rt := resourceTypeFromEndpointPath(m.Norm); rt != "" {
		compat := f.resourceGraph.findCompatibleResourcesInTenant(rt, tenantKey, LifecycleCreated, LifecycleReadable, LifecycleModified)
		if len(compat) > 0 {
			score += f.cfg.ResourceGraphAvailabilityWeight
		}
		// Async-operation model (async.go, Phase 4 #120): a GET candidate
		// whose resource type has a known, still-pending async submission
		// gets an extra bonus, so the planner keeps polling an in-flight
		// operation through to a terminal state rather than wandering off to
		// an unrelated endpoint mid-poll.
		if m.Method == "GET" {
			for _, inst := range compat {
				if isAsyncOperationPending(inst) {
					score += asyncPollBonus
					break
				}
			}
			// Multipart chain modeling (multipart_chain.go, Phase 4 #122): a
			// download/export-shaped GET candidate whose resource type has a
			// known multipart-upload-sourced instance gets a bonus, biasing
			// the planner toward actually completing the
			// upload->[process]->download chain.
			if looksLikeDownloadEndpoint(m.Norm) {
				for _, inst := range compat {
					if inst.Attributes != nil {
						if fromMultipart, _ := inst.Attributes["source_multipart"].(bool); fromMultipart {
							score += multipartDownloadBonus
							break
						}
					}
				}
			}
		}
	}

	return score
}

// rankConsumersCoverageDirected replaces findFollowups' static
// sort.SliceStable(...followupPriority...) with the scored model above, plus a
// bounded, seeded-deterministic epsilon-exploration step so a lower-scored
// candidate is never *permanently* starved: with probability
// f.cfg.ResourceGraphExploreRate, one lower-ranked candidate is promoted to the
// front instead of strictly following the score order.
func (f *Fuzzer) rankConsumersCoverageDirected(candidates []int, sourceMethod, sourceNorm, tenantKey string) []int {
	if len(candidates) <= 1 {
		return candidates
	}
	type scored struct {
		tid   int
		score float64
	}
	arr := make([]scored, len(candidates))
	for i, tid := range candidates {
		arr[i] = scored{tid, f.scoreConsumer(tid, sourceMethod, sourceNorm, tenantKey)}
	}
	sort.SliceStable(arr, func(i, j int) bool { return arr[i].score > arr[j].score })
	out := make([]int, len(arr))
	for i, s := range arr {
		out[i] = s.tid
	}
	if rand.Float64() < f.cfg.ResourceGraphExploreRate {
		j := 1 + rand.Intn(len(out)-1)
		out[0], out[j] = out[j], out[0]
	}
	return out
}
