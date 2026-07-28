package main

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
//     used as a sequence consumer (repeated_failure_penalty).
func (f *Fuzzer) scoreConsumer(tid int, sourceMethod, sourceNorm string) float64 {
	m := f.meta[tid]
	staticFit := float64(100 - followupPriority(sourceMethod, sourceNorm, m.Method, m.Norm))
	score := staticFit * 0.5 // one input among several, not the dominant term

	if f.resourceGraph.consumerReachedCount(tid) == 0 {
		score += f.cfg.ResourceGraphUnreachedWeight
	}

	if epKey := f.tmplEPKey[tid]; epKey != "" {
		if stats := f.endpointStats[epKey]; stats != nil {
			score += float64(stats.NewEdges) * f.cfg.ResourceGraphYieldWeight
		}
	}

	if fails := f.resourceGraph.consumerFailureCount(tid); fails > 0 {
		score -= float64(fails) * f.cfg.ResourceGraphFailurePenalty
	}

	return score
}

// rankConsumersCoverageDirected replaces findFollowups' static
// sort.SliceStable(...followupPriority...) with the scored model above, plus a
// bounded, seeded-deterministic epsilon-exploration step so a lower-scored
// candidate is never *permanently* starved: with probability
// f.cfg.ResourceGraphExploreRate, one lower-ranked candidate is promoted to the
// front instead of strictly following the score order.
func (f *Fuzzer) rankConsumersCoverageDirected(candidates []int, sourceMethod, sourceNorm string) []int {
	if len(candidates) <= 1 {
		return candidates
	}
	type scored struct {
		tid   int
		score float64
	}
	arr := make([]scored, len(candidates))
	for i, tid := range candidates {
		arr[i] = scored{tid, f.scoreConsumer(tid, sourceMethod, sourceNorm)}
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
