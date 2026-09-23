package engine

import "fmt"

// race.go — concurrency-pattern oracle (Phase 4 #119,
// docs/ARCHITECTURE_STATEFUL.md's security-scenario family "races: double
// spend, concurrent update, create/delete, approve/cancel"). identity.go's
// enqueueRaceBurst already fires N concurrent identical requests at a
// candidate endpoint (a pre-existing mechanism that historically only ever
// surfaced generic crashes if the target happened to 500 under contention).
// This file adds the missing half: once all N results from one burst are
// back, count how many actually SUCCEEDED. An endpoint doing something
// meant to happen at most once (approve, redeem, withdraw, cancel, refund,
// ...) that lets MORE THAN ONE of N simultaneous identical requests succeed
// is a genuine business-logic race -- double-spend/double-approval/etc. --
// not just "the server didn't crash."

// maxTrackedRaceBursts bounds raceBurstSuccess/raceBurstSeen growth --
// stale/never-completing bursts (a dropped request, a burst member that
// errored out and never called handleResult) must not leak memory
// indefinitely over a long run.
const maxTrackedRaceBursts = 2048

// recordRaceBurstResult accumulates one race-burst member's outcome and, once
// every member of that burst has reported in, evaluates whether more than one
// succeeded -- called from handleResult (worker.go) for every completed item
// carrying a non-empty BurstID.
func (f *Fuzzer) recordRaceBurstResult(res SendResult) {
	id := res.Item.BurstID
	if id == "" {
		return
	}
	if _, done := f.raceBurstEvaluated[id]; done {
		return
	}
	if res.Status >= 200 && res.Status < 300 {
		f.raceBurstSuccess[id]++
	}
	f.raceBurstSeen[id]++

	if f.raceBurstSeen[id] < res.Item.BurstSize {
		f.evictOldestRaceBurstIfOverCap()
		return
	}

	// Every member of this burst has now reported in -- evaluate once.
	f.raceBurstEvaluated[id] = struct{}{}
	if len(f.raceBurstEvaluated) > maxTrackedRaceBursts {
		for evictID := range f.raceBurstEvaluated {
			delete(f.raceBurstEvaluated, evictID)
			break
		}
	}
	successCount := f.raceBurstSuccess[id]
	delete(f.raceBurstSuccess, id)
	delete(f.raceBurstSeen, id)

	if !f.cfg.ProbeRaceOutcome || successCount <= 1 {
		return
	}

	class, severity := "likely_vuln", 6
	if _, sensitive := idempotencySensitiveActions[res.Item.BurstAction]; sensitive {
		class, severity = "likely_vuln_high", 9
	} else if res.Item.BurstAction == "delete" || res.Item.BurstAction == "update" {
		// A concurrent create/delete or concurrent-update race is real but
		// generally lower-consequence than a financial double-spend.
		severity = 7
	}
	f.recordAdversarialFinding(res.Item, res, "race_condition", class, severity, []string{
		"concurrency_race_multiple_success",
		fmt.Sprintf("succeeded:%d_of_%d", successCount, res.Item.BurstSize),
		"action:" + res.Item.BurstAction,
	})
}

// evictOldestRaceBurstIfOverCap drops tracking for an arbitrary (map
// iteration order, which is fine -- this is a defensive bound, not a
// precise LRU) in-progress burst when over cap, so a run with many
// never-fully-reporting bursts can't grow these maps unbounded.
func (f *Fuzzer) evictOldestRaceBurstIfOverCap() {
	if len(f.raceBurstSeen) <= maxTrackedRaceBursts {
		return
	}
	for id := range f.raceBurstSeen {
		delete(f.raceBurstSeen, id)
		delete(f.raceBurstSuccess, id)
		break
	}
}
