package main

import (
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// worker.go — Main fuzzing loop (mainLoop), HTTP send workers,
// result processing, corpus management, and adaptive concurrency tuning.

func (f *Fuzzer) mainLoop() error {
	epochs := []Epoch{
		{Name: "Baseline", Fraction: 0.05, Mode: "none"},
		{Name: "Harvest", Fraction: 0.25, Mode: "harvest"},
		{Name: "Deterministic", Fraction: 0.25, Mode: "mutate"},
		{Name: "Havoc", Fraction: 0.35, Mode: "havoc"},
		{Name: "Splicing", Fraction: 0.10, Mode: "havoc"},
	}

	// Adaptive epoch rebalancing: track edges found per epoch and shift budget
	// from unproductive phases to productive ones (like AFL++'s pilot/core modes).
	epochEdgesAtStart := map[string]int{}
	epochReqsAtStart := map[string]int{}

	f.startTime = time.Now()
	f.lastTuneTS = time.Now()
	f.lastUIRender = time.Time{}
	f.lastEdgeEvent = time.Time{}
	lastEpoch := ""
	workCh := make(chan WorkItem, maxInt(128, f.cfg.MaxConcurrency*4))
	resultCh := make(chan SendResult, maxInt(512, f.cfg.MaxConcurrency*16))
	stopCh := make(chan struct{}, 1)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	f.startStopInputListener(stopCh)

	markStopped := func(reason string) {
		if f.stoppedByUser {
			return
		}
		f.stoppedByUser = true
		f.addEvent("STOP requested: " + reason)
	}

	workerCount := maxInt(1, f.cfg.MaxConcurrency)
	for i := 0; i < workerCount; i++ {
		go func() {
			for it := range workCh {
				resultCh <- f.sendOne(it)
			}
		}()
	}
	defer close(workCh)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	pending := 0
	timeBudget := time.Duration(f.cfg.TimeBudgetMinutes * float64(time.Minute))

	for time.Since(f.startTime) < timeBudget && !f.stoppedByUser {
		select {
		case <-stopCh:
			markStopped("input command")
			break
		case <-sigCh:
			markStopped("signal")
			break
		default:
		}

		epIdx, ep := currentEpoch(epochs, time.Since(f.startTime), timeBudget)
		if ep.Name != lastEpoch {
			// On epoch transition: rebalance remaining time based on productivity.
			if lastEpoch != "" {
				prevEdges := f.currentEdges - epochEdgesAtStart[lastEpoch]
				prevReqs := f.totalDone - epochReqsAtStart[lastEpoch]
				edgeRate := 0.0
				if prevReqs > 0 {
					edgeRate = float64(prevEdges) / float64(prevReqs)
				}
				// If the phase was unproductive (< 0.001 edges/req after decent sample),
				// steal half its remaining fraction and give to Havoc.
				if prevReqs > 200 && edgeRate < 0.001 && lastEpoch != "Baseline" {
					for i := range epochs {
						if epochs[i].Name == lastEpoch {
							stolen := epochs[i].Fraction * 0.3
							epochs[i].Fraction -= stolen
							for j := range epochs {
								if epochs[j].Name == "Havoc" {
									epochs[j].Fraction += stolen
									break
								}
							}
							f.addEvent(fmt.Sprintf("REBALANCE %s -> Havoc (%.0f%% stolen, edgeRate=%.5f)", lastEpoch, stolen*100, edgeRate))
							break
						}
					}
				}
			}
			epochEdgesAtStart[ep.Name] = f.currentEdges
			epochReqsAtStart[ep.Name] = f.totalDone
			// Snapshot the baseline ceiling once — the moment we leave the Baseline epoch
			// (all templates sent unmutated), currentEdges is the best proxy for the
			// total reachable surface of the application under normal traffic.
			if lastEpoch == "Baseline" && f.baselineEdgesCeiling == 0 && f.currentEdges > 0 {
				f.baselineEdgesCeiling = f.currentEdges
				f.addEvent(fmt.Sprintf("BASELINE CEILING set: %d edges (real coverage ceiling)", f.baselineEdgesCeiling))
			}
			f.addEvent(fmt.Sprintf("EPOCH %d: %s", epIdx+1, ep.Name))
			lastEpoch = ep.Name
		}
		desired := f.currentConcurrency
		if ep.Name == "Baseline" && f.cfg.SequentialBaseline {
			desired = 1
		}
		queueSaturated := false
		for pending < desired {
			if len(workCh) >= cap(workCh) {
				break
			}
			item, ok := f.buildWorkItem(epIdx, ep)
			if !ok {
				break
			}
			select {
			case workCh <- item:
				pending++
				f.totalSent++
			default:
				// Worker queue is saturated; let workers catch up.
				queueSaturated = true
			}
			if pending >= desired || queueSaturated {
				break
			}
		}

		if pending == 0 {
			select {
			case <-stopCh:
				markStopped("input command")
			case <-sigCh:
				markStopped("signal")
			case <-tick.C:
			default:
				time.Sleep(10 * time.Millisecond)
			}
			f.renderUI(ep.Name, epIdx, pending)
			f.tuneConcurrency()
			continue
		}

		select {
		case <-stopCh:
			markStopped("input command")
		case <-sigCh:
			markStopped("signal")
		case res := <-resultCh:
			pending--
			f.handleResult(res)
		case <-tick.C:
		default:
			select {
			case <-stopCh:
				markStopped("input command")
			case <-sigCh:
				markStopped("signal")
			case res := <-resultCh:
				pending--
				f.handleResult(res)
			case <-tick.C:
			}
		}

		f.renderUI(ep.Name, epIdx, pending)
		f.tuneConcurrency()
	}

	// Drain a short tail.
	drainDeadline := time.Now().Add(2 * time.Second)
	for pending > 0 && time.Now().Before(drainDeadline) {
		select {
		case <-stopCh:
			markStopped("input command")
		case <-sigCh:
			markStopped("signal")
		case res := <-resultCh:
			pending--
			f.handleResult(res)
		case <-tick.C:
		}
	}

	_ = f.crashWriter.Flush()
	_ = f.uniqueWriter.Flush()
	f.printFinalReport()
	return nil
}
func (f *Fuzzer) sendOne(item WorkItem) SendResult {
	return f.sendOneWithClient(item, f.client)
}

func (f *Fuzzer) sendOneWithClient(item WorkItem, httpClient *http.Client) SendResult {
	if httpClient == nil {
		httpClient = f.client
	}
	t0 := time.Now()
	item = f.prepareItemForSend(item)
	u := f.target + item.Path
	var bodyReader io.Reader
	if (item.Method == "POST" || item.Method == "PUT" || item.Method == "PATCH" || item.Method == "DELETE") && strings.TrimSpace(item.Body) != "" {
		bodyReader = strings.NewReader(item.Body)
	}
	req, err := http.NewRequest(item.Method, u, bodyReader)
	if err != nil {
		return SendResult{Item: item, Err: err, Latency: time.Since(t0)}
	}
	for k, v := range item.Headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		req.Header.Set(k, v)
	}
	// Per-request coverage attribution: the .NET middleware reads this header and
	// returns X-Coverage-Delta / X-Exception-Type in the response — zero extra round-trips.
	requestID := atomic.AddUint64(&f.requestIDSeq, 1)
	req.Header.Set("X-Fuzz-Request-Id", "fz-"+strconv.FormatUint(requestID, 36))
	// Access-control auth-bypass probes are sent with NO credentials so the
	// absence of auth alone determines whether access is (wrongly) granted.
	if !item.NoAuth {
		idHeaders, idToken, _ := f.identityAuth(item.Identity)
		for k, v := range idHeaders {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
				continue
			}
			req.Header.Set(k, v)
		}
		if idToken != "" {
			req.Header.Set("Authorization", "Bearer "+idToken)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return SendResult{Item: item, Err: err, Latency: time.Since(t0)}
	}
	defer resp.Body.Close()

	maxBytes := int64(0)
	s := resp.StatusCode
	switch {
	case s >= 200 && s < 300:
		maxBytes = int64(maxInt(1024, f.cfg.MaxResponseBytes))
	case s >= 500:
		maxBytes = int64(minInt(maxInt(8192, f.cfg.MaxResponseBytes), 1<<20))
	case s >= 400 && s < 500:
		maxBytes = 4096
	default:
		maxBytes = 0
	}
	body := ""
	if maxBytes > 0 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		body = sanitizeText(string(buf), maxInt(1024, f.cfg.MaxResponseBytes))
	}
	headers := map[string]string{}
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	// Extract per-request coverage delta and exception type from response headers.
	coverageDelta := 0
	if v := headers["X-Coverage-Delta"]; v != "" {
		if n, err2 := strconv.Atoi(v); err2 == nil && n > 0 {
			coverageDelta = n
		}
	}
	exceptionType := headers["X-Exception-Type"]
	exceptionMsg := headers["X-Exception-Message"]
	// Fallback: if the header wasn't set (non-instrumented target, or an older middleware),
	// extract the exception class from the response body. In Development mode ASP.NET returns
	// full stack traces. The instrumentor now short-circuits fuzz-request 500s so the header
	// is reliably present even in production mode.
	if exceptionType == "" && resp.StatusCode >= 500 {
		exceptionType = extractExceptionType(body)
	}
	return SendResult{
		Item:          item,
		Status:        resp.StatusCode,
		Body:          body,
		Headers:       headers,
		Latency:       time.Since(t0),
		CoverageDelta: coverageDelta,
		ExceptionType: exceptionType,
		ExceptionMsg:  exceptionMsg,
	}
}

func (f *Fuzzer) handleResult(res SendResult) {
	if res.Err != nil {
		f.totalErrors++
		return
	}
	f.totalDone++
	f.latencySamples++
	f.latencyTotalMS += float64(res.Latency.Milliseconds())
	f.completedSinceCV++

	// Access-control probes bypass the normal crash/learn/coverage path: they are
	// evaluated purely for authorization outcome.
	if res.Item.OracleKind != "" {
		f.handleOracleResult(res)
		return
	}

	edgeShare := 0
	// Prefer per-request delta from X-Coverage-Delta response header (exact attribution).
	// Fall back to interval poll when header is absent (e.g. non-instrumented or HTTP-only targets).
	if res.CoverageDelta > 0 {
		f.currentEdges += res.CoverageDelta
		edgeShare = res.CoverageDelta
		f.stallCounter = 0
		f.completedSinceCV = 0
	} else if f.completedSinceCV >= maxInt(1, f.cfg.CoverageInterval) {
		after, err := f.coverage.GetEdges()
		if err == nil {
			delta := after - f.currentEdges
			if delta > 0 {
				f.currentEdges = after
				edgeShare = maxInt(1, delta)
				f.stallCounter = 0
			} else {
				f.stallCounter++
			}
		}
		f.completedSinceCV = 0
	}

	ep := f.ensureEndpointStats(res.Item.Method, res.Item.Path)
	ep.Reqs++
	ep.LastSeen = f.totalDone
	switch {
	case res.Status >= 200 && res.Status < 300:
		ep.S2xx++
	case res.Status == 401 || res.Status == 403:
		ep.S401403++
	case res.Status >= 400 && res.Status < 500:
		ep.S4xx++
	case res.Status >= 500:
		ep.S5xx++
		if res.Status == 500 {
			ep.S500++
		}
	}
	if edgeShare > 0 {
		ep.NewEdges += edgeShare
		ep.ReqsSinceEdge = 0
	} else {
		ep.ReqsSinceEdge++
	}
	epKey := endpointKey(res.Item.Method, ep.Path)
	f.maybeAddRequestSample(res)
	if f.cfg.AutoAntiForgery {
		if gained := f.learnAntiForgeryFromResponse(res.Item.Path, res.Status, res.Headers, res.Body, false); gained > 0 {
			atomic.AddInt64(&f.antiForgeryLearned, int64(gained))
		}
	}

	isFormMismatch := f.cfg.AdaptiveContentType && isFormContentTypeMismatch(res.Status, res.Body)
	if f.cfg.AdaptiveContentType && isWriteMethod(res.Item.Method) {
		if isFormMismatch && !isAPILikePath(res.Item.Path) {
			if _, ok := f.forceFormEndpoints[epKey]; !ok {
				f.forceFormEndpoints[epKey] = struct{}{}
				f.addEvent(fmt.Sprintf("ADAPT content-type -> form  %s %s", res.Item.Method, truncate(normalizePath(res.Item.Path), 60)))
			}
		}
		if res.Status == http.StatusUnsupportedMediaType {
			if _, ok := f.forceFormEndpoints[epKey]; ok {
				delete(f.forceFormEndpoints, epKey)
				f.addEvent(fmt.Sprintf("ADAPT content-type -> json  %s %s", res.Item.Method, truncate(normalizePath(res.Item.Path), 60)))
			}
		}
	}

	ms := f.ensureMutationStats(res.Item.MutationName)
	ms.Attempts++
	recordMutationCategoryAttempt(res.Item.MutationLabel)
	if edgeShare > 0 {
		ms.NewEdges += edgeShare
		recordMutationCategoryHit(res.Item.MutationLabel)
		f.addOrBoostSeed(res.Item, edgeShare)
		if edgeShare >= 3 || f.lastEdgeEvent.IsZero() || time.Since(f.lastEdgeEvent) > 5*time.Second {
			f.addEvent(fmt.Sprintf("NEW EDGE +%d  %s %s  %s", edgeShare, res.Item.Method, truncate(normalizePath(res.Item.Path), 60), truncate(res.Item.MutationName, 28)))
			f.lastEdgeEvent = time.Now()
		}
	}

	if res.Status >= 500 {
		if !isFormMismatch {
			f.recordCrash(res)
			ep.Logged5xx++
			if res.Status == 500 {
				ep.Logged500++
			}
		} else {
			ep.Filtered5xx++
			if res.Status == 500 {
				ep.Filtered500++
			}
			f.recordClientErrorSample(res.Item.Method, ep.Path, res.Status, res.Body)
		}
		if f.cfg.SkipOnCrash {
			f.removeActiveTemplate(res.Item.TemplateID)
		}
		if f.cfg.SkipEndpointOn500 && res.Status == 500 {
			if removed := f.blockEndpointByTemplateID(res.Item.TemplateID); removed > 0 {
				f.addEvent(fmt.Sprintf("BLOCK 500 endpoint %s %s removed_templates=%d", res.Item.Method, truncate(normalizePath(res.Item.Path), 60), removed))
			}
		}
	} else if res.Status == 401 || res.Status == 403 {
		f.recordAuthFailure(res.Item.Method, ep.Path, res.Status, res.Body)
		f.recordClientErrorSample(res.Item.Method, ep.Path, res.Status, res.Body)
		// Auth-bypass precondition: remember that this endpoint enforces auth. "strong"
		// when the rejected request itself carried no effective credentials (guest).
		f.markAuthRequired(res.Item.Method, res.Item.Path, !f.identityIsAuthed(res.Item.Identity))
		// Auto re-authenticate when a token has expired (persistent 401 stream on any endpoint).
		// Threshold of 9 avoids hammering auth on the very first 401; 30s cooldown prevents tight loops.
		if st := f.authBlocked[endpointKey(res.Item.Method, ep.Path)]; st != nil && st.Count == 9 {
			if !f.hasConfiguredIdentityAuth() || hasExplicitAuthLoginEnv() {
				if time.Since(f.lastAuthRefresh) > 30*time.Second {
					f.lastAuthRefresh = time.Now()
					if err := f.authenticate(); err == nil {
						f.addEvent("Re-authenticated after 401 stream (token refreshed)")
					}
				}
			}
		}
	} else if res.Status >= 400 && res.Status < 500 {
		if f.cfg.AutoAntiForgery && f.shouldHarvestAntiForgery(res) {
			if normPath, ok := f.reserveAntiForgeryHarvest(res.Item.Path); ok {
				go func(path string) {
					if learned := f.harvestAntiForgeryForPathReserved(path); learned > 0 {
						atomic.AddInt64(&f.antiForgeryLearned, int64(learned))
					}
				}(normPath)
			}
		}
		f.recordClientErrorSample(res.Item.Method, ep.Path, res.Status, res.Body)
	}

	if res.Status >= 200 && res.Status < 300 {
		f.recordAuthSuccess(res.Item.Method, ep.Path)
		learned := 0
		if f.shouldLearnFromSuccess(res) {
			learnReq := f.learnFromRequestContext(res.Item.Path, res.Item.Body)
			learnResp := f.learnFromResponse(res.Body, res.Headers)
			learned = learnReq + learnResp
		}
		if learned > 0 {
			f.learnedByEndpoint[epKey] += learned
		}
		if res.Item.SeqState != nil || f.shouldEnqueueSequence(res, learned) {
			if n := f.enqueueSequenceFollowups(res); n > 0 {
				// no-op, queue updated
			}
		}
		if learned == 0 && (res.Item.Method == "POST" || res.Item.Method == "PUT" || res.Item.Method == "PATCH") {
			// Writes are valuable for dependency chains, keep occasional light learning.
			if f.learnSampleCounter%5 == 0 {
				if v := f.learnFromResponse(res.Body, res.Headers); v > 0 {
					f.learnedByEndpoint[epKey] += v
				}
			}
		}
		if f.cfg.RaceMode {
			f.enqueueRaceBurst(res.Item)
		}
		// Access-control oracles: replay this successful resource request under
		// other identities / no auth to detect BOLA/IDOR and broken authentication.
		f.maybeEnqueueAccessProbes(res)
		// Mass-assignment: re-send this successful write with privileged fields over-posted.
		f.maybeEnqueueMassAssignProbe(res)
	}

	// Positive injection oracles on non-crash responses (reflected XSS, evaluated
	// SSTI, time-based SQLi). 5xx signals are handled by crash triage.
	f.checkInjectionOracle(res)

	if !f.coverageSaturationWarned {
		if sat := f.coverageSaturationPct(); sat >= 98.0 && f.coverageCapacity > 0 {
			f.coverageSaturationWarned = true
			f.addEvent(fmt.Sprintf("COVERAGE near saturation %.1f%% (%d/%d)", sat, f.currentEdges, f.coverageCapacity))
		}
	}

	// Coverage stagnation: if no new edges in 5 minutes, aggressively boost under-explored
	// endpoints by resetting their request counters. This forces the sampler to re-distribute
	// weight away from exhausted endpoints toward fresh ones.
	if !f.lastEdgeEvent.IsZero() && time.Since(f.lastEdgeEvent) > 5*time.Minute {
		boosted := 0
		for k, ep := range f.endpointStats {
			if ep.Reqs > 200 && ep.NewEdges == 0 && ep.ReqsSinceEdge > 100 {
				ep.ReqsSinceEdge = ep.Reqs + 1000
				f.endpointStats[k] = ep
			}
			if ep.Reqs < 50 || (ep.NewEdges > 0 && ep.ReqsSinceEdge > 50) {
				ep.ReqsSinceEdge = 0
				f.endpointStats[k] = ep
				boosted++
			}
		}
		if boosted > 0 {
			f.addEvent(fmt.Sprintf("STAGNATION boost: refreshed %d endpoint weights (no edges for 5min)", boosted))
		}
		f.lastEdgeEvent = time.Now()
	}

	// When the bitmap is > 85% full, coverage feedback becomes noise (hash collisions dominate).
	// Periodically reset so the fuzzer can still distinguish new paths — especially important
	// for runs > 30 minutes against large applications.
	if sat := f.coverageSaturationPct(); sat > 85.0 && f.coverageCapacity > 0 {
		if f.lastCoverageReset.IsZero() || time.Since(f.lastCoverageReset) > 90*time.Second {
			if err := f.coverage.Reset(); err == nil {
				f.addEvent(fmt.Sprintf("COVERAGE bitmap reset (sat=%.1f%% → 0%%)", sat))
				f.currentEdges = 0
				f.coverageSaturationWarned = false
				f.lastCoverageReset = time.Now()
			}
		}
	}
}

func (f *Fuzzer) coverageSaturationPct() float64 {
	// Prefer baselineEdgesCeiling (set at end of Baseline epoch) as the denominator:
	// this represents the reachable surface under normal traffic and gives a
	// meaningful "% of application surface covered" reading.
	// Fall back to raw bitmap capacity when the ceiling hasn't been set yet
	// (i.e. we're still in the Baseline epoch itself).
	ceiling := f.baselineEdgesCeiling
	if ceiling <= 0 {
		// Still in Baseline or ceiling never set — fall back to bitmap capacity.
		ceiling = f.coverageCapacity
	}
	if ceiling <= 0 {
		return 0
	}
	return clampFloat((float64(f.currentEdges)/math.Max(1.0, float64(ceiling)))*100.0, 0.0, 150.0)
}

func (f *Fuzzer) addOrBoostSeed(item WorkItem, newEdges int) {
	if f.isTemplateBlocked(item.TemplateID) {
		return
	}
	// Surprise factor: discovering edges on a heavily-fuzzed endpoint is more
	// valuable than on a fresh one — it means we reached new code territory.
	// Mirrors AFL++'s rare-branch favoring: log2(requests) scaling.
	surprise := 1.0
	epKey := endpointKey(item.Method, normalizeEndpointPath(item.Path))
	if ep := f.endpointStats[epKey]; ep != nil && ep.Reqs > 1 {
		surprise = 1.0 + math.Log2(float64(ep.Reqs))
		if ep.NewEdges == 0 {
			surprise *= 3.0
		}
	}
	if item.SeedIdx >= 0 && item.SeedIdx < len(f.corpus) {
		f.corpus[item.SeedIdx].EdgesFound += newEdges
		f.corpus[item.SeedIdx].Energy += float64(newEdges) * 5.0 * surprise
		f.seedSampler.Set(item.SeedIdx, f.corpus[item.SeedIdx].Energy)
	}
	seed := Seed{
		TemplateID:   item.TemplateID,
		Payload:      item.Raw,
		EdgesFound:   newEdges,
		Energy:       math.Max(1.0, float64(newEdges)*surprise),
		MutationName: item.MutationName,
	}
	f.corpus = append(f.corpus, seed)
	f.seedSampler.Append(seed.Energy)

	// Corpus minimization: prune exhausted seeds to prevent unbounded growth.
	// Keeps the Fenwick sampler healthy and focuses energy on seeds that still find edges.
	if len(f.corpus) > 500 {
		f.minimizeCorpus()
	}
}

// minimizeCorpus removes seeds with energy below threshold or that have been chosen
// many times without finding new edges. Rebuilds the Fenwick sampler from scratch.
func (f *Fuzzer) minimizeCorpus() {
	const maxCorpus = 400
	const minEnergy = 0.3
	const maxChosenNoEdge = 80
	kept := make([]Seed, 0, maxCorpus)
	for _, s := range f.corpus {
		if s.Energy < minEnergy && s.TimesChosen > maxChosenNoEdge && s.EdgesFound == 0 {
			continue
		}
		kept = append(kept, s)
	}
	// If pruning wasn't aggressive enough, sort by energy and keep top maxCorpus.
	if len(kept) > maxCorpus {
		sort.Slice(kept, func(i, j int) bool { return kept[i].Energy > kept[j].Energy })
		kept = kept[:maxCorpus]
	}
	f.corpus = kept
	// Rebuild Fenwick sampler to match new corpus slice.
	f.seedSampler = NewFenwickSampler()
	for _, s := range f.corpus {
		f.seedSampler.Append(math.Max(0.01, s.Energy))
	}
}
func (f *Fuzzer) shouldLearnFromSuccess(res SendResult) bool {
	f.learnSampleCounter++
	method := res.Item.Method
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		return true
	}
	if loc := strings.TrimSpace(res.Headers["Location"]); loc != "" {
		return true
	}
	if loc := strings.TrimSpace(res.Headers["location"]); loc != "" {
		return true
	}
	if res.Item.EpochName == "Harvest" || res.Item.EpochName == "Baseline" || res.Item.EpochName == "Sequence" {
		return true
	}
	if len(res.Body) == 0 || len(res.Body) > 64*1024 {
		return false
	}
	if !reJSONStartAny.MatchString(res.Body) {
		return false
	}
	return f.learnSampleCounter%3 == 0
}

func (f *Fuzzer) shouldEnqueueSequence(res SendResult, learned int) bool {
	method := res.Item.Method
	if method == "POST" || method == "PUT" || method == "PATCH" {
		return true
	}
	if learned > 0 {
		return true
	}
	// Light sampling on non-write successes to avoid expensive parsing each time.
	return f.learnSampleCounter%5 == 0
}

func (f *Fuzzer) addEvent(msg string) {
	if strings.TrimSpace(msg) == "" {
		return
	}
	elapsed := time.Since(f.startTime)
	totalSec := int(elapsed.Seconds())
	stamp := fmt.Sprintf("[%02d:%02d]", (totalSec/60)%60, totalSec%60)
	line := stamp + " " + msg

	f.eventMu.Lock()
	defer f.eventMu.Unlock()

	if len(f.eventLog) > 0 && f.eventLog[len(f.eventLog)-1] == line {
		return
	}
	f.eventLog = append(f.eventLog, line)
	if len(f.eventLog) > 6 {
		// Shift elements to avoid unbounded backing array growth from front-popping.
		copy(f.eventLog, f.eventLog[len(f.eventLog)-6:])
		f.eventLog = f.eventLog[:6]
	}
}

func (f *Fuzzer) maybeAddRequestSample(res SendResult) {
	if res.Err != nil {
		return
	}
	interesting := res.Status >= 500 ||
		strings.Contains(res.Item.MutationLabel, "dict_") ||
		strings.Contains(res.Item.MutationLabel, "dep_") ||
		strings.Contains(res.Item.MutationLabel, "path_") ||
		strings.Contains(res.Item.MutationLabel, "adapt_form")
	if !interesting && rand.Float64() > 0.01 {
		return
	}
	now := time.Now()
	if !f.lastValueSampleTS.IsZero() && now.Sub(f.lastValueSampleTS) < 250*time.Millisecond && !interesting {
		return
	}
	payload := compactPayloadForUI(res.Item.Body, 68)
	if payload == "" {
		payload = "<empty>"
	}
	line := fmt.Sprintf("%-5s %-34s %3d  %s", res.Item.Method, truncate(normalizePath(res.Item.Path), 34), res.Status, payload)
	f.requestSamples = append(f.requestSamples, sanitizeText(line, 240))
	if len(f.requestSamples) > 6 {
		copy(f.requestSamples, f.requestSamples[len(f.requestSamples)-6:])
		f.requestSamples = f.requestSamples[:6]
	}
	f.lastValueSampleTS = now
}

func (f *Fuzzer) tuneConcurrency() {
	if !f.cfg.AdaptiveConcurrency {
		return
	}
	now := time.Now()
	if now.Sub(f.lastTuneTS) < 1*time.Second {
		return
	}
	dt := now.Sub(f.lastTuneTS).Seconds()
	doneDelta := f.totalDone - f.lastTuneDone
	errDelta := f.totalErrors - f.lastTuneErr
	latDelta := f.latencyTotalMS - f.lastTuneLatMS

	doneRate := float64(doneDelta) / math.Max(0.001, dt)
	errRate := float64(errDelta) / math.Max(1.0, float64(doneDelta+errDelta))
	avgLat := 0.0
	if doneDelta > 0 {
		avgLat = latDelta / float64(doneDelta)
	}

	if avgLat > 0 {
		if f.baselineLatMS == 0 {
			f.baselineLatMS = avgLat
		} else {
			f.baselineLatMS = f.baselineLatMS*0.95 + avgLat*0.05
		}
	}
	highLat := math.Max(400.0, f.baselineLatMS*3.0)
	medLat := math.Max(200.0, f.baselineLatMS*2.0)
	growLat := math.Max(150.0, f.baselineLatMS*1.3)

	prev := f.currentConcurrency
	if errRate > 0.15 || avgLat > highLat {
		f.currentConcurrency = maxInt(f.cfg.MinConcurrency, f.currentConcurrency-2)
	} else if avgLat > medLat {
		f.currentConcurrency = maxInt(f.cfg.MinConcurrency, f.currentConcurrency-1)
	} else if doneRate > float64(f.currentConcurrency)*0.75 && avgLat < growLat && errRate < 0.05 {
		f.currentConcurrency = minInt(f.cfg.MaxConcurrency, f.currentConcurrency+1)
	}
	if prev != f.currentConcurrency {
		msg := fmt.Sprintf("concurrency %d -> %d (done=%.1f/s err=%.2f lat=%.1fms)", prev, f.currentConcurrency, doneRate, errRate, avgLat)
		f.addEvent("[ADAPT] " + msg)
		if !f.cfg.NoUI && !f.useDashboardUI() {
			fmt.Printf("[ADAPT] %s\n", msg)
		}
	}

	f.lastTuneTS = now
	f.lastTuneDone = f.totalDone
	f.lastTuneErr = f.totalErrors
	f.lastTuneLatMS = f.latencyTotalMS

	// MOpt: recalculate mutation category weights every tuning cycle.
	updateMutationCategoryWeights()
}
func (f *Fuzzer) pickWeightedTemplate() int {
	if len(f.activeIDs) == 0 {
		return -1
	}
	f.weightsBuf = f.weightsBuf[:0]
	f.tidsBuf = f.tidsBuf[:0]
	for _, tid := range f.activeIDs {
		w := f.templateHealthWeight(tid) * f.templateDependencyWeight(tid) * f.templateSourcePriorityWeight(tid)
		f.weightsBuf = append(f.weightsBuf, math.Max(0.03, w))
		f.tidsBuf = append(f.tidsBuf, tid)
	}
	idx := weightedPick(f.weightsBuf)
	if idx < 0 || idx >= len(f.tidsBuf) {
		return f.tidsBuf[rand.Intn(len(f.tidsBuf))]
	}
	return f.tidsBuf[idx]
}

func (f *Fuzzer) pickHarvestTemplate() int {
	if len(f.activeIDs) == 0 {
		return -1
	}
	f.weightsBuf = f.weightsBuf[:0]
	for _, tid := range f.activeIDs {
		meta := f.meta[tid]
		w := 1.0
		hasPathParams := strings.Contains(meta.Norm, "{") && strings.Contains(meta.Norm, "}")
		switch meta.Method {
		case "POST":
			w *= 7.0
		case "PUT", "PATCH":
			w *= 4.0
		case "GET":
			if hasPathParams {
				w *= 1.2
			} else {
				w *= 3.0
			}
		case "DELETE":
			w *= 0.6
		}
		k := endpointKey(meta.Method, meta.Norm)
		w *= 1.0 + math.Min(2.5, float64(f.learnedByEndpoint[k])*0.15)
		w *= f.templateHealthWeight(tid)
		w *= f.templateDependencyWeight(tid)
		w *= f.templateSourcePriorityWeight(tid)
		f.weightsBuf = append(f.weightsBuf, math.Max(0.05, w))
	}
	idx := weightedPick(f.weightsBuf)
	if idx < 0 || idx >= len(f.activeIDs) {
		return f.activeIDs[rand.Intn(len(f.activeIDs))]
	}
	return f.activeIDs[idx]
}

func (f *Fuzzer) pickSeed() int {
	if len(f.corpus) == 0 {
		return -1
	}
	idx := f.seedSampler.Pick()
	if idx < 0 || idx >= len(f.corpus) {
		return rand.Intn(len(f.corpus))
	}
	return idx
}

func (f *Fuzzer) templateDependencyWeight(tid int) float64 {
	info := f.depIndex[tid]
	if len(info.Reads) == 0 {
		if len(info.Writes) > 0 {
			return 1.2
		}
		return 1.0
	}
	ready := 0
	for dep := range info.Reads {
		if f.runtime.getDepValue(dep) != "" {
			ready++
		}
	}
	ratio := float64(ready) / math.Max(1, float64(len(info.Reads)))
	weight := 0.2 + ratio*1.8
	if len(info.Writes) > 0 {
		weight += 0.2
	}
	return clampFloat(weight, 0.05, 2.4)
}

func (f *Fuzzer) templateHealthWeight(tid int) float64 {
	meta := f.meta[tid]
	k := endpointKey(meta.Method, meta.Norm)
	// Crash amplification override: always heavily prioritize recently crashing endpoints.
	// This bypasses the normal health-weight penalty so that a first-seen crash leads to
	// intensive follow-up fuzzing rather than the endpoint getting down-weighted due to 4xx ratio.
	if remaining, ok := f.crashBoost[k]; ok && remaining > 0 {
		f.crashBoost[k] = remaining - 1
		return math.Max(0.0, f.cfg.CrashBoostWeight)
	}
	ep := f.endpointStats[k]
	if ep == nil || ep.Reqs == 0 {
		return 1.0
	}
	reqs := float64(ep.Reqs)
	succ := float64(ep.S2xx)
	client := float64(ep.S4xx + ep.S401403)
	successRate := succ / math.Max(1, reqs)
	clientRatio := client / math.Max(1, reqs)
	// Hard cap: no single endpoint should monopolize the run when it no longer yields edges.
	shareCap := clampFloat(f.cfg.EndpointReqShareCapPct, 0.0, 100.0) / 100.0
	capReqs := maxInt(f.cfg.EndpointReqCapMinReqs, int(float64(f.totalDone)*shareCap))
	if ep.Reqs > capReqs && ep.NewEdges == 0 {
		return f.cfg.EndpointNoEdgeCapWeight
	}

	// Crash rate throttle: reliably crashing endpoints should be down-weighted.
	crashTotal := ep.Logged5xx + ep.Filtered5xx
	crashRateThreshold := clampFloat(f.cfg.EndpointCrashRateThreshold, 0.0, 100.0) / 100.0
	if crashTotal > f.cfg.EndpointCrashRateMinCrashes && float64(crashTotal)/reqs > crashRateThreshold {
		return f.cfg.EndpointCrashRateWeight
	}

	w := 1.0
	if ep.Reqs >= 12 && ep.S2xx == 0 && clientRatio > 0.9 {
		if ep.Reqs >= 40 {
			w *= 0.08
		} else {
			w *= 0.2
		}
	} else {
		w *= math.Max(0.25, 0.25+successRate*1.75)
	}
	if ep.NewEdges == 0 && ep.Reqs >= maxInt(20, f.cfg.EndpointZeroEdgeReqs) {
		w *= 0.05
	}
	if ep.ReqsSinceEdge >= maxInt(20, f.cfg.EndpointStallReqs) {
		switch {
		case ep.ReqsSinceEdge >= f.cfg.EndpointStallReqs*4:
			w *= 0.05
		case ep.ReqsSinceEdge >= f.cfg.EndpointStallReqs*2:
			w *= 0.15
		default:
			w *= 0.35
		}
	}
	if ep.Reqs >= maxInt(100, f.cfg.EndpointZeroEdgeReqs*2) && float64(ep.NewEdges)/math.Max(1, reqs) < 0.002 {
		w *= 0.6
	}
	if st := f.authBlocked[k]; st != nil && ep.S2xx == 0 {
		if st.Count >= 15 {
			w *= 0.01
		} else if st.Count >= 5 {
			w *= 0.05
		}
	}
	return math.Max(0.03, w)
}

func (f *Fuzzer) ensureEndpointStats(method, path string) *EndpointStats {
	norm := normalizeEndpointPath(path)
	k := endpointKey(method, norm)
	ep := f.endpointStats[k]
	if ep == nil {
		ep = &EndpointStats{Method: method, Path: norm}
		f.endpointStats[k] = ep
	}
	return ep
}

func (f *Fuzzer) ensureMutationStats(name string) *MutationStats {
	if name == "" {
		name = "seed"
	}
	ms := f.mutationStats[name]
	if ms == nil {
		ms = &MutationStats{Name: name}
		f.mutationStats[name] = ms
	}
	return ms
}
func (f *Fuzzer) recordClientErrorSample(method, path string, status int, body string) {
	k := endpointKey(method, normalizePath(path))
	s := f.clientSamples[k]
	if len(s) >= 5 {
		return
	}
	msg := truncate(strings.TrimSpace(body), 300)
	if msg == "" {
		msg = "<empty response body>"
	}
	s = append(s, fmt.Sprintf("%d %s", status, msg))
	f.clientSamples[k] = s
}
