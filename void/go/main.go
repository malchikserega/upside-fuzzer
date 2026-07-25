package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// main.go — Entry point: CLI flag parsing and fuzzer bootstrap.

func parseFlags() Config {
	nowTS := time.Now().Format("20060102-150405")
	cfg := Config{}
	flag.StringVar(&cfg.Profile, "profile", "", "Preset knob bundle: fast | deep | security. Individual flags you pass still override the profile.")
	flag.StringVar(&cfg.GrammarDir, "grammar", ".", "Path to directory containing grammar.py and dict.json")
	flag.StringVar(&cfg.SourceDir, "src", "", "Path to source tree for source-aware endpoint prioritization")
	flag.Int64Var(&cfg.Seed, "seed", 0, "Seed math/rand's global source for reproducible mutation/scheduling draws (0 = unseeded/random, the default). Not bit-for-bit deterministic under concurrency, but removes the dominant source of run-to-run variance.")
	flag.StringVar(&cfg.RunID, "run-id", "", "Opaque run identifier stamped into every -event-log row (benchmark harness use; purely a label, no behavior change)")
	flag.StringVar(&cfg.EventLog, "event-log", "", "Path to a per-request JSONL event log (epoch, mutation category, coverage delta, sequence/corpus ancestry, identity, valid/state-change flags). Off by default -- opt in for benchmark data collection (BENCHMARK_PLAN.md Top-15 #6); adds one JSON-encode+write per completed request when enabled.")
	flag.StringVar(&cfg.DictPath, "dict", "", "Path to custom JSON dictionary")
	flag.StringVar(&cfg.TemplatesJSON, "templates-json", "", "Path to exported templates JSON (default: <grammar>/templates.export.json)")
	flag.BoolVar(&cfg.RefreshTemplates, "refresh-templates", false, "Re-export templates from grammar.py even if templates JSON exists")
	flag.StringVar(&cfg.ExporterPath, "exporter", "./export-templates.py", "Path to export-templates.py")
	flag.Float64Var(&cfg.TimeBudgetMinutes, "time-budget", 10, "Minutes")
	flag.IntVar(&cfg.Concurrency, "concurrency", 10, "Parallel requests")
	flag.IntVar(&cfg.MinConcurrency, "min-concurrency", 1, "Adaptive min concurrency")
	flag.IntVar(&cfg.MaxConcurrency, "max-concurrency", 64, "Adaptive max concurrency")
	flag.BoolVar(&cfg.AdaptiveConcurrency, "adaptive-concurrency", true, "Enable adaptive concurrency")
	flag.BoolVar(&cfg.AdaptiveContentType, "adaptive-content-type", true, "Adapt request Content-Type per endpoint using response feedback")
	flag.BoolVar(&cfg.AutoAntiForgery, "auto-antiforgery", true, "Auto-harvest and inject anti-forgery tokens for MVC form endpoints")
	flag.StringVar(&cfg.AntiForgeryField, "antiforgery-field", "__RequestVerificationToken", "Anti-forgery form field name")
	flag.StringVar(&cfg.AntiForgeryHeader, "antiforgery-header", "RequestVerificationToken", "Anti-forgery request header name")
	flag.Float64Var(&cfg.AntiForgeryCooldown, "antiforgery-cooldown", 10.0, "Cooldown seconds between anti-forgery harvest attempts per endpoint")
	flag.Float64Var(&cfg.AntiForgerySampleRate, "antiforgery-sample-rate", 0.10, "Sample rate for passive anti-forgery token harvest from HTML responses")
	flag.IntVar(&cfg.AntiForgeryMaxTokens, "antiforgery-max-tokens", 2048, "Max anti-forgery tokens kept in runtime pool")
	flag.Float64Var(&cfg.AntiForgeryTokenTTL, "antiforgery-token-ttl", 300.0, "Anti-forgery token TTL seconds in runtime pool")
	flag.Float64Var(&cfg.RequestTimeoutSec, "request-timeout", 5.0, "Per-request timeout seconds")
	flag.IntVar(&cfg.MaxResponseBytes, "max-response-bytes", 262144, "Max bytes to decode from successful responses")
	flag.IntVar(&cfg.CoverageInterval, "coverage-interval", 1, "Read coverage once every N completed requests")
	flag.IntVar(&cfg.CoverageBitmapSize, "coverage-bitmap-size", defaultSHMBitmapSize, "Desired SHM bitmap size in bytes for direct SHM mode")
	flag.IntVar(&cfg.EndpointStallReqs, "endpoint-stall-reqs", 220, "Down-weight endpoint after this many requests without new edges")
	flag.IntVar(&cfg.EndpointZeroEdgeReqs, "endpoint-zero-edge-reqs", 120, "Down-weight endpoint when total requests exceed threshold but no edges found")
	flag.BoolVar(&cfg.DirectSHM, "direct-shm", false, "Read coverage bitmap directly from SHM file")
	flag.StringVar(&cfg.SHMPath, "shm-path", "/coverage_shm/bitmap", "Path to mmap bitmap")
	flag.StringVar(&cfg.SHMReadMode, "shm-read-mode", "file", "Direct SHM read mode: file|mmap|auto")
	flag.BoolVar(&cfg.AllowDegradedCoverage, "allow-degraded-coverage", false, "Continue even if /shm/health reports degraded instrumentation (no app assembly linked). Default: refuse to start a blind run.")
	flag.BoolVar(&cfg.SkipOnCrash, "skip-on-crash", false, "Remove only the crashing template after any 5xx")
	flag.BoolVar(&cfg.SkipEndpointOn500, "skip-endpoint-on-500", false, "Stop fuzzing endpoint after first HTTP 500")
	flag.BoolVar(&cfg.SequentialBaseline, "sequential-baseline", false, "Run baseline epoch sequentially")
	flag.BoolVar(&cfg.SourceAwarePriority, "source-aware-priority", true, "Prioritize sensitive endpoints using source + route heuristics")
	flag.BoolVar(&cfg.RaceMode, "race-mode", true, "Enable conflict/race burst scheduling for stateful write endpoints")
	flag.IntVar(&cfg.RaceBurst, "race-burst", 4, "Number of concurrent conflicting requests to enqueue in race mode")
	flag.Float64Var(&cfg.RaceProb, "race-prob", 0.10, "Probability to enqueue race burst after successful write")
	flag.BoolVar(&cfg.CrashTriage, "crash-triage", true, "Classify crashes (noise vs likely vuln) with severity scoring")
	flag.StringVar(&cfg.CrashSignatureMode, "crash-signature-mode", "balanced", "Crash dedup signature mode: coarse|balanced|strict")
	flag.BoolVar(&cfg.CrashSigMutation, "crash-signature-mutation", false, "Include normalized mutation label in unique crash signature")
	flag.BoolVar(&cfg.CrashSigQueryValues, "crash-signature-query-values", false, "Include query values (not only query keys) in crash signature")
	flag.IntVar(&cfg.CrashReplayCount, "crash-replay-count", 4, "Follow-up replay requests per unique crash")
	flag.IntVar(&cfg.CrashReplayQueueMax, "crash-replay-queue-max", 96, "Global max queued crash replay requests")
	flag.IntVar(&cfg.CrashReplayPerEndpoint, "crash-replay-per-endpoint", 24, "Max replay requests per endpoint per run (0 = unlimited)")
	flag.Float64Var(&cfg.CrashReplayProb, "crash-replay-prob", 0.35, "Probability of draining crash replay queue on each scheduling step")
	flag.IntVar(&cfg.CrashBoostRequests, "crash-boost-requests", 80, "Temporary endpoint boost duration (requests) after a unique crash (0 = disable)")
	flag.IntVar(&cfg.CrashBoostMaxPerEndpoint, "crash-boost-max-per-endpoint", 2, "Max number of boost activations per endpoint")
	flag.Float64Var(&cfg.CrashBoostWeight, "crash-boost-weight", 8.0, "Template health weight while crash boost is active")
	flag.Float64Var(&cfg.EndpointReqShareCapPct, "endpoint-req-share-cap-pct", 2.0, "Soft cap on per-endpoint request share in percent when no new edges")
	flag.IntVar(&cfg.EndpointReqCapMinReqs, "endpoint-req-cap-min-reqs", 500, "Minimum requests before endpoint share cap applies")
	flag.Float64Var(&cfg.EndpointNoEdgeCapWeight, "endpoint-no-edge-cap-weight", 0.01, "Weight used when endpoint exceeds share cap without new edges")
	flag.IntVar(&cfg.EndpointCrashRateMinCrashes, "endpoint-crash-rate-min-crashes", 50, "Minimum 5xx count before crash-rate throttling applies")
	flag.Float64Var(&cfg.EndpointCrashRateThreshold, "endpoint-crash-rate-threshold", 50.0, "Crash-rate threshold in percent for endpoint throttling")
	flag.Float64Var(&cfg.EndpointCrashRateWeight, "endpoint-crash-rate-weight", 0.02, "Weight used for high crash-rate endpoints")
	flag.IntVar(&cfg.ReproRuns, "repro-runs", 5, "Repro check attempts for each unique crash (0 to disable)")
	flag.Float64Var(&cfg.ReproTargetPct, "repro-target", 80.0, "Target reproducibility percentage for confirmed crash")
	flag.Float64Var(&cfg.ReproTimeoutSec, "repro-timeout", 5.0, "Timeout per repro probe request")
	flag.BoolVar(&cfg.MinimizeCrash, "minimize-crash", true, "Run payload/path/query minimization on unique crashes")
	flag.IntVar(&cfg.MinimizeMaxProbes, "minimize-max-probes", 24, "Max probe requests for crash delta-reduction")
	flag.StringVar(&cfg.PocDir, "poc-dir", filepath.Join("./crashes", "pocs"), "Directory for generated reproducible PoC scripts")
	flag.StringVar(&cfg.TimelineDir, "timeline-dir", filepath.Join("./crashes", "timelines"), "Directory for generated Mermaid exploit timelines")
	flag.BoolVar(&cfg.MultiIdentity, "multi-identity", true, "Enable multi-identity scheduling from -auth-file/AUTH_FILE/AUTH_IDENTITIES_JSON")
	flag.StringVar(&cfg.AuthFile, "auth-file", "", "Path to auth identities JSON file (JWT/API-key/cookie headers)")
	flag.StringVar(&cfg.IdentitySampleMode, "identity-mode", "weighted", "Identity scheduling: weighted|round-robin|random")
	flag.BoolVar(&cfg.IdentityIncludeGuest, "identity-include-guest", true, "Include an anonymous guest identity during multi-identity fuzzing")
	flag.BoolVar(&cfg.NoUI, "no-ui", false, "Disable live UI")
	flag.BoolVar(&cfg.WebUI, "web-ui", false, "Enable the web UI dashboard server")
	flag.IntVar(&cfg.WebUIPort, "web-ui-port", 13377, "Port for the web UI dashboard")
	flag.BoolVar(&cfg.ForceUI, "force-ui", false, "Force dashboard UI even when stdout is not a terminal")
	flag.BoolVar(&cfg.PlainUI, "plain-ui", false, "Use plain line-by-line UI instead of dashboard")
	flag.BoolVar(&cfg.UINoClear, "ui-no-clear", false, "Do not clear screen between dashboard refreshes")
	flag.BoolVar(&cfg.ASCIIUI, "ascii-ui", false, "Use ASCII borders/progress in dashboard")
	flag.IntVar(&cfg.UIWidth, "ui-width", 0, "Fixed dashboard width (80..200)")
	flag.Float64Var(&cfg.UIIntervalSec, "ui-interval", 1.0, "UI refresh interval seconds")
	flag.StringVar(&cfg.UIEndpointSort, "ui-endpoint-sort", "hot", "Live endpoint sort: hot|recent|req|edges|alpha")
	flag.BoolVar(&cfg.UIEndpointRotate, "ui-endpoint-rotate", true, "Rotate endpoint pages in live dashboard")
	flag.Float64Var(&cfg.UIEndpointRotateSec, "ui-endpoint-rotate-sec", 1.0, "Seconds between endpoint page rotation")
	flag.Float64Var(&cfg.SequenceProb, "sequence-prob", 0.30, "Probability of draining sequence queue")
	flag.IntVar(&cfg.SequenceMaxDepth, "sequence-max-depth", 3, "Maximum sequence chain depth")
	flag.IntVar(&cfg.SequenceFanout, "sequence-fanout", 6, "Maximum follow-up requests per successful step")
	flag.StringVar(&cfg.CrashFile, "crash-file", filepath.Join("./crashes", "crashes-"+nowTS+".jsonl"), "Path to all crash JSONL")
	flag.StringVar(&cfg.UniqueCrashFile, "unique-crash-file", filepath.Join("./crashes", "unique-crashes-"+nowTS+".jsonl"), "Path to unique crash JSONL")
	flag.StringVar(&cfg.SummaryFile, "summary-file", filepath.Join("./summaries", "summary-"+nowTS+".json"), "Path to run summary JSON")
	flag.StringVar(&cfg.ReportFile, "report-file", "", "Path to structured crash report JSON (default: derived from --summary-file)")
	flag.IntVar(&cfg.BootstrapMax, "bootstrap-max", 20, "Max GET requests in runtime bootstrap harvest")
	flag.BoolVar(&cfg.AccessProbe, "access-probe", true, "Master toggle for access-control oracles (BOLA + auth-bypass + mass-assignment)")
	flag.BoolVar(&cfg.ProbeBOLA, "probe-bola", true, "Cross-identity BOLA/IDOR replay (requires -access-probe)")
	flag.BoolVar(&cfg.ProbeAuthBypass, "probe-auth-bypass", true, "No-credential replay; only fires on endpoints that already returned 401/403 to unauth (requires -access-probe)")
	flag.BoolVar(&cfg.ProbeMassAssign, "probe-mass-assign", true, "Privileged-field over-posting on writes (requires -access-probe)")
	flag.BoolVar(&cfg.ProbeDifferential, "probe-differential", true, "Verb/content-type/route-case/param-location parser-confusion auth-bypass replay; only fires on endpoints with strong evidence of auth enforcement (requires -access-probe)")
	flag.Float64Var(&cfg.AccessProbeProb, "access-probe-prob", 0.5, "Probability of firing access-control probes after a successful resource-scoped request")
	flag.IntVar(&cfg.AccessProbeMaxPerEndpoint, "access-probe-max-per-endpoint", 6, "Max access-control probes queued per endpoint per run")
	flag.IntVar(&cfg.AccessProbeQueueMax, "access-probe-queue-max", 256, "Global max queued access-control probes")
	flag.BoolVar(&cfg.InjectionOracle, "injection-oracle", true, "Enable positive injection oracles (time-based SQLi, SSTI arithmetic, reflection)")
	flag.Float64Var(&cfg.SQLiTimeThresholdSec, "sqli-time-threshold", 1.5, "Absolute latency (seconds) above which a sleep/benchmark SQLi payload is flagged (also requires >=3x baseline)")
	flag.BoolVar(&cfg.CmpLog, "cmplog", true, "Poll /shm/cmplog for comparison operands harvested from the target's own IL (Top-20+ #21) and blend them into string/int mutation. No-op against a target built without --cmplog or in --inject-mode source.")
	flag.Float64Var(&cfg.CmpLogInterval, "cmplog-interval", 3.0, "Seconds between /shm/cmplog polls")
	flag.Parse()

	// Apply the preset profile ONLY to knobs the user did not explicitly set,
	// so any individual flag the user passed still wins.
	setFlags := map[string]bool{}
	flag.Visit(func(fl *flag.Flag) { setFlags[fl.Name] = true })
	applyProfile(&cfg, setFlags)

	cfg.GrammarDir = absPath(cfg.GrammarDir)
	cfg.SourceDir = absPath(cfg.SourceDir)
	cfg.CrashFile = absPath(cfg.CrashFile)
	cfg.UniqueCrashFile = absPath(cfg.UniqueCrashFile)
	cfg.SummaryFile = absPath(cfg.SummaryFile)
	if strings.TrimSpace(cfg.ReportFile) == "" {
		cfg.ReportFile = deriveReportPathFromSummary(cfg.SummaryFile)
	} else {
		cfg.ReportFile = absPath(cfg.ReportFile)
	}
	cfg.PocDir = absPath(cfg.PocDir)
	cfg.TimelineDir = absPath(cfg.TimelineDir)
	if strings.TrimSpace(cfg.AuthFile) == "" {
		cfg.AuthFile = strings.TrimSpace(os.Getenv("AUTH_FILE"))
	}
	if strings.TrimSpace(cfg.AuthFile) != "" {
		cfg.AuthFile = absPath(cfg.AuthFile)
	}
	cfg.MinConcurrency = maxInt(1, cfg.MinConcurrency)
	cfg.MaxConcurrency = maxInt(cfg.MinConcurrency, cfg.MaxConcurrency)
	cfg.Concurrency = clampInt(maxInt(1, cfg.Concurrency), cfg.MinConcurrency, cfg.MaxConcurrency)
	cfg.SequenceMaxDepth = maxInt(1, cfg.SequenceMaxDepth)
	cfg.SequenceFanout = maxInt(1, cfg.SequenceFanout)
	cfg.CoverageInterval = maxInt(1, cfg.CoverageInterval)
	cfg.CoverageBitmapSize = maxInt(minSHMBitmapSize, cfg.CoverageBitmapSize)
	cfg.EndpointStallReqs = maxInt(20, cfg.EndpointStallReqs)
	cfg.EndpointZeroEdgeReqs = maxInt(20, cfg.EndpointZeroEdgeReqs)
	cfg.SHMReadMode = strings.ToLower(strings.TrimSpace(cfg.SHMReadMode))
	switch cfg.SHMReadMode {
	case "file", "mmap", "auto":
	default:
		cfg.SHMReadMode = "file"
	}
	cfg.UIIntervalSec = math.Max(0.2, cfg.UIIntervalSec)
	cfg.UIEndpointSort = strings.ToLower(strings.TrimSpace(cfg.UIEndpointSort))
	switch cfg.UIEndpointSort {
	case "hot", "recent", "req", "requests", "edges", "edge", "coverage", "alpha", "path":
	default:
		cfg.UIEndpointSort = "hot"
	}
	cfg.UIEndpointRotateSec = math.Max(0.5, cfg.UIEndpointRotateSec)
	cfg.AntiForgeryField = strings.TrimSpace(cfg.AntiForgeryField)
	if cfg.AntiForgeryField == "" {
		cfg.AntiForgeryField = "__RequestVerificationToken"
	}
	cfg.AntiForgeryHeader = strings.TrimSpace(cfg.AntiForgeryHeader)
	if cfg.AntiForgeryHeader == "" {
		cfg.AntiForgeryHeader = "RequestVerificationToken"
	}
	cfg.AntiForgeryCooldown = math.Max(0.5, cfg.AntiForgeryCooldown)
	cfg.AntiForgerySampleRate = clampFloat(cfg.AntiForgerySampleRate, 0.0, 1.0)
	cfg.AntiForgeryMaxTokens = maxInt(1, cfg.AntiForgeryMaxTokens)
	cfg.AntiForgeryTokenTTL = math.Max(0.0, cfg.AntiForgeryTokenTTL)
	cfg.RaceBurst = clampInt(cfg.RaceBurst, 2, 64)
	cfg.RaceProb = clampFloat(cfg.RaceProb, 0.0, 1.0)
	cfg.CrashSignatureMode = strings.ToLower(strings.TrimSpace(cfg.CrashSignatureMode))
	switch cfg.CrashSignatureMode {
	case "coarse", "balanced", "strict":
	default:
		cfg.CrashSignatureMode = "balanced"
	}
	cfg.CrashReplayCount = clampInt(cfg.CrashReplayCount, 0, 256)
	cfg.CrashReplayQueueMax = clampInt(cfg.CrashReplayQueueMax, 1, 10000)
	cfg.CrashReplayPerEndpoint = maxInt(0, cfg.CrashReplayPerEndpoint)
	cfg.CrashReplayProb = clampFloat(cfg.CrashReplayProb, 0.0, 1.0)
	cfg.CrashBoostRequests = maxInt(0, cfg.CrashBoostRequests)
	cfg.CrashBoostMaxPerEndpoint = maxInt(0, cfg.CrashBoostMaxPerEndpoint)
	cfg.CrashBoostWeight = math.Max(0.0, cfg.CrashBoostWeight)
	cfg.EndpointReqShareCapPct = clampFloat(cfg.EndpointReqShareCapPct, 0.0, 100.0)
	cfg.EndpointReqCapMinReqs = maxInt(1, cfg.EndpointReqCapMinReqs)
	cfg.EndpointNoEdgeCapWeight = clampFloat(cfg.EndpointNoEdgeCapWeight, 0.0, 1.0)
	cfg.EndpointCrashRateMinCrashes = maxInt(1, cfg.EndpointCrashRateMinCrashes)
	cfg.EndpointCrashRateThreshold = clampFloat(cfg.EndpointCrashRateThreshold, 0.0, 100.0)
	cfg.EndpointCrashRateWeight = clampFloat(cfg.EndpointCrashRateWeight, 0.0, 1.0)
	cfg.ReproRuns = clampInt(cfg.ReproRuns, 0, 20)
	cfg.ReproTargetPct = clampFloat(cfg.ReproTargetPct, 1.0, 100.0)
	cfg.ReproTimeoutSec = math.Max(0.2, cfg.ReproTimeoutSec)
	cfg.MinimizeMaxProbes = clampInt(cfg.MinimizeMaxProbes, 4, 200)
	cfg.IdentitySampleMode = strings.ToLower(strings.TrimSpace(cfg.IdentitySampleMode))
	switch cfg.IdentitySampleMode {
	case "weighted", "round-robin", "roundrobin", "rr", "random":
	default:
		cfg.IdentitySampleMode = "weighted"
	}
	if cfg.UIWidth > 0 {
		cfg.UIWidth = clampInt(cfg.UIWidth, 80, 200)
	}
	cfg.AccessProbeProb = clampFloat(cfg.AccessProbeProb, 0.0, 1.0)
	cfg.AccessProbeMaxPerEndpoint = maxInt(0, cfg.AccessProbeMaxPerEndpoint)
	cfg.AccessProbeQueueMax = maxInt(1, cfg.AccessProbeQueueMax)
	cfg.SQLiTimeThresholdSec = math.Max(0.5, cfg.SQLiTimeThresholdSec)
	return cfg
}

// applyProfile fills in a curated set of knobs for the named preset, but only
// for flags the user did not explicitly pass (tracked via flag.Visit). This keeps
// the full 90-flag surface available while giving newcomers three good starting points.
func applyProfile(cfg *Config, set map[string]bool) {
	p := strings.ToLower(strings.TrimSpace(cfg.Profile))
	if p == "" {
		return
	}
	setB := func(name string, target *bool, v bool) {
		if !set[name] {
			*target = v
		}
	}
	setF := func(name string, target *float64, v float64) {
		if !set[name] {
			*target = v
		}
	}
	setI := func(name string, target *int, v int) {
		if !set[name] {
			*target = v
		}
	}
	switch p {
	case "fast":
		// Maximize throughput (CI smoke): skip expensive per-crash work and oracles.
		setI("repro-runs", &cfg.ReproRuns, 0)
		setB("minimize-crash", &cfg.MinimizeCrash, false)
		setB("access-probe", &cfg.AccessProbe, false)
		setB("probe-bola", &cfg.ProbeBOLA, false)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, false)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, false)
		setB("probe-differential", &cfg.ProbeDifferential, false)
		setB("injection-oracle", &cfg.InjectionOracle, false)
		setB("race-mode", &cfg.RaceMode, false)
		setF("sequence-prob", &cfg.SequenceProb, 0.10)
	case "deep":
		// Balanced thorough scan: full crash analysis + oracles + stateful chains.
		setF("time-budget", &cfg.TimeBudgetMinutes, 60)
		setI("repro-runs", &cfg.ReproRuns, 5)
		setB("minimize-crash", &cfg.MinimizeCrash, true)
		setF("sequence-prob", &cfg.SequenceProb, 0.50)
		setB("access-probe", &cfg.AccessProbe, true)
		setB("probe-bola", &cfg.ProbeBOLA, true)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, true)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, true)
		setB("probe-differential", &cfg.ProbeDifferential, true)
		setB("injection-oracle", &cfg.InjectionOracle, true)
		setB("race-mode", &cfg.RaceMode, true)
	case "security":
		// Vulnerability-hunting: prioritize the access-control / injection oracles
		// and multi-identity coverage over raw throughput.
		setB("multi-identity", &cfg.MultiIdentity, true)
		setB("identity-include-guest", &cfg.IdentityIncludeGuest, true)
		setB("access-probe", &cfg.AccessProbe, true)
		setB("probe-bola", &cfg.ProbeBOLA, true)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, true)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, true)
		setB("probe-differential", &cfg.ProbeDifferential, true)
		setF("access-probe-prob", &cfg.AccessProbeProb, 0.75)
		setB("injection-oracle", &cfg.InjectionOracle, true)
		setB("source-aware-priority", &cfg.SourceAwarePriority, true)
		setF("sequence-prob", &cfg.SequenceProb, 0.50)
		setB("race-mode", &cfg.RaceMode, true)
		setB("crash-triage", &cfg.CrashTriage, true)
	default:
		fmt.Fprintf(os.Stderr, "warning: unknown -profile %q (expected fast|deep|security); ignoring\n", p)
	}
}

func main() {
	cfg := parseFlags()
	// Benchmark reproducibility (BENCHMARK_PLAN.md Top-15 #8): every mutation/
	// scheduling decision in this codebase draws from math/rand's top-level,
	// process-global source. Since Go 1.20 that source is auto-seeded randomly
	// at startup, so two runs never produce the same sequence of choices unless
	// -seed pins it explicitly. This does NOT make a run bit-for-bit
	// deterministic under concurrency (worker goroutines draw from the shared
	// source in scheduler-dependent order), but it removes the single biggest
	// source of run-to-run variance and is what the benchmark plan's fairness
	// contract (§5) requires as the honest baseline: "unseeded" unless stated.
	if cfg.Seed != 0 {
		rand.Seed(cfg.Seed)
		fmt.Printf("RNG seed: %d (deterministic mutation/scheduling draws, not bit-for-bit under concurrency)\n", cfg.Seed)
	} else {
		fmt.Printf("RNG seed: unseeded (default: random per run — pass -seed <n> for reproducibility)\n")
	}
	f, err := NewFuzzer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if cfg.WebUI {
		go RunWebUI(f)
	}
	if err := f.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
}
