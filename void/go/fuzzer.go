package main

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// fuzzer.go — Fuzzer struct definition, constructor (NewFuzzer),
// and top-level lifecycle: Run, Close, initialization helpers.

type Fuzzer struct {
	cfg            Config
	target         string
	shm            string
	token          string
	authHeaders    map[string]string
	identities     []AuthIdentity
	identityOrder  []string
	identityCursor int

	client   *http.Client
	coverage CoverageReader

	templates []Template
	tmplByID  map[int]*Template
	meta      map[int]TemplateMeta
	activeIDs []int
	tmplEPKey map[int]string

	depIndex         map[int]DepInfo
	depConsumers     map[string][]int
	idConsumers      map[string][]int
	templatePriority map[int]float64

	runtime       *RuntimeStore
	dict          *DictStore
	sequenceQueue []WorkItem
	raceQueue     []WorkItem
	corpus        []Seed
	seedSampler   *FenwickSampler

	endpointStats map[string]*EndpointStats
	mutationStats map[string]*MutationStats
	authBlocked   map[string]*AuthBlockedState
	clientSamples map[string][]string

	startTime        time.Time
	startEdges       int
	currentEdges     int
	coverageCapacity int
	totalDone        int
	totalSent        int
	totalErrors      int
	totalCrashes     int
	uniqueCrashes    int
	latencyTotalMS   float64
	latencySamples   int
	completedSinceCV int
	stallCounter     int

	learnedByEndpoint    map[string]int
	uniqueCrashKeys      map[string]struct{}
	crashLog             []map[string]any
	blockedEndpoints     map[string]struct{}
	forceFormEndpoints   map[string]struct{}
	antiForgeryHarvestAt map[string]time.Time
	antiForgeryLearned   int
	antiForgeryMu        sync.RWMutex
	harvestMu            sync.Mutex
	antiForgeryTokens    map[string]time.Time
	antiForgeryLastPrune time.Time

	crashWriter  *JSONLWriter
	uniqueWriter *JSONLWriter
	findings     []CrashFinding
	pocCount     int

	currentConcurrency       int
	lastTuneTS               time.Time
	lastTuneDone             int
	lastTuneErr              int
	lastTuneLatMS            float64
	baselineLatMS            float64
	lastUIRender             time.Time
	uiInline                 bool
	uiWidthLocked            int
	eventLog                 []string
	requestSamples           []string
	lastEdgeEvent            time.Time
	coverageSaturationWarned bool
	lastValueSampleTS        time.Time
	learnSampleCounter       int
	stoppedByUser            bool

	triageTimeSpent time.Duration

	// Crash amplification: endpoint key -> requests remaining at boosted weight.
	// Triggered only by unique crashes; capped per endpoint to prevent monopolization.
	crashBoost map[string]int
	// How many times we've boosted each endpoint (to cap total boost budget).
	crashBoostCount map[string]int
	// Replay queue: targeted follow-up requests queued after a unique crash.
	replayQueue []WorkItem
	// Replay budget consumed per endpoint to prevent single-route monopolization.
	replayByEndpoint map[string]int
	// Rate-limit re-auth attempts to avoid hammering the auth endpoint.
	lastAuthRefresh time.Time
	// Last time we reset the coverage bitmap (triggered on high saturation).
	lastCoverageReset time.Time
	// Monotonic request id sequence for low-overhead per-request attribution.
	requestIDSeq uint64

	// Reusable buffers for weighted template selection to avoid per-call allocations.
	weightsBuf []float64
	tidsBuf    []int
}

func NewFuzzer(cfg Config) (*Fuzzer, error) {
	target := strings.TrimRight(envOr("TARGET_HOST", "http://localhost:5200"), "/")
	shmHost := strings.TrimRight(envOr("SHM_HOST", target), "/")

	transport := &http.Transport{
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  true,
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout:   time.Duration(math.Max(0.1, cfg.RequestTimeoutSec) * float64(time.Second)),
		Transport: transport,
		Jar:       jar,
	}

	templatesPath := cfg.TemplatesJSON
	if templatesPath == "" {
		templatesPath = filepath.Join(cfg.GrammarDir, "templates.export.json")
	}
	if shouldRefreshTemplates(cfg, templatesPath) {
		fmt.Printf("Refreshing templates from grammar: %s\n", filepath.Join(cfg.GrammarDir, "grammar.py"))
		if err := exportTemplates(cfg.ExporterPath, cfg.GrammarDir, templatesPath); err != nil {
			return nil, err
		}
	}
	templates, err := loadTemplates(templatesPath)
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, errors.New("no templates loaded")
	}

	dictPath := resolveDictionaryPath(cfg.DictPath, cfg.GrammarDir)
	dict, err := loadDict(dictPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load dictionary: %w", err)
	}
	if dictPath != "" {
		fmt.Printf("Loaded dictionary: %s\n", dictPath)
	}

	coverage := CoverageReader(&HTTPCoverageReader{client: client, shmHost: shmHost})
	if cfg.DirectSHM {
		coverage = &SHMCoverageReader{path: cfg.SHMPath, size: cfg.CoverageBitmapSize, mode: cfg.SHMReadMode}
	}

	crashWriter, err := NewJSONLWriter(cfg.CrashFile)
	if err != nil {
		return nil, err
	}
	uniqueWriter, err := NewJSONLWriter(cfg.UniqueCrashFile)
	if err != nil {
		_ = crashWriter.Close()
		return nil, err
	}
	if err := ensureFileExists(cfg.SummaryFile, []byte("{}\n")); err != nil {
		_ = crashWriter.Close()
		_ = uniqueWriter.Close()
		return nil, err
	}
	if err := ensureFileExists(cfg.ReportFile, []byte("{\"bugs\":[]}\n")); err != nil {
		_ = crashWriter.Close()
		_ = uniqueWriter.Close()
		return nil, err
	}

	f := &Fuzzer{
		cfg:                  cfg,
		target:               target,
		shm:                  shmHost,
		client:               client,
		coverage:             coverage,
		templates:            templates,
		tmplByID:             map[int]*Template{},
		meta:                 map[int]TemplateMeta{},
		tmplEPKey:            map[int]string{},
		depIndex:             map[int]DepInfo{},
		depConsumers:         map[string][]int{},
		idConsumers:          map[string][]int{},
		templatePriority:     map[int]float64{},
		runtime:              newRuntimeStore(),
		dict:                 dict,
		seedSampler:          NewFenwickSampler(),
		endpointStats:        map[string]*EndpointStats{},
		mutationStats:        map[string]*MutationStats{},
		authBlocked:          map[string]*AuthBlockedState{},
		clientSamples:        map[string][]string{},
		learnedByEndpoint:    map[string]int{},
		uniqueCrashKeys:      map[string]struct{}{},
		blockedEndpoints:     map[string]struct{}{},
		forceFormEndpoints:   map[string]struct{}{},
		antiForgeryHarvestAt: map[string]time.Time{},
		antiForgeryTokens:    map[string]time.Time{},
		authHeaders:          map[string]string{},
		crashBoost:           map[string]int{},
		crashBoostCount:      map[string]int{},
		replayQueue:          make([]WorkItem, 0, 64),
		replayByEndpoint:     map[string]int{},
		identities:           nil,
		identityOrder:        nil,
		identityCursor:       0,
		crashWriter:          crashWriter,
		uniqueWriter:         uniqueWriter,
		findings:             make([]CrashFinding, 0, 64),
		raceQueue:            make([]WorkItem, 0, 128),
		currentConcurrency: clampInt(cfg.Concurrency,
			clampInt(cfg.MinConcurrency, 1, 4096),
			clampInt(cfg.MaxConcurrency, 1, 4096),
		),
		uiInline:       isTerminal(os.Stdout),
		eventLog:       make([]string, 0, 8),
		requestSamples: make([]string, 0, 8),
		uiWidthLocked:  0,
	}
	for i := range f.templates {
		t := &f.templates[i]
		f.tmplByID[t.ID] = t
	}
	return f, nil
}

func shouldRefreshTemplates(cfg Config, templatesPath string) bool {
	if cfg.RefreshTemplates || !fileExists(templatesPath) {
		return true
	}

	grammarPath := filepath.Join(cfg.GrammarDir, "grammar.py")
	tplInfo, tplErr := os.Stat(templatesPath)
	grInfo, grErr := os.Stat(grammarPath)
	if tplErr != nil || grErr != nil {
		return false
	}

	return grInfo.ModTime().After(tplInfo.ModTime())
}

func (f *Fuzzer) Close() {
	_ = f.coverage.Close()
	_ = f.crashWriter.Close()
	_ = f.uniqueWriter.Close()
}

func (f *Fuzzer) Run() error {
	fmt.Printf("Time budget: %.1f minutes\n", f.cfg.TimeBudgetMinutes)
	fmt.Printf("Concurrency: %d (adaptive=%v min=%d max=%d)\n", f.currentConcurrency, f.cfg.AdaptiveConcurrency, f.cfg.MinConcurrency, f.cfg.MaxConcurrency)
	fmt.Printf("Output files: crash=%s unique=%s summary=%s report=%s\n",
		f.cfg.CrashFile, f.cfg.UniqueCrashFile, f.cfg.SummaryFile, f.cfg.ReportFile)
	fmt.Printf("Content-Type adaptation: %v\n", f.cfg.AdaptiveContentType)
	fmt.Printf("Anti-forgery auto-harvest: %v (field=%s header=%s cooldown=%.1fs)\n",
		f.cfg.AutoAntiForgery, f.cfg.AntiForgeryField, f.cfg.AntiForgeryHeader, f.cfg.AntiForgeryCooldown)
	fmt.Printf("Anti-forgery learning: sample=%.2f max_tokens=%d ttl=%.0fs\n",
		f.cfg.AntiForgerySampleRate, f.cfg.AntiForgeryMaxTokens, f.cfg.AntiForgeryTokenTTL)
	fmt.Printf("Coverage bitmap target size: %d bytes\n", f.cfg.CoverageBitmapSize)
	fmt.Printf("Endpoint stall throttle: stall_reqs=%d zero_edge_reqs=%d\n", f.cfg.EndpointStallReqs, f.cfg.EndpointZeroEdgeReqs)
	fmt.Printf("UI endpoint view: sort=%s rotate=%v every=%.1fs\n", f.cfg.UIEndpointSort, f.cfg.UIEndpointRotate, f.cfg.UIEndpointRotateSec)
	fmt.Printf("Advanced: triage=%v repro_runs=%d minimize=%v race=%v burst=%d source_priority=%v multi_identity=%v\n",
		f.cfg.CrashTriage, f.cfg.ReproRuns, f.cfg.MinimizeCrash, f.cfg.RaceMode, f.cfg.RaceBurst, f.cfg.SourceAwarePriority, f.cfg.MultiIdentity)
	fmt.Printf("Crash dedup: mode=%s mutation=%v query_values=%v\n",
		f.cfg.CrashSignatureMode, f.cfg.CrashSigMutation, f.cfg.CrashSigQueryValues)
	fmt.Printf("Crash replay: prob=%.2f count=%d queue_max=%d endpoint_max=%d\n",
		f.cfg.CrashReplayProb, f.cfg.CrashReplayCount, f.cfg.CrashReplayQueueMax, f.cfg.CrashReplayPerEndpoint)
	fmt.Printf("Crash boost: requests=%d max_per_endpoint=%d weight=%.2f\n",
		f.cfg.CrashBoostRequests, f.cfg.CrashBoostMaxPerEndpoint, f.cfg.CrashBoostWeight)
	if f.cfg.SkipEndpointOn500 {
		fmt.Printf("Endpoint policy: stop fuzzing endpoint after first HTTP 500\n")
	}

	if err := f.authenticate(); err != nil {
		fmt.Printf("Auth warning: %v (continuing anonymous)\n", err)
	} else if f.token != "" {
		fmt.Printf("Authenticated (token available)\n")
	} else if f.hasAuthContext() {
		fmt.Printf("Authenticated (cookie/header auth available)\n")
	}
	f.initAuthIdentities()
	fmt.Printf("Identities loaded: %d (mode=%s)\n", len(f.identities), f.cfg.IdentitySampleMode)

	if err := f.coverage.Init(); err != nil {
		return fmt.Errorf("coverage init failed: %w", err)
	}
	if f.cfg.DirectSHM {
		if shmReader, ok := f.coverage.(*SHMCoverageReader); ok {
			fmt.Printf("Direct SHM read mode: requested=%s active=%s\n", f.cfg.SHMReadMode, shmReader.ActiveMode())
		}
	}
	if err := f.coverage.Reset(); err != nil {
		fmt.Printf("Coverage reset warning: %v\n", err)
	}
	// Also reset via HTTP so the .NET CoverageExtensions sees a clean bitmap
	// (in case the SHM file-level reset isn't visible through the mmap yet).
	if f.cfg.DirectSHM {
		httpReset := &HTTPCoverageReader{
			client:  &http.Client{Timeout: 5 * time.Second},
			shmHost: f.shm,
		}
		if err := httpReset.Reset(); err != nil {
			fmt.Printf("HTTP /shm/reset warning: %v\n", err)
		}
	}
	edges, err := f.coverage.GetEdges()
	if err != nil {
		return fmt.Errorf("coverage read failed: %w", err)
	}
	fmt.Printf("Coverage after reset: %d edges (should be 0)\n", edges)
	f.startEdges = edges
	f.currentEdges = edges
	f.coverageCapacity = maxInt(0, f.coverage.Capacity())
	if f.coverageCapacity > 0 {
		fmt.Printf("Coverage bitmap active size: %d bytes\n", f.coverageCapacity)
	}

	f.buildTemplateMetaAndDependencies()
	if f.cfg.SourceAwarePriority {
		boosted := f.loadSourceAwarePriority()
		fmt.Printf("Source-aware priority: boosted templates=%d\n", boosted)
	}
	if len(f.activeIDs) == 0 {
		return errors.New("no active templates after filtering")
	}
	fmt.Printf("Templates loaded: %d\n", len(f.activeIDs))

	boot := f.bootstrapRuntimeValues()
	if boot > 0 {
		fmt.Printf("Bootstrap learned runtime values: %d\n", boot)
	}

	f.seedBaselineCorpus()
	f.preHarvestAntiForgeryTokens()
	return f.mainLoop()
}
func (f *Fuzzer) buildTemplateMetaAndDependencies() {
	f.activeIDs = f.activeIDs[:0]
	endpointProfiles := map[string]*EndpointContentProfile{}
	for _, t := range f.templates {
		item, err := f.renderTemplate(t.ID, "none", 1, -1)
		if err != nil {
			continue
		}
		if strings.HasPrefix(item.Path, "/shm/") {
			continue
		}
		authURL := strings.TrimSpace(envOr("AUTH_URL", "/api/authenticate"))
		if authURL != "" && strings.HasPrefix(item.Path, authURL) {
			continue
		}
		norm := normalizePath(item.Path)
		epKey := endpointKey(item.Method, norm)
		ct := canonicalContentType(item.Headers)
		f.meta[t.ID] = TemplateMeta{Method: item.Method, Path: item.Path, Norm: norm, ContentType: ct}
		f.tmplEPKey[t.ID] = epKey
		f.activeIDs = append(f.activeIDs, t.ID)

		prof := endpointProfiles[epKey]
		if prof == nil {
			prof = &EndpointContentProfile{}
			endpointProfiles[epKey] = prof
		}
		switch {
		case strings.Contains(ct, "application/json"):
			prof.JSON++
		case strings.Contains(ct, "application/x-www-form-urlencoded"):
			prof.Form++
		case strings.Contains(ct, "multipart/form-data"):
			prof.Multipart++
		case ct != "":
			prof.Other++
		}
	}

	if f.cfg.AdaptiveContentType {
		for epKey, prof := range endpointProfiles {
			parts := strings.SplitN(epKey, " ", 2)
			if len(parts) != 2 {
				continue
			}
			method := strings.TrimSpace(parts[0])
			path := strings.TrimSpace(parts[1])
			if !isWriteMethod(method) {
				continue
			}
			if isAPILikePath(path) {
				continue
			}
			// If route has both JSON and form-like templates, prefer forms to avoid MVC/FormValueRequired noise.
			if prof.JSON > 0 && (prof.Form > 0 || prof.Multipart > 0) {
				f.forceFormEndpoints[epKey] = struct{}{}
			}
		}
	}
	if n := len(f.forceFormEndpoints); n > 0 {
		fmt.Printf("Request adaptation: preselected form-data on %d non-API write endpoints\n", n)
	}

	for _, tid := range f.activeIDs {
		t := f.tmplByID[tid]
		if t == nil {
			continue
		}
		info := DepInfo{
			Reads:    setFromSlice(t.Reads),
			Writes:   setFromSlice(t.Writes),
			IDReads:  map[string]struct{}{},
			IDWrites: map[string]struct{}{},
		}
		for dep := range info.Reads {
			for _, k := range inferDependencyKeys(dep) {
				if isIDLikeKey(k) {
					info.IDReads[canonicalKey(k)] = struct{}{}
				}
			}
		}
		for dep := range info.Writes {
			for _, k := range inferDependencyKeys(dep) {
				if isIDLikeKey(k) {
					info.IDWrites[canonicalKey(k)] = struct{}{}
				}
			}
		}
		for _, s := range t.Segments {
			if s.Kind == "custom_payload" && isIDLikeKey(s.PayloadKey) {
				info.IDReads[canonicalKey(s.PayloadKey)] = struct{}{}
			}
		}
		for _, token := range extractPathParamNames(t.RequestID) {
			if isIDLikeKey(token) {
				info.IDReads[canonicalKey(token)] = struct{}{}
			}
		}
		meta := f.meta[tid]
		if meta.Method == "POST" || meta.Method == "PUT" || meta.Method == "PATCH" {
			if rid := inferResourceIDKeyFromPath(meta.Norm); rid != "" && isIDLikeKey(rid) {
				info.IDWrites[canonicalKey(rid)] = struct{}{}
			}
		}
		f.depIndex[tid] = info

		for dep := range info.Reads {
			f.depConsumers[dep] = appendUniqueInt(f.depConsumers[dep], tid)
		}
		for idk := range info.IDReads {
			f.idConsumers[idk] = appendUniqueInt(f.idConsumers[idk], tid)
		}
	}

	producers := 0
	consumers := 0
	for _, tid := range f.activeIDs {
		info := f.depIndex[tid]
		if len(info.Writes) > 0 {
			producers++
		}
		if len(info.Reads) > 0 {
			consumers++
		}
	}
	fmt.Printf("Dependency graph: producers=%d consumers=%d\n", producers, consumers)
}

func (f *Fuzzer) seedBaselineCorpus() {
	for _, tid := range f.activeIDs {
		item, err := f.renderTemplate(tid, "none", 1, -1)
		if err != nil {
			continue
		}
		seed := Seed{
			TemplateID:   tid,
			Payload:      item.Raw,
			Energy:       1.0,
			MutationName: "seed",
		}
		f.corpus = append(f.corpus, seed)
		f.seedSampler.Append(seed.Energy)
	}
	fmt.Printf("Baseline corpus seeded: %d\n", len(f.corpus))
}
