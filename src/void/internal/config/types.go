// Package config holds the void fuzzer's Config type and CLI flag/profile
// handling -- split out of void/go/types.go and void/go/main.go during the
// repo-architecture refactor so cmd/void/main.go can stay flags-and-assembly
// only. No fields or behavior changed by the move.
package config

type Config struct {
	Seed          int64
	RunID         string
	EventLog      string
	GrammarDir    string
	SourceDir     string
	DictPath      string
	TemplatesJSON string
	// TargetImageDigest/OpenAPISpecHash/CampaignConfig (Phase 5 #127) are pure
	// pass-through provenance labels for the run manifest (manifest.go) --
	// void itself never inspects the running container or the original
	// OpenAPI document (only the already-exported templates JSON it actually
	// consumes, which IS hashed locally -- see Fuzzer.templatesHash). Left ""
	// by default; the orchestrating pipeline (campaign.py / fuzz-prep) is
	// expected to supply them when full reproducibility provenance matters.
	TargetImageDigest     string
	OpenAPISpecHash       string
	CampaignConfig        string
	RefreshTemplates      bool
	ExporterPath          string
	TimeBudgetMinutes     float64
	Concurrency           int
	MinConcurrency        int
	MaxConcurrency        int
	AdaptiveConcurrency   bool
	AdaptiveContentType   bool
	AutoAntiForgery       bool
	AntiForgeryField      string
	AntiForgeryHeader     string
	AntiForgeryCooldown   float64
	AntiForgerySampleRate float64
	AntiForgeryMaxTokens  int
	AntiForgeryTokenTTL   float64
	RequestTimeoutSec     float64
	MaxResponseBytes      int
	CoverageInterval      int
	CoverageBitmapSize    int
	EndpointStallReqs     int
	EndpointZeroEdgeReqs  int
	DirectSHM             bool
	SHMPath               string
	SHMReadMode           string
	AllowDegradedCoverage bool
	SkipOnCrash           bool
	SkipEndpointOn500     bool
	SequentialBaseline    bool
	SourceAwarePriority   bool
	RaceMode              bool
	RaceBurst             int
	RaceProb              float64
	// ProbeRaceOutcome (race.go, Phase 4 #119): evaluate a race burst's own
	// outcome (how many of the N concurrent identical requests succeeded),
	// not just rely on a crash if the target happens to 500 under
	// contention. Requires RaceMode (which controls whether bursts get
	// enqueued at all); this only gates the additional outcome check.
	ProbeRaceOutcome            bool
	CrashTriage                 bool
	CrashSignatureMode          string
	CrashSigMutation            bool
	CrashSigQueryValues         bool
	CrashReplayCount            int
	CrashReplayQueueMax         int
	CrashReplayPerEndpoint      int
	CrashReplayProb             float64
	CrashBoostRequests          int
	CrashBoostMaxPerEndpoint    int
	CrashBoostWeight            float64
	EndpointReqShareCapPct      float64
	EndpointReqCapMinReqs       int
	EndpointNoEdgeCapWeight     float64
	EndpointCrashRateMinCrashes int
	EndpointCrashRateThreshold  float64
	EndpointCrashRateWeight     float64
	ReproRuns                   int
	ReproTargetPct              float64
	ReproTimeoutSec             float64
	MinimizeCrash               bool
	MinimizeMaxProbes           int
	// MinimizeChain (minimize.go, Phase 5 #126): for a crash reached through
	// a multi-step sequence chain, also try dropping non-essential earlier
	// STEPS entirely (not just shrinking the final request's own fields,
	// which MinimizeCrash alone already does). Requires MinimizeCrash.
	MinimizeChain        bool
	PocDir               string
	TimelineDir          string
	MultiIdentity        bool
	AuthFile             string
	IdentitySampleMode   string
	IdentityIncludeGuest bool
	NoUI                 bool
	WebUI                bool
	WebUIPort            int
	ForceUI              bool
	PlainUI              bool
	UINoClear            bool
	ASCIIUI              bool
	UIWidth              int
	UIIntervalSec        float64
	UIEndpointSort       string
	UIEndpointRotate     bool
	UIEndpointRotateSec  float64
	SequenceProb         float64
	SequenceMaxDepth     int
	SequenceFanout       int
	// PaginationChaining (pagination.go, Phase 4 #121): a GET list response
	// carrying a recognized cursor/next-page field or Link rel="next" header
	// gets a follow-up request continuing the SAME endpoint with the next
	// page -- a shape the general dependency-based follow-up logic can't
	// produce (it excludes a template following up on itself).
	PaginationChaining bool
	// Resource state graph (docs/resource-state-graph-plan.md): typed
	// resource-lifecycle tracking + generalized extraction + coverage-directed
	// consumer scheduling, layered on top of the existing sequence engine.
	// ResourceGraphEnabled defaults true since the new path is additive (old
	// name/path-based extraction and static verb-affinity scoring still run and
	// still contribute) -- set false to reproduce the exact prior fanout
	// ordering and extraction set for comparison/rollback.
	ResourceGraphEnabled          bool
	ResourceGraphMaxPerType       int
	ResourceGraphMaxAliases       int
	ResourceGraphMaxTransitions   int
	ResourceGraphExploreRate      float64
	ResourceGraphMinConfidence    float64
	ResourceGraphUnreachedWeight  float64
	ResourceGraphYieldWeight      float64
	ResourceGraphFailurePenalty   float64
	ResourceGraphStaleExploreProb float64
	// ResourceGraphSuccessProbWeight scores a candidate consumer by its own
	// endpoint's historical 2xx rate (f.endpointStats' S2xx/Reqs) -- the
	// valid-workflow planner's "probability of a successful 2xx" term
	// (docs/ARCHITECTURE_STATEFUL.md §2.4). 0 disables the term entirely.
	ResourceGraphSuccessProbWeight float64
	// ResourceGraphAvailabilityWeight scores a candidate consumer by whether a
	// resource instance of its expected type is actually available right now
	// (findCompatibleResources) -- the valid-workflow planner's
	// "expected lifecycle state satisfiable" term. 0 disables the term entirely.
	ResourceGraphAvailabilityWeight float64
	// ResourceGraphValueBiasWeight (item #2, docs/resource-state-graph-report.md):
	// how many extra copies of a resource-graph-known, still-alive instance to
	// add to a value-substitution candidate pool before picking uniformly at
	// random -- raises its selection odds without removing any generic/
	// boundary-value candidates already in the pool. 0 disables the bias
	// entirely (falls back to the pre-existing uniform behavior).
	ResourceGraphValueBiasWeight int

	// Typed structural body mutation: TypedBodyMutation gates the whole feature
	// (internal/engine/body_*.go) -- when true and a template's grammar was
	// compiled with a body_schema (grammarc/schema_ast.py), renderTemplateContext
	// builds/mutates a typed value tree instead of the legacy flat-segment/
	// mutateJSONBody path; templates with no body_schema are entirely unaffected
	// either way. AdversarialBodyRate is the probability (during mutate/havoc
	// epochs only) of choosing "adversarial" mode -- exactly one deliberate
	// structural violation -- over "valid" (schema-correct) mode for a given
	// typed-body render.
	TypedBodyMutation   bool
	AdversarialBodyRate float64

	// Checkpoint/resume (docs/ARCHITECTURE_STATEFUL.md §2.7): periodically
	// snapshots the corpus + resource graph to CheckpointPath so a long
	// campaign survives a restart instead of rebuilding valid chains from
	// scratch. CheckpointPath empty disables checkpointing entirely (the
	// default) -- opt-in, zero behavior change for existing invocations.
	CheckpointPath        string
	CheckpointIntervalSec float64
	// Resume, when true, loads an existing CheckpointPath at startup (if the
	// file exists) instead of starting from a fresh baseline corpus/resource
	// graph. false with CheckpointPath set still WRITES checkpoints, just
	// never reads one back -- lets a user opt into "always save, resume only
	// when I ask for it" rather than silently resuming every run.
	Resume bool

	CrashFile       string
	UniqueCrashFile string
	SummaryFile     string
	ReportFile      string
	// SARIFFile, when set, additionally writes findings in SARIF 2.1.0 format
	// (Top-20 §16) so they drop directly into GitHub code scanning / DefectDojo /
	// any other SARIF-consuming dashboard. Opt-in: empty (the default) writes nothing.
	SARIFFile         string
	BootstrapMax      int
	AccessProbe       bool // master toggle for all access-control probes
	ProbeBOLA         bool // cross-identity BOLA/IDOR replay
	ProbeAuthBypass   bool // no-credential replay (gated by 401/403 precondition)
	ProbeMassAssign   bool // privileged-field over-posting
	ProbeDifferential bool // verb/content-type/route-case parser-confusion auth-bypass replay
	// ProbeStaleObject/ProbeStaleETag/ProbeWorkflowBypass (adversarial.go, the
	// adversarial branch planner -- docs/ARCHITECTURE_STATEFUL.md §2.4/§3):
	// each takes a resource the resource graph has ALREADY confirmed is real
	// (from a valid chain) and checks whether the server correctly rejects
	// exactly one controlled violation of it, instead of replaying the
	// current request under a different identity like BOLA/mass-assign do.
	ProbeStaleObject    bool // DELETE -> GET/PUT/DELETE: does a stale/deleted resource still accept operations
	ProbeStaleETag      bool // write replayed with a deliberately wrong If-Match: is optimistic locking enforced
	ProbeWorkflowBypass bool // action invoked on a resource whose known state doesn't satisfy the endpoint's declared predecessor (x-state-transition only -- see adversarial.go)
	// ProbeIdempotency (idempotency.go, Phase 4 #118): replay a just-succeeded
	// create-shaped POST verbatim; a second, DIFFERENT created resource id
	// means the endpoint isn't actually idempotent.
	ProbeIdempotency          bool
	AccessProbeProb           float64
	AccessProbeMaxPerEndpoint int
	AccessProbeQueueMax       int
	InjectionOracle           bool
	// SchemaConformance (Top-20+ #23): validate 2xx response bodies against the
	// declared OpenAPI response schema; flags fields present in the live response but
	// undeclared in the schema, and declared-vs-observed type drift. No-op (silent)
	// on any endpoint whose grammar carries no response_schemas data.
	SchemaConformance    bool
	SQLiTimeThresholdSec float64
	Profile              string
	// CmpLog (Top-20+ #21): poll /shm/cmplog for comparison operands harvested from
	// the target's own IL and blend them into string/int mutation. No-ops cleanly
	// (empty pool) against a target built without --cmplog, or in --inject-mode source.
	CmpLog         bool
	CmpLogInterval float64 // seconds between /shm/cmplog polls
}
