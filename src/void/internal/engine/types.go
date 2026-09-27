package engine

import (
	"bufio"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// types.go — Core data types: WorkItem, SendResult, Template, Seed, Epoch,
// JSONLWriter, FenwickSampler, and all stat/record structs. Config moved to
// internal/config/types.go during the repo-architecture refactor (imported
// here as config.Config where needed).

type Segment struct {
	Kind       string `json:"kind"`
	Value      string `json:"value,omitempty"`
	ValueType  string `json:"value_type,omitempty"`
	Default    string `json:"default,omitempty"`
	Quoted     bool   `json:"quoted,omitempty"`
	PayloadKey string `json:"payload_key,omitempty"`
	Name       string `json:"name,omitempty"`

	// Optional per-field constraint metadata (Top-20 #14), sourced from
	// grammarc/oas.py::FieldHint (OpenAPI + Roslyn-merged). Absent/zero-valued on any
	// template.export.json generated before this was added -- plain json.Unmarshal
	// leaves these nil/empty, so old grammars decode and mutate exactly as before.
	MinLength  *int     `json:"min_length,omitempty"`
	MaxLength  *int     `json:"max_length,omitempty"`
	Minimum    *float64 `json:"minimum,omitempty"`
	Maximum    *float64 `json:"maximum,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
	EnumValues []string `json:"enum_values,omitempty"`
}

type Template struct {
	ID        int       `json:"id"`
	RequestID string    `json:"request_id"`
	Segments  []Segment `json:"segments"`
	Reads     []string  `json:"reads"`
	Writes    []string  `json:"writes"`

	// ResponseSchemas (Top-20+ #23), sourced from grammarc/oas.py's parsed OpenAPI
	// response schemas: declared 2xx status -> {dotted field name: declared type}.
	// Absent/nil on any template.export.json generated before this was added -- plain
	// json.Unmarshal leaves it nil, so old grammars decode and behave exactly as
	// before (schema_oracle.go treats a nil/empty map as "nothing declared, skip").
	ResponseSchemas map[string]map[string]string `json:"response_schemas,omitempty"`

	// XStateTransition (Tier 1 of the transition-source priority chain,
	// resource_scheduling.go::deriveTransitionAction) -- an explicit
	// OpenAPI x-state-transition vendor extension, when the spec author
	// declared one. Absent on the overwhelming majority of real specs (this
	// isn't a standardized extension); omitempty keeps old grammars decoding
	// unchanged.
	XStateTransition *XStateTransitionHint `json:"x_state_transition,omitempty"`
	// RoslynAction (Tier 2) -- the C# controller action method name Roslyn
	// found for this endpoint (grammarc/roslyn_merge.py::RoslynIndex.endpoint_for_operation),
	// e.g. "ApproveOrder" for POST /orders/{id}/approve. A source-level
	// ground-truth signal, stronger than guessing the action from the URL
	// path alone -- but only when it's not a generic ASP.NET boilerplate
	// name (isGenericRoslynActionName, resource_scheduling.go), which carries
	// no more information than the path-based heuristic already has.
	RoslynAction string `json:"roslyn_action,omitempty"`

	// BodySchema is the full request-body schema AST (grammarc/schema_ast.py,
	// object/array/scalar/oneOf/anyOf/discriminator/required/nullable/
	// constraints), when the grammar was compiled with structural-body support.
	// Absent/nil on any template.export.json generated before this was added --
	// plain json.Unmarshal leaves it nil, so old grammars decode and render
	// through the existing flat-segment path exactly as before (see
	// renderTemplateContext's BodySchema != nil branch).
	BodySchema *BodyNode `json:"body_schema,omitempty"`
}

// XStateTransitionHint is one operation's explicitly-declared state
// transition, parsed from an x-state-transition OpenAPI vendor extension
// (grammarc/oas.py::parse_x_state_transition).
type XStateTransitionHint struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Action string `json:"action,omitempty"`
}

type TemplateExport struct {
	Count     int        `json:"count"`
	Skipped   int        `json:"skipped"`
	Templates []Template `json:"templates"`
}

type EndpointStats struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Reqs          int    `json:"reqs"`
	LastSeen      int    `json:"last_seen"`
	ReqsSinceEdge int    `json:"reqs_since_edge"`
	S2xx          int    `json:"s2xx"`
	S4xx          int    `json:"s4xx"`
	S500          int    `json:"s500"`
	Logged500     int    `json:"logged_500"`
	Filtered500   int    `json:"filtered_500"`
	S401403       int    `json:"s401403"`
	S5xx          int    `json:"s5xx"`
	Logged5xx     int    `json:"logged_5xx"`
	Filtered5xx   int    `json:"filtered_5xx"`
	NewEdges      int    `json:"edges_discovered"`
}

type MutationStats struct {
	Name     string
	Attempts int
	NewEdges int
}

type CrashRecord struct {
	TS           string `json:"ts"`
	ElapsedSec   string `json:"elapsed_secs"`
	Signature    string `json:"signature,omitempty"`
	ClusterKey   string `json:"cluster_key,omitempty"`
	ClusterLabel string `json:"cluster_label,omitempty"`
	// SequenceID (item #4, docs/resource-state-graph-report.md) is the
	// originating sequence's ID (SequenceState.ID) when this crash happened on
	// a sequence-engine follow-up request, empty otherwise. Lets a reader cross-
	// reference a crash back to its full request chain in crashes/workflows/
	// (when that sequence was also persisted there) or simply group multiple
	// crashes that came from exploring the same root sequence.
	SequenceID    string         `json:"sequence_id,omitempty"`
	Status        int            `json:"status_code"`
	Method        string         `json:"method"`
	Path          string         `json:"path"`
	Identity      string         `json:"identity,omitempty"`
	Mutation      string         `json:"mutation"`
	Payload       string         `json:"payload"`
	Response      string         `json:"response_body"`
	ExceptionType string         `json:"exception_type,omitempty"`
	AuthContext   map[string]any `json:"auth_context,omitempty"`
	Triage        map[string]any `json:"triage,omitempty"`
	Repro         map[string]any `json:"repro,omitempty"`
	Minimized     map[string]any `json:"minimized,omitempty"`
	PocFile       string         `json:"poc_file,omitempty"`
	TimelineFile  string         `json:"timeline_file,omitempty"`
}

type AuthBlockedState struct {
	Count  int
	Reason string
}

type TemplateMeta struct {
	Method      string
	Path        string
	Norm        string
	ContentType string

	// XStateTransition/RoslynAction mirror Template's own fields of the same
	// name (types.go) -- copied here so deriveTransitionAction can look them
	// up by template id without needing the full Template slice in scope.
	XStateTransition *XStateTransitionHint
	RoslynAction     string
}

type EndpointContentProfile struct {
	JSON      int
	Form      int
	Multipart int
	Other     int
}

type DepInfo struct {
	Reads    map[string]struct{}
	Writes   map[string]struct{}
	IDReads  map[string]struct{}
	IDWrites map[string]struct{}
}

type Seed struct {
	TemplateID   int
	Payload      string
	EdgesFound   int
	TimesChosen  int
	Energy       float64
	MutationName string
}
type FenwickSampler struct {
	tree    []float64 // 1-based Fenwick tree
	weights []float64 // 0-based source weights
}

func NewFenwickSampler() *FenwickSampler {
	return &FenwickSampler{
		tree:    []float64{0},
		weights: []float64{},
	}
}

func (f *FenwickSampler) add(i int, delta float64) {
	for i < len(f.tree) {
		f.tree[i] += delta
		i += i & -i
	}
}

func (f *FenwickSampler) Append(weight float64) {
	if weight < 0 {
		weight = 0
	}
	f.weights = append(f.weights, weight)
	f.tree = append(f.tree, 0)
	f.add(len(f.weights), weight)
}

func (f *FenwickSampler) Set(idx int, weight float64) {
	if idx < 0 || idx >= len(f.weights) {
		return
	}
	if weight < 0 {
		weight = 0
	}
	old := f.weights[idx]
	if old == weight {
		return
	}
	f.weights[idx] = weight
	f.add(idx+1, weight-old)
}

func (f *FenwickSampler) Total() float64 {
	if len(f.tree) == 0 {
		return 0
	}
	return f.prefix(len(f.weights))
}

func (f *FenwickSampler) prefix(i int) float64 {
	sum := 0.0
	for i > 0 {
		sum += f.tree[i]
		i -= i & -i
	}
	return sum
}

func (f *FenwickSampler) Pick() int {
	n := len(f.weights)
	if n == 0 {
		return -1
	}
	total := f.Total()
	if total <= 0 {
		return rand.Intn(n)
	}

	target := rand.Float64() * total
	idx := 0
	bit := 1
	for bit < len(f.tree) {
		bit <<= 1
	}
	for step := bit >> 1; step > 0; step >>= 1 {
		next := idx + step
		if next < len(f.tree) && f.tree[next] <= target {
			target -= f.tree[next]
			idx = next
		}
	}
	picked := idx
	if picked >= n {
		picked = n - 1
	}
	return picked
}

type SequenceStep struct {
	TemplateID    int               `json:"template_id"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	Status        int               `json:"status"`
	CoverageDelta int               `json:"coverage_delta"`
	MutationLabel string            `json:"mutation_label,omitempty"`
}

type SequenceState struct {
	ID         string            `json:"id"`
	Depth      int               `json:"depth"`
	Values     map[string]string `json:"values"`
	Provenance map[string]string `json:"provenance"`
	History    []SequenceStep    `json:"history"`
	Energy     float64           `json:"energy"`
	// TenantKey is this chain's own established tenant scope (resource_graph.go's
	// ResourceGraph.resolveTenantKey), set the first time a step in this chain
	// touches a resource whose TenantKey is already resolved (i.e. once the
	// chain has gone at least two levels deep into a nested resource, e.g.
	// org -> project). Stays "" for flat/non-nested APIs or chains that
	// haven't gone that deep yet -- pickFollowupPathValue treats "" as "no
	// tenant restriction," the exact prior behavior, so this is additive, not
	// a regression risk for simple targets.
	TenantKey string `json:"tenant_key,omitempty"`

	// Resources/Transitions (docs/resource-state-graph-plan.md) are populated
	// only at persistence time (persistWorkflow, sequence.go), from the run-wide
	// ResourceGraph's own snapshotForSequence -- additive, omitempty fields, so
	// a workflow JSON file written before this existed, or with -resource-graph=
	// false, decodes identically to before (nil slices, nothing reads them back
	// programmatically today).
	Resources   []*ResourceInstance  `json:"resources,omitempty"`
	Transitions []ResourceTransition `json:"transitions,omitempty"`
}

type WorkItem struct {
	TemplateID    int
	Method        string
	Path          string
	Headers       map[string]string
	Body          string
	Identity      string
	Trace         []TraceStep
	Raw           string
	MutationLabel string
	MutationName  string
	SeedIdx       int
	EpochName     string
	EpochIdx      int
	SeqDepth      int
	SeqState      *SequenceState
	// Access-control oracle fields (set only on replayed probes; see oracle.go).
	OracleKind           string // "" for normal items, else "bola" | "authbypass" | "massassign" | "differential"
	NoAuth               bool   // strip all credentials from this probe
	OracleOriginIdentity string
	OracleOriginStatus   int
	OracleOriginFP       string
	OracleOriginBodyLen  int
	// DiffTechnique names which differential-oracle variant produced this probe
	// (Top-20 #18): "verb" | "content-type" | "route-case" | "param-location".
	// Only set when OracleKind == oracleKindDifferential.
	DiffTechnique string
	// BurstID (race.go, Phase 4 #119) groups every item enqueued together by
	// enqueueRaceBurst, so their results can be correlated back into "how many
	// of these N concurrent identical requests succeeded" once they've all
	// completed. "" for every non-race-burst item.
	BurstID     string
	BurstSize   int
	BurstAction string // deriveTransitionActionForTemplate at enqueue time, for the finding's own severity classification

	// BodyTree is the typed structural-mutation value tree (body_value.go), set
	// only when the template's grammar declared a body_schema and
	// -typed-body-mutation is on (see renderTemplateContext). nil for every
	// other item -- the legacy flat Body string above is authoritative in that
	// case, exactly as before this field existed. When non-nil, Body is a
	// throwaway placeholder until prepareItemForSend serializes BodyTree into
	// it immediately before the HTTP send.
	BodyTree *BodyValue
}

type SendResult struct {
	Item          WorkItem
	Status        int
	Body          string
	Headers       map[string]string
	Latency       time.Duration
	Err           error
	CoverageDelta int    // per-request edge delta from X-Coverage-Delta response header
	ExceptionType string // .NET exception type from X-Exception-Type response header
	ExceptionMsg  string // .NET exception message from X-Exception-Message response header (prod-mode)
}

type Epoch struct {
	Name     string
	Fraction float64
	Mode     string
}

type JSONLWriter struct {
	mu      sync.Mutex
	f       *os.File
	w       *bufio.Writer
	pending int
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{f: f, w: bufio.NewWriterSize(f, 1<<20)}, nil
}

func (j *JSONLWriter) Write(v any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j == nil || j.w == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(b); err != nil {
		return err
	}
	if err := j.w.WriteByte('\n'); err != nil {
		return err
	}
	j.pending++
	if j.pending >= 64 {
		j.pending = 0
		return j.w.Flush()
	}
	return nil
}

func (j *JSONLWriter) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j == nil || j.w == nil {
		return nil
	}
	j.pending = 0
	return j.w.Flush()
}

func (j *JSONLWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j == nil {
		return nil
	}
	if j.w != nil {
		_ = j.w.Flush()
	}
	if j.f != nil {
		return j.f.Close()
	}
	return nil
}

type WebUIStats struct {
	EpochName        string          `json:"epoch_name"`
	EpochIdx         int             `json:"epoch_idx"`
	InFlight         int             `json:"in_flight"`
	TotalDone        int             `json:"total_done"`
	TotalSent        int             `json:"total_sent"`
	CurrentEdges     int             `json:"current_edges"`
	StartEdges       int             `json:"start_edges"`
	NewEdges         int             `json:"new_edges"`
	CoverageSatPct   float64         `json:"coverage_sat_pct"`
	TotalErrors      int             `json:"total_errors"`
	TotalCrashes     int             `json:"total_crashes"`
	UniqueCrashes    int             `json:"unique_crashes"`
	AvgLatency       float64         `json:"avg_latency"`
	Concurrency      int             `json:"concurrency"`
	CorpusSize       int             `json:"corpus_size"`
	ElapsedSecs      float64         `json:"elapsed_secs"`
	RequestsPerSec   float64         `json:"requests_per_sec"`
	AuthBlockedCount int             `json:"auth_blocked_count"`
	IdentityCount    int             `json:"identity_count"`
	TimeBudgetSecs   float64         `json:"time_budget_secs"`
	TopEndpoints     []EndpointStats `json:"top_endpoints"`
	RecentEvents     []string        `json:"recent_events"`
	RecentCrashes    []CrashRecord   `json:"recent_crashes"`
	TimeRemaining    string          `json:"time_remaining"`
}
