package main

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

// types.go — Core data types: Config, WorkItem, SendResult, Template,
// Seed, Epoch, JSONLWriter, FenwickSampler, and all stat/record structs.

type Config struct {
	GrammarDir                  string
	SourceDir                   string
	DictPath                    string
	TemplatesJSON               string
	RefreshTemplates            bool
	ExporterPath                string
	TimeBudgetMinutes           float64
	Concurrency                 int
	MinConcurrency              int
	MaxConcurrency              int
	AdaptiveConcurrency         bool
	AdaptiveContentType         bool
	AutoAntiForgery             bool
	AntiForgeryField            string
	AntiForgeryHeader           string
	AntiForgeryCooldown         float64
	AntiForgerySampleRate       float64
	AntiForgeryMaxTokens        int
	AntiForgeryTokenTTL         float64
	RequestTimeoutSec           float64
	MaxResponseBytes            int
	CoverageInterval            int
	CoverageBitmapSize          int
	EndpointStallReqs           int
	EndpointZeroEdgeReqs        int
	DirectSHM                   bool
	SHMPath                     string
	SHMReadMode                 string
	SkipOnCrash                 bool
	SkipEndpointOn500           bool
	SequentialBaseline          bool
	SourceAwarePriority         bool
	RaceMode                    bool
	RaceBurst                   int
	RaceProb                    float64
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
	PocDir                      string
	TimelineDir                 string
	MultiIdentity               bool
	AuthFile                    string
	IdentitySampleMode          string
	IdentityIncludeGuest        bool
	NoUI                        bool
	ForceUI                     bool
	PlainUI                     bool
	UINoClear                   bool
	ASCIIUI                     bool
	UIWidth                     int
	UIIntervalSec               float64
	UIEndpointSort              string
	UIEndpointRotate            bool
	UIEndpointRotateSec         float64
	SequenceProb                float64
	SequenceMaxDepth            int
	SequenceFanout              int
	CrashFile                   string
	UniqueCrashFile             string
	SummaryFile                 string
	ReportFile                  string
	BootstrapMax                int
}

type Segment struct {
	Kind       string `json:"kind"`
	Value      string `json:"value,omitempty"`
	ValueType  string `json:"value_type,omitempty"`
	Default    string `json:"default,omitempty"`
	Quoted     bool   `json:"quoted,omitempty"`
	PayloadKey string `json:"payload_key,omitempty"`
	Name       string `json:"name,omitempty"`
}

type Template struct {
	ID        int       `json:"id"`
	RequestID string    `json:"request_id"`
	Segments  []Segment `json:"segments"`
	Reads     []string  `json:"reads"`
	Writes    []string  `json:"writes"`
}

type TemplateExport struct {
	Count     int        `json:"count"`
	Skipped   int        `json:"skipped"`
	Templates []Template `json:"templates"`
}

type EndpointStats struct {
	Method        string
	Path          string
	Reqs          int
	LastSeen      int
	ReqsSinceEdge int
	S2xx          int
	S4xx          int
	S500          int
	Logged500     int
	Filtered500   int
	S401403       int
	S5xx          int
	Logged5xx     int
	Filtered5xx   int
	NewEdges      int
}

type MutationStats struct {
	Name     string
	Attempts int
	NewEdges int
}

type CrashRecord struct {
	TS            string         `json:"ts"`
	ElapsedSec    string         `json:"elapsed_secs"`
	Signature     string         `json:"signature,omitempty"`
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

func (f *FenwickSampler) Len() int { return len(f.weights) }

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
