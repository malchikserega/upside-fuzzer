package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cmplog.go — CmpLog/RedQueen via IL comparison instrumentation (Top-20+ #21).
//
// instrumentor/Program.cs's CmpLogInstrumentor rewrites the target's own IL (hook
// mode only) so that every String.Equals/op_Equality/StartsWith/EndsWith/Contains
// call and every integer-literal-vs-compare (ceq/beq/bne.un) site records its
// constant operand into UpsideFuzz.Coverage.CmpLogProbe at runtime, before the
// original comparison executes. The coverage hook exposes what's been observed so
// far over GET /shm/cmplog. This is the .NET analog of AFL++'s CmpLog: it recovers
// "magic value" checks (`if (code == "SUPER_SECRET_2026")`) that no OpenAPI spec,
// dictionary, or generic mutation could ever guess, because the constant only
// exists inside the target's own compiled logic.
//
// cmplogPool is a single process-wide pool (mirrors coverage.go's package-level
// countClass) — there is exactly one Fuzzer per process, so this doesn't need to
// be threaded through mutateStringCategorized/mutateInt's existing signatures.

const (
	maxCmpLogStrings  = 512
	maxCmpLogInts     = 256
	maxCmpLogStrLen   = 256
	cmpLogPollTimeout = 5
)

// CmpLogPool holds comparison operands harvested from the target's own IL at
// runtime. Bounded, deduped, FIFO-evicted — mirrors RuntimeStore.addValue's
// eviction strategy in store.go.
type CmpLogPool struct {
	mu      sync.RWMutex
	strs    []string
	strSeen map[string]struct{}
	ints    []int64
	intSeen map[int64]struct{}
}

func newCmpLogPool() *CmpLogPool {
	return &CmpLogPool{
		strSeen: map[string]struct{}{},
		intSeen: map[int64]struct{}{},
	}
}

func (p *CmpLogPool) addString(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxCmpLogStrLen {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.strSeen[v]; ok {
		return false
	}
	p.strs = append(p.strs, v)
	if len(p.strs) > maxCmpLogStrings {
		evicted := p.strs[0]
		p.strs = p.strs[1:]
		delete(p.strSeen, evicted)
	}
	p.strSeen[v] = struct{}{}
	return true
}

func (p *CmpLogPool) addInt(v int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.intSeen[v]; ok {
		return false
	}
	p.ints = append(p.ints, v)
	if len(p.ints) > maxCmpLogInts {
		evicted := p.ints[0]
		p.ints = p.ints[1:]
		delete(p.intSeen, evicted)
	}
	p.intSeen[v] = struct{}{}
	return true
}

// sampleString returns a random harvested string operand, if any exist yet.
func (p *CmpLogPool) sampleString() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.strs) == 0 {
		return "", false
	}
	return p.strs[rand.Intn(len(p.strs))], true
}

// sampleInt returns a random harvested integer operand, if any exist yet.
func (p *CmpLogPool) sampleInt() (int64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.ints) == 0 {
		return 0, false
	}
	return p.ints[rand.Intn(len(p.ints))], true
}

func (p *CmpLogPool) size() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.strs), len(p.ints)
}

// resetForTest clears the pool in place (no struct copy, so the embedded mutex is
// never duplicated) — used by tests that need the shared global cmplogPool empty.
func (p *CmpLogPool) resetForTest() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strs = nil
	p.strSeen = map[string]struct{}{}
	p.ints = nil
	p.intSeen = map[int64]struct{}{}
}

// cmpLogResponse mirrors the JSON shape served by /shm/cmplog (see
// fuzz-prep-multi.py's _COVERAGE_HOOK_CS, CmpLogProbe.ToJson). Ints are
// serialized as decimal strings so int64 values never risk float64 precision
// loss through Go's default JSON number decoding.
type cmpLogResponse struct {
	Strings []string `json:"strings"`
	Ints    []string `json:"ints"`
}

// fetchCmpLog polls the target's /shm/cmplog control endpoint and merges any
// newly-observed operands into pool. Returns the number of genuinely new values
// absorbed. A 404 (target built before this feature existed, or running in
// --inject-mode source, which doesn't wire the probe) is treated as "nothing
// available", not an error — this must never block or fail a run against an
// older or source-mode target image.
func fetchCmpLog(client *http.Client, host string, pool *CmpLogPool) (int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(host, "/")+"/shm/cmplog", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, fmt.Errorf("/shm/cmplog status=%d body=%s", resp.StatusCode, string(b))
	}
	var payload cmpLogResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return 0, fmt.Errorf("/shm/cmplog decode failed: %w", err)
	}
	added := 0
	for _, s := range payload.Strings {
		if pool.addString(s) {
			added++
		}
	}
	for _, s := range payload.Ints {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			continue
		}
		if pool.addInt(n) {
			added++
		}
	}
	return added, nil
}

// cmplogPool is the process-wide pool mutation_engine.go's mutateStringCategorized
// and mutateInt sample from. Populated by pollCmpLogIfDue during mainLoop.
var cmplogPool = newCmpLogPool()

// pollCmpLogIfDue fetches /shm/cmplog at most once per cfg.CmpLogInterval seconds.
// Called from mainLoop's per-tick body; cheap no-op between due polls (a single
// time comparison), and failures are logged to the event feed, never fatal — a
// target without the /shm/cmplog endpoint (older build, or --inject-mode source)
// simply never populates the pool, and mutation falls back to its pre-existing
// generic/hint-based behavior exactly as if this feature didn't exist.
func (f *Fuzzer) pollCmpLogIfDue() {
	if !f.cfg.CmpLog {
		return
	}
	interval := time.Duration(math.Max(0.5, f.cfg.CmpLogInterval) * float64(time.Second))
	if !f.lastCmpLogPoll.IsZero() && time.Since(f.lastCmpLogPoll) < interval {
		return
	}
	f.lastCmpLogPoll = time.Now()
	added, err := fetchCmpLog(f.client, f.shm, cmplogPool)
	if err != nil {
		f.cmpLogPollErrs++
		if f.cmpLogPollErrs == 1 {
			f.addEvent(fmt.Sprintf("CMPLOG poll warning (will keep retrying silently): %v", err))
		}
		return
	}
	if added > 0 {
		strs, ints := cmplogPool.size()
		f.addEvent(fmt.Sprintf("CMPLOG +%d new operand(s) (pool: %d strings, %d ints)", added, strs, ints))
	}
}
