package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// constants.go — Constant/string dictionary extraction (Top-20+ #22).
//
// instrumentor/Program.cs's ConstantExtractor harvests string/int literals straight
// out of the target's own compiled IL (read-only, before SharpFuzz's own coverage
// rewrite so its injected per-branch-site IDs never pollute the pool) into a
// per-assembly file. The coverage hook exposes the union of those over GET
// /shm/constants. This is the .NET analog of AFL's `-x` auto-dictionary: it recovers
// magic values (`if (couponCode == "SUMMER2026")`) no OpenAPI spec, dictionary, or
// generic mutation could ever guess, because the literal only exists inside the
// target's own compiled logic.
//
// Unlike CmpLog (cmplog.go), which is *learned live* via repeated polling as traffic
// flows and comparisons actually execute, these constants are static -- extracted
// once at instrument time and never change during a run. So constantsPool is
// populated by a single fetch at fuzzer startup, not a poll loop.

const (
	maxConstantsStrings = 512
	maxConstantsInts    = 256
	maxConstantsStrLen  = 256
)

// ConstantsPool holds string/int literals harvested from the target's own IL at
// instrument time. Bounded, deduped -- mirrors CmpLogPool's shape exactly, minus the
// FIFO eviction (a one-shot fetch never grows past its caps, since the server-side
// extraction and merge already enforce the same bounds).
type ConstantsPool struct {
	mu   sync.RWMutex
	strs []string
	ints []int64
}

func newConstantsPool() *ConstantsPool {
	return &ConstantsPool{}
}

func (p *ConstantsPool) load(strs []string, ints []int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strs = strs
	p.ints = ints
}

// sampleString returns a random harvested string literal, if any were loaded.
func (p *ConstantsPool) sampleString() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.strs) == 0 {
		return "", false
	}
	return p.strs[rand.Intn(len(p.strs))], true
}

// sampleInt returns a random harvested integer literal, if any were loaded.
func (p *ConstantsPool) sampleInt() (int64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.ints) == 0 {
		return 0, false
	}
	return p.ints[rand.Intn(len(p.ints))], true
}

func (p *ConstantsPool) size() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.strs), len(p.ints)
}

// resetForTest clears the pool in place (no struct copy, so the embedded mutex is
// never duplicated) — used by tests that need the shared global constantsPool empty.
func (p *ConstantsPool) resetForTest() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strs = nil
	p.ints = nil
}

// constantsResponse mirrors the JSON shape served by /shm/constants (same shape as
// cmpLogResponse in cmplog.go). Ints are decimal strings so int64 values never risk
// float64 precision loss through Go's default JSON number decoding.
type constantsResponse struct {
	Strings []string `json:"strings"`
	Ints    []string `json:"ints"`
}

// fetchConstants performs a single GET against the target's /shm/constants control
// endpoint and loads whatever it returns into pool. A 404 (target built before this
// feature existed) is treated as "nothing available", not an error -- this must never
// block or fail a run against an older target image.
func fetchConstants(client *http.Client, host string, pool *ConstantsPool) (int, int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(host, "/")+"/shm/constants", nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, 0, fmt.Errorf("/shm/constants status=%d body=%s", resp.StatusCode, string(b))
	}
	var payload constantsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); err != nil {
		return 0, 0, fmt.Errorf("/shm/constants decode failed: %w", err)
	}

	strs := make([]string, 0, len(payload.Strings))
	for _, s := range payload.Strings {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > maxConstantsStrLen {
			continue
		}
		strs = append(strs, s)
		if len(strs) >= maxConstantsStrings {
			break
		}
	}
	ints := make([]int64, 0, len(payload.Ints))
	for _, s := range payload.Ints {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			continue
		}
		ints = append(ints, n)
		if len(ints) >= maxConstantsInts {
			break
		}
	}
	pool.load(strs, ints)
	return len(strs), len(ints), nil
}

// constantsPool is the process-wide pool mutation_engine.go's mutateStringCategorized
// and mutateInt sample from. Populated once by fetchConstantsAtStartup during fuzzer
// startup; empty (both call sites no-op) against a target built before this feature
// existed.
var constantsPool = newConstantsPool()

// fetchConstantsAtStartup performs the one-shot /shm/constants fetch. Failures are
// logged to the event feed, never fatal -- exactly like pollCmpLogIfDue's handling in
// cmplog.go, so a target without this endpoint behaves as if the feature doesn't exist.
func (f *Fuzzer) fetchConstantsAtStartup() {
	strs, ints, err := fetchConstants(f.client, f.shm, constantsPool)
	if err != nil {
		f.addEvent(fmt.Sprintf("CONSTANTS fetch warning (continuing without): %v", err))
		return
	}
	if strs > 0 || ints > 0 {
		f.addEvent(fmt.Sprintf("CONSTANTS loaded %d string(s), %d int(s) from target IL", strs, ints))
	}
}
