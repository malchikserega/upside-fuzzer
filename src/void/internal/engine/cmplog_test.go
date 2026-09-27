package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"void/internal/config"
)

// TestCmpLogPoolAddDedup verifies string/int dedup and rejects empty/oversized values.
func TestCmpLogPoolAddDedup(t *testing.T) {
	p := newCmpLogPool()
	if !p.addString("MAGIC_TOKEN") {
		t.Fatal("expected first addString to report a new value")
	}
	if p.addString("MAGIC_TOKEN") {
		t.Error("expected duplicate addString to report no new value")
	}
	if p.addString("") || p.addString(strings.Repeat("x", maxCmpLogStrLen+1)) {
		t.Error("expected empty/oversized strings to be rejected")
	}
	if !p.addInt(8675309) {
		t.Fatal("expected first addInt to report a new value")
	}
	if p.addInt(8675309) {
		t.Error("expected duplicate addInt to report no new value")
	}
	strs, ints := p.size()
	if strs != 1 || ints != 1 {
		t.Errorf("expected pool size (1,1), got (%d,%d)", strs, ints)
	}
}

// TestCmpLogPoolEviction verifies the pool stays bounded via FIFO eviction, and that
// the evicted value can be re-added later (proves the seen-set was cleaned up too).
func TestCmpLogPoolEviction(t *testing.T) {
	p := newCmpLogPool()
	for i := 0; i < maxCmpLogStrings+10; i++ {
		p.addString("v" + itoa(i))
	}
	strs, _ := p.size()
	if strs != maxCmpLogStrings {
		t.Errorf("expected pool capped at %d, got %d", maxCmpLogStrings, strs)
	}
	if !p.addString("v0") {
		t.Error("expected the long-evicted first value to be addable again (seen-set must have been cleaned up on eviction)")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestCmpLogPoolSample verifies sample{String,Int} report ok=false on an empty pool
// and return a value that was actually added once populated.
func TestCmpLogPoolSample(t *testing.T) {
	p := newCmpLogPool()
	if _, ok := p.sampleString(); ok {
		t.Error("expected sampleString on empty pool to report ok=false")
	}
	if _, ok := p.sampleInt(); ok {
		t.Error("expected sampleInt on empty pool to report ok=false")
	}
	p.addString("hello")
	p.addInt(42)
	if v, ok := p.sampleString(); !ok || v != "hello" {
		t.Errorf("expected sampleString to return %q, got %q ok=%v", "hello", v, ok)
	}
	if v, ok := p.sampleInt(); !ok || v != 42 {
		t.Errorf("expected sampleInt to return 42, got %d ok=%v", v, ok)
	}
}

// TestFetchCmpLogParsesAndMerges verifies fetchCmpLog decodes the /shm/cmplog JSON
// shape (strings + decimal-string ints) and reports the count of genuinely new values.
func TestFetchCmpLogParsesAndMerges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shm/cmplog" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cmpLogResponse{
			Strings: []string{"SUPER_SECRET_2026", "admin"},
			Ints:    []string{"8675309", "not-a-number", "-42"},
		})
	}))
	defer srv.Close()

	pool := newCmpLogPool()
	added, err := fetchCmpLog(srv.Client(), srv.URL, pool)
	if err != nil {
		t.Fatalf("fetchCmpLog returned error: %v", err)
	}
	// 2 strings + 2 valid ints ("not-a-number" is skipped, not an error) = 4.
	if added != 4 {
		t.Errorf("expected 4 newly-added values, got %d", added)
	}
	strs, ints := pool.size()
	if strs != 2 || ints != 2 {
		t.Errorf("expected pool (2,2), got (%d,%d)", strs, ints)
	}
	if v, ok := pool.sampleInt(); !ok || (v != 8675309 && v != -42) {
		t.Errorf("expected a harvested int, got %d ok=%v", v, ok)
	}

	// Second poll with the same payload must add nothing new.
	added2, err := fetchCmpLog(srv.Client(), srv.URL, pool)
	if err != nil {
		t.Fatalf("second fetchCmpLog returned error: %v", err)
	}
	if added2 != 0 {
		t.Errorf("expected 0 new values on a repeat poll of identical data, got %d", added2)
	}
}

// TestFetchCmpLog404IsNotAnError verifies a 404 (older target build, or --inject-mode
// source, which doesn't wire the probe) is treated as "nothing available", not a
// hard failure -- this must never block or fail a run against such a target.
func TestFetchCmpLog404IsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pool := newCmpLogPool()
	added, err := fetchCmpLog(srv.Client(), srv.URL, pool)
	if err != nil {
		t.Fatalf("expected no error on 404, got %v", err)
	}
	if added != 0 {
		t.Errorf("expected 0 added on 404, got %d", added)
	}
}

func TestFetchCmpLog_NonOKNonNotFoundStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pool := newCmpLogPool()
	if _, err := fetchCmpLog(srv.Client(), srv.URL, pool); err == nil {
		t.Error("expected an error for a 500 /shm/cmplog response")
	}
}

func TestFetchCmpLog_InvalidJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	pool := newCmpLogPool()
	if _, err := fetchCmpLog(srv.Client(), srv.URL, pool); err == nil {
		t.Error("expected an error for an invalid JSON body")
	}
}

func TestPollCmpLogIfDue_DisabledIsNoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CmpLog: false}}
	f.pollCmpLogIfDue() // must not panic even with a nil client/shm
	if !f.lastCmpLogPoll.IsZero() {
		t.Error("expected lastCmpLogPoll to stay zero when CmpLog is disabled")
	}
}

func TestPollCmpLogIfDue_PollsAndRecordsNewOperands(t *testing.T) {
	cmplogPool.resetForTest()
	defer cmplogPool.resetForTest()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cmpLogResponse{Strings: []string{"POLL_SECRET"}})
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg:       config.Config{CmpLog: true, CmpLogInterval: 60},
		client:    srv.Client(),
		shm:       srv.URL,
		startTime: time.Now(),
		eventLog:  make([]string, 0, 8),
	}
	f.pollCmpLogIfDue()
	if f.lastCmpLogPoll.IsZero() {
		t.Fatal("expected lastCmpLogPoll to be set after a due poll")
	}
	if len(f.eventLog) == 0 {
		t.Error("expected an event logged for newly-absorbed operands")
	}

	// A second call within CmpLogInterval must be a no-op (same lastCmpLogPoll).
	first := f.lastCmpLogPoll
	f.pollCmpLogIfDue()
	if f.lastCmpLogPoll != first {
		t.Error("expected the poll to be skipped while still within CmpLogInterval")
	}
}

func TestPollCmpLogIfDue_ErrorIsLoggedOnceNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &Fuzzer{
		cfg:       config.Config{CmpLog: true, CmpLogInterval: 0.01},
		client:    srv.Client(),
		shm:       srv.URL,
		startTime: time.Now(),
		eventLog:  make([]string, 0, 8),
	}
	f.pollCmpLogIfDue()
	if f.cmpLogPollErrs != 1 {
		t.Fatalf("expected cmpLogPollErrs=1 after the first failed poll, got %d", f.cmpLogPollErrs)
	}
	if len(f.eventLog) != 1 {
		t.Errorf("expected exactly 1 warning event logged, got %d", len(f.eventLog))
	}
}

// TestMutateStringCategorizedUsesCmpLogPool verifies a value seeded into the global
// cmplogPool can surface through mutateStringCategorized's "mcat_cmplog" category.
func TestMutateStringCategorizedUsesCmpLogPool(t *testing.T) {
	cmplogPool.resetForTest()
	defer cmplogPool.resetForTest()
	cmplogPool.addString("HARVESTED_MAGIC_VALUE")

	found := false
	for i := 0; i < 2000; i++ {
		v, cat := mutateStringCategorized("whatever", nil)
		if cat == "mcat_cmplog" {
			if v != "HARVESTED_MAGIC_VALUE" {
				t.Fatalf("mcat_cmplog produced unexpected value %q", v)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mutateStringCategorized to surface a cmplog-sourced candidate at least once over 2000 attempts")
	}
}

// TestMutateIntUsesCmpLogPool verifies a value seeded into the global cmplogPool is
// blended into mutateInt's candidate union.
func TestMutateIntUsesCmpLogPool(t *testing.T) {
	cmplogPool.resetForTest()
	defer cmplogPool.resetForTest()
	cmplogPool.addInt(8675309)

	seen := map[string]bool{}
	for i := 0; i < 3000; i++ {
		seen[mutateInt("1", nil)] = true
	}
	if !seen["8675309"] {
		t.Errorf("expected mutateInt to surface the cmplog-harvested value 8675309 among outputs, got: %v", seen)
	}
}
