package main

import (
	"testing"
	"time"
)

func newAntiForgeryTestFuzzer(cfg Config) *Fuzzer {
	if cfg.AntiForgeryMaxTokens == 0 {
		cfg.AntiForgeryMaxTokens = 100
	}
	cfg.AutoAntiForgery = true
	return &Fuzzer{
		cfg:               cfg,
		runtime:           newRuntimeStore(),
		antiForgeryTokens: map[string]time.Time{},
		startTime:         time.Now(),
	}
}

func TestRegisterAntiForgeryTokenDedupsAndCountsPoolSize(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{})
	now := time.Now()

	if !f.registerAntiForgeryToken("token-a", now) {
		t.Error("expected the first registration of a new token to report added")
	}
	if f.registerAntiForgeryToken("token-a", now) {
		t.Error("expected re-registering the same token to report not-added (dedup)")
	}
	if f.antiForgeryTokenPoolSize() != 1 {
		t.Errorf("expected pool size 1, got %d", f.antiForgeryTokenPoolSize())
	}
}

func TestRegisterAntiForgeryTokenRejectsUselessValues(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{})
	now := time.Now()
	for _, v := range []string{"", "null", "None", "{}", "[]"} {
		if f.registerAntiForgeryToken(v, now) {
			t.Errorf("expected %q to be rejected as a useless value", v)
		}
	}
	if f.antiForgeryTokenPoolSize() != 0 {
		t.Errorf("expected pool to stay empty, got size %d", f.antiForgeryTokenPoolSize())
	}
}

func TestRegisterAntiForgeryTokenEvictsOldestAtCapacity(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{AntiForgeryMaxTokens: 2})
	base := time.Now()

	f.registerAntiForgeryToken("oldest", base)
	f.registerAntiForgeryToken("middle", base.Add(1*time.Second))
	// Adding a 3rd token at capacity 2 must evict the oldest ("oldest"), not "middle".
	f.registerAntiForgeryToken("newest", base.Add(2*time.Second))

	if f.antiForgeryTokenPoolSize() != 2 {
		t.Fatalf("expected pool capped at 2, got %d", f.antiForgeryTokenPoolSize())
	}
	f.antiForgeryMu.RLock()
	_, hasOldest := f.antiForgeryTokens["oldest"]
	_, hasNewest := f.antiForgeryTokens["newest"]
	f.antiForgeryMu.RUnlock()
	if hasOldest {
		t.Error("expected the oldest token to have been evicted")
	}
	if !hasNewest {
		t.Error("expected the newest token to still be present")
	}
}

func TestPruneAntiForgeryTokensRemovesExpiredEntries(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{AntiForgeryTokenTTL: 10}) // 10s TTL
	old := time.Now().Add(-1 * time.Hour)
	f.antiForgeryTokens["stale"] = old
	f.antiForgeryTokens["fresh"] = time.Now()

	f.pruneAntiForgeryTokens(time.Now())

	f.antiForgeryMu.RLock()
	_, hasStale := f.antiForgeryTokens["stale"]
	_, hasFresh := f.antiForgeryTokens["fresh"]
	f.antiForgeryMu.RUnlock()
	if hasStale {
		t.Error("expected the stale (past-TTL) token to be pruned")
	}
	if !hasFresh {
		t.Error("expected the fresh token to survive pruning")
	}
}

func TestPruneAntiForgeryTokensZeroTTLNeverExpires(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{AntiForgeryTokenTTL: 0})
	f.antiForgeryTokens["forever"] = time.Now().Add(-24 * time.Hour)
	f.pruneAntiForgeryTokens(time.Now())
	if _, ok := f.antiForgeryTokens["forever"]; !ok {
		t.Error("expected a zero TTL to mean tokens never expire")
	}
}

func TestShouldHarvestAntiForgeryGating(t *testing.T) {
	cases := []struct {
		name   string
		res    SendResult
		expect bool
	}{
		{
			name:   "GET requests never trigger harvest",
			res:    SendResult{Item: WorkItem{Method: "GET", Path: "/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 400},
			expect: false,
		},
		{
			name:   "API-like JSON paths are excluded",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/api/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 400},
			expect: false,
		},
		{
			name:   "non-form content type excluded",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/items", Headers: map[string]string{"Content-Type": "application/json"}}, Status: 400},
			expect: false,
		},
		{
			name:   "200 OK never triggers harvest even on a form POST",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 200},
			expect: false,
		},
		{
			name:   "empty-body 400 on a form POST triggers harvest",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 400, Body: ""},
			expect: true,
		},
		{
			name:   "403 with an antiforgery-shaped body triggers harvest",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 403, Body: "The required antiforgery cookie is not present"},
			expect: true,
		},
		{
			name:   "400 with an unrelated body does not trigger harvest",
			res:    SendResult{Item: WorkItem{Method: "POST", Path: "/items", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, Status: 400, Body: "Name is required"},
			expect: false,
		},
	}
	f := newAntiForgeryTestFuzzer(Config{})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := f.shouldHarvestAntiForgery(c.res)
			if got != c.expect {
				t.Errorf("shouldHarvestAntiForgery() = %v, want %v", got, c.expect)
			}
		})
	}
}

func TestLearnAntiForgeryFromResponseExtractsAndRegistersTokens(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{AntiForgeryField: "__RequestVerificationToken"})
	body := `<html><body><form>
		<input name="__RequestVerificationToken" type="hidden" value="abc123token" />
	</form></body></html>`
	headers := map[string]string{"Content-Type": "text/html; charset=utf-8"}

	learned := f.learnAntiForgeryFromResponse("/checkout", 200, headers, body, true)

	if learned != 1 {
		t.Fatalf("expected 1 token learned, got %d", learned)
	}
	if f.antiForgeryTokenPoolSize() != 1 {
		t.Errorf("expected the token to be registered in the pool, size=%d", f.antiForgeryTokenPoolSize())
	}
}

func TestLearnAntiForgeryFromResponseIgnoresErrorStatuses(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{})
	body := `<input name="__RequestVerificationToken" value="abc123" />`
	headers := map[string]string{"Content-Type": "text/html"}

	learned := f.learnAntiForgeryFromResponse("/checkout", 500, headers, body, true)
	if learned != 0 {
		t.Errorf("expected 0 tokens learned from a 500 response, got %d", learned)
	}
}

func TestLearnAntiForgeryFromResponseIgnoresNonHTMLNonTokenBodies(t *testing.T) {
	f := newAntiForgeryTestFuzzer(Config{})
	headers := map[string]string{"Content-Type": "application/json"}
	learned := f.learnAntiForgeryFromResponse("/items", 200, headers, `{"id":1}`, true)
	if learned != 0 {
		t.Errorf("expected 0 tokens learned from an unrelated JSON body, got %d", learned)
	}
}
