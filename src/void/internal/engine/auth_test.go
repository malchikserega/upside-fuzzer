package engine

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"void/internal/config"
)

func newAntiForgeryTestFuzzer(cfg config.Config) *Fuzzer {
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
	f := newAntiForgeryTestFuzzer(config.Config{})
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
	f := newAntiForgeryTestFuzzer(config.Config{})
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
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryMaxTokens: 2})
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
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryTokenTTL: 10}) // 10s TTL
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
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryTokenTTL: 0})
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
	f := newAntiForgeryTestFuzzer(config.Config{})
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
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryField: "__RequestVerificationToken"})
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
	f := newAntiForgeryTestFuzzer(config.Config{})
	body := `<input name="__RequestVerificationToken" value="abc123" />`
	headers := map[string]string{"Content-Type": "text/html"}

	learned := f.learnAntiForgeryFromResponse("/checkout", 500, headers, body, true)
	if learned != 0 {
		t.Errorf("expected 0 tokens learned from a 500 response, got %d", learned)
	}
}

func TestLearnAntiForgeryFromResponseIgnoresNonHTMLNonTokenBodies(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{})
	headers := map[string]string{"Content-Type": "application/json"}
	learned := f.learnAntiForgeryFromResponse("/items", 200, headers, `{"id":1}`, true)
	if learned != 0 {
		t.Errorf("expected 0 tokens learned from an unrelated JSON body, got %d", learned)
	}
}

func TestHasSessionCookies(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	f := &Fuzzer{target: "http://example.test", client: &http.Client{Jar: jar}}
	if f.hasSessionCookies() {
		t.Error("expected false with no cookies set")
	}
	u, _ := http.NewRequest(http.MethodGet, f.target, nil)
	jar.SetCookies(u.URL, []*http.Cookie{{Name: "session", Value: "abc"}})
	if !f.hasSessionCookies() {
		t.Error("expected true once a cookie is set for the target host")
	}
}

func TestHasSessionCookies_NoJarOrNilClientIsFalse(t *testing.T) {
	var fNil *Fuzzer
	if fNil.hasSessionCookies() {
		t.Error("expected false for a nil Fuzzer")
	}
	f := &Fuzzer{target: "http://example.test", client: &http.Client{}}
	if f.hasSessionCookies() {
		t.Error("expected false when the client has no cookie jar")
	}
}

func TestHasAuthContextLocked(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	f := &Fuzzer{target: "http://example.test", client: &http.Client{Jar: jar}}
	if f.hasAuthContextLocked() {
		t.Error("expected false with no token, headers, or cookies")
	}
	f.token = "abc"
	if !f.hasAuthContextLocked() {
		t.Error("expected true once a token is set")
	}
	f2 := &Fuzzer{target: "http://example.test", client: &http.Client{Jar: jar}, authHeaders: map[string]string{"X-Api-Key": "k"}}
	if !f2.hasAuthContextLocked() {
		t.Error("expected true once auth headers are set")
	}
}

func TestHasAuthContext(t *testing.T) {
	f := &Fuzzer{token: "abc"}
	if !f.hasAuthContext() {
		t.Error("expected hasAuthContext to reflect a set token via the RLock wrapper")
	}
}

func TestHasConfiguredIdentityAuth(t *testing.T) {
	var fNil *Fuzzer
	if fNil.hasConfiguredIdentityAuth() {
		t.Error("expected false for a nil Fuzzer")
	}
	f := &Fuzzer{cfg: config.Config{MultiIdentity: false}}
	if f.hasConfiguredIdentityAuth() {
		t.Error("expected false when MultiIdentity is disabled")
	}
	f2 := &Fuzzer{cfg: config.Config{MultiIdentity: true, AuthFile: "identities.json"}}
	if !f2.hasConfiguredIdentityAuth() {
		t.Error("expected true when MultiIdentity is enabled and AuthFile is set")
	}
}

func TestHasExplicitAuthLoginEnv(t *testing.T) {
	for _, k := range []string{"AUTH_URL", "AUTH_METHOD", "AUTH_BODY", "AUTH_TOKEN_FIELD"} {
		t.Setenv(k, "")
	}
	if hasExplicitAuthLoginEnv() {
		t.Error("expected false when none of the auth-login env vars are set")
	}
	t.Setenv("AUTH_URL", "/api/login")
	if !hasExplicitAuthLoginEnv() {
		t.Error("expected true once AUTH_URL is set")
	}
}

func TestIdentityHasAuth(t *testing.T) {
	if identityHasAuth(AuthIdentity{}) {
		t.Error("expected false for an identity with no token or headers")
	}
	if !identityHasAuth(AuthIdentity{Token: "abc"}) {
		t.Error("expected true for an identity with a token")
	}
	if !identityHasAuth(AuthIdentity{Headers: map[string]string{"X": "y"}}) {
		t.Error("expected true for an identity with headers")
	}
}

func TestHasAnyAuthContext(t *testing.T) {
	f := &Fuzzer{}
	if f.hasAnyAuthContext() {
		t.Error("expected false with no primary auth context and no identities")
	}
	f.identities = []AuthIdentity{{Name: "guest"}, {Name: "admin", Token: "abc"}}
	if !f.hasAnyAuthContext() {
		t.Error("expected true once at least one identity has auth")
	}
}

func TestPrimaryAuthContextForHarvest_PrefersPrimaryTokenOverIdentities(t *testing.T) {
	f := &Fuzzer{token: "primary-token", identities: []AuthIdentity{{Name: "admin", Token: "id-token"}}}
	headers, token := f.primaryAuthContextForHarvest()
	if token != "primary-token" {
		t.Errorf("expected the primary token to win, got %q", token)
	}
	if len(headers) != 0 {
		t.Errorf("expected no headers from the primary-token path, got %v", headers)
	}
}

func TestPrimaryAuthContextForHarvest_SkipsGuestAndAnonIdentities(t *testing.T) {
	f := &Fuzzer{identities: []AuthIdentity{
		{Name: "guest", Token: "guest-token"},
		{Name: "anon-user", Token: "anon-token"},
		{Name: "admin", Token: "admin-token"},
	}}
	_, token := f.primaryAuthContextForHarvest()
	if token != "admin-token" {
		t.Errorf("expected the first non-guest/non-anon identity to be picked, got %q", token)
	}
}

func TestPrimaryAuthContextForHarvest_FallsBackToAnyIdentityIfAllAreGuestLike(t *testing.T) {
	f := &Fuzzer{identities: []AuthIdentity{{Name: "guest", Token: "guest-token"}}}
	_, token := f.primaryAuthContextForHarvest()
	if token != "guest-token" {
		t.Errorf("expected the fallback pass to still pick the guest identity, got %q", token)
	}
}

func TestPrimaryAuthContextForHarvest_NothingAvailable(t *testing.T) {
	f := &Fuzzer{}
	headers, token := f.primaryAuthContextForHarvest()
	if token != "" || len(headers) != 0 {
		t.Errorf("expected empty context when nothing is configured, got (%v,%q)", headers, token)
	}
}

func TestSeedAuthContextValues_NilSafe(t *testing.T) {
	var fNil *Fuzzer
	fNil.seedAuthContextValues() // must not panic
	f := &Fuzzer{}
	f.seedAuthContextValues() // nil runtime, must not panic
}

func TestPickAntiForgeryToken_PrefersLiveTokenPool(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{})
	f.registerAntiForgeryToken("live-token", time.Now())
	if got := f.pickAntiForgeryToken(); got != "live-token" {
		t.Errorf("expected the single live token to be picked, got %q", got)
	}
}

func TestPickAntiForgeryToken_FallsBackToRuntimeStore(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryField: "__RequestVerificationToken"})
	f.runtime.addValue("__RequestVerificationToken", "fallback-token")
	if got := f.pickAntiForgeryToken(); got != "fallback-token" {
		t.Errorf("expected the runtime-store fallback value, got %q", got)
	}
}

func TestPickAntiForgeryToken_NothingAvailableReturnsEmpty(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{})
	if got := f.pickAntiForgeryToken(); got != "" {
		t.Errorf("expected an empty string when no tokens are known, got %q", got)
	}
}

func TestRecordAuthFailureAndSuccess(t *testing.T) {
	f := &Fuzzer{authBlocked: map[string]*AuthBlockedState{}, cfg: config.Config{NoUI: true}}
	f.recordAuthFailure("GET", "/api/orders/1", 403, "insufficient permission for this role")
	k := endpointKey("GET", normalizePath("/api/orders/1"))
	st := f.authBlocked[k]
	if st == nil || st.Count != 1 {
		t.Fatalf("expected an AuthBlockedState with Count=1 recorded, got %+v", st)
	}
	if st.Reason != "permission" {
		t.Errorf("expected the first matching marker 'permission' to be recorded as the reason, got %q", st.Reason)
	}

	f.recordAuthSuccess("GET", "/api/orders/1")
	if _, ok := f.authBlocked[k]; ok {
		t.Error("expected recordAuthSuccess to clear the blocked-state entry")
	}
}

func TestHarvestAntiForgeryForPathReserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<input name="__RequestVerificationToken" value="harvested-abc" />`))
	}))
	defer srv.Close()

	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryField: "__RequestVerificationToken", MaxResponseBytes: 65536})
	f.target = srv.URL
	f.client = srv.Client()
	f.token = "test-token"

	learned := f.harvestAntiForgeryForPathReserved("/checkout")
	if learned == 0 {
		t.Fatal("expected at least one anti-forgery token harvested from the live HTTP response")
	}
	if f.antiForgeryTokenPoolSize() == 0 {
		t.Error("expected the harvested token to be registered in the pool")
	}
}

func TestReserveAntiForgeryHarvest_CooldownGating(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{AntiForgeryCooldown: 60})
	f.token = "abc"
	f.antiForgeryHarvestAt = map[string]time.Time{}

	norm, ok := f.reserveAntiForgeryHarvest("/checkout")
	if !ok || norm == "" {
		t.Fatal("expected the first reservation to succeed")
	}
	if _, ok := f.reserveAntiForgeryHarvest("/checkout"); ok {
		t.Error("expected a second reservation within the cooldown window to be rejected")
	}
}

func TestReserveAntiForgeryHarvest_NoAuthContextRejects(t *testing.T) {
	f := newAntiForgeryTestFuzzer(config.Config{})
	f.antiForgeryHarvestAt = map[string]time.Time{}
	if _, ok := f.reserveAntiForgeryHarvest("/checkout"); ok {
		t.Error("expected reservation to fail with no auth context at all")
	}
}

func TestAuthenticate_UsesAuthTokenEnvDirectly(t *testing.T) {
	t.Setenv("AUTH_HEADERS_JSON", "")
	t.Setenv("AUTH_COOKIE", "")
	t.Setenv("AUTH_HEADER", "")
	t.Setenv("AUTH_TOKEN", "Bearer my-token")
	jar, _ := cookiejar.New(nil)
	f := &Fuzzer{target: "http://example.test", client: &http.Client{Jar: jar}, runtime: newRuntimeStore()}
	if err := f.authenticate(); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if f.token != "my-token" {
		t.Errorf("expected the bearer prefix stripped, got %q", f.token)
	}
}

func TestAuthenticate_LoginFlowExtractsTokenFromJSONField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token":"session-token-value"}`))
	}))
	defer srv.Close()

	for _, k := range []string{"AUTH_HEADERS_JSON", "AUTH_COOKIE", "AUTH_HEADER", "AUTH_TOKEN", "AUTH_URL", "AUTH_METHOD", "AUTH_BODY", "AUTH_TOKEN_FIELD", "AUTH_CONTENT_TYPE"} {
		t.Setenv(k, "")
	}
	t.Setenv("AUTH_URL", "/login")

	jar, _ := cookiejar.New(nil)
	f := &Fuzzer{target: srv.URL, client: &http.Client{Jar: jar}, runtime: newRuntimeStore()}
	if err := f.authenticate(); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if f.token != "session-token-value" {
		t.Errorf("expected the token extracted from the JSON field, got %q", f.token)
	}
}

func TestAuthenticate_LoginFailureReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	for _, k := range []string{"AUTH_HEADERS_JSON", "AUTH_COOKIE", "AUTH_HEADER", "AUTH_TOKEN", "AUTH_URL", "AUTH_METHOD", "AUTH_BODY", "AUTH_TOKEN_FIELD", "AUTH_CONTENT_TYPE"} {
		t.Setenv(k, "")
	}
	t.Setenv("AUTH_URL", "/login")

	jar, _ := cookiejar.New(nil)
	f := &Fuzzer{target: srv.URL, client: &http.Client{Jar: jar}, runtime: newRuntimeStore()}
	if err := f.authenticate(); err == nil {
		t.Error("expected an error when the login endpoint returns a 5xx status")
	}
}
