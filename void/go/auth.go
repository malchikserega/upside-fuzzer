package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// auth.go — Authentication: JWT bearer tokens, session cookies,
// anti-forgery token harvesting, pruning, and rotation.

func (f *Fuzzer) authenticate() error {
	f.authMu.Lock()
	defer f.authMu.Unlock()

	f.authHeaders = parseAuthHeadersJSON(os.Getenv("AUTH_HEADERS_JSON"))
	if cookie := strings.TrimSpace(os.Getenv("AUTH_COOKIE")); cookie != "" {
		setHeaderCI(f.authHeaders, "Cookie", cookie)
	}
	// AUTH_HEADER: plain "HeaderName: value" string (written by get_apikey.py).
	if ah := strings.TrimSpace(os.Getenv("AUTH_HEADER")); ah != "" {
		if idx := strings.Index(ah, ":"); idx > 0 {
			k := strings.TrimSpace(ah[:idx])
			v := strings.TrimSpace(ah[idx+1:])
			if k != "" && v != "" {
				setHeaderCI(f.authHeaders, k, v)
			}
		}
	}
	f.seedAuthContextValues()
	if tok := strings.TrimSpace(os.Getenv("AUTH_TOKEN")); tok != "" {
		f.token = stripBearerPrefix(tok)
		return nil
	}
	if f.hasAuthContextLocked() {
		return nil
	}
	if f.hasConfiguredIdentityAuth() && !hasExplicitAuthLoginEnv() {
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
				f.token = stripBearerPrefix(tv)
				return nil
			}
		case map[string]any:
			if v, ok := tv[tokenField]; ok {
				t := strings.TrimSpace(toString(v))
				if len(t) > 10 {
					f.token = stripBearerPrefix(t)
					return nil
				}
			}
		}
	}
	text = strings.Trim(text, `"`)
	if len(text) > 10 {
		f.token = stripBearerPrefix(text)
		return nil
	}
	if f.hasAuthContextLocked() {
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
	f.authMu.RLock()
	defer f.authMu.RUnlock()
	return f.hasAuthContextLocked()
}

// hasAuthContextLocked is for use when authMu is already held.
func (f *Fuzzer) hasAuthContextLocked() bool {
	if strings.TrimSpace(f.token) != "" {
		return true
	}
	if len(f.authHeaders) > 0 {
		return true
	}
	return f.hasSessionCookies()
}

func (f *Fuzzer) hasConfiguredIdentityAuth() bool {
	if f == nil || !f.cfg.MultiIdentity {
		return false
	}
	return strings.TrimSpace(f.cfg.AuthFile) != "" || strings.TrimSpace(os.Getenv("AUTH_IDENTITIES_JSON")) != ""
}

func hasExplicitAuthLoginEnv() bool {
	for _, k := range []string{"AUTH_URL", "AUTH_METHOD", "AUTH_BODY", "AUTH_TOKEN_FIELD"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return false
}

func (f *Fuzzer) hasAnyAuthContext() bool {
	if f.hasAuthContext() {
		return true
	}
	for _, id := range f.identities {
		if identityHasAuth(id) {
			return true
		}
	}
	return false
}

func identityHasAuth(id AuthIdentity) bool {
	return strings.TrimSpace(id.Token) != "" || len(id.Headers) > 0
}

func (f *Fuzzer) primaryAuthContextForHarvest() (map[string]string, string) {
	f.authMu.RLock()
	if strings.TrimSpace(f.token) != "" || len(f.authHeaders) > 0 {
		headers := cloneStringMap(f.authHeaders)
		token := strings.TrimSpace(f.token)
		f.authMu.RUnlock()
		return headers, token
	}
	f.authMu.RUnlock()

	for _, id := range f.identities {
		name := strings.ToLower(strings.TrimSpace(id.Name))
		if identityHasAuth(id) && !strings.EqualFold(name, "guest") && !strings.Contains(name, "anon") {
			return cloneStringMap(id.Headers), strings.TrimSpace(id.Token)
		}
	}
	for _, id := range f.identities {
		if identityHasAuth(id) {
			return cloneStringMap(id.Headers), strings.TrimSpace(id.Token)
		}
	}
	return map[string]string{}, ""
}

func (f *Fuzzer) seedAuthContextValues() {
	if f == nil || f.runtime == nil {
		return
	}
}

func (f *Fuzzer) preHarvestAntiForgeryTokens() int {
	if !f.cfg.AutoAntiForgery || !f.hasAnyAuthContext() {
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
	if !f.cfg.AutoAntiForgery || !f.hasAnyAuthContext() {
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

	authHdrs, authToken := f.primaryAuthContextForHarvest()

	for _, p := range candidates {
		req, err := http.NewRequest(http.MethodGet, f.target+p, nil)
		if err != nil {
			continue
		}
		for k, v := range authHdrs {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
				continue
			}
			req.Header.Set(k, v)
		}
		if authToken != "" {
			req.Header.Set("Authorization", "Bearer "+authToken)
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
