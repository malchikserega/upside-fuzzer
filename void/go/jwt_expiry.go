package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// jwt_expiry.go — best-effort JWT expiry awareness for -auth-file identities.
//
// void never verifies a JWT's signature -- it's a client of whatever auth scheme
// the target uses, not a verifier -- but reading the unsigned `exp` claim out of
// a token it was already handed costs nothing and closes a real, previously
// disclosed trust gap (ARCHITECTURE_REVIEW.md's security-researcher section:
// "pasting JWTs that expire mid-run ... no refresh at all once a token expires").
// Best-effort throughout: any identity whose token isn't JWT-shaped (API keys,
// cookies, opaque session tokens) or has no `exp` claim is silently skipped,
// never treated as an error -- most identities in a given auth file won't be JWTs.

// decodeJWTExpiry extracts the `exp` (NumericDate, RFC 7519 SS4.1.4) claim from a
// JWT's payload segment without verifying its signature. Returns false for any
// non-JWT-shaped token (wrong segment count, non-base64 payload, no `exp` claim).
func decodeJWTExpiry(token string) (time.Time, bool) {
	token = strings.TrimSpace(stripBearerPrefix(strings.TrimSpace(token)))
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		return time.Time{}, false
	}
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return time.Time{}, false
		}
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(claims.Exp), 0), true
}

// effectiveBearerToken returns the token this identity would actually present as
// `Authorization: Bearer <token>`, checking both the legacy Token field and the
// Authorization header (parseAuthIdentitiesBytes stores JWT-shaped `jwt` values
// in the header, not the Token field -- see its own tryAdd closure).
func effectiveBearerToken(id AuthIdentity) string {
	if t := strings.TrimSpace(id.Token); t != "" {
		return t
	}
	if h := getHeaderCI(id.Headers, "Authorization"); h != "" {
		return stripBearerPrefix(h)
	}
	return ""
}

// checkIdentityTokenExpiry inspects every identity's bearer token for JWT expiry
// and returns one human-readable warning line per identity that has either
// already expired or will expire before a run of timeBudgetMinutes finishes.
// Pure function (no I/O), called once at startup right after identities load.
func checkIdentityTokenExpiry(identities []AuthIdentity, timeBudgetMinutes float64) []string {
	now := time.Now()
	runEnd := now.Add(time.Duration(timeBudgetMinutes * float64(time.Minute)))
	var warnings []string
	for _, id := range identities {
		exp, ok := decodeJWTExpiry(effectiveBearerToken(id))
		if !ok {
			continue
		}
		switch {
		case !exp.After(now):
			warnings = append(warnings, fmt.Sprintf(
				"identity %q: JWT already expired %s ago (at %s) -- requests will get 401s all run",
				id.Name, now.Sub(exp).Round(time.Second), exp.Format(time.RFC3339)))
		case exp.Before(runEnd):
			warnings = append(warnings, fmt.Sprintf(
				"identity %q: JWT expires in %s (at %s), before this %.0f-minute run finishes -- requests will start getting 401s partway through",
				id.Name, exp.Sub(now).Round(time.Second), exp.Format(time.RFC3339), timeBudgetMinutes))
		}
	}
	return warnings
}

// checkTokenExpiryDuringRun is the runtime half of the same check: it emits a
// ONE-TIME event the moment an identity's token that was still valid at startup
// actually crosses its expiry during a long run -- the concrete "why did this
// identity suddenly start getting 401s" signal the startup check alone can't
// provide once the run is already going.
//
// Called from renderUI, which itself is invoked on every scheduling-loop
// iteration (potentially thousands of times per second under load), not just
// once per UI refresh -- so this self-throttles to once every 5s rather than
// relying on renderUI's own (UI-mode-dependent) throttle, to keep the
// per-identity base64/JSON decode off the hot request path.
func (f *Fuzzer) checkTokenExpiryDuringRun() {
	if len(f.identities) == 0 {
		return
	}
	now := time.Now()
	if !f.lastJWTExpiryCheck.IsZero() && now.Sub(f.lastJWTExpiryCheck) < 5*time.Second {
		return
	}
	f.lastJWTExpiryCheck = now
	for _, id := range f.identities {
		if f.jwtExpiryWarned[id.Name] {
			continue
		}
		exp, ok := decodeJWTExpiry(effectiveBearerToken(id))
		if !ok || exp.After(now) {
			continue
		}
		if f.jwtExpiryWarned == nil {
			f.jwtExpiryWarned = map[string]bool{}
		}
		f.jwtExpiryWarned[id.Name] = true
		f.addEvent(fmt.Sprintf("JWT-EXPIRED identity=%q at=%s -- expect 401s for this identity for the rest of the run", id.Name, exp.Format(time.RFC3339)))
	}
}
