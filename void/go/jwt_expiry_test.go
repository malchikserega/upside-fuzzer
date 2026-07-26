package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func makeTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(map[string]any{"sub": "1", "exp": exp})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".fakesignature"
}

func TestDecodeJWTExpiry(t *testing.T) {
	future := time.Now().Add(2 * time.Hour).Unix()
	token := makeTestJWT(future)

	exp, ok := decodeJWTExpiry(token)
	if !ok {
		t.Fatalf("expected ok=true for a well-formed JWT")
	}
	if exp.Unix() != future {
		t.Fatalf("expected exp=%d, got %d", future, exp.Unix())
	}

	// "Bearer " prefix must be stripped transparently, matching how identities
	// actually store the token (see effectiveBearerToken/parseAuthIdentitiesBytes).
	exp2, ok2 := decodeJWTExpiry("Bearer " + token)
	if !ok2 || exp2.Unix() != future {
		t.Fatalf("Bearer-prefixed token not decoded correctly: ok=%v exp=%v", ok2, exp2)
	}
}

func TestDecodeJWTExpiry_NonJWTShapes(t *testing.T) {
	cases := []string{
		"",
		"not-a-jwt-at-all",
		"only.two-parts",
		"a.b.c.d",        // 4 segments, not a JWT
		"YQ==.YQ==.YQ==", // valid base64 but not a JSON object with an exp claim
	}
	for _, c := range cases {
		if _, ok := decodeJWTExpiry(c); ok {
			t.Errorf("expected ok=false for non-JWT-shaped token %q", c)
		}
	}
}

func TestCheckIdentityTokenExpiry(t *testing.T) {
	now := time.Now()
	expired := makeTestJWT(now.Add(-1 * time.Hour).Unix())
	expiringSoon := makeTestJWT(now.Add(2 * time.Minute).Unix())
	longLived := makeTestJWT(now.Add(12 * time.Hour).Unix())

	identities := []AuthIdentity{
		{Name: "alice-expired", Headers: map[string]string{"Authorization": "Bearer " + expired}},
		{Name: "bob-expiring-soon", Headers: map[string]string{"Authorization": "Bearer " + expiringSoon}},
		{Name: "carol-long-lived", Headers: map[string]string{"Authorization": "Bearer " + longLived}},
		{Name: "dave-api-key", Headers: map[string]string{"X-Api-Key": "some-opaque-key"}},
		{Name: "guest", Headers: map[string]string{}},
	}

	warnings := checkIdentityTokenExpiry(identities, 5 /* minute run */)

	if len(warnings) != 2 {
		t.Fatalf("expected exactly 2 warnings (expired + expiring-soon), got %d: %v", len(warnings), warnings)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "alice-expired") || !strings.Contains(joined, "already expired") {
		t.Errorf("expected an already-expired warning for alice-expired, got: %v", warnings)
	}
	if !strings.Contains(joined, "bob-expiring-soon") || !strings.Contains(joined, "expires in") {
		t.Errorf("expected an expires-in warning for bob-expiring-soon, got: %v", warnings)
	}
	if strings.Contains(joined, "carol-long-lived") {
		t.Errorf("carol-long-lived's token outlives the run; should not warn: %v", warnings)
	}
	if strings.Contains(joined, "dave-api-key") {
		t.Errorf("dave-api-key is not a JWT and should be silently skipped: %v", warnings)
	}
}

func TestEffectiveBearerToken(t *testing.T) {
	id1 := AuthIdentity{Token: "legacy-token"}
	if got := effectiveBearerToken(id1); got != "legacy-token" {
		t.Errorf("expected legacy Token field to be used, got %q", got)
	}

	id2 := AuthIdentity{Headers: map[string]string{"Authorization": "Bearer header-token"}}
	if got := effectiveBearerToken(id2); got != "header-token" {
		t.Errorf("expected Bearer prefix stripped from header, got %q", got)
	}

	id3 := AuthIdentity{}
	if got := effectiveBearerToken(id3); got != "" {
		t.Errorf("expected empty string when neither Token nor Authorization header is set, got %q", got)
	}
}

func TestCheckTokenExpiryDuringRun_WarnsOncePerIdentity(t *testing.T) {
	now := time.Now()
	expired := makeTestJWT(now.Add(-1 * time.Hour).Unix())

	f := &Fuzzer{
		startTime: now,
		identities: []AuthIdentity{
			{Name: "alice", Headers: map[string]string{"Authorization": "Bearer " + expired}},
		},
	}

	f.checkTokenExpiryDuringRun()
	if !f.jwtExpiryWarned["alice"] {
		t.Fatalf("expected alice to be marked as warned after the first call")
	}
	eventsAfterFirst := len(f.eventLog)
	if eventsAfterFirst == 0 {
		t.Fatalf("expected a JWT-EXPIRED event to be recorded")
	}

	// Bypass the 5s self-throttle to isolate the warned-once behavior specifically
	// (not just "it didn't run again because it was throttled").
	f.lastJWTExpiryCheck = time.Time{}
	f.checkTokenExpiryDuringRun()
	if len(f.eventLog) != eventsAfterFirst {
		t.Fatalf("expected no duplicate event on a second call, eventLog grew from %d to %d", eventsAfterFirst, len(f.eventLog))
	}
}

func TestCheckTokenExpiryDuringRun_SelfThrottles(t *testing.T) {
	now := time.Now()
	expired := makeTestJWT(now.Add(-1 * time.Hour).Unix())

	f := &Fuzzer{
		startTime: now,
		identities: []AuthIdentity{
			{Name: "alice", Headers: map[string]string{"Authorization": "Bearer " + expired}},
		},
	}
	f.checkTokenExpiryDuringRun()
	stampAfterFirst := f.lastJWTExpiryCheck
	if stampAfterFirst.IsZero() {
		t.Fatalf("expected lastJWTExpiryCheck to be set after the first call")
	}

	f.checkTokenExpiryDuringRun()
	if !f.lastJWTExpiryCheck.Equal(stampAfterFirst) {
		t.Fatalf("expected a call within the 5s throttle window to be a no-op, but lastJWTExpiryCheck advanced")
	}
}
