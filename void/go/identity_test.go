package main

import (
	"math"
	"testing"
)

func TestParseAuthIdentitiesFileSchema(t *testing.T) {
	t.Setenv("PARTNER_API_KEY", "partner-secret")

	raw := []byte(`{
		"version": "1",
		"identities": [
			{"name": "admin", "jwt": "Bearer admin.jwt.token", "weight": 2.0},
			{"name": "partner", "api_key_env": "PARTNER_API_KEY", "api_key_header": "X-Partner-Key", "weight": 1.5},
			{"name": "cookie-user", "cookie": "session=abc; xsrf=def"},
			{"name": "viewer", "headers": {"Authorization": "Bearer viewer.jwt.token", "X-Tenant": "acme"}},
			{"name": "guest", "weight": 0.3}
		]
	}`)

	ids, err := parseAuthIdentitiesBytes(raw)
	if err != nil {
		t.Fatalf("parseAuthIdentitiesBytes returned error: %v", err)
	}
	if len(ids) != 5 {
		t.Fatalf("expected 5 identities, got %d: %#v", len(ids), ids)
	}

	admin := mustFindIdentity(t, ids, "admin")
	if got := getHeaderCI(admin.Headers, "Authorization"); got != "Bearer admin.jwt.token" {
		t.Fatalf("admin Authorization header = %q", got)
	}
	if admin.Token != "" {
		t.Fatalf("jwt identities should not set legacy Token, got %q", admin.Token)
	}

	partner := mustFindIdentity(t, ids, "partner")
	if got := getHeaderCI(partner.Headers, "X-Partner-Key"); got != "partner-secret" {
		t.Fatalf("partner API key header = %q", got)
	}
	if math.Abs(partner.Weight-1.5) > 0.0001 {
		t.Fatalf("partner weight = %f", partner.Weight)
	}

	cookieUser := mustFindIdentity(t, ids, "cookie-user")
	if got := getHeaderCI(cookieUser.Headers, "Cookie"); got != "session=abc; xsrf=def" {
		t.Fatalf("cookie header = %q", got)
	}

	viewer := mustFindIdentity(t, ids, "viewer")
	if got := getHeaderCI(viewer.Headers, "Authorization"); got != "Bearer viewer.jwt.token" {
		t.Fatalf("viewer Authorization header = %q", got)
	}
	if got := getHeaderCI(viewer.Headers, "X-Tenant"); got != "acme" {
		t.Fatalf("viewer X-Tenant header = %q", got)
	}

	guest := mustFindIdentity(t, ids, "guest")
	if len(guest.Headers) != 0 {
		t.Fatalf("guest should be anonymous, got headers %#v", guest.Headers)
	}
	if math.Abs(guest.Weight-0.3) > 0.0001 {
		t.Fatalf("guest weight = %f", guest.Weight)
	}
}

func TestParseAuthIdentitiesObjectSchema(t *testing.T) {
	raw := []byte(`{
		"viewer": {"token": "Bearer viewer.jwt.token"},
		"service": {"api_key": "service-key"}
	}`)

	ids, err := parseAuthIdentitiesBytes(raw)
	if err != nil {
		t.Fatalf("parseAuthIdentitiesBytes returned error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 identities, got %d: %#v", len(ids), ids)
	}

	service := mustFindIdentity(t, ids, "service")
	if got := getHeaderCI(service.Headers, "X-Api-Key"); got != "service-key" {
		t.Fatalf("service X-Api-Key header = %q", got)
	}

	viewer := mustFindIdentity(t, ids, "viewer")
	if got := getHeaderCI(viewer.Headers, "Authorization"); got != "Bearer viewer.jwt.token" {
		t.Fatalf("viewer Authorization header = %q", got)
	}
	if viewer.Token != "viewer.jwt.token" {
		t.Fatalf("viewer legacy Token = %q", viewer.Token)
	}
}

func TestAuthenticateStripsBearerPrefixFromAuthToken(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "Bearer pasted.jwt.token")

	f := &Fuzzer{}
	if err := f.authenticate(); err != nil {
		t.Fatalf("authenticate returned error: %v", err)
	}
	if f.token != "pasted.jwt.token" {
		t.Fatalf("token = %q", f.token)
	}
}

func TestAuthenticateSkipsDefaultLoginWhenAuthFileConfigured(t *testing.T) {
	f := &Fuzzer{cfg: Config{MultiIdentity: true, AuthFile: "auth.identities.json"}}

	if err := f.authenticate(); err != nil {
		t.Fatalf("authenticate returned error: %v", err)
	}
	if f.token != "" {
		t.Fatalf("token = %q", f.token)
	}
}

func TestIdentityAuthDoesNotFallBackForSelectedGuest(t *testing.T) {
	f := &Fuzzer{
		token: "default.jwt.token",
		identities: []AuthIdentity{
			{Name: "guest", Headers: map[string]string{}},
			{Name: "admin", Headers: map[string]string{"Authorization": "Bearer admin.jwt.token"}},
		},
	}

	headers, token, selected := f.identityAuth("guest")
	if !selected {
		t.Fatal("guest identity should be selected")
	}
	if token != "" {
		t.Fatalf("guest token = %q", token)
	}
	if got := getHeaderCI(headers, "Authorization"); got != "" {
		t.Fatalf("guest Authorization header = %q", got)
	}
}

func TestPrimaryAuthContextForHarvestUsesNonGuestIdentity(t *testing.T) {
	f := &Fuzzer{
		identities: []AuthIdentity{
			{Name: "guest", Headers: map[string]string{}},
			{Name: "org-a-admin", Headers: map[string]string{"Authorization": "Bearer admin.jwt.token"}},
		},
	}

	headers, token := f.primaryAuthContextForHarvest()
	if token != "" {
		t.Fatalf("harvest token = %q", token)
	}
	if got := getHeaderCI(headers, "Authorization"); got != "Bearer admin.jwt.token" {
		t.Fatalf("harvest Authorization header = %q", got)
	}
}

func mustFindIdentity(t *testing.T, ids []AuthIdentity, name string) AuthIdentity {
	t.Helper()
	for _, id := range ids {
		if id.Name == name {
			return id
		}
	}
	t.Fatalf("identity %q not found in %#v", name, ids)
	return AuthIdentity{}
}
