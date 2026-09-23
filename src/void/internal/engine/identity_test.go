package engine

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"void/internal/config"
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
	f := &Fuzzer{cfg: config.Config{MultiIdentity: true, AuthFile: "auth.identities.json"}}

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

func TestParseAuthIdentitiesJSONEmptyStringReturnsNil(t *testing.T) {
	if got := parseAuthIdentitiesJSON(""); got != nil {
		t.Fatalf("expected nil for empty input, got %#v", got)
	}
}

func TestParseAuthIdentitiesJSONValidRawString(t *testing.T) {
	ids := parseAuthIdentitiesJSON(`{"viewer": {"token": "Bearer viewer.jwt.token"}}`)
	if len(ids) != 1 {
		t.Fatalf("expected 1 identity, got %d: %#v", len(ids), ids)
	}
	if ids[0].Name != "viewer" {
		t.Fatalf("expected identity named viewer, got %q", ids[0].Name)
	}
}

func TestParseAuthIdentitiesFileEmptyPathReturnsNil(t *testing.T) {
	if got := parseAuthIdentitiesFile(""); got != nil {
		t.Fatalf("expected nil for an empty path, got %#v", got)
	}
}

func TestParseAuthIdentitiesFileMissingFileReturnsNilNotError(t *testing.T) {
	// Must degrade gracefully (empty result), not panic or crash startup, when the
	// configured auth file doesn't exist -- initAuthIdentities has no error return.
	if got := parseAuthIdentitiesFile("/nonexistent/path/auth.identities.json"); got != nil {
		t.Fatalf("expected nil for a missing file, got %#v", got)
	}
}

func TestParseAuthIdentitiesFileReadsRealFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/auth.identities.json"
	if err := os.WriteFile(path, []byte(`{"admin": {"token": "Bearer admin.jwt.token"}}`), 0o644); err != nil {
		t.Fatalf("failed to write test fixture: %v", err)
	}
	ids := parseAuthIdentitiesFile(path)
	if len(ids) != 1 || ids[0].Name != "admin" {
		t.Fatalf("expected 1 identity named admin, got %#v", ids)
	}
}

func TestInitAuthIdentitiesDefaultsToSingleIdentityWithNoConfig(t *testing.T) {
	f := &Fuzzer{}
	f.initAuthIdentities()
	if len(f.identities) != 1 || f.identities[0].Name != "default" {
		t.Fatalf("expected a single \"default\" identity with no config, got %#v", f.identities)
	}
}

func TestInitAuthIdentitiesAddsGuestWhenConfigured(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{MultiIdentity: true, IdentityIncludeGuest: true}}
	f.initAuthIdentities()

	names := map[string]bool{}
	for _, id := range f.identities {
		names[id.Name] = true
	}
	if !names["guest"] {
		t.Fatalf("expected a guest identity to be added, got %#v", f.identities)
	}
}

func TestInitAuthIdentitiesFromEnvJSON(t *testing.T) {
	t.Setenv("AUTH_IDENTITIES_JSON", `{"admin": {"token": "Bearer admin.jwt.token"}, "guest": {}}`)
	f := &Fuzzer{cfg: config.Config{MultiIdentity: true}}
	f.initAuthIdentities()

	names := map[string]bool{}
	for _, id := range f.identities {
		names[id.Name] = true
	}
	if !names["admin"] || !names["guest"] {
		t.Fatalf("expected admin and guest identities from AUTH_IDENTITIES_JSON, got %#v", f.identities)
	}
}

func TestInitAuthIdentitiesDedupsByName(t *testing.T) {
	t.Setenv("AUTH_IDENTITIES_JSON", `{"admin": {"token": "Bearer a"}, "guest": {}}`)
	f := &Fuzzer{cfg: config.Config{MultiIdentity: true, IdentityIncludeGuest: true}}
	f.initAuthIdentities()

	seen := map[string]int{}
	for _, id := range f.identities {
		seen[id.Name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("identity %q appeared %d times, expected exactly once", name, count)
		}
	}
}

func TestPickIdentityForEndpointEmptyReturnsEmptyString(t *testing.T) {
	f := &Fuzzer{}
	if got := f.pickIdentityForEndpoint("GET", "/items"); got != "" {
		t.Fatalf("expected empty string with no identities configured, got %q", got)
	}
}

func TestPickIdentityForEndpointSingleIdentityAlwaysReturnsIt(t *testing.T) {
	f := &Fuzzer{identities: []AuthIdentity{{Name: "solo", Weight: 1.0}}}
	if got := f.pickIdentityForEndpoint("GET", "/items"); got != "solo" {
		t.Fatalf("expected \"solo\", got %q", got)
	}
}

func TestPickIdentityForEndpointRoundRobinCyclesInOrder(t *testing.T) {
	f := &Fuzzer{
		cfg: config.Config{IdentitySampleMode: "round-robin"},
		identities: []AuthIdentity{
			{Name: "a", Weight: 1.0}, {Name: "b", Weight: 1.0}, {Name: "c", Weight: 1.0},
		},
	}
	var got []string
	for i := 0; i < 6; i++ {
		got = append(got, f.pickIdentityForEndpoint("GET", "/items"))
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("round-robin sequence = %v, want %v", got, want)
		}
	}
}

func TestPickIdentityForEndpointWeightedStronglyFavorsAdminOnAdminPaths(t *testing.T) {
	f := &Fuzzer{
		identities: []AuthIdentity{
			{Name: "admin", Weight: 1.0},
			{Name: "guest", Weight: 1.0},
		},
	}
	counts := map[string]int{}
	const n = 2000
	for i := 0; i < n; i++ {
		counts[f.pickIdentityForEndpoint("GET", "/admin/settings")]++
	}
	// admin gets *5.0, guest gets *0.3 on an /admin path -- roughly a 16.7x skew.
	// Generous threshold (3x) to avoid flakiness while still proving real bias.
	if counts["admin"] < counts["guest"]*3 {
		t.Errorf("expected admin identity strongly favored on /admin path, got counts %v", counts)
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

// --- triageCrash: the honest-triage taxonomy engine -------------------------
//
// This is the single most correctness-critical function in the project: it
// decides whether a 500 gets reported as a genuine vulnerability, a robustness
// bug, noise, or a build artifact. Each test below constructs a body/status
// combination that deliberately trips a specific, named set of markers in
// triageCrash's own source (identity.go) so the classification is derived from
// real logic, not an assumed outcome.

func TestTriageCrashDisabledReturnsUnclassified(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CrashTriage: false}}
	got := f.triageCrash(SendResult{Status: 500, Body: "anything"})
	if got["classification"] != "unclassified" {
		t.Fatalf("expected unclassified when CrashTriage is disabled, got %#v", got)
	}
}

func TestTriageCrashTargetMisconfigurationExcludedFromVulnCount(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body:   "Unable to resolve service for type 'IFoo' while attempting to activate 'Bar'.",
	}
	got := f.triageCrash(res)
	if got["classification"] != "target_misconfiguration" {
		t.Fatalf("expected target_misconfiguration for a DI resolution failure, got %#v", got)
	}
}

func TestTriageCrashConfirmedUnhandledExceptionForRealControllerCrash(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body: "System.NullReferenceException: Object reference not set to an instance of an object.\n" +
			"   at Bit.Api.Controllers.ItemsController.GetById(Int32 id)",
	}
	got := f.triageCrash(res)
	if got["classification"] != "confirmed_unhandled_exception" {
		t.Fatalf("expected confirmed_unhandled_exception for a post-auth controller crash with no exploit signal, got %#v", got)
	}
	if got["crash_layer"] != "controller" {
		t.Fatalf("expected crash_layer=controller, got %#v", got["crash_layer"])
	}
}

func TestTriageCrashBenignInputValidationCappedAtNeedsReview(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body:   "System.Exception at somewhere\nTimeout waiting for the operation.\nUnrecognized Guid format",
	}
	got := f.triageCrash(res)
	// A malformed-input parse exception (a bad GUID) must never be reported as a
	// "confirmed_unhandled_exception" even when its raw score would otherwise
	// clear that bar -- it's explicitly capped at needs_review.
	if got["classification"] != "needs_review" {
		t.Fatalf("expected needs_review (capped) for a benign GUID-parse failure, got %#v", got)
	}
}

func TestTriageCrashLikelyVulnHighRequiresRealExploitSignal(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body: "System.Exception: unhandled\n   at Bit.Api.Controllers.FilesController.Read(String path)\n" +
			"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
	}
	got := f.triageCrash(res)
	if got["classification"] != "likely_vuln_high" {
		t.Fatalf("expected likely_vuln_high when a concrete file-read exploit signal is present, got %#v", got)
	}
	sigs, _ := got["exploitation_signals"].([]string)
	found := false
	for _, s := range sigs {
		if s == "file_read_success" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected file_read_success among exploitation_signals, got %v", sigs)
	}
}

func TestTriageCrashPreAuthDeserializationNeverRatedLikelyVulnEvenWithExploitSignal(t *testing.T) {
	// A crash purely in the JSON deserializer means no application code ever ran --
	// it proves instability, not unauthorized access to business logic. Even a
	// technically-matching exploit-signal body must not be rated likely_vuln* here.
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body: "Newtonsoft.Json.JsonSerializationException: JsonSerializerInternalReader failed\n" +
			"root:x:0:0:root:/root:/bin/bash",
	}
	got := f.triageCrash(res)
	if got["crash_layer"] != "deserialization" {
		t.Fatalf("expected crash_layer=deserialization, got %#v", got["crash_layer"])
	}
	cls, _ := got["classification"].(string)
	if strings.HasPrefix(cls, "likely_vuln") {
		t.Errorf("expected a pre-auth deserialization crash to never be rated likely_vuln*, got %q", cls)
	}
}

func TestExtendTrace_CapturesIdentityAtBuildTime(t *testing.T) {
	f := &Fuzzer{}
	item := WorkItem{Method: "GET", Path: "/widgets/1", Identity: "acme-admin"}
	trace := f.extendTrace(nil, item)
	if len(trace) != 1 {
		t.Fatalf("expected 1 trace step, got %d", len(trace))
	}
	if trace[0].Identity != "acme-admin" {
		t.Fatalf("expected the step's Identity to be captured at build time, got %q", trace[0].Identity)
	}
	if trace[0].Status != 0 {
		t.Fatalf("expected Status to be unset at build time (unknown until the response comes back), got %d", trace[0].Status)
	}
}

func TestExtendTrace_AppendsToExistingTraceInOrder(t *testing.T) {
	f := &Fuzzer{}
	step1 := f.extendTrace(nil, WorkItem{Method: "POST", Path: "/orgs", Identity: "acme-admin"})
	step2 := f.extendTrace(step1, WorkItem{Method: "POST", Path: "/orgs/{id}/projects", Identity: "acme-admin"})
	if len(step2) != 2 {
		t.Fatalf("expected 2 trace steps after extending once, got %d", len(step2))
	}
	if step2[0].Path != normalizePath("/orgs") || step2[1].Path != normalizePath("/orgs/{id}/projects") {
		t.Fatalf("expected trace steps in chronological order, got %+v", step2)
	}
}

func TestPatchTraceStatus_UpdatesLastStepInPlace(t *testing.T) {
	item := WorkItem{
		Method: "GET", Path: "/widgets/1", Identity: "acme-admin",
		Trace: []TraceStep{
			{Method: "POST", Path: "/orgs/acme/widgets", Identity: "acme-admin", Status: 201},
			{Method: "GET", Path: "/widgets/1", Identity: "acme-admin"},
		},
	}
	patchTraceStatus(item, 404)

	if item.Trace[1].Status != 404 {
		t.Fatalf("expected the LAST trace step's Status to be patched, got %d", item.Trace[1].Status)
	}
	if item.Trace[0].Status != 201 {
		t.Fatalf("expected an earlier step's already-known Status to be left untouched, got %d", item.Trace[0].Status)
	}
}

func TestPatchTraceStatus_EmptyTraceIsNoOp(t *testing.T) {
	item := WorkItem{Method: "GET", Path: "/x"}
	patchTraceStatus(item, 500) // must not panic
	if item.Trace != nil {
		t.Fatalf("expected patching an empty trace to remain a no-op, got %+v", item.Trace)
	}
}

func TestTriageCrashSeverityScoreNeverExceedsItsClassificationBand(t *testing.T) {
	// Regression guard for the documented floor-not-round rule: severity_score is
	// floor()'d so it never crosses into a band its own classification didn't earn.
	f := &Fuzzer{cfg: config.Config{CrashTriage: true}}
	res := SendResult{
		Status: 500,
		Body:   "System.Exception at somewhere\nTimeout waiting for the operation.\nUnrecognized Guid format",
	}
	got := f.triageCrash(res)
	scoreStr, _ := got["score"].(string)
	severity, _ := got["severity_score"].(int)
	var scoreFloat float64
	fmt.Sscanf(scoreStr, "%f", &scoreFloat)
	if float64(severity) > scoreFloat {
		t.Errorf("severity_score (%d) must never exceed the raw score (%v)", severity, scoreFloat)
	}
}

func TestIsRaceCandidatePath(t *testing.T) {
	for _, p := range []string{"/api/cart/checkout", "/api/coupons/redeem", "/api/orders/1/approve", "/api/payments/withdraw"} {
		if !isRaceCandidatePath(p) {
			t.Errorf("expected %q to be recognized as a race-candidate path", p)
		}
	}
	if isRaceCandidatePath("/api/widgets/1") {
		t.Error("expected a plain non-commerce/action path to not be a race candidate")
	}
}

func TestEnqueueRaceBurst_DisabledOrNonWriteIsNoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{RaceMode: false}}
	f.enqueueRaceBurst(WorkItem{Method: "POST", Path: "/api/cart/checkout"})
	if len(f.raceQueue) != 0 {
		t.Error("expected no burst enqueued when RaceMode is disabled")
	}

	f2 := &Fuzzer{cfg: config.Config{RaceMode: true, RaceProb: 1.0}}
	f2.enqueueRaceBurst(WorkItem{Method: "GET", Path: "/api/cart/checkout"})
	if len(f2.raceQueue) != 0 {
		t.Error("expected no burst enqueued for a non-write method")
	}
}

func TestEnqueueRaceBurst_NonCandidatePathIsNoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{RaceMode: true, RaceProb: 1.0, RaceBurst: 4}}
	f.enqueueRaceBurst(WorkItem{Method: "POST", Path: "/api/widgets"})
	if len(f.raceQueue) != 0 {
		t.Error("expected no burst enqueued for a non-race-candidate path")
	}
}

func TestEnqueueRaceBurst_EnqueuesNItemsWithSharedBurstID(t *testing.T) {
	f := &Fuzzer{
		cfg:       config.Config{RaceMode: true, RaceProb: 1.0, RaceBurst: 5},
		meta:      map[int]TemplateMeta{1: {Method: "POST", Norm: "/api/cart/checkout"}},
		eventLog:  make([]string, 0, 8),
		startTime: time.Now(),
	}
	source := WorkItem{TemplateID: 1, Method: "POST", Path: "/api/cart/checkout", MutationLabel: "seed"}
	f.enqueueRaceBurst(source)

	if len(f.raceQueue) != 5 {
		t.Fatalf("expected RaceBurst=5 items enqueued, got %d", len(f.raceQueue))
	}
	burstID := f.raceQueue[0].BurstID
	if burstID == "" {
		t.Fatal("expected a non-empty burst id")
	}
	for _, it := range f.raceQueue {
		if it.BurstID != burstID {
			t.Errorf("expected every item in the burst to share the same BurstID, got %q vs %q", it.BurstID, burstID)
		}
		if it.BurstSize != 5 {
			t.Errorf("expected BurstSize=5, got %d", it.BurstSize)
		}
		if it.MutationName != "race_conflict" {
			t.Errorf("expected MutationName=race_conflict, got %q", it.MutationName)
		}
	}
	if len(f.eventLog) == 0 {
		t.Error("expected a RACE enqueue event logged")
	}
}

func TestEnqueueRaceBurst_QueueIsRingBounded(t *testing.T) {
	f := &Fuzzer{
		cfg:       config.Config{RaceMode: true, RaceProb: 1.0, RaceBurst: 64},
		meta:      map[int]TemplateMeta{},
		eventLog:  make([]string, 0, 8),
		startTime: time.Now(),
		raceQueue: make([]WorkItem, 0, raceQueueMax),
	}
	for i := 0; i < raceQueueMax; i++ {
		f.raceQueue = append(f.raceQueue, WorkItem{})
	}
	f.enqueueRaceBurst(WorkItem{Method: "POST", Path: "/api/cart/checkout"})
	if len(f.raceQueue) > raceQueueMax {
		t.Errorf("expected the race queue to stay bounded at %d once already at capacity, got %d", raceQueueMax, len(f.raceQueue))
	}
}
