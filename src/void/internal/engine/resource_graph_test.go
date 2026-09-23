package engine

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestLifecycleState_JSONRoundTrip(t *testing.T) {
	all := []LifecycleState{
		LifecycleUnknown, LifecycleDiscovered, LifecycleCreated, LifecycleReadable,
		LifecycleModified, LifecycleDeleted, LifecycleInvalidated, LifecycleFailedCreation,
		LifecycleFailedModification, LifecycleFailedDeletion, LifecycleStale,
	}
	for _, s := range all {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", s, err)
		}
		var got LifecycleState
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal(%s) failed round-tripping through %s: %v", s, data, err)
		}
		if got != s {
			t.Fatalf("round-trip mismatch: %s -> %s -> %s", s, data, got)
		}
	}
}

func TestLifecycleState_UnmarshalUnknownNameDegradesGracefully(t *testing.T) {
	var got LifecycleState
	if err := json.Unmarshal([]byte(`"SOME_FUTURE_STATE_THIS_BUILD_DOESNT_KNOW"`), &got); err != nil {
		t.Fatalf("expected an unrecognized name to decode without error, got %v", err)
	}
	if got != LifecycleUnknown {
		t.Fatalf("expected an unrecognized name to degrade to LifecycleUnknown, got %s", got)
	}
}

func userIdentity(raw string) ResourceIdentity {
	return ResourceIdentity{
		ResourceType:    "user",
		IdentityKind:    "scalar",
		NormalizedValue: normalizeResourceValue("user", "scalar", raw),
		RawValue:        raw,
		SourcePath:      "$.id",
		Confidence:      0.8,
	}
}

func orderIdentity(raw string) ResourceIdentity {
	return ResourceIdentity{
		ResourceType:    "order",
		IdentityKind:    "scalar",
		NormalizedValue: normalizeResourceValue("order", "scalar", raw),
		RawValue:        raw,
		SourcePath:      "$.id",
		Confidence:      0.8,
	}
}

func TestResourceGraph_TypedIdentityIsolation(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	g.recordInstance(userIdentity("1"), "GET /users/1", "seq-1", LifecycleReadable, 0.8)
	g.recordInstance(orderIdentity("1"), "GET /orders/1", "seq-1", LifecycleReadable, 0.8)

	if g.instanceCount() != 2 {
		t.Fatalf("expected user id=1 and order id=1 to be two DISTINCT instances (typed identity), got %d instance(s)", g.instanceCount())
	}
	userInst := g.getInstance(userIdentity("1"))
	orderInst := g.getInstance(orderIdentity("1"))
	if userInst == nil || orderInst == nil {
		t.Fatal("expected both typed instances to be independently retrievable")
	}
	if userInst.ResourceType != "user" || orderInst.ResourceType != "order" {
		t.Fatalf("resource type isolation broken: user=%s order=%s", userInst.ResourceType, orderInst.ResourceType)
	}
}

func TestResourceGraph_RecordInstanceUpsertsAndTracksObservedCount(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	id := userIdentity("42")
	g.recordInstance(id, "POST /users", "seq-1", LifecycleCreated, 0.9)
	inst := g.recordInstance(id, "GET /users/42", "seq-1", LifecycleReadable, 0.6)

	if inst.ObservedCount != 2 {
		t.Fatalf("expected ObservedCount=2 after two recordInstance calls for the same identity, got %d", inst.ObservedCount)
	}
	if inst.Lifecycle != LifecycleReadable {
		t.Fatalf("expected lifecycle to update to the latest recorded state (READABLE), got %s", inst.Lifecycle)
	}
	if inst.Confidence != 0.9 {
		t.Fatalf("expected confidence to keep the highest-seen value (0.9), got %v", inst.Confidence)
	}
	if g.instanceCount() != 1 {
		t.Fatalf("expected exactly one instance after upserting the same identity twice, got %d", g.instanceCount())
	}
}

func TestResourceGraph_AliasTracking(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	primary := userIdentity("42")
	g.recordInstance(primary, "POST /users", "seq-1", LifecycleCreated, 0.9)

	alias := ResourceIdentity{
		ResourceType: "user", IdentityKind: "uri",
		NormalizedValue: normalizeResourceValue("user", "uri", "/users/42"),
		RawValue:        "/users/42", SourcePath: "Location", Confidence: 0.85,
	}
	g.recordAlias(primary, alias)

	inst := g.getInstance(primary)
	if len(inst.Aliases) != 1 {
		t.Fatalf("expected 1 alias recorded, got %d", len(inst.Aliases))
	}
	if inst.Aliases[0].IdentityKind != "uri" {
		t.Fatalf("expected the alias to keep its own identity kind (uri), got %s", inst.Aliases[0].IdentityKind)
	}

	// Recording the same alias again must not duplicate it.
	g.recordAlias(primary, alias)
	if len(inst.Aliases) != 1 {
		t.Fatalf("expected recording the same alias twice to stay deduped at 1, got %d", len(inst.Aliases))
	}
}

func TestResourceGraph_AliasIsNoOpForUnknownPrimary(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	g.recordAlias(userIdentity("does-not-exist"), userIdentity("also-does-not-exist"))
	if g.instanceCount() != 0 {
		t.Fatalf("recordAlias for an unknown primary must not create an instance, got count=%d", g.instanceCount())
	}
}

func TestResourceGraph_MaxAliasesPerInstanceEnforced(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{MaxAliasesPerInstance: 2})
	primary := userIdentity("1")
	g.recordInstance(primary, "POST /users", "seq-1", LifecycleCreated, 0.9)
	for i := 0; i < 5; i++ {
		g.recordAlias(primary, ResourceIdentity{
			ResourceType: "user", IdentityKind: "uri",
			NormalizedValue: normalizeResourceValue("user", "uri", "alias-"+string(rune('a'+i))),
			RawValue:        "alias-" + string(rune('a'+i)),
		})
	}
	inst := g.getInstance(primary)
	if len(inst.Aliases) > 2 {
		t.Fatalf("expected alias count bounded at 2, got %d", len(inst.Aliases))
	}
}

func TestResourceGraph_MaxInstancesPerTypeEvictsOldest(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{MaxInstancesPerType: 3})
	for i := 0; i < 3; i++ {
		g.recordInstance(userIdentity(string(rune('a'+i))), "POST /users", "seq-1", LifecycleCreated, 0.5)
	}
	if g.instanceCount() != 3 {
		t.Fatalf("expected 3 instances before eviction pressure, got %d", g.instanceCount())
	}
	// A 4th distinct instance of the same type must evict the oldest (lowest
	// LastSeenOrder), not silently exceed the cap.
	g.recordInstance(userIdentity("d"), "POST /users", "seq-1", LifecycleCreated, 0.5)
	if g.instanceCount() != 3 {
		t.Fatalf("expected instance count to stay bounded at 3 after inserting a 4th, got %d", g.instanceCount())
	}
	if g.getInstance(userIdentity("a")) != nil {
		t.Fatal("expected the oldest instance (a) to have been evicted")
	}
	if g.getInstance(userIdentity("d")) == nil {
		t.Fatal("expected the newly-inserted instance (d) to be present")
	}
}

func TestResourceGraph_MaxTransitionsRingBounded(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{MaxTransitions: 5})
	for i := 0; i < 20; i++ {
		g.recordTransition(ResourceTransition{
			From: LifecycleUnknown, To: LifecycleCreated,
			ConsumerOp: "POST /users", SequenceID: "seq-1", Result: "valid",
		})
	}
	if len(g.transitions) > 5 {
		t.Fatalf("expected transitions ring-bounded at 5, got %d", len(g.transitions))
	}
}

func TestResourceGraph_TransitionNoveltyDetection(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	t1 := ResourceTransition{From: LifecycleUnknown, To: LifecycleCreated, ConsumerOp: "POST /users", Result: "valid"}
	if novel := g.recordTransition(t1); !novel {
		t.Fatal("expected the first-ever transition signature to be reported as novel")
	}
	if novel := g.recordTransition(t1); novel {
		t.Fatal("expected an identical transition signature to NOT be reported as novel the second time")
	}
	t2 := ResourceTransition{From: LifecycleCreated, To: LifecycleDeleted, ConsumerOp: "DELETE /users/{id}", Result: "valid"}
	if novel := g.recordTransition(t2); !novel {
		t.Fatal("expected a genuinely different (from,to,consumerOp) transition to be reported as novel")
	}
}

func TestResourceGraph_FindCompatibleResourcesFiltersByLifecycle(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	g.recordInstance(userIdentity("1"), "POST /users", "seq-1", LifecycleCreated, 0.9)
	g.recordInstance(userIdentity("2"), "POST /users", "seq-1", LifecycleCreated, 0.9)
	g.recordInstance(userIdentity("2"), "DELETE /users/2", "seq-1", LifecycleDeleted, 0.9)

	created := g.findCompatibleResources("user", LifecycleCreated)
	if len(created) != 1 || created[0].Canonical.RawValue != "1" {
		t.Fatalf("expected exactly instance '1' in CREATED state, got %+v", created)
	}
	deleted := g.findCompatibleResources("user", LifecycleDeleted)
	if len(deleted) != 1 || deleted[0].Canonical.RawValue != "2" {
		t.Fatalf("expected exactly instance '2' in DELETED state, got %+v", deleted)
	}
	all := g.findCompatibleResources("user")
	if len(all) != 2 {
		t.Fatalf("expected findCompatibleResources with no state filter to return both instances, got %d", len(all))
	}
}

func TestResourceGraph_ConsumerReachedAndFailureTracking(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	if g.consumerReachedCount(7) != 0 {
		t.Fatal("expected an unreached consumer to report 0")
	}
	g.markConsumerReached(7)
	g.markConsumerReached(7)
	if got := g.consumerReachedCount(7); got != 2 {
		t.Fatalf("expected reached count 2, got %d", got)
	}

	g.markConsumerResult(7, true)
	g.markConsumerResult(7, true)
	if got := g.consumerFailureCount(7); got != 2 {
		t.Fatalf("expected failure count 2 after two failures, got %d", got)
	}
	g.markConsumerResult(7, false)
	if got := g.consumerFailureCount(7); got != 1 {
		t.Fatalf("expected a success to decrement the failure count to 1, got %d", got)
	}
}

func TestResourceGraph_SnapshotForSequenceFiltersBySequenceID(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	g.recordInstance(userIdentity("1"), "POST /users", "seq-A", LifecycleCreated, 0.9)
	g.recordInstance(userIdentity("2"), "POST /users", "seq-B", LifecycleCreated, 0.9)
	g.recordTransition(ResourceTransition{From: LifecycleUnknown, To: LifecycleCreated, ConsumerOp: "POST /users", SequenceID: "seq-A", Result: "valid"})
	g.recordTransition(ResourceTransition{From: LifecycleUnknown, To: LifecycleCreated, ConsumerOp: "POST /users", SequenceID: "seq-B", Result: "valid"})

	instances, transitions := g.snapshotForSequence("seq-A")
	if len(instances) != 1 || instances[0].Canonical.RawValue != "1" {
		t.Fatalf("expected snapshot for seq-A to contain only instance '1', got %+v", instances)
	}
	if len(transitions) != 1 || transitions[0].SequenceID != "seq-A" {
		t.Fatalf("expected snapshot for seq-A to contain only its own transition, got %+v", transitions)
	}
}

func TestResourceGraph_LifecycleStateJSONIsReadableNotNumeric(t *testing.T) {
	b, err := LifecycleDeleted.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(b) != `"DELETED"` {
		t.Fatalf(`expected lifecycle state to marshal as "DELETED" (human-readable), got %s`, string(b))
	}
}

// TestResourceGraph_ConcurrentAccessDoesNotRace is an adversarial test: in
// normal operation the graph is only ever mutated from the single main-loop
// goroutine (see resource_graph.go's ownership comment), but the mutex is
// present defensively. This proves that guarantee actually holds under
// concurrent access, run with `go test -race`.
func TestResourceGraph_ConcurrentAccessDoesNotRace(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{MaxInstancesPerType: 50})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := userIdentity(string(rune('a' + (i+worker)%26)))
				g.recordInstance(id, "POST /users", "seq-x", LifecycleCreated, 0.5)
				g.recordAlias(id, ResourceIdentity{ResourceType: "user", IdentityKind: "uri", NormalizedValue: "u", RawValue: "u"})
				g.recordTransition(ResourceTransition{From: LifecycleUnknown, To: LifecycleCreated, ConsumerOp: "POST /users", SequenceID: "seq-x"})
				g.findCompatibleResources("user")
				g.markConsumerReached(worker)
				g.markConsumerResult(worker, i%2 == 0)
				_ = g.instanceCount()
			}
		}(w)
	}
	wg.Wait()
}

func TestResourceGraph_RecordInstanceOptsOwnerVersionAttributes(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	id := userIdentity("42")
	inst := g.recordInstance(id, "POST /users", "seq-1", LifecycleCreated, 0.9, RecordInstanceOpts{
		OwnerIdentity: "tenant-a-admin",
		Version:       `"etag-1"`,
		Attributes:    map[string]any{"status": "draft"},
	})
	if inst.OwnerIdentity != "tenant-a-admin" {
		t.Fatalf("expected OwnerIdentity=tenant-a-admin, got %q", inst.OwnerIdentity)
	}
	if inst.Version != `"etag-1"` {
		t.Fatalf("expected Version to be set from opts, got %q", inst.Version)
	}
	if inst.Attributes["status"] != "draft" {
		t.Fatalf("expected Attributes[status]=draft, got %v", inst.Attributes)
	}
}

func TestResourceGraph_OwnerIdentityFirstWriterWins(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	id := userIdentity("42")
	g.recordInstance(id, "POST /users", "seq-1", LifecycleCreated, 0.9, RecordInstanceOpts{OwnerIdentity: "tenant-a-admin"})
	// A later re-observation by a DIFFERENT identity (e.g. cross-tenant probe
	// traffic reading the same resource) must never relabel who created it.
	inst := g.recordInstance(id, "GET /users/42", "seq-1", LifecycleReadable, 0.6, RecordInstanceOpts{OwnerIdentity: "tenant-b-attacker"})
	if inst.OwnerIdentity != "tenant-a-admin" {
		t.Fatalf("expected OwnerIdentity to stay first-writer-wins (tenant-a-admin), got %q", inst.OwnerIdentity)
	}
}

func TestResourceGraph_VersionAndAttributesRefreshOnReobservation(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	id := userIdentity("42")
	g.recordInstance(id, "POST /users", "seq-1", LifecycleCreated, 0.9, RecordInstanceOpts{
		Version: `"etag-1"`, Attributes: map[string]any{"status": "draft"},
	})
	inst := g.recordInstance(id, "PUT /users/42", "seq-1", LifecycleModified, 0.9, RecordInstanceOpts{
		Version: `"etag-2"`, Attributes: map[string]any{"status": "published"},
	})
	if inst.Version != `"etag-2"` {
		t.Fatalf("expected Version to refresh to etag-2, got %q", inst.Version)
	}
	if inst.Attributes["status"] != "published" {
		t.Fatalf("expected Attributes to refresh to published, got %v", inst.Attributes)
	}
}

func TestResourceGraph_ResolveTenantKeyWalksMultiLevelParentChain(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	orgID := ResourceIdentity{ResourceType: "organization", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("organization", "scalar", "org-7"), RawValue: "org-7"}
	wsID := ResourceIdentity{ResourceType: "workspace", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("workspace", "scalar", "ws-9"), RawValue: "ws-9"}
	prjID := ResourceIdentity{ResourceType: "project", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("project", "scalar", "prj-42"), RawValue: "prj-42"}

	g.recordInstance(orgID, "POST /organizations", "seq-1", LifecycleCreated, 0.9)
	ws := g.recordInstance(wsID, "POST /organizations/org-7/workspaces", "seq-1", LifecycleCreated, 0.9)
	ws.ParentKey = orgID.graphKey()
	g.resolveTenantKey(ws)

	prj := g.recordInstance(prjID, "POST /organizations/org-7/workspaces/ws-9/projects", "seq-1", LifecycleCreated, 0.9)
	prj.ParentKey = wsID.graphKey()
	g.resolveTenantKey(prj)

	if prj.TenantKey != orgID.graphKey() {
		t.Fatalf("expected project's TenantKey to resolve to the root organization (%s), got %q", orgID.graphKey(), prj.TenantKey)
	}
	if ws.TenantKey != orgID.graphKey() {
		t.Fatalf("expected workspace's TenantKey to resolve to the root organization (%s), got %q", orgID.graphKey(), ws.TenantKey)
	}
}

func TestResourceGraph_ResolveTenantKeyNoOpWithoutParent(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	inst := g.recordInstance(userIdentity("1"), "POST /users", "seq-1", LifecycleCreated, 0.9)
	g.resolveTenantKey(inst)
	if inst.TenantKey != "" {
		t.Fatalf("expected TenantKey to stay empty with no ParentKey set, got %q", inst.TenantKey)
	}
}

// projectInTenant records a project instance parented under orgRaw, resolving
// its TenantKey to that organization -- shared setup for the tenant-filtering
// tests below.
func projectInTenant(g *ResourceGraph, orgRaw, projectRaw string) (org, prj *ResourceInstance) {
	orgID := ResourceIdentity{ResourceType: "organization", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("organization", "scalar", orgRaw), RawValue: orgRaw}
	prjID := ResourceIdentity{ResourceType: "project", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("project", "scalar", projectRaw), RawValue: projectRaw}
	org = g.recordInstance(orgID, "POST /organizations", "seq-1", LifecycleCreated, 0.9)
	prj = g.recordInstance(prjID, "POST /organizations/"+orgRaw+"/projects", "seq-1", LifecycleCreated, 0.9)
	prj.ParentKey = orgID.graphKey()
	g.resolveTenantKey(prj)
	return org, prj
}

func TestResourceGraph_FindCompatibleResourcesInTenant_FiltersToMatchingTenant(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	orgA, prjA := projectInTenant(g, "org-a", "prj-a")
	_, prjB := projectInTenant(g, "org-b", "prj-b")

	got := g.findCompatibleResourcesInTenant("project", orgA.Canonical.graphKey())
	if len(got) != 1 || got[0].Canonical.RawValue != prjA.Canonical.RawValue {
		t.Fatalf("expected only org-a's project (%s), got %+v", prjA.Canonical.RawValue, got)
	}
	for _, inst := range got {
		if inst.Canonical.RawValue == prjB.Canonical.RawValue {
			t.Fatal("expected org-b's project to be excluded from an org-a tenant-scoped query")
		}
	}
}

func TestResourceGraph_FindCompatibleResourcesInTenant_EmptyTenantKeyNoRestriction(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	projectInTenant(g, "org-a", "prj-a")
	projectInTenant(g, "org-b", "prj-b")

	got := g.findCompatibleResourcesInTenant("project", "")
	if len(got) != 2 {
		t.Fatalf("expected an empty tenantKey to apply no restriction (both projects), got %d", len(got))
	}
}

func TestResourceGraph_FindCompatibleResourcesInTenant_TenantRootItselfMatches(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	orgA, _ := projectInTenant(g, "org-a", "prj-a")

	// A query for the tenant's OWN resource type (organization), scoped to its
	// own graph key, must return the organization itself -- its TenantKey
	// field is empty (it has no parent), so this must be matched via the
	// graph-key-equals-tenantKey branch, not TenantKey equality.
	got := g.findCompatibleResourcesInTenant("organization", orgA.Canonical.graphKey())
	if len(got) != 1 || got[0].Canonical.RawValue != "org-a" {
		t.Fatalf("expected the tenant root organization itself to match its own tenant scope, got %+v", got)
	}
}
