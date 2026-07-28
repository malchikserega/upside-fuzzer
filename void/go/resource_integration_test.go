package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// resource_integration_test.go — an in-process fixture server modeling a small
// multi-style API (conventional ids, GUIDs, HAL links, a parent/child pair),
// proving end-to-end that real HTTP responses drive the resource graph
// correctly, and that the OLD extractEntityIDs pipeline is blind to the
// non-conventional shapes while the NEW pipeline is not.

func newMixedStyleFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Conventional: POST /orders -> 201 with bare "id" (the one shape the OLD
	// pipeline already handled).
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Location", "/orders/9001")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": "9001", "status": "pending"}`))
			return
		}
		http.NotFound(w, r)
	})

	// GUID-identified resource under a HAL body with a self link and a
	// customer relation -- the shape the OLD pipeline is provably blind to.
	mux.HandleFunc("/reservations/create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"_links": {
				"self": {"href": "/reservations/550e8400-e29b-41d4-a716-446655440000"},
				"customer": {"href": "/customers/456"}
			},
			"confirmed": true
		}`))
	})

	// Parent/child: /organizations/{orgId}/projects/{projectSlug}
	mux.HandleFunc("/organizations/acme/projects/create", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/organizations/acme/projects/demo-app")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"visibility": "public"}`))
	})

	// A deletable resource, for lifecycle-transition testing against a real
	// response (deleted -> a later GET against the same id returns 404).
	deleted := map[string]bool{}
	mux.HandleFunc("/widgets/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/widgets/"):]
		switch r.Method {
		case http.MethodDelete:
			deleted[id] = true
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if deleted[id] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": "` + id + `", "name": "gadget"}`))
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func doRequest(t *testing.T, method, url string) (int, string, map[string]string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return resp.StatusCode, string(body), headers
}

func TestIntegration_GUIDResourceViaHAL_OldBlindNewFinds(t *testing.T) {
	srv := newMixedStyleFixtureServer(t)
	status, body, _ := doRequest(t, "POST", srv.URL+"/reservations/create")
	if status != http.StatusCreated {
		t.Fatalf("expected 201 from fixture, got %d", status)
	}

	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected the OLD pipeline to find nothing in a real HAL response with no bare id/Id field, got %v", old)
	}

	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "POST /reservations/create")
	var gotReservation, gotCustomer bool
	for _, c := range candidates {
		if c.RawValue == "550e8400-e29b-41d4-a716-446655440000" {
			gotReservation = true
		}
		if c.RawValue == "456" {
			gotCustomer = true
		}
	}
	if !gotReservation {
		t.Fatalf("expected the NEW pipeline to extract the GUID reservation id from a real HAL response, got %+v", candidates)
	}
	if !gotCustomer {
		t.Fatalf("expected the NEW pipeline to also extract the HAL customer relation, got %+v", candidates)
	}
}

func TestIntegration_ParentChildRouteTemplateFromRealLocationHeader(t *testing.T) {
	srv := newMixedStyleFixtureServer(t)
	status, _, headers := doRequest(t, "POST", srv.URL+"/organizations/acme/projects/create")
	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", status)
	}

	f := newTestFuzzerForExtraction()
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/organizations/{param}/projects/{param}"}

	candidates := f.extractResourceCandidates("", headers, "POST /organizations/acme/projects")
	var gotOrg, gotProject bool
	for _, c := range candidates {
		if c.RawValue == "acme" && c.ResourceType == "organization" {
			gotOrg = true
		}
		if c.RawValue == "demo-app" && c.ResourceType == "project" {
			gotProject = true
		}
	}
	if !gotOrg || !gotProject {
		t.Fatalf("expected both organization and project typed candidates from a real Location header, got %+v", candidates)
	}
}

func TestIntegration_FullLifecycle_CreateReadDeleteReadAgainstRealServer(t *testing.T) {
	srv := newMixedStyleFixtureServer(t)
	f := newTestFuzzerForScheduling()
	// In a real run, buildTemplateMetaAndDependencies (fuzzer.go) registers
	// every active template's own route in f.meta/f.activeIDs at startup --
	// including the exact template a request was rendered from. That's what
	// lets matchRouteTemplateCandidates recognize the request's OWN path (not
	// just response-derived URIs). Registering it here mirrors that real
	// startup-time population rather than special-casing the test.
	f.activeIDs = []int{100}
	f.meta[100] = TemplateMeta{Method: "DELETE", Norm: "/widgets/{param}"}
	seqID := "seq-integration-1"

	// 1. Create (conventional bare id -- exercises the OLD extraction path
	//    staying intact, plus the NEW lifecycle recording).
	status, body, headers := doRequest(t, "POST", srv.URL+"/orders")
	novel := f.recordResourceGraphStepForTest("POST", "/orders", status, body, headers, seqID)
	if !novel {
		t.Fatal("expected the first-ever transition (UNKNOWN->CREATED) to be novel")
	}
	inst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "order", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("order", "scalar", "9001")})
	if inst == nil {
		t.Fatal("expected an order instance with id 9001 to be recorded")
	}
	if inst.Lifecycle != LifecycleCreated {
		t.Fatalf("expected lifecycle CREATED after POST 201, got %s", inst.Lifecycle)
	}

	// 2. Delete a *different* fixture resource (widgets) to drive a real
	//    create->delete->read-stale sequence against the server.
	_, _, _ = doRequest(t, "GET", srv.URL+"/widgets/w1") // seed nothing; widget "exists" implicitly (no create endpoint in fixture)
	statusDel, bodyDel, headersDel := doRequest(t, "DELETE", srv.URL+"/widgets/w1")
	f.recordResourceGraphStepForTest("DELETE", "/widgets/w1", statusDel, bodyDel, headersDel, seqID)
	widgetIdentity := ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "w1")}
	widgetInst := f.resourceGraph.getInstance(widgetIdentity)
	if widgetInst == nil || widgetInst.Lifecycle != LifecycleDeleted {
		t.Fatalf("expected widget w1 to be DELETED after a real DELETE request, got %+v", widgetInst)
	}

	// 3. Read it again against the REAL server -- fixture returns 404 for a
	//    deleted widget, so this must classify as "confirmed deletion", not a
	//    fresh unknown 404.
	statusGet, bodyGet, headersGet := doRequest(t, "GET", srv.URL+"/widgets/w1")
	if statusGet != http.StatusNotFound {
		t.Fatalf("expected the fixture to return 404 for a deleted widget, got %d", statusGet)
	}
	f.recordResourceGraphStepForTest("GET", "/widgets/w1", statusGet, bodyGet, headersGet, seqID)
	widgetInst = f.resourceGraph.getInstance(widgetIdentity)
	if widgetInst.Lifecycle != LifecycleDeleted {
		t.Fatalf("expected a 404 GET on an already-deleted widget to confirm DELETED (not regress to UNKNOWN), got %s", widgetInst.Lifecycle)
	}

	// Confirm findCompatibleResources can select it specifically as a
	// deliberately-stale resource for exploration (Phase 7's "select deleted
	// resource").
	staleCandidates := f.resourceGraph.findCompatibleResources("widget", LifecycleDeleted)
	if len(staleCandidates) != 1 || staleCandidates[0].Canonical.RawValue != "w1" {
		t.Fatalf("expected findCompatibleResources(widget, DELETED) to return w1, got %+v", staleCandidates)
	}
}

// recordResourceGraphStepForTest is a thin adapter so the integration test can
// drive recordResourceGraphStep with plain (method, path, status, body,
// headers) values from a real httptest response, without needing to
// construct a full WorkItem/SendResult pair (which requires far more Fuzzer
// machinery -- coverage readers, templates, workers -- than this test needs).
func (f *Fuzzer) recordResourceGraphStepForTest(method, path string, status int, body string, headers map[string]string, seqID string) bool {
	source := WorkItem{Method: method, Path: path}
	res := SendResult{Item: source, Status: status, Body: body, Headers: headers}
	provKey := method + " " + path
	return f.recordResourceGraphStep(source, res, seqID, provKey)
}
