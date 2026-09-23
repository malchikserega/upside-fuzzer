package engine

import "testing"

func TestIsMultipartUpload(t *testing.T) {
	if !isMultipartUpload("multipart/form-data; boundary=----abc123") {
		t.Fatal("expected a multipart/form-data content type to be recognized")
	}
	if !isMultipartUpload("MULTIPART/FORM-DATA") {
		t.Fatal("expected case-insensitive matching")
	}
	if isMultipartUpload("application/json") {
		t.Fatal("expected application/json to NOT be recognized as multipart")
	}
	if isMultipartUpload("") {
		t.Fatal("expected an empty content type to NOT be recognized as multipart")
	}
}

func TestLooksLikeDownloadEndpoint(t *testing.T) {
	yes := []string{"/files/{param}/download", "/documents/{param}/content", "/reports/export", "/attachments/{param}"}
	for _, p := range yes {
		if !looksLikeDownloadEndpoint(p) {
			t.Errorf("expected %q to be recognized as a download-shaped endpoint", p)
		}
	}
	no := []string{"/users/{param}", "/orders", "/health"}
	for _, p := range no {
		if looksLikeDownloadEndpoint(p) {
			t.Errorf("expected %q to NOT be recognized as a download-shaped endpoint", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: recordResourceGraphStep tags source_multipart on a real upload
// ---------------------------------------------------------------------------

func TestRecordResourceGraphStep_MultipartUploadTagsSourceMultipart(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/files", ContentType: "multipart/form-data; boundary=x"}

	upload := WorkItem{Method: "POST", Path: "/files", TemplateID: 1}
	f.recordResourceGraphStep(upload, SendResult{
		Item: upload, Status: 201, Body: `{"id":"file-1","filename":"report.pdf"}`,
	}, "seq-1", "POST /files")

	inst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "file", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("file", "scalar", "file-1")})
	if inst == nil {
		t.Fatal("expected the uploaded file resource to be recorded")
	}
	fromMultipart, _ := inst.Attributes["source_multipart"].(bool)
	if !fromMultipart {
		t.Fatalf("expected source_multipart=true, got Attributes=%+v", inst.Attributes)
	}
}

func TestRecordResourceGraphStep_OrdinaryJSONCreateDoesNotTagMultipart(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/widgets", ContentType: "application/json"}

	create := WorkItem{Method: "POST", Path: "/widgets", TemplateID: 1}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1"}`}, "seq-1", "POST /widgets")

	inst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1")})
	if inst == nil {
		t.Fatal("expected the widget to be recorded")
	}
	if inst.Attributes != nil {
		if fromMultipart, _ := inst.Attributes["source_multipart"].(bool); fromMultipart {
			t.Fatal("expected an ordinary JSON create to NOT be tagged source_multipart")
		}
	}
}

func TestScoreConsumer_DownloadBonusForMultipartSourcedFile(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/files/{param}/download"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "file", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("file", "scalar", "file-1"), RawValue: "file-1"},
		"POST /files", "seq-1", LifecycleCreated, 0.9,
		RecordInstanceOpts{Attributes: map[string]any{"source_multipart": true}},
	)
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"POST /widgets", "seq-1", LifecycleCreated, 0.9,
	)
	f.resourceGraph.markConsumerReached(1)
	f.resourceGraph.markConsumerReached(2)

	downloadScore := f.scoreConsumer(1, "POST", "/files", "")
	ordinaryScore := f.scoreConsumer(2, "POST", "/widgets", "")
	if downloadScore <= ordinaryScore {
		t.Fatalf("expected the download candidate for a multipart-sourced file (score=%v) to outscore an ordinary resource (score=%v)", downloadScore, ordinaryScore)
	}
}

func TestScoreConsumer_NoDownloadBonusForNonMultipartFile(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/files/{param}/download"}
	// A "file" resource that did NOT come from a multipart upload.
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "file", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("file", "scalar", "file-1"), RawValue: "file-1"},
		"POST /files", "seq-1", LifecycleCreated, 0.9,
	)
	f.resourceGraph.markConsumerReached(1)

	withoutTag := f.scoreConsumer(1, "POST", "/files", "")

	f2 := newTestFuzzerForScheduling()
	f2.meta[1] = TemplateMeta{Method: "GET", Norm: "/files/{param}/download"}
	f2.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "file", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("file", "scalar", "file-1"), RawValue: "file-1"},
		"POST /files", "seq-1", LifecycleCreated, 0.9,
		RecordInstanceOpts{Attributes: map[string]any{"source_multipart": true}},
	)
	f2.resourceGraph.markConsumerReached(1)
	withTag := f2.scoreConsumer(1, "POST", "/files", "")

	if withTag <= withoutTag {
		t.Fatalf("expected the multipart-tagged instance (score=%v) to outscore the untagged one (score=%v)", withTag, withoutTag)
	}
}

func TestKnownTransitionActionVerbs_IncludesProcessScanConvert(t *testing.T) {
	for _, verb := range []string{"process", "scan", "convert", "transcode", "validate"} {
		if got := deriveTransitionAction("POST", "/files/1/"+verb); got != verb {
			t.Errorf("expected %q to be recognized as its own action verb, got %q", verb, got)
		}
	}
}
