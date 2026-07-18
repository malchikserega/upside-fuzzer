package main

import "testing"

const guidErrBody = `{"message":"An unhandled server error has occurred.","validationErrors":null,` +
	`"exceptionMessage":"Unrecognized Guid format.","exceptionStackTrace":"   at System.Guid.Parse(String s)\n   at Bit.Api.Controllers.CiphersController.Delete(String id)"}`

const guidErrBody2 = `{"message":"An unhandled server error has occurred.",` +
	`"exceptionMessage":"Unrecognized Guid format.","exceptionStackTrace":"   at System.Guid.Parse(String s)\n   at Bit.Api.Controllers.CiphersController.Delete(String id)"}`

const nreBody = `{"message":"An unhandled server error has occurred.",` +
	`"exceptionMessage":"Object reference not set to an instance of an object.",` +
	`"exceptionStackTrace":"   at Bit.Api.Vault.Controllers.AttachmentsController.Share(Guid id)"}`

// Same root cause (GUID parse) reached from two different routes + payloads must
// collapse into ONE cluster.
func TestRootCauseClusterCollapsesVariants(t *testing.T) {
	k1, _, ex1 := rootCauseClusterKey("DELETE", 500, "", "", guidErrBody, "/ciphers/{id}")
	k2, _, ex2 := rootCauseClusterKey("GET", 500, "", "", guidErrBody2, "/organizations/{id}/users")
	if !ex1 || !ex2 {
		t.Fatalf("expected exception detail on both, got %v %v", ex1, ex2)
	}
	if k1 != k2 {
		t.Errorf("same GUID-parse bug produced different cluster keys: %s vs %s", k1, k2)
	}
}

// Distinct exceptions must NOT collapse.
func TestRootCauseClusterSeparatesDistinctBugs(t *testing.T) {
	kGuid, _, _ := rootCauseClusterKey("DELETE", 500, "", "", guidErrBody, "/ciphers/{id}")
	kNre, _, _ := rootCauseClusterKey("POST", 500, "", "", nreBody, "/ciphers/{id}/attachment")
	if kGuid == kNre {
		t.Errorf("GUID-parse and NullReference collapsed into the same cluster (%s)", kGuid)
	}
}

// With no exception detail we fall back to endpoint template: same template +
// different payload = one cluster; different template = different cluster.
func TestRootCauseClusterFallbackByEndpoint(t *testing.T) {
	kA, _, hasEx := rootCauseClusterKey("GET", 500, "", "", "", "/organizations/{id}/policies")
	kB, _, _ := rootCauseClusterKey("GET", 500, "", "", "", "/organizations/{id}/policies")
	kC, _, _ := rootCauseClusterKey("GET", 500, "", "", "", "/secrets/{id}/trash")
	if hasEx {
		t.Errorf("empty body should report no exception detail")
	}
	if kA != kB {
		t.Errorf("same endpoint template should share a cluster key")
	}
	if kA == kC {
		t.Errorf("different endpoint templates should not share a cluster key")
	}
}

// The same route must map to one cluster whether the fuzzer injected a uuid,
// an int, or a business-id into the parameter segments.
func TestRootCauseClusterCoarsensParamTypes(t *testing.T) {
	kUUID, _, _ := rootCauseClusterKey("PUT", 500, "", "", "", "/organizations/{uuid}/users/{uuid}/confirm")
	kMixed, _, _ := rootCauseClusterKey("PUT", 500, "", "", "", "/organizations/{param}/users/{id}/confirm")
	kInt, _, _ := rootCauseClusterKey("PUT", 500, "", "", "", "/organizations/{int}/users/{hex}/confirm")
	if kUUID != kMixed || kUUID != kInt {
		t.Errorf("same route with different injected param types split into separate clusters: %s %s %s", kUUID, kMixed, kInt)
	}
}

func TestNormalizeExceptionMessageStripsPayloadTokens(t *testing.T) {
	a := normalizeExceptionMessage("Cannot insert duplicate key row in object 'dbo.Device' with index 12345")
	b := normalizeExceptionMessage("Cannot insert duplicate key row in object 'dbo.Cipher' with index 99")
	if a != b {
		t.Errorf("quoted identifiers/numbers should be normalized away:\n  %q\n  %q", a, b)
	}
}

func TestExtractTopAppFrameSkipsFramework(t *testing.T) {
	frame := extractTopAppFrame(guidErrBody)
	if frame != "Bit.Api.Controllers.CiphersController.Delete" {
		t.Errorf("expected the Bit.Api application frame, got %q", frame)
	}
}

func TestExploitationSignalsSQLi(t *testing.T) {
	res := SendResult{
		Item: WorkItem{Method: "GET", Path: "/products?id=1'", Body: ""},
		Body: `{"exceptionMessage":"You have an error in your SQL syntax near '1'"}`,
	}
	sigs := exploitationSignals(res)
	if len(sigs) == 0 || sigs[0] != "sqli_error_reflected" {
		t.Errorf("expected sqli_error_reflected, got %v", sigs)
	}
}

func TestExploitationSignalsNoneForPlain500(t *testing.T) {
	res := SendResult{
		Item: WorkItem{Method: "DELETE", Path: "/ciphers/admin", Body: ""},
		Body: nreBody,
	}
	if sigs := exploitationSignals(res); len(sigs) != 0 {
		t.Errorf("plain unhandled exception should yield no exploitation signal, got %v", sigs)
	}
}

func TestExploitationSignalsFileRead(t *testing.T) {
	res := SendResult{
		Item: WorkItem{Method: "GET", Path: "/download?f=../../../etc/passwd"},
		Body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
	}
	sigs := exploitationSignals(res)
	found := false
	for _, s := range sigs {
		if s == "file_read_success" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected file_read_success, got %v", sigs)
	}
}
