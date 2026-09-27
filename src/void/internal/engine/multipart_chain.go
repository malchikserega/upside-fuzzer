package engine

import "strings"

// multipart_chain.go — multipart upload -> process -> download chain
// modeling (Phase 4 #122, docs/ARCHITECTURE_STATEFUL.md's
// "multipart/file -> scan/process -> download flows" security-scenario
// family). Builds on infrastructure that's already mostly generic enough: a
// multipart upload's response gets picked up by the ordinary extraction
// pipeline (resource_extraction.go) like any other create, and the
// async-operation model (async.go) already biases polling if the upload
// responds 202/Retry-After (the "scan/process" step, when it's async). What
// was missing is a way to bias the planner toward actually COMPLETING the
// upload -> [process] -> download chain once an upload has happened,
// instead of treating the uploaded file like any other equally-weighted
// resource -- named filenames prefixed "multipart_chain" (not "multipart",
// which collides with grammarc's own unrelated Python module of the same
// name and would be a confusing cross-reference in this repo's docs).

// isMultipartUpload reports whether a template's own declared content type
// (TemplateMeta.ContentType, fuzzer.go's canonicalContentType) is
// multipart -- the signal that a resource just created belongs to this
// chain shape.
func isMultipartUpload(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "multipart")
}

// downloadCandidateKeywords are path-segment keywords identifying a
// download/export/fetch-content-shaped endpoint.
var downloadCandidateKeywords = []string{"download", "content", "export", "attachment", "file"}

// looksLikeDownloadEndpoint reports whether norm (a normalized endpoint
// path) is download/export-shaped -- used to bias the planner toward
// completing an upload->download chain once a multipart-sourced resource is
// known.
func looksLikeDownloadEndpoint(norm string) bool {
	low := strings.ToLower(norm)
	for _, kw := range downloadCandidateKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// multipartDownloadBonus, applied by scoreConsumer (resource_scheduling.go),
// biases a download-shaped GET candidate toward a resource known to have
// come from a multipart upload -- completing the upload->[process]->download
// chain rather than treating the file like an equally-weighted ordinary
// resource. Comparable in weight to the async poll bonus, the closest
// analog (both exist to keep a specific multi-step chain shape from being
// crowded out by unrelated endpoints).
const multipartDownloadBonus = 10.0
