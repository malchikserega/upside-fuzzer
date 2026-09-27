package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"void/internal/config"
)

func TestSha256FileHashIsStableForSameContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "templates.export.json")
	if err := os.WriteFile(path, []byte(`{"templates":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	h1 := sha256FileHash(path)
	h2 := sha256FileHash(path)
	if h1 == "" {
		t.Fatal("expected a non-empty hash for an existing file")
	}
	if h1 != h2 {
		t.Errorf("expected the same file to hash identically, got %q vs %q", h1, h2)
	}
}

func TestSha256FileHashDiffersOnContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "templates.export.json")
	_ = os.WriteFile(path, []byte(`{"templates":[]}`), 0o644)
	h1 := sha256FileHash(path)
	_ = os.WriteFile(path, []byte(`{"templates":[{"id":1}]}`), 0o644)
	h2 := sha256FileHash(path)
	if h1 == h2 {
		t.Error("expected the hash to change when file content changes")
	}
}

func TestSha256FileHashMissingFileReturnsEmpty(t *testing.T) {
	if got := sha256FileHash("/nonexistent/path/templates.export.json"); got != "" {
		t.Errorf("expected empty string for a missing file, got %q", got)
	}
}

func TestBuildRunManifestCarriesLocalAndPassThroughProvenance(t *testing.T) {
	f := &Fuzzer{
		cfg: config.Config{
			RunID:             "run-42",
			Seed:              1337,
			Profile:           "security",
			GrammarDir:        "/grammar",
			TargetImageDigest: "sha256:abc123",
			OpenAPISpecHash:   "sha256:def456",
			CampaignConfig:    "campaign.yaml",
		},
		target:        "http://localhost:5200",
		templatesPath: "/grammar/templates.export.json",
		templatesHash: "deadbeef",
		startTime:     time.Now(),
	}

	m := f.buildRunManifest()

	want := map[string]any{
		"run_id":              "run-42",
		"seed":                int64(1337),
		"profile":             "security",
		"target_host":         "http://localhost:5200",
		"grammar_dir":         "/grammar",
		"templates_json":      "/grammar/templates.export.json",
		"templates_sha256":    "deadbeef",
		"target_image_digest": "sha256:abc123",
		"openapi_spec_hash":   "sha256:def456",
		"campaign_config":     "campaign.yaml",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("manifest[%q] = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["started_at"]; !ok {
		t.Error("expected started_at to be present")
	}
	if _, ok := m["generated_at"]; !ok {
		t.Error("expected generated_at to be present")
	}
}

func TestBuildRunManifestEmptyPassThroughFieldsStayEmpty(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{}, startTime: time.Now()}
	m := f.buildRunManifest()
	for _, k := range []string{"target_image_digest", "openapi_spec_hash", "campaign_config", "templates_sha256"} {
		if m[k] != "" {
			t.Errorf("expected manifest[%q] to default to empty string when unset, got %v", k, m[k])
		}
	}
}
