package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// manifest.go — Run manifest (Phase 5 #127, docs/ARCHITECTURE_STATEFUL.md §2.7):
// the reproducibility-facing metadata surfaced once per run in the JSON bug
// report (report.go) and SARIF output (sarif.go), rather than embedded per-finding.
// Deliberately split into two provenance tiers:
//   - locally verifiable: templates_sha256, computed here from the exact file
//     bytes this run actually loaded (sha256FileHash, called from NewFuzzer).
//   - pass-through only: target_image_digest / openapi_spec_hash / campaign_config
//     (Config fields) are labels supplied by the orchestrating pipeline
//     (campaign.py / fuzz-prep) -- void has no way to independently verify a
//     running container's digest or the document a grammar was generated from,
//     and the manifest does not pretend otherwise.

// sha256FileHash returns the lowercase hex SHA-256 of path's contents, or ""
// if the file can't be read (e.g. -templates-json pointed somewhere unusual,
// or refresh-templates regenerated it between load and hash -- never fatal,
// since this is provenance metadata, not something the run depends on).
func sha256FileHash(path string) string {
	buf, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// buildRunManifest assembles the reproducibility manifest: everything needed
// to describe *what ran*, independent of any single finding -- run identity,
// target, the grammar/templates this run actually consumed (with a verifiable
// hash), and whatever upstream provenance the caller chose to pass through.
func (f *Fuzzer) buildRunManifest() map[string]any {
	return map[string]any{
		"run_id":              f.cfg.RunID,
		"seed":                f.cfg.Seed,
		"profile":             f.cfg.Profile,
		"target_host":         f.target,
		"grammar_dir":         f.cfg.GrammarDir,
		"templates_json":      f.templatesPath,
		"templates_sha256":    f.templatesHash,
		"target_image_digest": f.cfg.TargetImageDigest,
		"openapi_spec_hash":   f.cfg.OpenAPISpecHash,
		"campaign_config":     f.cfg.CampaignConfig,
		"started_at":          f.startTime.Format(time.RFC3339),
		"generated_at":        time.Now().Format(time.RFC3339),
	}
}
