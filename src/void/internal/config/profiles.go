package config

import (
	"fmt"
	"os"
	"strings"
)

// ApplyProfile fills in a curated set of knobs for the named preset, but only
// for flags the user did not explicitly pass (tracked via flag.Visit in
// ParseFlags). This keeps the full 90-flag surface available while giving
// newcomers three good starting points. Exported (moved here from
// void/go/main.go's unexported applyProfile) since callers now live in a
// different package (cmd/void, and internal/engine's own tests that exercise
// profile behavior).
func ApplyProfile(cfg *Config, set map[string]bool) {
	p := strings.ToLower(strings.TrimSpace(cfg.Profile))
	if p == "" {
		return
	}
	setB := func(name string, target *bool, v bool) {
		if !set[name] {
			*target = v
		}
	}
	setF := func(name string, target *float64, v float64) {
		if !set[name] {
			*target = v
		}
	}
	setI := func(name string, target *int, v int) {
		if !set[name] {
			*target = v
		}
	}
	switch p {
	case "fast":
		// Maximize throughput (CI smoke): skip expensive per-crash work and oracles.
		setI("repro-runs", &cfg.ReproRuns, 0)
		setB("minimize-crash", &cfg.MinimizeCrash, false)
		setB("minimize-chain", &cfg.MinimizeChain, false)
		setB("access-probe", &cfg.AccessProbe, false)
		setB("probe-bola", &cfg.ProbeBOLA, false)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, false)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, false)
		setB("probe-differential", &cfg.ProbeDifferential, false)
		setB("probe-stale-object", &cfg.ProbeStaleObject, false)
		setB("probe-stale-etag", &cfg.ProbeStaleETag, false)
		setB("probe-workflow-bypass", &cfg.ProbeWorkflowBypass, false)
		setB("probe-idempotency", &cfg.ProbeIdempotency, false)
		setB("injection-oracle", &cfg.InjectionOracle, false)
		setB("schema-conformance", &cfg.SchemaConformance, false)
		setB("race-mode", &cfg.RaceMode, false)
		setF("sequence-prob", &cfg.SequenceProb, 0.10)
		// Typed structural mutation measurably costs throughput (real-target A/B:
		// ~35% fewer requests/sec, since schema-correct bodies clear validation
		// and reach real business logic instead of failing fast on malformed
		// JSON the way the legacy flat mutator's output usually does) in exchange
		// for deeper coverage and a much cleaner crash signal -- exactly the
		// wrong trade for a throughput-first CI smoke profile.
		setB("typed-body-mutation", &cfg.TypedBodyMutation, false)
	case "deep":
		// Balanced thorough scan: full crash analysis + oracles + stateful chains.
		setF("time-budget", &cfg.TimeBudgetMinutes, 60)
		setI("repro-runs", &cfg.ReproRuns, 5)
		setB("minimize-crash", &cfg.MinimizeCrash, true)
		setB("minimize-chain", &cfg.MinimizeChain, true)
		setF("sequence-prob", &cfg.SequenceProb, 0.50)
		setB("access-probe", &cfg.AccessProbe, true)
		setB("probe-bola", &cfg.ProbeBOLA, true)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, true)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, true)
		setB("probe-differential", &cfg.ProbeDifferential, true)
		setB("probe-stale-object", &cfg.ProbeStaleObject, true)
		setB("probe-stale-etag", &cfg.ProbeStaleETag, true)
		setB("probe-workflow-bypass", &cfg.ProbeWorkflowBypass, true)
		setB("probe-idempotency", &cfg.ProbeIdempotency, true)
		setB("injection-oracle", &cfg.InjectionOracle, true)
		setB("schema-conformance", &cfg.SchemaConformance, true)
		setB("race-mode", &cfg.RaceMode, true)
		// Explicit (matches the flag's own default) rather than a behavior
		// change -- named here so -profile deep is self-documenting about
		// exercising the typed nested/oneOf-aware body path, balanced evenly
		// between schema-correct "reach business logic" requests and
		// deliberate single-violation ones.
		setB("typed-body-mutation", &cfg.TypedBodyMutation, true)
		setF("adversarial-body-rate", &cfg.AdversarialBodyRate, 0.5)
	case "security":
		// Vulnerability-hunting: prioritize the access-control / injection oracles
		// and multi-identity coverage over raw throughput.
		setB("multi-identity", &cfg.MultiIdentity, true)
		setB("identity-include-guest", &cfg.IdentityIncludeGuest, true)
		setB("access-probe", &cfg.AccessProbe, true)
		setB("probe-bola", &cfg.ProbeBOLA, true)
		setB("probe-auth-bypass", &cfg.ProbeAuthBypass, true)
		setB("probe-mass-assign", &cfg.ProbeMassAssign, true)
		setB("probe-differential", &cfg.ProbeDifferential, true)
		setB("probe-stale-object", &cfg.ProbeStaleObject, true)
		setB("probe-stale-etag", &cfg.ProbeStaleETag, true)
		setB("probe-workflow-bypass", &cfg.ProbeWorkflowBypass, true)
		setB("probe-idempotency", &cfg.ProbeIdempotency, true)
		setF("access-probe-prob", &cfg.AccessProbeProb, 0.75)
		setB("injection-oracle", &cfg.InjectionOracle, true)
		setB("schema-conformance", &cfg.SchemaConformance, true)
		setB("source-aware-priority", &cfg.SourceAwarePriority, true)
		setF("sequence-prob", &cfg.SequenceProb, 0.50)
		setB("race-mode", &cfg.RaceMode, true)
		setB("crash-triage", &cfg.CrashTriage, true)
		// Vulnerability-hunting wants MORE single-violation pressure than the
		// flag's own 0.5 default, not less -- mass assignment via an
		// undeclared nested property, discriminator/variant confusion, and
		// exact-boundary constraint violations are structural vulnerability
		// classes this profile should bias toward finding, mirroring the
		// access-probe-prob bump two lines above.
		setB("typed-body-mutation", &cfg.TypedBodyMutation, true)
		setF("adversarial-body-rate", &cfg.AdversarialBodyRate, 0.75)
	default:
		fmt.Fprintf(os.Stderr, "warning: unknown -profile %q (expected fast|deep|security); ignoring\n", p)
	}
}
