package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsPath(t *testing.T) {
	if got := absPath(""); got != "" {
		t.Fatalf("expected empty string to stay empty, got %q", got)
	}
	wd, _ := os.Getwd()
	abs := absPath("some/relative/path")
	if !filepath.IsAbs(abs) {
		t.Fatalf("expected an absolute path, got %q", abs)
	}
	if !strings.HasPrefix(abs, wd) {
		t.Fatalf("expected %q to be resolved against cwd %q", abs, wd)
	}
	// Already-absolute input is returned unchanged (Abs is a no-op on it).
	already := filepath.Join(wd, "x", "y")
	if got := absPath(already); got != already {
		t.Fatalf("expected already-absolute path unchanged, got %q want %q", got, already)
	}
}

func TestDeriveReportPathFromSummary(t *testing.T) {
	cases := []struct {
		name    string
		summary string
		wantEnd string
	}{
		{"empty falls back to summaries/report.json", "", filepath.Join("summaries", "report.json")},
		{"bare summary.json -> report.json", "summary.json", "report.json"},
		{"summary-<ts>.json -> report-<ts>.json", "summary-20260729-120000.json", "report-20260729-120000.json"},
		{"arbitrary name -> name-report.json", "custom.json", "custom-report.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveReportPathFromSummary(tc.summary)
			if !strings.HasSuffix(got, tc.wantEnd) {
				t.Fatalf("deriveReportPathFromSummary(%q) = %q, want suffix %q", tc.summary, got, tc.wantEnd)
			}
			if !filepath.IsAbs(got) {
				t.Fatalf("expected an absolute path, got %q", got)
			}
		})
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{5, 0, 10, 5},
		{-5, 0, 10, 0},
		{50, 0, 10, 10},
		{0, 0, 0, 0},
	}
	for _, tc := range cases {
		if got := clampInt(tc.v, tc.lo, tc.hi); got != tc.want {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d", tc.v, tc.lo, tc.hi, got, tc.want)
		}
	}
}

func TestClampFloat(t *testing.T) {
	cases := []struct{ v, lo, hi, want float64 }{
		{0.5, 0.0, 1.0, 0.5},
		{-0.5, 0.0, 1.0, 0.0},
		{1.5, 0.0, 1.0, 1.0},
	}
	for _, tc := range cases {
		if got := clampFloat(tc.v, tc.lo, tc.hi); got != tc.want {
			t.Errorf("clampFloat(%v, %v, %v) = %v, want %v", tc.v, tc.lo, tc.hi, got, tc.want)
		}
	}
}

func TestMaxInt(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{1, 2, 2},
		{2, 1, 2},
		{-1, -2, -1},
		{5, 5, 5},
	}
	for _, tc := range cases {
		if got := maxInt(tc.a, tc.b); got != tc.want {
			t.Errorf("maxInt(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// withParsedFlags resets the global flag.CommandLine (ParseFlags registers
// every flag fresh on each call, via package-level flag.StringVar/BoolVar/...
// calls inside its own body -- not at init time) and os.Args, runs
// ParseFlags(), and returns the result. Must not run in parallel with other
// tests in this package since flag.CommandLine and os.Args are process-global.
func withParsedFlags(t *testing.T, args ...string) Config {
	t.Helper()
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	os.Args = args
	return ParseFlags()
}

func TestParseFlags_Defaults(t *testing.T) {
	cfg := withParsedFlags(t, "void", "-grammar", "/tmp/g")
	if cfg.GrammarDir == "" {
		t.Fatal("expected GrammarDir to be set (absolutized)")
	}
	if !filepath.IsAbs(cfg.GrammarDir) {
		t.Fatalf("expected GrammarDir to be absolutized, got %q", cfg.GrammarDir)
	}
	if cfg.TimeBudgetMinutes != 10 {
		t.Errorf("expected default TimeBudgetMinutes=10, got %v", cfg.TimeBudgetMinutes)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("expected default Concurrency=10, got %v", cfg.Concurrency)
	}
	if !cfg.AdaptiveConcurrency {
		t.Error("expected AdaptiveConcurrency default true")
	}
	if !cfg.AccessProbe || !cfg.ProbeBOLA {
		t.Error("expected access-control oracles on by default")
	}
	if cfg.SHMReadMode != "file" {
		t.Errorf("expected default SHMReadMode=file, got %q", cfg.SHMReadMode)
	}
	if cfg.CoverageBitmapSize != defaultSHMBitmapSize {
		t.Errorf("expected default CoverageBitmapSize=%d, got %d", defaultSHMBitmapSize, cfg.CoverageBitmapSize)
	}
}

func TestParseFlags_ExplicitFlagsOverrideDefaults(t *testing.T) {
	cfg := withParsedFlags(t, "void",
		"-grammar", "/tmp/g",
		"-time-budget", "42",
		"-concurrency", "7",
		"-min-concurrency", "2",
		"-max-concurrency", "20",
		"-race-mode=false",
	)
	if cfg.TimeBudgetMinutes != 42 {
		t.Errorf("expected TimeBudgetMinutes=42, got %v", cfg.TimeBudgetMinutes)
	}
	if cfg.Concurrency != 7 {
		t.Errorf("expected Concurrency=7, got %v", cfg.Concurrency)
	}
	if cfg.RaceMode {
		t.Error("expected RaceMode=false to stick")
	}
}

func TestParseFlags_ConcurrencyClampedIntoMinMaxRange(t *testing.T) {
	// Concurrency requested below MinConcurrency must be raised to it.
	cfg := withParsedFlags(t, "void",
		"-grammar", "/tmp/g",
		"-min-concurrency", "10",
		"-max-concurrency", "20",
		"-concurrency", "1",
	)
	if cfg.Concurrency != 10 {
		t.Errorf("expected Concurrency clamped up to MinConcurrency=10, got %v", cfg.Concurrency)
	}

	// MaxConcurrency below MinConcurrency must be raised to match it.
	cfg2 := withParsedFlags(t, "void",
		"-grammar", "/tmp/g",
		"-min-concurrency", "50",
		"-max-concurrency", "5",
	)
	if cfg2.MaxConcurrency != 50 {
		t.Errorf("expected MaxConcurrency raised to MinConcurrency=50, got %v", cfg2.MaxConcurrency)
	}
}

func TestParseFlags_InvalidEnumFallsBackToDefault(t *testing.T) {
	cfg := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-shm-read-mode", "bogus")
	if cfg.SHMReadMode != "file" {
		t.Errorf("expected invalid -shm-read-mode to fall back to %q, got %q", "file", cfg.SHMReadMode)
	}

	cfg2 := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-shm-read-mode", "MMAP")
	if cfg2.SHMReadMode != "mmap" {
		t.Errorf("expected -shm-read-mode to be lowercased, got %q", cfg2.SHMReadMode)
	}
}

func TestParseFlags_ProfileAppliedThenExplicitFlagStillWins(t *testing.T) {
	// -profile fast turns access-probe off by default...
	cfg := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "fast")
	if cfg.AccessProbe {
		t.Error("expected -profile fast to disable AccessProbe")
	}
	if cfg.CrashTriage == false {
		// crash-triage isn't touched by the fast profile's flag list; should
		// keep its own true default.
		t.Error("expected CrashTriage to keep its default (unaffected by fast profile)")
	}

	// ...but an explicit -access-probe=true passed alongside -profile fast
	// must still win (ApplyProfile only fills in flags the user didn't set).
	cfg2 := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "fast", "-access-probe=true")
	if !cfg2.AccessProbe {
		t.Error("expected explicit -access-probe=true to override the fast profile's default")
	}
}

func TestParseFlags_ProfilesSetTypedBodyMutationKnobsButExplicitFlagsStillWin(t *testing.T) {
	fast := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "fast")
	if fast.TypedBodyMutation {
		t.Error("expected -profile fast to disable TypedBodyMutation (throughput-first)")
	}

	deep := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "deep")
	if !deep.TypedBodyMutation {
		t.Error("expected -profile deep to enable TypedBodyMutation")
	}
	if deep.AdversarialBodyRate != 0.5 {
		t.Errorf("expected -profile deep's balanced 0.5 adversarial-body-rate, got %v", deep.AdversarialBodyRate)
	}

	security := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "security")
	if !security.TypedBodyMutation {
		t.Error("expected -profile security to enable TypedBodyMutation")
	}
	if security.AdversarialBodyRate != 0.75 {
		t.Errorf("expected -profile security's elevated 0.75 adversarial-body-rate, got %v", security.AdversarialBodyRate)
	}

	// An explicit flag alongside a profile must still win (ApplyProfile only
	// fills in flags the user didn't set) -- same contract already proven for
	// -access-probe above, checked here for the two new knobs specifically.
	overridden := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-profile", "fast", "-typed-body-mutation=true", "-adversarial-body-rate", "0.9")
	if !overridden.TypedBodyMutation {
		t.Error("expected explicit -typed-body-mutation=true to override -profile fast's default")
	}
	if overridden.AdversarialBodyRate != 0.9 {
		t.Errorf("expected explicit -adversarial-body-rate to override the profile default, got %v", overridden.AdversarialBodyRate)
	}
}

func TestParseFlags_AuthFileFallsBackToEnvAndIsAbsolutized(t *testing.T) {
	t.Setenv("AUTH_FILE", "relative/auth.json")
	cfg := withParsedFlags(t, "void", "-grammar", "/tmp/g")
	if !filepath.IsAbs(cfg.AuthFile) {
		t.Fatalf("expected AUTH_FILE env fallback to be absolutized, got %q", cfg.AuthFile)
	}
	if !strings.HasSuffix(cfg.AuthFile, filepath.Join("relative", "auth.json")) {
		t.Fatalf("expected AuthFile to derive from AUTH_FILE env var, got %q", cfg.AuthFile)
	}
}

func TestParseFlags_ReportFileDefaultsFromSummaryFile(t *testing.T) {
	cfg := withParsedFlags(t, "void", "-grammar", "/tmp/g", "-summary-file", "/tmp/summary.json")
	want := filepath.Join(filepath.Dir(absPath("/tmp/summary.json")), "report.json")
	if cfg.ReportFile != want {
		t.Errorf("expected ReportFile derived from -summary-file, got %q want %q", cfg.ReportFile, want)
	}
}

func TestParseFlags_ClampsOutOfRangeNumericFlags(t *testing.T) {
	cfg := withParsedFlags(t, "void",
		"-grammar", "/tmp/g",
		"-repro-runs", "999",
		"-race-burst", "1",
		"-access-probe-prob", "5.0",
	)
	if cfg.ReproRuns != 20 {
		t.Errorf("expected ReproRuns clamped to 20, got %v", cfg.ReproRuns)
	}
	if cfg.RaceBurst != 2 {
		t.Errorf("expected RaceBurst clamped up to 2, got %v", cfg.RaceBurst)
	}
	if cfg.AccessProbeProb != 1.0 {
		t.Errorf("expected AccessProbeProb clamped to 1.0, got %v", cfg.AccessProbeProb)
	}
}
