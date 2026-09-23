// Command void is the coverage-guided API-security fuzzer's entrypoint.
// Flag parsing/profile handling lives in internal/config; the fuzzing engine
// itself lives in internal/engine. This file is intentionally thin: parse
// flags, seed the RNG, construct and run the Fuzzer -- no business logic.
package main

import (
	"fmt"
	"math/rand"
	"os"

	"void/internal/config"
	"void/internal/engine"
)

func main() {
	cfg := config.ParseFlags()
	// Benchmark reproducibility (BENCHMARK_PLAN.md Top-15 #8): every mutation/
	// scheduling decision in this codebase draws from math/rand's top-level,
	// process-global source. Since Go 1.20 that source is auto-seeded randomly
	// at startup, so two runs never produce the same sequence of choices unless
	// -seed pins it explicitly. This does NOT make a run bit-for-bit
	// deterministic under concurrency (worker goroutines draw from the shared
	// source in scheduler-dependent order), but it removes the single biggest
	// source of run-to-run variance and is what the benchmark plan's fairness
	// contract (§5) requires as the honest baseline: "unseeded" unless stated.
	if cfg.Seed != 0 {
		rand.Seed(cfg.Seed)
		fmt.Printf("RNG seed: %d (deterministic mutation/scheduling draws, not bit-for-bit under concurrency)\n", cfg.Seed)
	} else {
		fmt.Printf("RNG seed: unseeded (default: random per run — pass -seed <n> for reproducibility)\n")
	}
	f, err := engine.NewFuzzer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if cfg.WebUI {
		go engine.RunWebUI(f)
	}
	if err := f.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
}
