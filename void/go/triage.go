package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
)

// triage.go — Crash classification and source-aware endpoint priority.
//
// Crash triage scoring (triageCrash) lives in identity.go
// alongside the other Fuzzer methods it depends on.

func (f *Fuzzer) templateSourcePriorityWeight(tid int) float64 {
	if w, ok := f.templatePriority[tid]; ok && w > 0 {
		return w
	}
	return 1.0
}

func (f *Fuzzer) loadSourceAwarePriority() int {
	out := map[int]float64{}
	routeScores := map[string]float64{}
	if strings.TrimSpace(f.cfg.SourceDir) != "" {
		routeScores = scanSourceRouteScores(f.cfg.SourceDir)
	}
	boosted := 0
	for _, tid := range f.activeIDs {
		meta, ok := f.meta[tid]
		if !ok {
			continue
		}
		w := 1.0
		w *= sensitivePathScore(meta.Method, meta.Norm)
		if len(routeScores) > 0 {
			rp := normalizeRoutePattern(meta.Norm)
			if s := routeScores[rp]; s > 0 {
				w *= s
			}
		}
		w = clampFloat(w, 0.2, 8.0)
		out[tid] = w
		if w > 1.05 {
			boosted++
		}
	}
	f.templatePriority = out
	return boosted
}

func sensitivePathScore(method, path string) float64 {
	low := strings.ToLower(strings.TrimSpace(normalizePath(path)))
	score := 1.0
	sensitive := []string{
		"/billing", "/payment", "/checkout", "/order", "/cart", "/invoice",
		"/auth", "/token", "/login", "/password", "/account", "/admin", "/role",
		"/tenant", "/customer", "/wishlist", "/discount", "/coupon", "/stock",
	}
	hits := 0
	for _, kw := range sensitive {
		if strings.Contains(low, kw) {
			hits++
		}
	}
	if hits > 0 {
		score *= 1.0 + float64(minInt(4, hits))*0.45
	}
	if isWriteMethod(method) {
		score *= 1.25
	}
	return clampFloat(score, 0.8, 6.0)
}

func scanSourceRouteScores(srcDir string) map[string]float64 {
	scores := map[string]float64{}
	if strings.TrimSpace(srcDir) == "" {
		return scores
	}
	_ = filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if name == "bin" || name == "obj" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".cs") {
			return nil
		}
		buf, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		src := string(buf)
		if len(src) > 1<<20 {
			src = src[:1<<20]
		}
		low := strings.ToLower(src)
		fileWeight := 1.0
		for _, k := range []string{"order", "billing", "payment", "checkout", "auth", "login", "role", "admin", "tenant", "wishlist", "cart"} {
			if strings.Contains(low, k) {
				fileWeight += 0.15
			}
		}
		matches := reSourceRoute.FindAllStringSubmatch(src, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			rp := normalizeRoutePattern(m[1])
			if rp == "" {
				continue
			}
			scores[rp] += fileWeight
		}
		return nil
	})
	for k, v := range scores {
		scores[k] = clampFloat(1.0+math.Log1p(v)*0.55, 1.0, 4.0)
	}
	return scores
}

func normalizeRoutePattern(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	parts := splitPathTokens(p)
	if len(parts) == 0 {
		return "/"
	}
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		s := strings.TrimSpace(seg)
		if _, ok := pathPlaceholderName(s); ok {
			out = append(out, "{param}")
			continue
		}
		if strings.HasPrefix(s, ":") || strings.ContainsAny(s, "*?") {
			out = append(out, "{param}")
			continue
		}
		out = append(out, normalizeEndpointSegment(s))
	}
	return "/" + strings.Join(out, "/")
}
