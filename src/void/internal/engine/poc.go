package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// poc.go — Proof-of-concept artifact generation: PoC shell scripts,
// exploit timeline Markdown files, curl command builder, and header resolution.

func (f *Fuzzer) resolvedCrashHeaders(item WorkItem) map[string]string {
	headers := cloneStringMap(item.Headers)
	idHeaders, idToken, _ := f.identityAuth(item.Identity)
	for k, v := range idHeaders {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		setHeaderCI(headers, k, v)
	}
	if idToken != "" {
		setHeaderCI(headers, "Authorization", "Bearer "+idToken)
	}
	if strings.TrimSpace(getHeaderCI(headers, "Content-Type")) == "" && strings.TrimSpace(item.Body) != "" {
		setHeaderCI(headers, "Content-Type", "application/json")
	}
	return headers
}

func redactedCrashHeaders(headers map[string]string) map[string]string {
	out := cloneStringMap(headers)
	for k, v := range out {
		if !isSensitiveHeaderName(k) {
			continue
		}
		out[k] = redactedHeaderValue(k, v)
	}
	return out
}

func maskedAuthContext(identity string, headers map[string]string) map[string]any {
	out := map[string]any{
		"identity": strings.TrimSpace(identity),
		"redacted": true,
	}
	entries := make([]map[string]any, 0, 4)
	for _, hk := range crashHeaderKeys(headers) {
		if !isSensitiveHeaderName(hk) {
			continue
		}
		raw := strings.TrimSpace(headers[hk])
		if raw == "" {
			continue
		}
		entry := map[string]any{
			"header":      hk,
			"fingerprint": secretFingerprint(raw),
			"value_len":   len(raw),
			"masked":      redactedHeaderValue(hk, raw),
		}
		if strings.EqualFold(hk, "Authorization") {
			parts := strings.Fields(raw)
			if len(parts) > 0 {
				entry["scheme"] = parts[0]
			}
			if len(parts) == 2 && strings.Count(parts[1], ".") == 2 {
				entry["token_format"] = "jwt"
				entry["token_len"] = len(parts[1])
				entry["token_fingerprint"] = secretFingerprint(parts[1])
			}
		}
		if strings.EqualFold(hk, "Cookie") || strings.EqualFold(hk, "Set-Cookie") {
			entry["cookie_names"] = cookieNames(raw)
		}
		entries = append(entries, entry)
	}
	out["credential_count"] = len(entries)
	out["credentials"] = entries
	if len(entries) == 0 {
		out["redacted"] = false
	}
	return out
}

func secretFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

func cookieNames(raw string) []string {
	parts := strings.Split(raw, ";")
	names := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if idx := strings.Index(name, "="); idx >= 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func isSensitiveHeaderName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "authorization" || n == "cookie" || n == "set-cookie" {
		return true
	}
	return strings.Contains(n, "api-key") ||
		strings.Contains(n, "apikey") ||
		strings.Contains(n, "auth-token") ||
		strings.Contains(n, "token") ||
		strings.Contains(n, "secret")
}

func redactedHeaderValue(name, value string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "authorization" {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "bearer ") {
			return "Bearer ${AUTH_TOKEN:?set AUTH_TOKEN}"
		}
		return "${AUTHORIZATION:?set AUTHORIZATION}"
	}
	if n == "cookie" || n == "set-cookie" {
		return "${AUTH_COOKIE:?set AUTH_COOKIE}"
	}
	env := headerEnvPlaceholder(name)
	return "${" + env + ":?set " + env + "}"
}

func headerEnvPlaceholder(name string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToUpper(strings.TrimSpace(name)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "AUTH_SECRET"
	}
	return out
}

func crashHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func escapeHeaderForDoubleQuotedBash(name, value string) string {
	prefix := escapeForDoubleQuotedBash(name + ": ")
	if strings.Contains(value, "${") && strings.Contains(value, ":?set ") {
		v := strings.ToValidUTF8(value, "?")
		v = strings.ReplaceAll(v, "\\", "\\\\")
		v = strings.ReplaceAll(v, "\"", "\\\"")
		v = strings.ReplaceAll(v, "`", "\\`")
		return prefix + v
	}
	return escapeForDoubleQuotedBash(name + ": " + value)
}

func (f *Fuzzer) buildInlineCurlCommand(item WorkItem, headers map[string]string) string {
	path := item.Path
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := strings.ToUpper(strings.TrimSpace(item.Method))
	if method == "" {
		method = "GET"
	}

	parts := []string{
		"TARGET_HOST=\"${TARGET_HOST:-" + escapeForDoubleQuotedBash(strings.TrimRight(f.target, "/")) + "}\";",
		"curl -i -sS -X \"" + escapeForDoubleQuotedBash(method) + "\"",
		"\"$TARGET_HOST" + escapeForDoubleQuotedBash(path) + "\"",
	}
	for _, hk := range crashHeaderKeys(headers) {
		parts = append(parts, "-H \""+escapeHeaderForDoubleQuotedBash(hk, headers[hk])+"\"")
	}
	if strings.TrimSpace(item.Body) != "" {
		parts = append(parts, "--data-raw \""+escapeForDoubleQuotedBash(item.Body)+"\"")
	} else {
		parts = append(parts, "--data ''")
	}
	return strings.Join(parts, " ")
}

func (f *Fuzzer) writeCrashPoC(sig string, res SendResult, pocItem WorkItem, triage, repro, minimized map[string]any) string {
	if strings.TrimSpace(f.cfg.PocDir) == "" {
		return ""
	}
	if err := os.MkdirAll(f.cfg.PocDir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(f.cfg.PocDir, "poc-"+sig+".sh")
	headers := redactedCrashHeaders(f.resolvedCrashHeaders(pocItem))
	headerKeys := crashHeaderKeys(headers)

	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n\n")
	b.WriteString("# Auto-generated by Void\n")
	b.WriteString("# signature: " + sig + "\n")
	b.WriteString("# method: " + pocItem.Method + "\n")
	b.WriteString("# path: " + normalizePath(pocItem.Path) + "\n")
	if cls := toString(triage["classification"]); cls != "" {
		b.WriteString("# triage: " + cls + " severity=" + toString(triage["severity_score"]) + " dev_mode=" + toString(triage["dev_mode"]) + "\n")
	}
	if layer := toString(triage["crash_layer"]); layer != "" && layer != "unknown" {
		b.WriteString("# crash_layer: " + layer + "\n")
	}
	if st := toString(repro["stability_pct"]); st != "" {
		b.WriteString("# repro stability: " + st + "%\n")
	}
	if len(pocItem.Trace) > 1 {
		b.WriteString("# sequence trace:\n")
		for i, step := range pocItem.Trace {
			line := fmt.Sprintf("#   %d) %s %s", i+1, step.Method, step.Path)
			if step.Identity != "" {
				line += " [identity=" + step.Identity + "]"
			}
			if step.Status != 0 {
				line += fmt.Sprintf(" -> %d", step.Status)
			}
			b.WriteString(line + "\n")
		}
	}
	b.WriteString("\nTARGET_HOST=\"${TARGET_HOST:-" + shellQuoteDouble(f.target) + "}\"\n\n")
	if strings.TrimSpace(getHeaderCI(headers, "Authorization")) != "" {
		b.WriteString("# Set AUTH_TOKEN before running this PoC if the original crash required bearer auth.\n")
	}
	if strings.TrimSpace(getHeaderCI(headers, "Cookie")) != "" {
		b.WriteString("# Set AUTH_COOKIE before running this PoC if the original crash required cookie auth.\n")
	}
	b.WriteString("curl -i -sS -X " + shellQuoteDouble(strings.ToUpper(pocItem.Method)) + " \"$TARGET_HOST" + escapeForDoubleQuotedBash(pocItem.Path) + "\" \\\n")
	for _, hk := range headerKeys {
		b.WriteString("  -H \"" + escapeHeaderForDoubleQuotedBash(hk, headers[hk]) + "\" \\\n")
	}
	if strings.TrimSpace(pocItem.Body) != "" {
		b.WriteString("  --data-raw \"" + escapeForDoubleQuotedBash(pocItem.Body) + "\"\n")
	} else {
		b.WriteString("  --data ''\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		return ""
	}
	f.pocCount++
	return path
}

func (f *Fuzzer) writeExploitTimeline(sig string, res SendResult, pocItem WorkItem) string {
	if strings.TrimSpace(f.cfg.TimelineDir) == "" {
		return ""
	}
	if err := os.MkdirAll(f.cfg.TimelineDir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(f.cfg.TimelineDir, "timeline-"+sig+".md")
	trace := pocItem.Trace
	if len(trace) == 0 {
		trace = []TraceStep{{Method: pocItem.Method, Path: normalizePath(pocItem.Path), Mutation: pocItem.MutationName}}
	}
	if len(trace) > traceDepthMax {
		trace = trace[len(trace)-traceDepthMax:]
	}

	var b strings.Builder
	b.WriteString("# Exploit Timeline " + sig + "\n\n")
	b.WriteString("```mermaid\nsequenceDiagram\n")
	b.WriteString("    participant F as Fuzzer\n")
	b.WriteString("    participant API as API\n")
	for i, st := range trace {
		msg := fmt.Sprintf("%d. %s %s", i+1, strings.ToUpper(st.Method), sanitizeText(normalizePath(st.Path), 80))
		if st.Identity != "" {
			msg += " (" + st.Identity + ")"
		}
		b.WriteString("    F->>API: " + mermaidEscape(msg) + "\n")
		switch {
		case i == len(trace)-1:
			b.WriteString(fmt.Sprintf("    API-->>F: %d crash\n", res.Status))
		case st.Status != 0:
			// A real, previously-unknown-at-build-time status, patched in by
			// handleResult (worker.go) once this step's own response came
			// back -- replaces the old unconditional "success/transition"
			// placeholder with the step's ACTUAL outcome.
			b.WriteString(fmt.Sprintf("    API-->>F: %d\n", st.Status))
		default:
			// Legacy/no-status trace entry (e.g. a trace built before this
			// field existed, or a step whose status was never patched in).
			b.WriteString("    API-->>F: success/transition\n")
		}
	}
	b.WriteString("```\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return ""
	}
	return path
}
