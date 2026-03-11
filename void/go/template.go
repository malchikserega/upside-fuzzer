package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// template.go — Template loading, rendering, segment-level value resolution,
// path parameter adaptation from runtime values, and request preparation.

func (f *Fuzzer) bootstrapRuntimeValues() int {
	if f.cfg.BootstrapMax <= 0 {
		return 0
	}
	cands := make([]int, 0, len(f.activeIDs))
	seen := map[string]struct{}{}
	for _, tid := range f.activeIDs {
		meta := f.meta[tid]
		if meta.Method != "GET" {
			continue
		}
		if strings.Contains(meta.Norm, "{") || strings.Contains(meta.Norm, "}") {
			continue
		}
		if _, ok := seen[meta.Norm]; ok {
			continue
		}
		seen[meta.Norm] = struct{}{}
		cands = append(cands, tid)
	}
	shuffleInts(cands)
	if len(cands) > f.cfg.BootstrapMax {
		cands = cands[:f.cfg.BootstrapMax]
	}

	// Parallel bootstrap with 3s total deadline to avoid slow startup.
	type bootstrapResult struct {
		body    string
		headers map[string]string
	}
	resultCh := make(chan bootstrapResult, len(cands))
	concurrency := minInt(8, len(cands))
	sem := make(chan struct{}, concurrency)
	deadline := time.After(3 * time.Second)
	var wg sync.WaitGroup

	for _, tid := range cands {
		select {
		case <-deadline:
			goto done
		default:
		}
		item, err := f.renderTemplate(tid, "none", 1, -1)
		if err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it WorkItem) {
			defer wg.Done()
			defer func() { <-sem }()
			res := f.sendOne(it)
			if res.Err == nil && res.Status == 200 {
				resultCh <- bootstrapResult{body: res.Body, headers: res.Headers}
			}
		}(item)
	}
done:
	go func() { wg.Wait(); close(resultCh) }()

	learned := 0
	for r := range resultCh {
		learned += f.learnFromResponse(r.body, r.headers)
	}
	return learned
}

func (f *Fuzzer) startStopInputListener(stopCh chan<- struct{}) {
	if !isTerminal(os.Stdin) {
		return
	}
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToLower(strings.TrimSpace(line))
			switch cmd {
			case "q", "quit", "s", "stop", "exit":
				select {
				case stopCh <- struct{}{}:
				default:
				}
				return
			}
		}
	}()
}
func (f *Fuzzer) buildWorkItem(epIdx int, ep Epoch) (WorkItem, bool) {
	// Drain crash replay queue probabilistically to avoid monopolization by one crashing endpoint.
	if len(f.replayQueue) > 0 && rand.Float64() < clampFloat(f.cfg.CrashReplayProb, 0.0, 1.0) {
		for len(f.replayQueue) > 0 {
			item := f.replayQueue[0]
			f.replayQueue = f.replayQueue[1:]
			if f.isTemplateBlocked(item.TemplateID) {
				continue
			}
			item = f.decorateWorkItem(item)
			return item, true
		}
	}

	for len(f.raceQueue) > 0 {
		item := f.raceQueue[0]
		f.raceQueue = f.raceQueue[1:]
		if f.isTemplateBlocked(item.TemplateID) {
			continue
		}
		item = f.decorateWorkItem(item)
		return item, true
	}

	for len(f.sequenceQueue) > 0 && rand.Float64() < clampFloat(f.cfg.SequenceProb, 0.0, 1.0) {
		item := f.sequenceQueue[0]
		f.sequenceQueue = f.sequenceQueue[1:]
		if f.isTemplateBlocked(item.TemplateID) {
			continue
		}
		item = f.decorateWorkItem(item)
		return item, true
	}

	if len(f.activeIDs) == 0 {
		return WorkItem{}, false
	}

	tid := -1
	if ep.Name == "Harvest" {
		tid = f.pickHarvestTemplate()
	} else if (ep.Mode == "mutate" || ep.Mode == "havoc") && len(f.corpus) > 0 {
		for tries := 0; tries < 8; tries++ {
			seedIdx := f.pickSeed()
			if seedIdx < 0 {
				break
			}
			seed := &f.corpus[seedIdx]
			if f.isTemplateBlocked(seed.TemplateID) {
				f.seedSampler.Set(seedIdx, 0)
				continue
			}
			seed.TimesChosen++
			seed.Energy = math.Max(0.5, seed.Energy*0.995)
			f.seedSampler.Set(seedIdx, seed.Energy)
			it, err := f.renderTemplate(seed.TemplateID, ep.Mode, f.havocDepth(ep.Mode), seedIdx)
			if err == nil {
				it.EpochName = ep.Name
				it.EpochIdx = epIdx
				if ep.Name == "Splicing" && len(f.corpus) >= 2 {
					it.MutationLabel += "+splice"
					it.MutationName = "splicing"
				}
				it = f.decorateWorkItem(it)
				return it, true
			}
		}
		tid = f.pickWeightedTemplate()
	} else {
		tid = f.pickWeightedTemplate()
	}

	if tid < 0 || f.isTemplateBlocked(tid) {
		return WorkItem{}, false
	}
	it, err := f.renderTemplate(tid, ep.Mode, f.havocDepth(ep.Mode), -1)
	if err != nil {
		return WorkItem{}, false
	}
	it.EpochName = ep.Name
	it.EpochIdx = epIdx
	it = f.decorateWorkItem(it)
	return it, true
}

func (f *Fuzzer) templateEndpointKey(tid int) string {
	if k, ok := f.tmplEPKey[tid]; ok && k != "" {
		return k
	}
	m, ok := f.meta[tid]
	if !ok {
		return ""
	}
	return endpointKey(m.Method, m.Norm)
}

func (f *Fuzzer) isTemplateBlocked(tid int) bool {
	k := f.templateEndpointKey(tid)
	if k == "" {
		return false
	}
	_, blocked := f.blockedEndpoints[k]
	return blocked
}

func (f *Fuzzer) shouldForceForm(method, path string) bool {
	if !f.cfg.AdaptiveContentType {
		return false
	}
	if !isWriteMethod(method) {
		return false
	}
	_, ok := f.forceFormEndpoints[endpointKey(method, normalizeEndpointPath(path))]
	return ok
}

func (f *Fuzzer) adaptPathParamsFromRuntime(t *Template, path string) (string, []string) {
	if t == nil || t.RequestID == "" || !strings.Contains(t.RequestID, "{") || !strings.Contains(path, "/") {
		return path, nil
	}
	rawPath := path
	query := ""
	if i := strings.Index(rawPath, "?"); i >= 0 {
		query = rawPath[i:]
		rawPath = rawPath[:i]
	}
	pattern := normalizePath(t.RequestID)
	actual := normalizePath(rawPath)
	pSegs := splitPathTokens(pattern)
	aSegs := splitPathTokens(actual)
	if len(pSegs) == 0 || len(pSegs) != len(aSegs) {
		return path, nil
	}

	changed := false
	labels := make([]string, 0, 4)
	for i := 0; i < len(pSegs); i++ {
		name, ok := pathPlaceholderName(pSegs[i])
		if !ok {
			continue
		}
		cur := aSegs[i]
		if !isPathPlaceholderValue(cur) {
			continue
		}
		cand := f.runtime.pickCustomPayloadValue(name, f.dict, cur)
		cand = normalizePathParamValue(cand, cur)
		if cand == "" || cand == cur {
			continue
		}
		aSegs[i] = cand
		labels = append(labels, "path_"+name)
		changed = true
	}
	if !changed {
		return path, nil
	}
	out := "/" + strings.Join(aSegs, "/")
	if query != "" {
		out += query
	}
	return out, dedupStrings(labels)
}

func (f *Fuzzer) blockEndpointByTemplateID(tid int) int {
	k := f.templateEndpointKey(tid)
	if k == "" {
		return 0
	}
	if _, ok := f.blockedEndpoints[k]; ok {
		return 0
	}
	f.blockedEndpoints[k] = struct{}{}

	removed := 0
	next := make([]int, 0, len(f.activeIDs))
	for _, id := range f.activeIDs {
		if f.templateEndpointKey(id) == k {
			removed++
			continue
		}
		next = append(next, id)
	}
	f.activeIDs = next

	if len(f.sequenceQueue) > 0 {
		q := make([]WorkItem, 0, len(f.sequenceQueue))
		for _, wi := range f.sequenceQueue {
			if f.templateEndpointKey(wi.TemplateID) == k {
				continue
			}
			q = append(q, wi)
		}
		f.sequenceQueue = q
	}

	if len(f.corpus) > 0 {
		for i := range f.corpus {
			if f.templateEndpointKey(f.corpus[i].TemplateID) == k {
				f.seedSampler.Set(i, 0)
			}
		}
	}
	return removed
}

func (f *Fuzzer) havocDepth(mode string) int {
	if mode != "havoc" {
		return 1
	}
	return clampInt(1+f.stallCounter/8, 1, 4)
}

func (f *Fuzzer) renderTemplate(templateID int, mutateMode string, havocDepth int, seedIdx int) (WorkItem, error) {
	t := f.tmplByID[templateID]
	if t == nil {
		return WorkItem{}, fmt.Errorf("template not found: %d", templateID)
	}
	customKeys := make([]string, 0, 8)
	dynKeys := make([]string, 0, 8)
	for _, s := range t.Segments {
		if s.Kind == "custom_payload" && s.PayloadKey != "" {
			customKeys = append(customKeys, s.PayloadKey)
		}
		if s.Kind == "dynamic" {
			dynKeys = append(dynKeys, inferDependencyKeys(s.Name)...)
		}
	}
	corrKeys := append([]string{}, customKeys...)
	corrKeys = append(corrKeys, dynKeys...)
	corr := f.runtime.pickCorrelated(corrKeys)
	useCorr := len(corr) > 0
	if useCorr && (mutateMode == "mutate" || mutateMode == "havoc") && rand.Float64() < 0.20 {
		useCorr = false
	}

	var b strings.Builder
	mutParts := make([]string, 0, 8)
	for _, s := range t.Segments {
		switch s.Kind {
		case "static":
			b.WriteString(s.Value)
		case "custom_payload":
			val := s.Default
			if useCorr {
				if cv, ok := corr[s.PayloadKey]; ok {
					val = cv
					mutParts = append(mutParts, "corr_"+s.PayloadKey)
				}
			}
			if val == "" || strings.HasPrefix(val, "CUSTOM_PAYLOAD") {
				val = f.runtime.pickCustomPayloadValue(s.PayloadKey, f.dict, s.Default)
				mutParts = append(mutParts, "dict_"+s.PayloadKey)
			}
			if mutateMode == "mutate" && rand.Float64() < 0.15 {
				val, _ = mutateAny(val, "string")
				mutParts = append(mutParts, "mutate_string")
			} else if mutateMode == "havoc" && rand.Float64() < 0.30 {
				val, _ = mutateHavoc(val, "string", havocDepth)
				mutParts = append(mutParts, "havoc_string")
			}
			if s.Quoted {
				b.WriteByte('"')
				b.WriteString(val)
				b.WriteByte('"')
			} else {
				b.WriteString(val)
			}
		case "fuzzable":
			val := s.Default
			if mutateMode == "mutate" {
				if rand.Float64() > 0.40 {
					var name string
					val, name = mutateAny(val, s.ValueType)
					mutParts = append(mutParts, name)
				}
			} else if mutateMode == "havoc" {
				var name string
				val, name = mutateHavoc(val, s.ValueType, havocDepth)
				mutParts = append(mutParts, name)
			}
			if s.Quoted {
				b.WriteByte('"')
				b.WriteString(val)
				b.WriteByte('"')
			} else {
				b.WriteString(val)
			}
		case "dynamic":
			v, m := f.runtime.pickDynamic(s.Name, f.dict)
			b.WriteString(v)
			if m != "" {
				mutParts = append(mutParts, m)
			}
		default:
			b.WriteString(s.Value)
		}
	}
	raw := b.String()
	method, path, headers, body, err := parseRawRequest(raw)
	if err != nil {
		return WorkItem{}, err
	}
	if ap, labels := f.adaptPathParamsFromRuntime(t, path); ap != path {
		path = ap
		mutParts = append(mutParts, labels...)
	}
	if f.shouldForceForm(method, path) {
		if ah, ab, ok := adaptJSONRequestToForm(headers, body); ok {
			headers = ah
			body = ab
			mutParts = append(mutParts, "adapt_form")
		}
	}
	if (mutateMode == "mutate" || mutateMode == "havoc") && (method == "POST" || method == "PUT" || method == "PATCH") {
		chance := 0.15
		if mutateMode == "havoc" {
			chance = 0.30
		}
		if rand.Float64() < chance {
			if mb, label := mutateJSONBody(body, havocDepth); label != "" {
				body = mb
				mutParts = append(mutParts, label)
			}
		}
	}
	// Path parameter mutation: replace ID-like segments with boundary/injection values.
	// 15% chance in mutate mode, 25% in havoc mode.
	if mutateMode == "mutate" || mutateMode == "havoc" {
		pathMutChance := 0.15
		if mutateMode == "havoc" {
			pathMutChance = 0.25
		}
		if rand.Float64() < pathMutChance {
			if mutatedPath, pathLabel := mutatePath(path); mutatedPath != "" {
				path = mutatedPath
				mutParts = append(mutParts, pathLabel)
			}
		}
	}
	mutParts = dedupStrings(mutParts)
	label := "seed"
	if len(mutParts) > 0 {
		label = strings.Join(mutParts, "+")
	}
	mname := "seed"
	if len(mutParts) > 0 {
		mname = mutParts[0]
	}
	return WorkItem{
		TemplateID:    templateID,
		Method:        method,
		Path:          path,
		Headers:       headers,
		Body:          body,
		Raw:           raw,
		MutationLabel: label,
		MutationName:  mname,
		SeedIdx:       seedIdx,
		SeqDepth:      0,
	}, nil
}

func parseRawRequest(raw string) (string, string, map[string]string, string, error) {
	sep := "\r\n\r\n"
	i := strings.Index(raw, sep)
	if i < 0 {
		sep = "\n\n"
		i = strings.Index(raw, sep)
		if i < 0 {
			return "", "", nil, "", errors.New("invalid raw request: missing header/body separator")
		}
	}
	hdrPart := raw[:i]
	body := raw[i+len(sep):]
	lines := splitLines(hdrPart)
	if len(lines) == 0 {
		return "", "", nil, body, errors.New("empty request line")
	}
	rq := strings.Fields(strings.TrimSpace(lines[0]))
	if len(rq) < 2 {
		return "", "", nil, body, errors.New("invalid request line")
	}
	method := strings.ToUpper(strings.TrimSpace(rq[0]))
	path := strings.TrimSpace(rq[1])
	headers := map[string]string{}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.Index(line, ":")
		if p < 0 {
			continue
		}
		k := strings.TrimSpace(line[:p])
		v := strings.TrimSpace(line[p+1:])
		headers[k] = v
	}
	return method, path, headers, body, nil
}

func (f *Fuzzer) prepareItemForSend(item WorkItem) WorkItem {
	if !f.cfg.AutoAntiForgery {
		return item
	}
	if !isWriteMethod(item.Method) || isAPILikePath(item.Path) {
		return item
	}
	ct := canonicalContentType(item.Headers)
	if !isFormLikeContentType(ct) {
		return item
	}
	token := f.pickAntiForgeryToken()
	if token == "" {
		return item
	}
	if strings.TrimSpace(getHeaderCI(item.Headers, f.cfg.AntiForgeryHeader)) == "" {
		setHeaderCI(item.Headers, f.cfg.AntiForgeryHeader, token)
	}
	if strings.Contains(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		if body, changed := upsertFormField(item.Body, f.cfg.AntiForgeryField, token); changed {
			item.Body = body
		}
	}
	return item
}
func (f *Fuzzer) removeActiveTemplate(tid int) {
	out := make([]int, 0, len(f.activeIDs))
	for _, id := range f.activeIDs {
		if id != tid {
			out = append(out, id)
		}
	}
	f.activeIDs = out
}

func currentEpoch(epochs []Epoch, elapsed, total time.Duration) (int, Epoch) {
	frac := 1.0
	if total > 0 {
		frac = float64(elapsed) / float64(total)
	}
	cum := 0.0
	for i, ep := range epochs {
		cum += ep.Fraction
		if frac < cum {
			return i, ep
		}
	}
	return len(epochs) - 1, epochs[len(epochs)-1]
}

func exportTemplates(exporterPath, grammarDir, outPath string) error {
	exp := resolveExporterPath(exporterPath)
	if !fileExists(exp) {
		return fmt.Errorf("exporter not found: %s", exp)
	}
	cmd := exec.Command("python3", exp, "--grammar-dir", grammarDir, "--out", outPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadTemplates(path string) ([]Template, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var exp TemplateExport
	if err := json.Unmarshal(buf, &exp); err != nil {
		return nil, err
	}
	out := make([]Template, 0, len(exp.Templates))
	seen := map[int]struct{}{}
	for _, t := range exp.Templates {
		if _, ok := seen[t.ID]; ok {
			continue
		}
		seen[t.ID] = struct{}{}
		out = append(out, t)
	}
	return out, nil
}

func resolveDictionaryPath(dictArg, grammarDir string) string {
	cands := []string{}
	if dictArg != "" {
		cands = append(cands, dictArg)
	}
	if grammarDir != "" {
		cands = append(cands, filepath.Join(grammarDir, "dict.json"))
	}
	for _, p := range cands {
		if p == "" {
			continue
		}
		ap, err := filepath.Abs(p)
		if err == nil && fileExists(ap) {
			return ap
		}
	}
	return ""
}

func resolveExporterPath(path string) string {
	if path == "" {
		path = "./export-templates.py"
	}
	if filepath.IsAbs(path) && fileExists(path) {
		return path
	}
	if fileExists(path) {
		ap, _ := filepath.Abs(path)
		return ap
	}
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		cand := filepath.Join(dir, filepath.Base(path))
		if fileExists(cand) {
			return cand
		}
	}
	cwd, _ := os.Getwd()
	cand := filepath.Join(cwd, path)
	if fileExists(cand) {
		return cand
	}
	return path
}

func extractPathParamNames(requestID string) []string {
	res := []string{}
	for _, m := range rePathParam.FindAllString(requestID, -1) {
		t := strings.Trim(m, "{}")
		if t != "" {
			res = append(res, t)
		}
	}
	return dedupStrings(res)
}
