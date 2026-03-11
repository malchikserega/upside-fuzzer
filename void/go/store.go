package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"sync"
)

// store.go — DictStore (grammar dictionary lookup from dict.json)
// and RuntimeStore (values learned from API responses at runtime).

type DictStore struct {
	arrays     map[string][]string
	containers map[string]map[string][]string
}

func loadDict(path string) (*DictStore, error) {
	d := &DictStore{
		arrays:     map[string][]string{},
		containers: map[string]map[string][]string{},
	}
	if path == "" {
		return d, nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(buf, &raw); err != nil {
		return nil, err
	}
	if wrap, ok := raw["dictionaries"].(map[string]any); ok {
		raw = wrap
	}
	for k, v := range raw {
		switch tv := v.(type) {
		case []any:
			d.arrays[k] = uniqStrings(anySliceToStrings(tv))
		case map[string]any:
			inner := map[string][]string{}
			for ik, iv := range tv {
				switch iiv := iv.(type) {
				case []any:
					inner[ik] = uniqStrings(anySliceToStrings(iiv))
				default:
					inner[ik] = uniqStrings([]string{toString(iv)})
				}
			}
			d.containers[k] = inner
		default:
			d.arrays[k] = uniqStrings([]string{toString(v)})
		}
	}
	return d, nil
}

func (d *DictStore) candidatesForKey(key string) []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, 32)
	keyNorm := strings.TrimSpace(key)
	keyCanon := canonicalKey(keyNorm)

	if arr, ok := d.arrays[keyNorm]; ok {
		out = append(out, arr...)
	}
	for k, vals := range d.arrays {
		if canonicalKey(k) == keyCanon {
			out = append(out, vals...)
		}
	}
	if strings.Contains(keyNorm, ".") {
		short := keyNorm[strings.LastIndex(keyNorm, ".")+1:]
		shortCanon := canonicalKey(short)
		if arr, ok := d.arrays[short]; ok {
			out = append(out, arr...)
		}
		for k, vals := range d.arrays {
			if canonicalKey(k) == shortCanon {
				out = append(out, vals...)
			}
		}
	}

	for _, cname := range []string{
		"restler_custom_payload",
		"restler_custom_payload_unquoted",
		"restler_custom_payload_query",
		"restler_custom_payload_header",
	} {
		container := d.containers[cname]
		if container == nil {
			continue
		}
		if vals, ok := container[keyNorm]; ok {
			out = append(out, vals...)
		}
		for k, vals := range container {
			if canonicalKey(k) == keyCanon {
				out = append(out, vals...)
			}
		}
	}

	out = filterUsefulStrings(out)
	return uniqStrings(out)
}

func (d *DictStore) allIDLikeValues() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, 64)
	for k, vals := range d.arrays {
		if strings.HasSuffix(canonicalKey(k), "id") {
			out = append(out, vals...)
		}
	}
	for _, cname := range []string{
		"restler_custom_payload",
		"restler_custom_payload_unquoted",
		"restler_custom_payload_query",
		"restler_custom_payload_header",
	} {
		container := d.containers[cname]
		for k, vals := range container {
			if strings.HasSuffix(canonicalKey(k), "id") {
				out = append(out, vals...)
			}
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}
type RuntimeStore struct {
	mu        sync.RWMutex
	values    map[string][]string
	// valueSeen is a parallel set for O(1) dedup in addValue, avoiding O(n) linear scan.
	valueSeen map[string]map[string]struct{}
	relations map[string][][2]string
	depValues    map[string][]string
	// depValueSeen is a parallel set for O(1) dedup in addDepValue.
	depValueSeen map[string]map[string]struct{}
}

func newRuntimeStore() *RuntimeStore {
	return &RuntimeStore{
		values:       map[string][]string{},
		valueSeen:    map[string]map[string]struct{}{},
		relations:    map[string][][2]string{},
		depValues:    map[string][]string{},
		depValueSeen: map[string]map[string]struct{}{},
	}
}

func (r *RuntimeStore) addValue(key, value string) bool {
	v := normalizeValue(value)
	if !isUsefulValue(v) {
		return false
	}
	// Don't store injection payloads (SSTI, JNDI, template strings) as runtime values —
	// they would be reused in path parameters creating a garbage feedback loop in the UI.
	if strings.ContainsAny(v, "{}$") {
		return false
	}
	ck := canonicalKey(key)
	if ck == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// O(1) dedup via parallel set (vs. O(n) linear scan with contains()).
	if seen := r.valueSeen[ck]; seen != nil {
		if _, exists := seen[v]; exists {
			return false
		}
	}
	cur := append(r.values[ck], v)
	if len(cur) > maxRuntimeValuesPerKey {
		// Evict oldest entry from the seen-set when the slice is trimmed.
		evicted := cur[0]
		cur = cur[1:]
		if s := r.valueSeen[ck]; s != nil {
			delete(s, evicted)
		}
	}
	r.values[ck] = cur
	if r.valueSeen[ck] == nil {
		r.valueSeen[ck] = make(map[string]struct{})
	}
	r.valueSeen[ck][v] = struct{}{}
	return true
}

func pairKey(a, b string) (string, bool, string, string) {
	ca := canonicalKey(a)
	cb := canonicalKey(b)
	if ca == "" || cb == "" || ca == cb {
		return "", false, "", ""
	}
	if ca <= cb {
		return ca + "|" + cb, true, ca, cb
	}
	return cb + "|" + ca, false, cb, ca
}

func (r *RuntimeStore) addRelation(keyA, valueA, keyB, valueB string) bool {
	va := normalizeValue(valueA)
	vb := normalizeValue(valueB)
	if !isUsefulValue(va) || !isUsefulValue(vb) {
		return false
	}
	pk, asc, _, _ := pairKey(keyA, keyB)
	if pk == "" {
		return false
	}
	p := [2]string{va, vb}
	if !asc {
		p = [2]string{vb, va}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.relations[pk]
	for _, e := range cur {
		if e == p {
			return false
		}
	}
	cur = append(cur, p)
	if len(cur) > maxRuntimeRelationsPerKV {
		cur = cur[len(cur)-maxRuntimeRelationsPerKV:]
	}
	r.relations[pk] = cur
	return true
}

func (r *RuntimeStore) addDepValue(depName, value string) {
	v := normalizeValue(value)
	if !isUsefulValue(v) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// O(1) dedup via parallel set.
	if seen := r.depValueSeen[depName]; seen != nil {
		if _, exists := seen[v]; exists {
			return
		}
	}
	cur := append(r.depValues[depName], v)
	if len(cur) > maxRuntimeValuesPerKey {
		evicted := cur[0]
		cur = cur[1:]
		if s := r.depValueSeen[depName]; s != nil {
			delete(s, evicted)
		}
	}
	r.depValues[depName] = cur
	if r.depValueSeen[depName] == nil {
		r.depValueSeen[depName] = make(map[string]struct{})
	}
	r.depValueSeen[depName][v] = struct{}{}
}

func (r *RuntimeStore) getDepValue(depName string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vals := r.depValues[depName]
	if len(vals) == 0 {
		return ""
	}
	return vals[rand.Intn(len(vals))]
}

func (r *RuntimeStore) valuesForKey(key string) []string {
	ck := canonicalKey(key)
	if ck == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	vals := r.values[ck]
	out := make([]string, len(vals))
	copy(out, vals)
	return out
}

func (r *RuntimeStore) allIDLikeValues() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, 64)
	for k, vals := range r.values {
		if strings.HasSuffix(k, "id") {
			out = append(out, vals...)
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

func (r *RuntimeStore) pickCorrelated(keys []string) map[string]string {
	canonToOrig := map[string]string{}
	canonKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		ck := canonicalKey(k)
		if ck == "" {
			continue
		}
		if _, ok := canonToOrig[ck]; !ok {
			canonToOrig[ck] = k
			canonKeys = append(canonKeys, ck)
		}
	}
	if len(canonKeys) < 2 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	bestKey := ""
	bestLen := 0
	for i := 0; i < len(canonKeys); i++ {
		for j := i + 1; j < len(canonKeys); j++ {
			a, b := canonKeys[i], canonKeys[j]
			pk, _, _, _ := pairKey(a, b)
			bucket := r.relations[pk]
			if len(bucket) > bestLen {
				bestLen = len(bucket)
				bestKey = pk
			}
		}
	}
	if bestKey == "" || bestLen == 0 {
		return nil
	}
	parts := strings.Split(bestKey, "|")
	if len(parts) != 2 {
		return nil
	}
	bucket := r.relations[bestKey]
	pick := bucket[rand.Intn(len(bucket))]
	out := map[string]string{}
	out[canonToOrig[parts[0]]] = pick[0]
	out[canonToOrig[parts[1]]] = pick[1]
	return out
}

func (r *RuntimeStore) customPayloadCandidates(key string, dict *DictStore) []string {
	keyNorm := strings.TrimSpace(key)
	keyCanon := canonicalKey(keyNorm)
	out := make([]string, 0, 64)

	out = append(out, r.valuesForKey(keyNorm)...)
	if strings.Contains(keyNorm, ".") {
		short := keyNorm[strings.LastIndex(keyNorm, ".")+1:]
		out = append(out, r.valuesForKey(short)...)
	}
	out = append(out, dict.candidatesForKey(keyNorm)...)

	if strings.HasSuffix(keyCanon, "id") {
		out = append(out, r.allIDLikeValues()...)
		out = append(out, dict.allIDLikeValues()...)
		for i := 0; i < 3; i++ {
			out = append(out, mutateBusinessID(r.allIDLikeValues()))
		}
	}
	out = filterUsefulStrings(out)
	out = uniqStrings(out)
	return out
}

func (r *RuntimeStore) pickCustomPayloadValue(key string, dict *DictStore, fallback string) string {
	cands := r.customPayloadCandidates(key, dict)
	if len(cands) > 0 {
		return cands[rand.Intn(len(cands))]
	}
	if fallback != "" {
		return fallback
	}
	return "CUSTOM_PAYLOAD"
}

func (r *RuntimeStore) pickDynamic(depName string, dict *DictStore) (string, string) {
	if v := r.getDepValue(depName); v != "" {
		return v, "dep_known"
	}
	for _, k := range inferDependencyKeys(depName) {
		cands := r.customPayloadCandidates(k, dict)
		if len(cands) > 0 {
			return cands[rand.Intn(len(cands))], "dep_" + k
		}
	}
	return "1", "dep_default"
}
