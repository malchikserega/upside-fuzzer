# UpsideFuzz — Jellyfin Quick Start

> Run the full coverage-guided fuzzing pipeline on **Jellyfin** (`jellyfin/jellyfin`) from
> scratch on any machine.

**→ [Back to README](../../../README.md) · [Full Runbook](../../getting-started/quickstart.md) · [Authentication Guide](../authentication.md) · [Findings Report](../../reports/JELLYFIN_REPORT.md) · [Docs Index](../../index.md)**

---

## Why Jellyfin

A real, large, actively-maintained open-source media server — 60 controllers, 364
OpenAPI operations, ~1900 `.cs` files — picked specifically as a new target this repo
hadn't fully documented bring-up for. This quickstart covers multi-identity `-auth-file`
fuzzing exactly like every other target in this repo, verified end to end from a
completely fresh clone.

Unlike `fixtures/demo-app`/eShopOnWeb/Bitwarden, Jellyfin ships **no Dockerfile at
all** in its own repo (the official `jellyfin/jellyfin` Docker image is built from a
separate packaging pipeline) — so `bin/fuzz-prep-multi.py` falls back to generating one
from scratch. That path had never been exercised end-to-end against a real ASP.NET
Core app before this quickstart, and exposed three real, worth-knowing issues (one
was a genuine bug in `bin/fuzz-prep-multi.py` itself, now fixed; two are Jellyfin-specific
Dockerfile quirks documented below as manual patches, the same way Bitwarden needed a
hand-written compose file).

## Prerequisites

```bash
docker --version        # Docker 24+
docker compose version  # Compose v2+
python3 --version       # Python 3.9+
```

No local .NET SDK is required for the fuzzing pipeline itself (everything builds
inside Docker) — only if you want the optional standalone sanity-check in Step 0.

---

## Step 0: Clone

```bash
git clone https://github.com/malchikserega/upside-fuzzer.git
cd upside-fuzzer

git clone https://github.com/jellyfin/jellyfin.git jellyfin_src
```

`jellyfin_src/global.json` pins the SDK to `10.0.x` (`rollForward: latestMinor`) — the
main project (`Jellyfin.Server/Jellyfin.Server.csproj`) targets `net10.0`.
`bin/fuzz-prep-multi.py` reads this automatically; nothing to configure.

---

## Step 1: Instrument the project

```bash
python3 bin/fuzz-prep-multi.py --src jellyfin_src --out /tmp/jf-prep --main Jellyfin.Server
```

Expect:
```
No original Dockerfile found, generating from scratch.
Generated Dockerfile from scratch.
Generated compose file from scratch.
Generated zero-edit coverage hook assembly in coverage_hook_src/ (TFM net10.0)
Instrumented Projects: 17
```

### Required manual patches (Jellyfin-specific — apply before building)

The generated `/tmp/jf-prep/Dockerfile`'s final (runtime) stage needs three additions.
All three were found by actually trying to bring the container up, not guessed —
each is a real startup failure with a one-line fix:

1. **ffmpeg.** Jellyfin hard-requires `ffmpeg` at startup
   (`MediaEncoder.ValidateVersion`) even for pure API fuzzing that never transcodes
   anything — without it, the app throws `FfmpegException: Failed to find valid
   ffmpeg` and never binds a port at all.
2. **The static-web-assets manifest.** The generated Dockerfile's build stage uses
   `dotnet build`, not `dotnet publish` (needed so each project keeps its own `bin/`
   folder for per-project instrumentation — see the comment already in
   `docker_gen.py`). For an ASP.NET Core app, `dotnet build` bakes the **build
   machine's own absolute `wwwroot`/`obj/.../compressed` paths** into a static-web-
   assets manifest; none of those paths exist in the runtime image (only the compiled
   DLLs get copied there), so `StaticWebAssetsLoader` throws
   `DirectoryNotFoundException` on the first missing path and the app never starts.
   Since this target never serves static content anyway (`--nowebclient` below),
   deleting the manifest is enough — `UseStaticWebAssets()` no-ops when it's absent.
3. **`--nowebclient` + explicit data dirs.** `jellyfin-web` (the JS frontend) is a
   separate repo, never copied into this image, and isn't part of the REST API
   surface being fuzzed.

```bash
cd /tmp/jf-prep
python3 - <<'PY'
from pathlib import Path
p = Path("Dockerfile")
content = p.read_text()
content = content.replace(
    'WORKDIR /app\nCOPY --from=instrumentation /src/Jellyfin.Server/bin/Release/net10.0/ .',
    'WORKDIR /app\n'
    'RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*\n'
    'COPY --from=instrumentation /src/Jellyfin.Server/bin/Release/net10.0/ .\n'
    'RUN rm -f jellyfin.staticwebassets.runtime.json jellyfin.staticwebassets.endpoints.json',
)
content = content.replace(
    'EXPOSE 8080\nENV ASPNETCORE_URLS=http://+:8080\nENTRYPOINT ["dotnet", "jellyfin.dll"]',
    'EXPOSE 8096\n'
    'ENTRYPOINT ["dotnet", "jellyfin.dll", "--nowebclient", "--datadir", "/data", "--cachedir", "/cache", "--configdir", "/config"]',
)
p.write_text(content)
PY
```

> **⚠️ Jellyfin always listens on 8096, never on `ASPNETCORE_URLS`/`EXPOSE`'s
> port.** Jellyfin manages its own Kestrel endpoint config (`network.xml` under
> `--configdir`) and **ignores `ASPNETCORE_URLS`/`HTTP_PORTS` entirely** — setting
> `ASPNETCORE_URLS=http://+:8080` (this template's usual convention for every other
> target) still leaves the server answering only on 8096. Get this wrong and every
> request comes back `connection reset by peer` on the host side (Docker's
> port-forward proxy resets rather than refuses when nothing's listening on the
> mapped container port) with **zero** application-level log output — nothing ever
> reaches Kestrel. The patch above already fixes `EXPOSE`; also fix the port mapping
> in `docker-compose.instrumented.yml` (next step).

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docker-compose.instrumented.yml")
p.write_text(p.read_text().replace(":8080", ":8096"))
PY
```

---

## Step 2: Build and start the instrumented container

```bash
cd /tmp/jf-prep
docker compose -f docker-compose.instrumented.yml up -d --build
curl http://localhost:7777/health   # -> "Healthy"
```

First build takes a few minutes (restores + instruments 17 projects across a ~1900-file
solution). `docker compose down` when you're done.

---

## Step 3: Verify coverage instrumentation

```bash
curl -s http://localhost:7777/shm/health
# -> {"linked_assemblies":1,"total_classes":6608,"shm_bound":true,
#     "mode":"file-backed-mmap","instrumented_types":2646,...}

cd /tmp/jf-prep
chmod +x verify_coverage.sh
./verify_coverage.sh http://localhost:7777 /health
# -> {"edges":6950,"hits":43293,...}
# -> OK: coverage is active (edges=6950). Instrumentation verified.
```

---

## Step 4: Complete the first-run wizard, then compile the grammar

Jellyfin requires an admin account before most endpoints do anything useful. Do this
once per fresh container:

```bash
curl -s http://localhost:7777/Startup/User        # -> {"Name":"root"} (default seed name)

curl -s -X POST http://localhost:7777/Startup/User \
  -H "Content-Type: application/json" \
  -d '{"Name":"admin","Password":"FuzzAdmin123!"}'  # -> 204

curl -s -X POST http://localhost:7777/Startup/Complete   # -> 204
```

Grammar compilation reads the live OpenAPI spec — Jellyfin serves it at
**`/api-docs/openapi.json`**, not the `/swagger/v1/swagger.json` convention most other
targets in this repo use:

```bash
cd /path/to/upside-fuzzer
curl -s http://localhost:7777/api-docs/openapi.json -o /tmp/jf-swagger.json
./bin/compile-grammar.sh /tmp/jf-swagger.json --out grammars/jellyfin --src jellyfin_src
```

Expect:
```
[analyzer] Parsed 1906 files (0 failed), 1592 classes, 63 controller candidates.
[grammarc] operations=364 templates=364 skipped=0 multipart_endpoints=0 roslyn_matched_types=0 dict_keys=946
```

> **Honest caveat:** `roslyn_matched_types=0` — the Roslyn constraint extractor found
> 386 endpoints but couldn't correlate any of them back to a matching request-DTO type
> for boundary-value extraction (`[Range]`/`[StringLength]`), unlike `fixtures/demo-app`
> where this reliably matches. The grammar still compiles correctly from the OpenAPI
> spec alone (all 364 operations present); you just don't get Top-20 #14's
> boundary-aware mutation bonus on this target. Not investigated further — flagging it
> here rather than silently pretending it works.

---

## Step 5: Collect auth tokens — Jellyfin's non-standard auth scheme

**Jellyfin does not accept `Authorization: Bearer <token>`** — the fuzzer's default
scheme for every other target. Its `AuthorizationContext` only recognizes
`Authorization: MediaBrowser Token="...", Client="...", Device="...", DeviceId="...",
Version="..."` (or the legacy `Emby` scheme name, only if `EnableLegacyAuthorization`
is on). Use `auth.identities.json`'s per-identity `headers` field (not `jwt`) to set
this exact header.

First create a second, non-admin user for genuine cross-identity BOLA coverage —
grab an admin token, then use it once to create `member`:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:7777/Users/AuthenticateByName \
  -H "Content-Type: application/json" \
  -H 'Authorization: MediaBrowser Client="UpsideFuzz", Device="UpsideFuzz", DeviceId="upsidefuzz-setup", Version="1.0.0"' \
  -d '{"Username":"admin","Pw":"FuzzAdmin123!"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessToken'])")

curl -s -X POST http://localhost:7777/Users/New \
  -H "Content-Type: application/json" \
  -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\", Client=\"UpsideFuzz\", Device=\"UpsideFuzz\", DeviceId=\"upsidefuzz-setup\", Version=\"1.0.0\"" \
  -d '{"Name":"member","Password":"FuzzMember123!"}'
```

Then build `auth.identities.json` with both real users plus `guest` — this is the
exact 3-identity set the verified run below used:

```bash
python3 - <<'EOF'
import json, urllib.request

base = "http://localhost:7777"
users = [("admin", "FuzzAdmin123!", "admin", 1.5), ("member", "FuzzMember123!", "member", 1.0)]

identities = []
for username, password, name, weight in users:
    req = urllib.request.Request(
        f"{base}/Users/AuthenticateByName",
        data=json.dumps({"Username": username, "Pw": password}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": 'MediaBrowser Client="UpsideFuzz", Device="UpsideFuzz", DeviceId="upsidefuzz-1", Version="1.0.0"',
        },
    )
    token = json.load(urllib.request.urlopen(req))["AccessToken"]
    auth_header = f'MediaBrowser Token="{token}", Client="UpsideFuzz", Device="UpsideFuzz", DeviceId="upsidefuzz-1", Version="1.0.0"'
    identities.append({"name": name, "weight": weight, "headers": {"Authorization": auth_header}})

identities.append({"name": "guest", "weight": 0.3})

with open("/tmp/jf-auth.identities.json", "w") as f:
    json.dump({"version": "1", "identities": identities}, f, indent=2)
print("wrote /tmp/jf-auth.identities.json")
EOF
```

A single admin identity plus `guest` is enough to prove the pipeline works, but won't
exercise BOLA the way a second real user does — skip the `POST /Users/New` step and
drop `member` from the `users` list above if you just want the fast path.

---

## Step 6: Strip self-destructive endpoints from the grammar

> **⚠️ Required whenever `admin` is one of your identities.** `POST /System/Restart`
> and `POST /System/Shutdown` are real, admin-gated Jellyfin endpoints
> (`SystemController.RestartApplication`/`.Shutdown`) — with `admin` in the identity
> pool, the fuzzer *will* eventually call one of them, which tears down the whole
> server process (`IHostApplicationLifetime.StopApplication()`) with no Docker
> `--restart` policy in place to bring it back. First attempt at the verified run
> below died at ~7 minutes exactly this way — the container just silently exits
> (code 0) and stays down; the remaining time budget is wasted hitting a dead target.
> See [JELLYFIN_REPORT.md](../../reports/JELLYFIN_REPORT.md)'s "Operational Note" for
> the full log trace.

```bash
python3 -c "
import json
p = 'grammars/jellyfin/templates.export.json'
d = json.load(open(p))
before = len(d['templates'])
d['templates'] = [t for t in d['templates']
                   if '/System/Restart' not in t.get('request_id', '')
                   and '/System/Shutdown' not in t.get('request_id', '')]
d['count'] = len(d['templates'])
json.dump(d, open(p, 'w'), indent=2)
print(f'{before} -> {len(d[\"templates\"])} templates')
"
```

---

## Step 7: Build the fuzzer image and run it

```bash
cd /path/to/upside-fuzzer
docker build -t void-fuzzer -f deployments/docker/Dockerfile.void .
```

Quick check (~3 minutes):

```bash
mkdir -p crashes summaries
docker run --rm \
  --network jf-prep_default \
  -v jf-prep_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/jellyfin:/grammar:ro" \
  -v "/tmp/jf-auth.identities.json:/auth/auth.identities.json:ro" \
  -v "$(pwd)/crashes:/fuzzer/crashes" \
  -v "$(pwd)/summaries:/fuzzer/summaries" \
  -e TARGET_HOST=http://jf-prep-instrumented-1:8096 \
  -e SHM_HOST=http://jf-prep-instrumented-1:8096 \
  void-fuzzer \
  -grammar /grammar -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode mmap \
  -profile security -auth-file /auth/auth.identities.json -time-budget 3 \
  -crash-file /fuzzer/crashes/unique-crashes.jsonl \
  -summary-file /fuzzer/summaries/summary.json
```

`-time-budget` is **minutes**, not seconds (`src/void/internal/config/flags.go`) — `3` here is
a real ~3-minute run. `jf-prep_default`/`jf-prep_coverage_shm` are the compose
project's auto-named network/volume (`jf-prep` = the `--out` directory's basename);
adjust if you picked a different path. `TARGET_HOST`/`SHM_HOST` use the **container
name** (`jf-prep-instrumented-1`) and **container port** (`8096`, not `8080` —
see Step 1's warning), reachable over the compose network, not the host's published
port mapping.

### Longer scan (20 minutes, max settings — what produced the verified results below)

```bash
docker run -d --name jf-fuzz-run20 \
  --network jf-prep_default \
  -v jf-prep_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/jellyfin:/grammar:ro" \
  -v "/tmp/jf-auth.identities.json:/auth/auth.identities.json:ro" \
  -v "$(pwd)/crashes:/fuzzer/crashes" \
  -v "$(pwd)/summaries:/fuzzer/summaries" \
  -e TARGET_HOST=http://jf-prep-instrumented-1:8096 \
  -e SHM_HOST=http://jf-prep-instrumented-1:8096 \
  void-fuzzer \
  -grammar /grammar -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode mmap \
  -profile security -auth-file /auth/auth.identities.json -time-budget 20 \
  -concurrency 32 -sequence-max-depth 4 -no-ui \
  -crash-file /fuzzer/crashes/unique-crashes.jsonl \
  -summary-file /fuzzer/summaries/summary.json
```

Runs detached (`-d`, named container instead of `--rm`) so a 20-minute run isn't tied
to a foreground shell; `docker logs jf-fuzz-run20` to check on it, `docker wait
jf-fuzz-run20` to block until it finishes.

### Verified result (2026-07-30, fresh clone, 20-minute run, `-concurrency 32`)

**100,076 coverage edges** (baseline-ceiling 49,137 — mutation found +103.7% beyond
the initial baseline epoch), 400,255 requests sent at 333 req/s, 9 crashes
deduplicating to **2 unique** signatures (one root cause, two endpoints), plus 12
schema-conformance findings. Full writeup, stack traces, and repro commands for every
finding: **[JELLYFIN_REPORT.md](../../reports/JELLYFIN_REPORT.md)**.

- **`GET /LiveTv/Timers/Defaults?programId=<non-GUID>` → real 500** —
  `System.FormatException: Unrecognized Guid format.` at
  `LiveTvManager.GetNewTimerDefaults` → `Guid..ctor`. 100% reproducible.
- **`POST /Sessions/Viewing?itemId=<non-GUID>` → real 500** — same
  `FormatException`/`Guid..ctor` root cause, reached through
  `SessionManager.ReportNowViewingItem` instead. 100% reproducible.
- **12 schema-conformance findings** (`-schema-conformance`, on by default in
  `-profile security`) — response bodies don't match the declared OpenAPI schema on
  `/System/Info/Storage` (37 undeclared/mismatched fields), `/System/Configuration`
  (23, largely an entire undeclared `TrickplayOptions` object),
  `/LiveTv/ListingProviders/SchedulesDirect/Countries` (26), and 9 other endpoints.
  Not vulnerabilities — API-contract drift, see the report for the full table.

No BOLA/mass-assignment/injection/race findings in this run — Jellyfin's privileged
resources (`/Users/*`, `/System/*`) correctly gated on `IsAdministrator` against the
`member`/`guest` identities. Absence here means "not found in this run," not "absent
from the app" — see the report's "What you should not overclaim" section.

> **Known Jellyfin operational quirk**: under sustained faulting, Jellyfin can enter a
> degraded state that returns many `503 "Server is loading"` responses. This is a real
> target behavior, not a fuzzer bug — don't read a burst of `503`s as new findings
> without checking whether the server is just recovering.

---

## Cleanup

```bash
cd /tmp/jf-prep
docker compose -f docker-compose.instrumented.yml down -v

# Remove the cloned source + instrumented copy (optional)
cd /path/to/upside-fuzzer
rm -rf jellyfin_src grammars/jellyfin
```

---

## What building this exposed in the fuzzer pipeline itself

One real bug in `bin/fuzz-prep-multi.py`, found and fixed while bringing this target up,
benefits every future target with the same shape (not just Jellyfin):

**Projects with a custom `<AssemblyName>` produced a Dockerfile that referenced the
wrong `.dll` filename everywhere.** `Jellyfin.Server.csproj` sets
`<AssemblyName>jellyfin</AssemblyName>`, so its real build output is `jellyfin.dll`,
not `Jellyfin.Server.dll`. Every DLL path `docker_gen.py` constructed — the
instrumentation `RUN` commands, the cross-project DLL-sync step, and the final
`ENTRYPOINT` — assumed `{project_name}.dll`, which happened to be true for every
target tried before this one (`fixtures/demo-app`'s `TeamFlow.Infrastructure.dll`,
eShopOnWeb, Bitwarden) but is a real, unremarkable MSBuild property to override in
general. Fixed by reading `<AssemblyName>` from each project's `.csproj` during
analysis (`ProjectInfo.assembly_name`/`.dll_name` in `tools/prep/fuzzprep/models.py`,
`analysis.py`) and using it everywhere a `.dll` path was previously built from the
bare project name (`tools/prep/fuzzprep/docker_gen.py`). Covered by
`tools/prep/fuzzprep/test_fuzz_prep_multi.py::AssemblyNameTests`.

The two other issues found (ffmpeg/static-web-assets/port) are genuinely
Jellyfin-specific — not something `bin/fuzz-prep-multi.py` could infer automatically —
and are documented above as manual Dockerfile patches instead, the same way
Bitwarden's multi-service compose file is hand-authored rather than generated.

---

**→ [Back to README](../../../README.md) · [Full Runbook](../../getting-started/quickstart.md) · [Findings Report](../../reports/JELLYFIN_REPORT.md)**
