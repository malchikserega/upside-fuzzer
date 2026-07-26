# UpsideFuzz — SimplCommerce Quick Start

> Run the full coverage-guided fuzzing pipeline on **SimplCommerce** (a complex, modular e-commerce application) from scratch on any machine. This guide demonstrates how to inject custom authorization into the fuzzer.

**→ [Back to README](../README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](FUZZER_AUTHENTICATION.md) · [Docs Index](INDEX.md)**

---

## Prerequisites

```bash
docker --version        # Docker 24+
docker compose version  # Compose v2+
python3 --version       # Python 3.9+
```

---

## Step 1: Clone repositories

```bash
# Clone the fuzzer
git clone https://github.com/malchikserega/upside-fuzzer.git
cd upside-fuzzer

# Clone SimplCommerce (target application)
git clone https://github.com/simplcommerce/SimplCommerce.git simplcommerce
cd simplcommerce
git checkout 4b0d1e5 # Use a specific commit if necessary, or latest main
cd ..
```

---

## Step 2: Instrument the project

SimplCommerce is a highly modular application. We provide a `simpl_namespaces.json` file in the `examples/simplcommerce/` directory to instruct the instrumentor to only track coverage in the core modules and avoid noisy third-party dependencies.

```bash
python3 fuzz-prep-multi.py \
  --src ./simplcommerce \
  --out ./simplcommerce_prep \
  --main src/SimplCommerce.WebHost \
  --namespaces examples/simplcommerce/simpl_namespaces.json
```

> **Zero-edit by default** (`--inject-mode hook`): the target's `Program.cs`/`Startup.cs`/`.csproj` are not modified. SimplCommerce loads its store modules **dynamically at runtime** — the hook's `AssemblyLoad` handler links those module assemblies to coverage as they load (the legacy one-shot linker missed them). To use the legacy source-injection path instead, append `--inject-mode source`. After startup, verify module coverage is linked: `curl -s http://localhost:8080/shm/health` → `linked_assemblies` should climb as modules load.

**Docker Workdir Adjustment**:
Because SimplCommerce compiles its modular DLLs into the `src/SimplCommerce.WebHost/out` directory during the Docker build stage, you must edit the generated `Dockerfile` in `simplcommerce_prep` to ensure the instrumentor runs in the right path.

Find the instrumentation section in `simplcommerce_prep/Dockerfile` and insert `WORKDIR /app/src/SimplCommerce.WebHost`:

```dockerfile
# (Inside simplcommerce_prep/Dockerfile)
# ... build steps ...
WORKDIR /app/src/SimplCommerce.WebHost
COPY instrumentor /instrumentor
RUN dotnet /instrumentor/instrumentor.dll out out
# ...
```

---

## Step 3: Sanitize Swagger

SimplCommerce's automatically generated Swagger definition contains some redundant or invalid path parameters that a strict OpenAPI parser (including `grammarc/oas.py`, RESTler's first-party replacement — see `ARCHITECTURE_REVIEW.md`'s Grammar Generation section) chokes on.

Start the instrumented stack, download the swagger, then run the provided patch helper:

```bash
cd simplcommerce_prep
docker compose -f docker-compose.instrumented.yml up -d simpldb instrumented
sleep 40
curl -s http://localhost:7777/swagger/v1/swagger.json -o swagger-simplcommerce.json

cd ..
python3 examples/simplcommerce/fix_swagger_paths.py
```
The checked-in helper rewrites the downloaded swagger into `simplcommerce_prep/swagger-sanitized.json`.

---

## Step 4: Compile the Grammar

RESTler is retired (Top-20 #9/#10) — compile the sanitized swagger file directly with
`grammarc/` + `dotnet/analyzer/` (one command, no Docker), writing `templates.export.json` +
`dict.json` straight to `grammars/simplcommerce/`:

```bash
./compile-grammar.sh simplcommerce_prep/swagger-sanitized.json --src ./simplcommerce --out grammars/simplcommerce
```

No extra flags needed for two things that run automatically during the fuzz run below:
constrained fields get boundary-aware mutation (`ARCHITECTURE_REVIEW.md`'s Fuzzing Engine section), and
400 validation-error responses get mined for required fields/valid values fed back into the
runtime dictionary (Top-20 #11) — useful here given SimplCommerce's anti-forgery/Identity
validation layer.

---

## Step 5: Inject Authentication

SimplCommerce's APIs are heavily protected by `[Authorize(Roles = "admin, vendor")]` attributes and Anti-Forgery tokens. Without credentials, the fuzzer will only hit `401 Unauthorized`.

We use a Python script to perform an automated login and dump the session cookies into an environment file.

```bash
cd simplcommerce_prep

# Reuse the running stack from Step 3 and generate the auth cookie
python3 ../examples/simplcommerce/get_cookie.py
```

This script will log in as `admin@simplcommerce.com` and generate a `fuzzer.env` file containing the `AUTH_COOKIE` environment variable.

Edit `docker-compose.instrumented.yml` to inject this file into the `smartfuzzer` service:

```yaml
  smartfuzzer:
    image: upsidefuzz-void
    env_file:
      - fuzzer.env
    environment:
      - TARGET_URL=http://instrumented:80
      # ...
```

---

## Step 6: Start Fuzzing

With everything prepared, launch the fuzzer!

```bash
docker compose -f docker-compose.instrumented.yml up -d --force-recreate smartfuzzer

# View live logs
docker logs -f simplcommerce_prep-smartfuzzer-1
```

**What to look for in the logs:**
- `Authenticated (cookie/header auth available)`
- `Pre-harvested 1 anti-forgery token(s) from /`
- Rapidly increasing `edges=` coverage count!

## Step 7: Analyze Results

By default, the fuzzer runs for the allocated time budget (e.g., 5 hours / 300 minutes). To stop it earlier and dump the final reports, issue a graceful stop with a timeout:

```bash
docker stop -t 10 simplcommerce_prep-smartfuzzer-1

# Copy the crash reports to your host machine
docker cp simplcommerce_prep-smartfuzzer-1:/fuzzer/crashes .
docker cp simplcommerce_prep-smartfuzzer-1:/fuzzer/summaries .
```

You can find the reproduced CURL scripts for any 500 Internal Server Errors in `summaries/report-*.json` and the unique stack traces in `crashes/unique-crashes-*.jsonl`.

---

## The same thing, via the `upsidefuzz` CLI

Step 2 (instrument) and Step 4 (grammar) map directly onto CLI subcommands. Steps 3
(swagger sanitize) and 5 (cookie login) are SimplCommerce-specific helper scripts with no
generic CLI equivalent — keep running those exactly as documented above, then hand their
output to the CLI subcommands. Step 6's fuzz run switches from the Docker-Compose
`smartfuzzer` service to `upsidefuzz fuzz` running `void` directly against the same
published port:

```bash
# Native: python3 upsidefuzz.py ...   |   Zero-install (only Docker needed): ./upsidefuzz ...
upsidefuzz instrument --src ./simplcommerce --out ./simplcommerce_prep --main src/SimplCommerce.WebHost

upsidefuzz up --dir ./simplcommerce_prep --services simpldb instrumented --wait-secs 40

# Step 3 (swagger download + fix_swagger_paths.py) stays manual -- see above -- then:
upsidefuzz verify --base http://localhost:7777

upsidefuzz grammar simplcommerce_prep/swagger-sanitized.json --src ./simplcommerce --out grammars/simplcommerce

# Step 5 (get_cookie.py) stays manual -- see above -- then, instead of editing
# docker-compose.instrumented.yml's smartfuzzer service, just export what it wrote:
export $(cat simplcommerce_prep/fuzzer.env | xargs)   # loads AUTH_COOKIE
upsidefuzz fuzz --grammar grammars/simplcommerce --target http://localhost:7777 \
  --profile security --time-budget 15
```

See [docs/CLI.md](docs/CLI.md) for the full subcommand reference.

---

**→ [Back to README](../README.md) · [Full Runbook](INSTRUCTIONS.md) · [SimplCommerce Report](reports/SIMPLCOMMERCE_REPORT.md)**
