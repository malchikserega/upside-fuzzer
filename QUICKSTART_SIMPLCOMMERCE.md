# UpsideFuzz — SimplCommerce Quick Start

> Run the full coverage-guided fuzzing pipeline on **SimplCommerce** (a complex, modular e-commerce application) from scratch on any machine. This guide demonstrates how to inject custom authorization into the fuzzer.

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
git clone https://github.com/simplcommerce/SimplCommerce.git simplcommerce_prep
cd simplcommerce_prep
git checkout 4b0d1e5 # Use a specific commit if necessary, or latest main
cd ..
```

---

## Step 2: Instrument the project

SimplCommerce is a highly modular application. We provide a `simpl_namespaces.json` file in the `examples/simplcommerce/` directory to instruct the instrumentor to only track coverage in the core modules and avoid noisy third-party dependencies.

```bash
python3 fuzz-prep-multi.py \
  --src ./simplcommerce_prep \
  --out ./simplcommerce_prep \
  --main src/SimplCommerce.WebHost \
  --namespaces examples/simplcommerce/simpl_namespaces.json
```

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

SimplCommerce's automatically generated Swagger definition contains some redundant or invalid path parameters that conflict with the RESTler compiler.

Run the provided python script to automatically patch the `swagger.json`:

```bash
cd simplcommerce_prep
curl -s http://localhost:7777/swagger/v1/swagger.json -o swagger-simplcommerce.json
# (If SimplCommerce is not running, start it first to get the swagger, or get it from source)

cd ..
python3 examples/simplcommerce/fix_swagger_paths.py
```
*(Ensure `fix_swagger_paths.py` points to the correct location of your downloaded swagger file)*.

---

## Step 4: Compile the Grammar

Compile the sanitized swagger file into the RESTler grammar and export it for the UpsideFuzzer Go engine:

```bash
# Compile grammar (RESTler compiler + source-aware enhancement)
./compile-grammar.sh simplcommerce_prep/swagger-sanitized.json --src ./simplcommerce_prep

# Save grammar files
mkdir -p grammars/simplcommerce
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/simplcommerce/

# Export templates for the Go fuzzer
python3 void/export-templates.py \
  --grammar grammars/simplcommerce/grammar.py \
  --dict grammars/simplcommerce/dict.json \
  --out grammars/simplcommerce/
```

---

## Step 5: Inject Authentication

SimplCommerce's APIs are heavily protected by `[Authorize(Roles = "admin, vendor")]` attributes and Anti-Forgery tokens. Without credentials, the fuzzer will only hit `401 Unauthorized`.

We use a Python script to perform an automated login and dump the session cookies into an environment file.

```bash
cd simplcommerce_prep

# Start the application first
docker compose -f docker-compose.instrumented.yml up -d simpldb
docker compose -f docker-compose.instrumented.yml up -d instrumented

# Wait for the DB to initialize (~40 seconds)
sleep 40

# Run the authentication script
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
