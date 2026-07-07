# UpsideFuzz — BTCPayServer Quick Start

> Run the full coverage-guided fuzzing pipeline on **BTCPayServer** (Greenfield API) from scratch on any machine.

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

# Clone BTCPayServer (target application)
git clone https://github.com/btcpayserver/btcpayserver.git
```

---

## Step 2: Instrument the project

```bash
python3 fuzz-prep-multi.py \
  --src ./btcpayserver \
  --out ./btcpayserver_prep \
  --main BTCPayServer
```

This creates an instrumented copy in `./btcpayserver_prep/` with:
- SharpFuzz IL instrumentation for all business logic DLLs
- Docker Compose configuration adapted for testing

> **Note:** BTCPayServer relies on background PostgreSQL, NBXplorer, and Bitcoin node containers for its initialization. The `docker-compose.instrumented.yml` automatically connects to these services assuming they are running (e.g. via `BTCPayServer.Tests`).

---

## Step 3: Build and start the target

```bash
cd btcpayserver_prep
docker compose -f docker-compose.instrumented.yml up -d instrumented

# Wait for database migrations and connection to NBXplorer
sleep 45
```

---

## Step 4: Authentication & API Key

BTCPayServer's Greenfield API requires an API key. 

You can automatically register an admin user and generate an API key by running the helper script:

```bash
# Inside btcpayserver_prep
python3 get_apikey.py
```

This will save the generated API key as an authorization header in `fuzzer.env`.

---

## Step 5: Extract OpenAPI Spec (Swagger)

The fuzzer uses the OpenAPI specification to generate its grammar. Download the Swagger JSON from the running server:

```bash
curl -s -u admin@btcpayserver.local:Password123! http://localhost:7777/swagger/v1/swagger.json > swagger-btc.json
```

---

## Step 6: Compile the grammar

```bash
cd ..  # back to upside-fuzzer root

# Compile grammar (RESTler compiler + source-aware enhancement)
# Note: BTCPayServer's Swagger JSON has a malformed reference that needs to be patched
python3 fix_swagger_paths.py  # A script you must create to replace "#/components/parameters/Subscriptions/Currency" with "#/components/parameters/Subscriptions_Currency"
./compile-grammar.sh btcpayserver_prep/swagger-btc.json --src ./btcpayserver

# Save grammar files
mkdir -p grammars/btcpay
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/btcpay/

# Export templates for the Go fuzzer
python3 void/export-templates.py \
  --grammar-dir grammars/btcpay \
  --out grammars/btcpay/templates.export.json
```

> **Pro Tip:** Open `grammars/btcpay/dict.json` and augment the `restler_fuzzable_string` array with domain-specific professional terms (e.g., `"BTC"`, `"SATS"`, `"HighSpeed"`, `"Settled"`, `"xpub661..."`). This significantly increases the probability of passing strict API validation checks, allowing the fuzzer to explore deeper state transitions rather than being blocked at the schema validation layer.

---

## Step 7: Build the fuzzer Docker image

```bash
# Create empty go.sum if missing (no external deps)
touch void/go/go.sum

docker build -t void-fuzzer -f void/Dockerfile.go void/
```

---

## Step 8: Run the fuzzer (Direct SHM mode)

```bash
mkdir -p crashes

docker run -it --rm \
  --network btcpayserver_prep_default \
  -v btcpayserver_prep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/btcpay:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  --env-file btcpayserver_prep/fuzzer.env \
  -e TARGET_HOST=http://btcpayserver_prep-instrumented-1:8080 \
  -e SHM_HOST=http://btcpayserver_prep-instrumented-1:8080 \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 15 \
  -concurrency 10 \
  -sequence-prob 0.35
```

**What happens:**
- The fuzzer automatically loads the authorization header from `fuzzer.env`. *(Note: the underlying auth parsing logic universally supports arbitrary custom headers like `Authorization: token <key>` without breaking standard `Bearer` tokens for other projects).*
- The exported templates retain full RESTler Producer/Consumer mapping, allowing the Sequence Engine to test deep stateful workflows automatically.
- The fuzzer reads the coverage bitmap directly from the shared `coverage_shm` tmpfs volume.
- Runs with high concurrency and deep fuzzing sequences for 15 minutes.

> **Note on 401/404 Errors in Logs:** During fuzzing, you will likely see many `401 Unauthorized` or `404 Not Found` blocks in the UI logs (e.g., `[AUTH-BLOCK] DELETE /api/v1/stores/{param}`). This is **expected and desirable**. It means the fuzzer is dynamically testing Resource-Based Authorization by attempting to access or mutate resources with fuzzed IDs (e.g., trying to delete a store owned by another user, or an invalid UUID). The Sequence Engine specifically falls back to randomized UUIDs when producers fail to generate real IDs, ensuring these critical authorization boundaries are stress-tested.

---

## Step 9: View results

```bash
# Unique crashes (deduplicated)
cat crashes/unique-crashes-*.jsonl | \
  python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"

# Generated PoC scripts
ls crashes/pocs/
```
