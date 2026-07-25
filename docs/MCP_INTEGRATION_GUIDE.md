# Using MCP to Enrich the Fuzzer Dictionary

Model Context Protocol (MCP) is an excellent way to provide an AI agent with access to your application's real data (database, internal REST API, or logs). This allows the agent to automatically extract valid identifiers, tokens, and business values for fuzzing.

In UpsideFuzz, the dictionary is loaded from `dict.json` — a flat `{fieldName: [values...]}` map — and the engine (`void/go/store.go::loadDict`/`candidatesForKey`) uses it to pick real-looking values for request fields it recognizes by name. By populating this dictionary with real data, the fuzzer's effectiveness (especially for GET, PUT, and DELETE requests) increases dramatically, as it stops hitting `404 Not Found` errors on IDs that don't exist.

**Have the agent write to `dict.custom.json`, not `dict.json`.** `dict.json` is regenerated and fully overwritten by every `compile-grammar.sh` run, so an MCP-enriched `dict.json` survives exactly until someone next recompiles the grammar (e.g. because the target's API changed) — an easy, silent way to lose an agent's work. `dict.custom.json`, in the same `grammars/<target>/` directory, has the opposite lifecycle: written once as a starter file, never touched again by the tooling, and auto-merged into `dict.json` on every compile from then on. Same flat format, same directory, zero downside — see [INSTRUCTIONS.md §10](../INSTRUCTIONS.md#10-custom-dictionary-format) for the full mechanism. Everything below applies identically to `dict.custom.json`; just point the agent at that filename instead.

Here is a step-by-step guide on how to set up this process.

## Step 1: Connect an MCP Server

You need an MCP server that can read data from your target system. Possible options:

1. **Direct Database Access:** You can use standard MCP servers for PostgreSQL, MySQL, or SQLite. The agent will be able to execute SQL queries to extract data.
2. **Internal REST API:** If you have an administrative API, you can write a simple MCP server (in Python or TypeScript) that queries this API and provides the agent with the resulting JSON data.
3. **Logs / ELK / Splunk:** An MCP server can search for recent successful requests in logs and extract valid parameters from them.

*Example of connecting the Postgres MCP in Cursor or Claude Desktop:*
```json
{
  "mcpServers": {
    "eshop-db": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://user:pass@localhost:5432/eshop"]
    }
  }
}
```

## Step 2: AI Agent Prompt

Once the MCP server is connected, you can give the AI agent a task to gather data and update the dictionary. The prompt should look something like this:

> "Use the `query_database` tool (or access the REST API via MCP) to retrieve 50 existing `ProductId`s, 20 `CategoryId`s, and 10 valid `UserEmail`s from the eShop database.
> After that, open `grammars/eshop/dict.custom.json` (create it by running `compile-grammar.sh` once first if it doesn't exist yet) and add these values under the matching field-name keys (`productId`, `categoryId`, `userEmail`), keeping the existing `_readme` key as-is."

## Step 3: How to Populate `dict.custom.json`

`dict.custom.json` is a **flat map**, identical in format to `dict.json` (the auto-generated file it gets merged into — see [INSTRUCTIONS.md §10](../INSTRUCTIONS.md#10-custom-dictionary-format)): each key is a request field/payload name, each value an array of candidate strings. `void/go/store.go::candidatesForKey` matches keys case-insensitively with canonical normalization, so `productId`, `ProductID`, and `product_id` all resolve to the same pool — you don't need multiple casings.

**Example BEFORE enrichment** (the starter scaffold `compile-grammar.sh` writes the first time — its `_readme` key is safe to leave in place, the engine never looks up a field literally named `_readme`):
```json
{
  "_readme": ["... — see INSTRUCTIONS.md section 10"],
  "exampleFieldName": ["REPLACE-ME -- not a real field in this target, delete this key once you've added your own"]
}
```

**Example AFTER enrichment by the AI agent via MCP** — delete the placeholder, add real keys:
```json
{
  "_readme": ["... — see INSTRUCTIONS.md section 10"],
  "productId": ["101", "102", "105", "200"],
  "categoryId": ["1", "2", "3"],
  "userEmail": ["admin@eshop.com", "test@user.com"],
  "status": ["true", "false"]
}
```

No separate "quoted vs. unquoted" or "query vs. header vs. body" sections needed — the value is inserted quoted or unquoted based on the *segment's* own declared type in `templates.export.json` (`quoted: true/false`, set at grammar-compile time from the OpenAPI schema), not from where in the dictionary it came from.

*Legacy note: older dictionaries used a one-level-nested RESTler-shaped format (`{"restler_custom_payload": {"productId": [...]}}`). That format still works as `--dict` input — `grammarc/emit_dict.py::merge_external_dict` flattens it automatically — but `compile-grammar.sh` never generates it anymore, and there's no reason to write it by hand today. Use the flat format above.*

## Step 4: Run — one caveat depending on which file you edited

The Go engine only ever reads `dict.json` at startup — `void/go/store.go::loadDict` is called fresh each time from the path you pass via `-dict` or `<grammar-dir>/dict.json`. It never reads `dict.custom.json` directly. That gives you two options, trading off speed against durability:

| You edited... | To pick it up | Survives the next `compile-grammar.sh`? |
|---|---|---|
| `dict.json` directly | Just restart the fuzzer — no compile step | **No.** Overwritten on the next compile. Fine for a quick one-off session. |
| `dict.custom.json` | Run `compile-grammar.sh` once more first (fast, no Docker — it only re-derives `templates.export.json`/`dict.json` from the spec) to merge it in, *then* start the fuzzer | **Yes.** This is the durable path — recommended for anything you'll want again. |

```bash
# Durable path: merge dict.custom.json into a fresh dict.json, then run
./compile-grammar.sh swagger.json --out grammars/eshop
docker run ... void-fuzzer -grammar /grammar ...
# In logs:
# Loaded dictionary: /grammar/dict.json
# Bootstrap learned runtime values: 85  <-- Was 23, now 85!
```

If you don't see the value count increase, double check you edited the file the running container actually mounts (`-grammar`'s directory), not a stale copy elsewhere — and, if you edited `dict.custom.json`, that you re-ran `compile-grammar.sh` before starting the fuzzer.

## Conclusion: Automated Pipeline (Advanced)

In the future, you can fully automate this process by writing a small Python script, e.g., `mcp-dict-enricher.py`, that:
1. Acts as an MCP client.
2. Connects to your database/REST API MCP server.
3. Programmatically requests the necessary keys (taking the list of keys from the swagger, or by reading the field names already present in an existing `dict.json`/`templates.export.json`).
4. Automatically parses the responses and merges new values into `dict.custom.json`'s flat key→values map (not `dict.json` — see Step 4).

This runs cleanly in CI/CD pipelines where the dictionary is always fresh and relevant to the current state of the test database: enrich `dict.custom.json` from the database, then run `compile-grammar.sh` (which merges it into a freshly-regenerated `dict.json`) before each fuzzing run.
