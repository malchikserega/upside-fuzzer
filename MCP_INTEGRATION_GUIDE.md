# Using MCP to Enrich the Fuzzer Dictionary

Model Context Protocol (MCP) is an excellent way to provide an AI agent with access to your application's real data (database, internal REST API, or logs). This allows the agent to automatically extract valid identifiers, tokens, and business values for fuzzing.

In UpsideFuzz, the dictionary is loaded from `dict.json` — a flat `{fieldName: [values...]}` map — and the engine (`void/go/store.go::loadDict`/`candidatesForKey`) uses it to pick real-looking values for request fields it recognizes by name. By populating this dictionary with real data, the fuzzer's effectiveness (especially for GET, PUT, and DELETE requests) increases dramatically, as it stops hitting `404 Not Found` errors on IDs that don't exist.

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
> After that, open `grammars/eshop/dict.json` and add these values under the matching field-name keys (`productId`, `categoryId`, `userEmail`)."

## Step 3: How to Populate `dict.json`

`dict.json` is a **flat map**: each key is a request field/payload name, each value an array of candidate strings. `void/go/store.go::candidatesForKey` matches keys case-insensitively with canonical normalization, so `productId`, `ProductID`, and `product_id` all resolve to the same pool — you don't need multiple casings.

**Example BEFORE enrichment** (this is roughly what `compile-grammar.sh` auto-generates from OpenAPI/Roslyn constraints — see [INSTRUCTIONS.md §10](INSTRUCTIONS.md#10-custom-dictionary-format)):
```json
{
  "name": ["fuzzstring", "sample"],
  "price": ["0", "1", "-1", "0.01"]
}
```

**Example AFTER enrichment by the AI agent via MCP** — just add new keys or extend existing ones:
```json
{
  "name": ["fuzzstring", "sample"],
  "price": ["0", "1", "-1", "0.01"],
  "productId": ["101", "102", "105", "200"],
  "categoryId": ["1", "2", "3"],
  "userEmail": ["admin@eshop.com", "test@user.com"],
  "status": ["true", "false"]
}
```

No separate "quoted vs. unquoted" or "query vs. header vs. body" sections needed — the value is inserted quoted or unquoted based on the *segment's* own declared type in `templates.export.json` (`quoted: true/false`, set at grammar-compile time from the OpenAPI schema), not from where in the dictionary it came from.

*Legacy note: older dictionaries used a one-level-nested RESTler-shaped format (`{"restler_custom_payload": {"productId": [...]}}`). That format still works as `--dict` input — `grammarc/emit_dict.py::merge_external_dict` flattens it automatically — but `compile-grammar.sh` never generates it anymore, and there's no reason to write it by hand today. Use the flat format above.*

## Step 4: Run — no export/compile step needed

Unlike the pipeline in a previous version of this project (which used to require re-exporting a compiled `grammar.py`-derived template file after any dictionary edit), the Go engine reads `dict.json` **directly at startup**, every run — `void/go/store.go::loadDict` is called fresh each time from the path you pass via `-dict` or `<grammar-dir>/dict.json`. Just edit the file and start the fuzzer:

```bash
docker run ... void-fuzzer -grammar /grammar ...
# In logs:
# Loaded dictionary: /grammar/dict.json
# Bootstrap learned runtime values: 85  <-- Was 23, now 85!
```

If you don't see the value count increase, double check you edited the `dict.json` the running container actually mounts (`-grammar`'s directory), not a stale copy elsewhere.

## Conclusion: Automated Pipeline (Advanced)

In the future, you can fully automate this process by writing a small Python script, e.g., `mcp-dict-enricher.py`, that:
1. Acts as an MCP client.
2. Connects to your database/REST API MCP server.
3. Programmatically requests the necessary keys (taking the list of keys from the swagger, or by reading the field names already present in an existing `dict.json`/`templates.export.json`).
4. Automatically parses the responses and merges new values into `dict.json`'s flat key→values map.

Because there's no compile/export step, this will run cleanly in CI/CD pipelines where the dictionary is always fresh and relevant to the current state of the test database — just regenerate `dict.json` before each fuzzing run.
