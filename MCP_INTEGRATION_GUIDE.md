# Using MCP to Enrich the Fuzzer Dictionary

Model Context Protocol (MCP) is an excellent way to provide an AI agent with access to your application's real data (database, internal REST API, or logs). This allows the agent to automatically extract valid identifiers, tokens, and business values for fuzzing.

In UpsideFuzzer, the dictionary is loaded from the `dict.json` file, and the engine (in `store.go`) actively uses the `restler_custom_payload*` sections to inject values into request parameters. By populating this dictionary with real data, the fuzzer's effectiveness (especially for GET, PUT, and DELETE requests) increases dramatically, as it stops hitting `404 Not Found` errors.

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
> After that, open the `grammars/eshop/dict.json` file and add these values to the `restler_custom_payload` section."

## Step 3: How to Properly Populate `dict.json`

The `dict.json` file contains several sections for custom data. The UpsideFuzzer engine (in the `store.go` file) reads them and uses them for substitution.

The format for adding data to `restler_custom_payload` should be a mapping of "parameter name" -> "array of values".

**Example BEFORE enrichment:**
```json
{
  "restler_fuzzable_string": ["fuzzstring"],
  "restler_custom_payload": {},
  "restler_custom_payload_unquoted": {}
}
```

**Example AFTER enrichment by the AI agent via MCP:**
```json
{
  "restler_fuzzable_string": ["fuzzstring"],
  "restler_custom_payload": {
    "productId": ["101", "102", "105", "200"],
    "categoryId": ["1", "2", "3"],
    "userEmail": ["admin@eshop.com", "test@user.com"]
  },
  "restler_custom_payload_unquoted": {
    "status": ["true", "false"]
  }
}
```

### Differences Between Sections:
- `restler_custom_payload`: Values will be used in the JSON body as strings (in quotes) or as path/query parameters.
- `restler_custom_payload_unquoted`: Values will be inserted into JSON without quotes (useful for numbers and booleans).
- `restler_custom_payload_header`: For specific HTTP headers (e.g., authorization tokens).
- `restler_custom_payload_query`: Strictly for Query String parameters.

*Note: The UpsideFuzzer Go engine automatically canonicalizes keys (removes special characters, converts to lowercase), so `productId`, `ProductID`, and `product_id` will all be matched successfully.*

## Step 4: Export and Run

Since the Go engine doesn't read `dict.json` directly but uses compiled templates, you must rebuild the export file after updating the dictionary:

```bash
# Export the updated dictionary to the fuzzer format
python3 void/export-templates.py \
  --grammar-dir grammars/eshop \
  --out grammars/eshop/templates.export.json
```

Now, when you start the fuzzer, you will see an increased number of loaded values in the logs:

```bash
docker run ... void-fuzzer -grammar /grammar ...
# In logs:
# Loaded dictionary: /grammar/dict.json
# Bootstrap learned runtime values: 85  <-- Was 23, now 85!
```

## Conclusion: Automated Pipeline (Advanced)

In the future, you can fully automate this process by writing a small Python script, e.g., `mcp-dict-enricher.py`, that:
1. Acts as an MCP client.
2. Connects to your database/REST API MCP server.
3. Programmatically requests the necessary keys (taking the list of keys from the swagger).
4. Automatically parses the responses and modifies `dict.json`.
5. Calls `export-templates.py`.

This will allow you to run the fuzzer in CI/CD pipelines where the dictionary is always fresh and relevant to the current state of the test database.
