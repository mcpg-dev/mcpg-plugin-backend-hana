# SAP HANA Binding (`dev.mcpg.backend.hana`)

A **backend (binding)** plugin that runs an operator-fixed SQL statement against
a SAP HANA database over its native HDB SQL protocol and returns rows as JSON.
Each binding declares **one statement** against an operator-configured
`host`/`port` + credentials, and that binding becomes one MCP tool (or resource
/ prompt) — the `sql`/`oracle`/`clickhouse` envelope model. Dispatches over the
pure-Rust `hdbconnect_async` driver (rustls TLS — no native-tls / OpenSSL) with
a lazy `bb8` connection pool.

## How a binding runs

- The statement uses `?` **positional placeholders** bound from `params` — an
  ordered list of CEL expressions evaluated against the tool arguments
  (`arguments.*`). Each value is bound as a **server-side prepared-statement
  parameter** (`HdbValue`), never interpolated into the statement text, so
  caller input can **never alter the statement** (injection-safe). `params[i]`
  → the i-th `?`.
- Only scalar binds are allowed (string / int / float / bool / null); arrays and
  objects are rejected at call time (a single `?` can't carry them).
- Each call gets a pooled connection, prepares the operator-fixed statement,
  executes it with the bound row, and materializes capped JSON object-rows
  (column display-name → value). A statement that returns no result set (a write
  under `read_only: false`) yields zero rows.

## Binding config (`backend: { kind: hana, ... }`)

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | *(required)* | HANA host. Operator-configured, never caller-templated → no SSRF. |
| `port` | int | *(required)* | HDB SQL port (e.g. `39015` for a single-host HANA Express tenant). |
| `user` | string | *(required)* | HANA dbuser. |
| `password` | string | *(required)* | dbuser password, resolved from a config-origin `${cred://…}` / `${env.X}` reference. A missing / empty value is rejected at register. |
| `database` | string | `host:port` (label) | Optional explicit tenant DB (HANA MDC); also the envelope `request.database` label. |
| `use_tls` | bool | `true` | Connect over TLS. `false` → plaintext (trusted networks only). |
| `tls_verify_peer` | bool | `true` | Verify the server TLS certificate chain. `false` → no-verify (self-signed dev only). |
| `tls_ca_cert` | string | *(none)* | Trust-anchor PEM (resolved from `${file://…}`); when set the server chain is checked against it, else the webpki roots. |
| `operation` | enum | `query` | `query` \| `list_tables` \| `list_columns`. The catalog operations introspect HANA's `SYS.TABLES` / `SYS.TABLE_COLUMNS` and ignore `query` / `params` / `read_only` (see [Schema discovery](#schema-discovery)). |
| `query` | string | *(required for `operation: query`)* | The operator-fixed statement; `?` placeholders bound from `params`. Ignored (omittable) for the catalog operations. |
| `params` | string[] | `[]` | Ordered CEL expressions; `params[i]` → the i-th `?`. Used by `operation: query` only. |
| `read_only` | bool | `true` | Read-only guard (see below). Ignored by the catalog operations (always read-only). |
| `schema` / `table` / `table_type` / `column` | string | *(none)* | Static catalog filters for `operation: list_tables` / `list_columns`. Each is **bound** as a `?` parameter (never interpolated). `table_type` is `list_tables`-only; `column` is `list_columns`-only. **`list_columns` requires a `table` (or `table_arg`).** |
| `schema_arg` / `table_arg` / `table_type_arg` / `column_arg` | string | *(none)* | Tool-argument name supplying the matching filter at call time. When the named argument is a string it overrides the static filter; the value is **bound** as a `?` parameter — never interpolated into SQL. |
| `pool_max_size` | int | `6` | bb8 connection-pool max size. The pool is lazy — no socket opens until the first call. |
| `timeout_ms` | int | `5000` | Per-call ceiling (outer tokio timeout around connect + prepare + fetch); also the pool `connection_timeout`. |
| `max_rows` | int | `10000` | Client-side row cap; extra rows set the envelope `truncated` flag. |
| `max_result_bytes` | int | `8388608` | Client-side serialized-row byte cap; reaching it stops materializing and sets `truncated`. |
| `surface` | enum | `tool` | `tool` \| `resource` \| `prompt` — the MCP surface this binding serves. |
| `uri` | string | *(none)* | Static resource URI for `surface: resource` (else the requested URI is used). |
| `list_query` | object | *(none)* | Operator-fixed listing statement for `resources/list` (keyset / offset pagination). |
| `read_query` | string | *(none)* | Operator-fixed per-`{id}` single-row read for a `resource_templates[]` binding (`surface: resource`). `?` placeholders bound from `params`; the gateway-extracted `{var}` arrives as `arguments.<var>` and binds **server-side** (never interpolated). Held to the read-only guard. When set, `query` may be omitted (see [Resource templates](#resource-templates-per-id-read)). |
| `variable_completions` | map | `{}` | Per-template-variable completion query for `completion/complete`; the single `?` is bound to the typed prefix. |

### Read-only guard

When `read_only` is `true` (the default):

- The operator-fixed `query` (and any `list_query` / `variable_completions` SQL)
  must begin with a read-only keyword (`SELECT` / `WITH`) — checked at register
  (leading whitespace + `--` / `/* */` comments are stripped first; fail-closed
  on an empty/unparseable statement) and re-asserted per call.

Set `read_only: false` to allow writes / `CALL` (operator responsibility).

### TLS

The driver's transport is rustls 0.23 + rustls-webpki (a hard dependency of
`hdbconnect_impl`) — there is **no native-tls / OpenSSL** anywhere in the tree.
With `use_tls: true` (default) and `tls_verify_peer: true` the server chain is
verified against `tls_ca_cert` (when set) or the webpki roots. `tls_verify_peer:
false` opts into a no-verify connection (self-signed dev only); `use_tls: false`
is a plaintext connection for trusted internal networks.

### Secrets

The password (and any other secret) must arrive through a config-origin
`${cred://…}` / `${env.X}` reference resolved at config load. A **bare** `cred://`
left in the `query` (or `list_query` / `variable_completions` SQL) is rejected at
register — it would otherwise be sent to HANA verbatim.

## Response envelope

The tool surface emits the structured envelope:

```json
{
  "toolName": "...",
  "profile": "...",
  "request": { "database": "HXE" },
  "response": { "rows": [ ... ], "count": 12, "truncated": false, "durationMs": 7 },
  "downstreamError": null,
  "downstreamErrors": [],
  "error": null
}
```

A non-null `downstreamError` is the gateway's `is_error` signal. Transient
network / timeout / pool failures are retryable `transport_error`s; syntax /
type / privilege rejections are non-retryable `hana_error`s.

The `resource` surface reshapes successful rows into `{contents:[{uri,text,
mimeType}]}` and the `prompt` surface into `{messages:[{role,content}]}`.

## Resource templates (per-`{id}` read)

A `surface: resource` binding placed under `resource_templates[]` serves a
parameterised resource family (`uri_template: "hana://orders/{id}"`). On a
`resources/read` of a concrete URI the gateway extracts each `{var}` and supplies
it in the call arguments as `arguments.<var>`. Set `read_query` to the
single-row read and bind the extracted variable from `params` — it is bound
**server-side** as a prepared-statement parameter, never interpolated into SQL,
so a crafted value (e.g. `1 OR 1=1; DROP TABLE x`) is carried as one opaque
string bind and can never alter the statement. When `read_query` is set, `query`
may be omitted. The matched row is returned as the `resources/read`
`{contents:[…]}` body.

```yaml
resource_templates:
  - name: order
    uri_template: "hana://orders/{id}"
    backend:
      kind: hana
      host: hana.example
      port: 39015
      user: MCPG
      password: ${cred://hana/mcpg#password}
      surface: resource
      read_query: "SELECT * FROM ORDERS WHERE ID = ?"
      params: ["arguments.id"]
```

## Schema discovery

Set `operation` to one of the two catalog-introspection modes to let an agent
discover the schema of the HANA database without writing SQL:

- `operation: list_tables` → selects from **`SYS.TABLES`** — one row per table /
  view with columns `SCHEMA_NAME`, `TABLE_NAME`, `TABLE_TYPE`.
- `operation: list_columns` → selects from **`SYS.TABLE_COLUMNS`** — one row per
  column with `SCHEMA_NAME`, `TABLE_NAME`, `COLUMN_NAME`, `DATA_TYPE_NAME`,
  `LENGTH`, `IS_NULLABLE`, `POSITION` (ordered by table then `POSITION`).

Both are inherently **read-only** metadata selects (no read-only-guard concern)
and ignore `query` / `params` / `read_only`. The SQL skeleton is **code-fixed**
(only `SYS.*` column names appear in it); the schema / table / type / column
filters are **bound as `?` parameters** — they are **never** interpolated into
SQL — so a caller-supplied filter can only narrow the metadata returned, never
alter the select (injection-safe by construction). A static filter pins a value;
a `*_arg` filter lets the caller choose one per call (and overrides the static
value when present as a string). An absent / empty filter matches all. The result
is marshalled through the same row → JSON path as a query and wrapped in the same
`response.rows` envelope; `output_schema` types the rows to the catalog column set
above, and `input_schema` surfaces the configured `*_arg` names.

`list_columns` requires a `table` filter or a `table_arg` (the table whose
columns to list), so a call never enumerates every column in the database.

### Discover tables, caller-scoped by schema

```yaml
mcp:
  configurations:
    - tools:
        - name: hana.list_tables
          backend:
            kind: hana
            host: "hana.internal"
            port: 39015
            user: "MCPG"
            password: "${cred://hana/password}"
            operation: list_tables
            # Caller may pass {"schema": "SALES"} to scope; bound as a parameter.
            schema_arg: schema
```

### Discover a table's columns

```yaml
mcp:
  configurations:
    - tools:
        - name: hana.list_columns
          backend:
            kind: hana
            host: "hana.internal"
            port: 39015
            user: "MCPG"
            password: "${cred://hana/password}"
            operation: list_columns
            table: ORDERS        # or table_arg to let the caller choose
            schema: SALES
```

## Change-watching

A resource can subscribe to HANA changes through the plugin's second entity — a
**polling `watch_strategy`** (kind `hana_poll`). HANA has no native change-push
channel for this binding, so the strategy runs a cheap read-only scalar
**high-water query** (`tracking_query`) on a cadence and emits
`notifications/resources/updated` whenever that scalar advances. The first tick
only records a baseline, so a watcher never fires spuriously at startup.

Attach it under a resource's `watch:` block. The watch carries its own
connection (it is not tied to the binding's profile) plus the tracking query:

```yaml
mcp.configurations[].resources[].watch:
  type: plugin
  kind: hana_poll
  host: "hana.internal"
  port: 39015
  user: "MCPG"
  password: "${cred://hana/password}"
  database: "HXE"
  tracking_query: "SELECT max(UPDATED_AT) FROM EVENTS"
  interval_ms: 30000
```

**Watch spec fields**

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | *(required)* | HANA host. Operator-fixed. |
| `port` | int | *(required)* | HDB SQL port (e.g. `39015`). |
| `user` | string | *(required)* | HANA dbuser. |
| `password` | string | *(none)* | dbuser password (config-resolved `${cred://…}` / `${env.X}`). |
| `database` | string | *(none)* | Optional explicit tenant DB (HANA MDC). |
| `use_tls` | bool | `true` | Connect over TLS; `false` → plaintext. |
| `tls_verify_peer` | bool | `true` | Verify the server TLS chain; `false` → no-verify (self-signed dev only). |
| `tls_ca_cert` | string | *(none)* | Trust-anchor PEM; when set the server chain is verified against it, else the webpki roots. |
| `pool_max_size` | int | `1` | bb8 pool size for the watcher's polling connection. |
| `tracking_query` | string | *(required)* | Read-only scalar high-water query; its first-row first-column value is the cursor. |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick query budget (server-side + wall-clock). |

The `tracking_query` is held to the same read-only keyword guard (`SELECT` /
`WITH`) as the backend `query`; an empty or non-read-only query is rejected at
watch start. A tick returning zero rows (or a NULL scalar) is treated as "no
change"; transient connect / query failures are logged and retried on the next
tick.

## Observability

- `mcpg_hana_backend_latency_seconds` (histogram, `outcome` label)
- `mcpg_hana_backend_calls_total` (counter, `outcome` label)
- audit events `dev.mcpg.backend.hana.{request_timeout,request_failed,query_rejected}` on failures
- `audit_metadata` → `{ "hana.transport": "plugin" }`

## Tests

`cargo test -p mcpg-plugin-backend-hana --lib` runs the offline unit suite (no
live HANA) — config parse/validate, CEL params, the `HdbValue` → JSON
marshaller, surface shaping, list/completion mapping, schemas, the read-only
guard, the lazy-pool guarantee (registration opens no socket), and the
catalog-discovery query builders (asserting filters bind as `?` parameters and
never appear in the SQL text).

The integration suite is **env-gated** (SAP HANA Express is license-locked — no
testcontainer):

```bash
export HANA_TEST_HOST=my-hana.example
export HANA_TEST_PORT=39015          # HDB SQL port
export HANA_TEST_USER=MCPG
export HANA_TEST_PASSWORD=...
# optional:
export HANA_TEST_DATABASE=HXE
export HANA_TEST_TLS=1                # "1"/"true" → TLS (default plaintext)
export HANA_TEST_TLS_VERIFY=0         # "0"/"false" → no-verify (self-signed)
cargo test -p mcpg-plugin-backend-hana \
    --features integration-tests --test integration -- --test-threads 1
```

When `HANA_TEST_*` is unset the suite SKIPS (returns early). When set it
registers a parameterised read profile, runs a bound `SELECT … = ?`, asserts the
bound `?` filters correctly, and proves an injection probe is treated as data.
