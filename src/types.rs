//! Operator-facing spec for the SAP HANA backend plugin.
//!
//! One binding = one operator-fixed SQL statement = one MCP tool (or resource /
//! prompt). The server connection (`host` / `port` / `user` / `password` / TLS
//! knobs), the read-only guard, the statement and the query bounds all live on
//! the per-binding spec, mirroring the clickhouse/oracle one-profile-per-binding
//! shape.

use serde::Deserialize;

/// Operator-facing spec the gateway serializes when calling `register_profile`.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct HanaBackendSpec {
    /// HANA host (operator-configured, never caller-templated — no SSRF vector).
    pub host: String,

    /// HDB SQL port (e.g. 39015 for the SYSTEMDB / a tenant on a single-host
    /// HANA Express). Operator-configured.
    pub port: u16,

    /// HANA database user.
    pub user: String,

    /// HANA password (resolved from `${cred://…}` / `${env.X}` at config load;
    /// a bare `cred://` is rejected at register — see `lib.rs`). Required: HANA
    /// authenticates with a password, so a missing / empty value is rejected at
    /// register with a clear hint.
    #[serde(default)]
    pub password: Option<String>,

    /// Optional explicit tenant database name (HANA MDC). When omitted the
    /// connection targets the database the `port` resolves to; the value is
    /// purely a label on the response envelope when set.
    #[serde(default)]
    pub database: Option<String>,

    /// Verify the server's TLS certificate chain + hostname. Default true. When
    /// true the connection runs over rustls; with a `tls_ca_cert` the server
    /// chain is checked against that PEM, otherwise against the webpki roots.
    /// Set false ONLY for self-signed dev servers (the chain is not verified).
    #[serde(default = "default_tls_verify_peer")]
    pub tls_verify_peer: bool,

    /// Optional trust-anchor PEM for TLS. When set the server certificate chain
    /// is verified against this CA (resolved from `${file://…}` at config load).
    /// When omitted (and `tls_verify_peer` is true) the webpki roots are used.
    /// An empty / whitespace value means "no TLS" — a plaintext connection.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,

    /// Whether to connect over TLS at all. Default true. When false the
    /// connection is plaintext (HDB SQL without TLS) and the TLS knobs are
    /// ignored — for trusted internal networks only.
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,

    /// Which operation this binding performs. `query` (default) runs the
    /// operator-fixed `query` statement; `list_tables` / `list_columns` query
    /// HANA's `SYS.TABLES` / `SYS.TABLE_COLUMNS` catalog views for portable
    /// schema discovery. The catalog operations ignore `query` / `params` /
    /// `read_only` (they are inherently read-only metadata selects).
    #[serde(default)]
    pub operation: HanaOperation,

    /// The operator-fixed statement for `operation: query`. Uses `?` positional
    /// bind placeholders bound from `params`. The statement text is
    /// operator-fixed — it is NOT templated from caller arguments. Required for
    /// `operation: query`; ignored (and may be omitted) for the catalog
    /// operations.
    #[serde(default)]
    pub query: String,

    /// Static schema-name filter for the catalog operations (`SCHEMA_NAME`).
    /// Bound as a `?` parameter — never interpolated into the SQL. Absent =
    /// match all schemas. May be overridden per call via `schema_arg`.
    #[serde(default)]
    pub schema: Option<String>,
    /// Static table-name filter for the catalog operations (`TABLE_NAME`). For
    /// `operation: list_columns` this is the table whose columns are listed.
    /// Bound as a `?` parameter — never interpolated. Absent = match all tables.
    #[serde(default)]
    pub table: Option<String>,
    /// Static table-type filter for `operation: list_tables` (`TABLE_TYPE`, e.g.
    /// `TABLE`, `VIEW`). Bound as a `?` parameter. Ignored by `list_columns`.
    #[serde(default)]
    pub table_type: Option<String>,
    /// Static column-name filter for `operation: list_columns` (`COLUMN_NAME`).
    /// Bound as a `?` parameter. Ignored by `list_tables`.
    #[serde(default)]
    pub column: Option<String>,

    /// Tool-argument name supplying the schema filter at call time. When set and
    /// present as a JSON string in the call arguments, the caller value
    /// overrides the static `schema`. Bound as a `?` parameter — never SQL.
    #[serde(default)]
    pub schema_arg: Option<String>,
    /// Tool-argument name supplying the table filter at call time.
    #[serde(default)]
    pub table_arg: Option<String>,
    /// Tool-argument name supplying the table-type filter (`list_tables`).
    #[serde(default)]
    pub table_type_arg: Option<String>,
    /// Tool-argument name supplying the column filter (`list_columns`).
    #[serde(default)]
    pub column_arg: Option<String>,

    /// Ordered CEL expressions; `params[i]` → the i-th `?`. Each is evaluated
    /// against the call arguments (`arguments.*`) and bound as a server-side
    /// prepared-statement parameter — injection-safe.
    #[serde(default)]
    pub params: Vec<String>,

    /// Read-only guard. When true (default) the operator-fixed statement must
    /// begin with a read-only keyword (SELECT / WITH) at register. Set false to
    /// allow writes / CALL (operator responsibility).
    #[serde(default = "default_read_only")]
    pub read_only: bool,

    /// bb8 connection-pool max size (default 6). The pool is built at register
    /// but opens NO connection until the first call.
    #[serde(default = "default_pool_max_size")]
    pub pool_max_size: u32,

    /// Per-call ceiling (ms) on the whole request (default 5000). Enforced as
    /// the outer tokio timeout around connect + prepare + fetch.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Client-side cap on returned rows (default 10000). Extra rows set the
    /// envelope `truncated` flag.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,

    /// Client-side cap on the serialized result-row byte size (default 8 MiB).
    /// Reaching the cap stops materializing further rows and sets `truncated`.
    #[serde(default = "default_max_result_bytes")]
    pub max_result_bytes: usize,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope; `resource` reshapes successful rows into the
    /// `resources/read` `{contents:[…]}` body; `prompt` reshapes them into the
    /// `prompts/get` `{messages:[…]}` body.
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding (`surface: resource` with a `uri_template` like
    /// `hana://orders/{id}`). On a `resources/read` of a concrete URI the gateway
    /// extracts the template variables and supplies them in the call arguments
    /// (each `{var}` as `arguments.<var>`); this statement's `?` placeholders are
    /// bound from the binding's `params` CEL expressions (`arguments.<var>`), so
    /// the extracted value binds SERVER-SIDE as a prepared-statement parameter —
    /// never interpolated into SQL (injection-safe). When omitted the
    /// resource-read branch falls back to `query`. Operator-fixed; required to be
    /// read-only under the read-only guard.
    #[serde(default)]
    pub read_query: Option<String>,

    /// Optional listing statement for `resources/list`. On a `surface: resource`
    /// binding this runs at list time to enumerate concrete resource URIs.
    /// Operator-fixed; the only caller-derived inputs are the paginated
    /// `?cursor` / `?page_size` binds. Empty → no dynamic listing.
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,

    /// Optional per-template-variable completion config for
    /// `completion/complete`. Keyed by the URI template variable name; each
    /// entry is an operator-fixed query whose single `?` is bound to the
    /// caller-typed prefix (never interpolated — injection-safe). Empty → no
    /// completion candidates.
    #[serde(default)]
    pub variable_completions: std::collections::BTreeMap<String, CompletionConfig>,
}

/// The operation a binding performs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HanaOperation {
    /// Run the operator-fixed `query` statement with `?` binds (the default).
    #[default]
    Query,
    /// Discover tables/views via `SYS.TABLES`.
    ListTables,
    /// Discover a table's columns via `SYS.TABLE_COLUMNS`.
    ListColumns,
}

impl HanaOperation {
    /// Lowercase wire token (matches the `serde` rename).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HanaOperation::Query => "query",
            HanaOperation::ListTables => "list_tables",
            HanaOperation::ListColumns => "list_columns",
        }
    }

    /// Whether this is a catalog-introspection operation (inherently read-only,
    /// driven by a `SYS.*` select, not by the `query` statement).
    #[must_use]
    pub fn is_catalog(self) -> bool {
        matches!(self, HanaOperation::ListTables | HanaOperation::ListColumns)
    }
}

fn default_tls_verify_peer() -> bool {
    true
}
fn default_use_tls() -> bool {
    true
}
fn default_read_only() -> bool {
    true
}
fn default_pool_max_size() -> u32 {
    6
}
fn default_timeout_ms() -> u64 {
    5_000
}
fn default_max_rows() -> usize {
    10_000
}
fn default_max_result_bytes() -> usize {
    8 * 1024 * 1024
}

/// Pagination strategy for [`ListQueryConfig`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListQueryMode {
    /// `WHERE cursor_column > ? ORDER BY cursor_column LIMIT ?`. The first `?`
    /// is the keyset cursor (NULL on the first page); the second is page_size.
    #[default]
    Keyset,
    /// `LIMIT ? OFFSET ?` — the first `?` is page_size, the second the offset.
    Offset,
}

/// Operator-fixed listing statement + pagination shape for `resources/list`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListQueryConfig {
    /// SELECT that returns one row per enumerable resource. Required column:
    /// `uri`. Optional columns: `name`, `description`, `mime_type`. The
    /// statement is operator-fixed; the pagination binds (`?cursor` /
    /// `?page_size`) are the only non-operator values.
    pub sql: String,
    /// Pagination mode — `keyset` (default) or `offset`.
    #[serde(default)]
    pub mode: ListQueryMode,
    /// Column the keyset cursor tracks (typically `id` or `updated_at`).
    /// Required for `mode: keyset`; ignored for `mode: offset`.
    #[serde(default)]
    pub cursor_column: Option<String>,
    /// Rows per page (1..=1000). Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Operator-fixed completion query for one template variable.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompletionConfig {
    /// SQL returning candidate values in its first column. MUST reference a
    /// single `?` placeholder — bound to the caller-typed prefix at call time
    /// (e.g. `SELECT name FROM repos WHERE name LIKE ? || '%' LIMIT 100`).
    pub sql: String,
    /// Optional cap on returned candidates; defaults to 100.
    #[serde(default)]
    pub max_results: Option<u32>,
}

fn default_list_page_size() -> u64 {
    100
}

/// Read-only / safe-identifier validation for an operator-fixed
/// [`ListQueryConfig`]. Fail-closed at register so misconfig never reaches a
/// `resources/list` call.
pub fn validate_list_query(cfg: &ListQueryConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err("list_query.sql must not be empty".into());
    }
    if cfg.page_size == 0 || cfg.page_size > 1_000 {
        return Err(format!(
            "list_query.page_size ({}) must be in 1..=1000",
            cfg.page_size
        ));
    }
    if cfg.mode == ListQueryMode::Keyset {
        let col = cfg.cursor_column.as_deref().unwrap_or("").trim();
        if col.is_empty() {
            return Err("list_query.cursor_column is required for mode: keyset".into());
        }
        if !is_safe_sql_identifier(col) {
            return Err(format!(
                "list_query.cursor_column '{col}' is not a safe SQL identifier"
            ));
        }
    }
    Ok(())
}

/// Validate an operator-fixed [`CompletionConfig`]: non-empty SQL referencing
/// exactly one `?` placeholder (the bound prefix).
pub fn validate_completion(name: &str, cfg: &CompletionConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err(format!("variable_completions.{name}.sql must not be empty"));
    }
    if count_bind_placeholders(&cfg.sql) != 1 {
        return Err(format!(
            "variable_completions.{name}.sql must reference exactly one `?` placeholder (bound to the typed prefix)"
        ));
    }
    Ok(())
}

/// Count `?` bind placeholders. HANA SQL uses `?` for positional parameters and
/// has no `??` escape, so each `?` is one bind.
pub fn count_bind_placeholders(sql: &str) -> usize {
    sql.bytes().filter(|&b| b == b'?').count()
}

/// A safe SQL identifier — `[A-Za-z_][A-Za-z0-9_]*`. Used to fence the
/// operator-declared keyset `cursor_column`, which is interpolated into the
/// next-cursor projection.
fn is_safe_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_applies_defaults_when_omitted() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "query": "SELECT 1 AS ONE FROM DUMMY",
        }))
        .unwrap();
        assert!(spec.read_only);
        assert!(spec.tls_verify_peer);
        assert!(spec.use_tls);
        assert_eq!(spec.pool_max_size, 6);
        assert_eq!(spec.timeout_ms, 5_000);
        assert_eq!(spec.max_rows, 10_000);
        assert_eq!(spec.max_result_bytes, 8 * 1024 * 1024);
        assert!(spec.password.is_none());
        assert!(spec.database.is_none());
        assert!(spec.params.is_empty());
    }

    #[test]
    fn operation_defaults_to_query() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "query": "SELECT 1 AS ONE FROM DUMMY",
        }))
        .unwrap();
        assert_eq!(spec.operation, HanaOperation::Query);
        assert!(!spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "query");
    }

    #[test]
    fn parses_list_tables_operation_with_filters() {
        // `query` may be omitted for catalog operations.
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "operation": "list_tables",
            "schema": "SALES",
            "table_type": "VIEW",
            "schema_arg": "schema",
        }))
        .unwrap();
        assert_eq!(spec.operation, HanaOperation::ListTables);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "list_tables");
        assert_eq!(spec.schema.as_deref(), Some("SALES"));
        assert_eq!(spec.table_type.as_deref(), Some("VIEW"));
        assert_eq!(spec.schema_arg.as_deref(), Some("schema"));
        assert!(spec.query.is_empty());
    }

    #[test]
    fn parses_list_columns_operation() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "operation": "list_columns",
            "table": "ORDERS",
            "column_arg": "column",
        }))
        .unwrap();
        assert_eq!(spec.operation, HanaOperation::ListColumns);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.table.as_deref(), Some("ORDERS"));
        assert_eq!(spec.column_arg.as_deref(), Some("column"));
    }

    #[test]
    fn parses_overrides_and_auth() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 30015,
            "user": "READER",
            "password": "s3cr3t",
            "database": "HXE",
            "tls_verify_peer": false,
            "use_tls": false,
            "query": "SELECT * FROM EVENTS WHERE ID = ?",
            "params": ["arguments.id"],
            "read_only": false,
            "pool_max_size": 12,
            "timeout_ms": 2000,
            "max_rows": 50,
            "max_result_bytes": 1024,
        }))
        .unwrap();
        assert_eq!(spec.user, "READER");
        assert_eq!(spec.password.as_deref(), Some("s3cr3t"));
        assert_eq!(spec.database.as_deref(), Some("HXE"));
        assert!(!spec.tls_verify_peer);
        assert!(!spec.use_tls);
        assert!(!spec.read_only);
        assert_eq!(spec.pool_max_size, 12);
        assert_eq!(spec.timeout_ms, 2000);
        assert_eq!(spec.max_rows, 50);
        assert_eq!(spec.max_result_bytes, 1024);
    }

    #[test]
    fn parses_list_query_and_completions() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "query": "SELECT 1 AS ONE FROM DUMMY",
            "surface": "resource",
            "list_query": {
                "sql": "SELECT ID AS URI FROM T WHERE ID > ? ORDER BY ID LIMIT ?",
                "cursor_column": "ID",
                "page_size": 50,
            },
            "variable_completions": {
                "name": { "sql": "SELECT NAME FROM T WHERE NAME LIKE ? || '%' LIMIT 100" },
            },
        }))
        .unwrap();
        let lq = spec.list_query.expect("list_query");
        assert_eq!(lq.page_size, 50);
        assert_eq!(lq.mode, ListQueryMode::Keyset);
        assert_eq!(lq.cursor_column.as_deref(), Some("ID"));
        assert!(spec.variable_completions.contains_key("name"));
    }

    #[test]
    fn parses_resource_template_read_query() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "surface": "resource",
            "read_query": "SELECT * FROM ORDERS WHERE ID = ?",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(
            spec.read_query.as_deref(),
            Some("SELECT * FROM ORDERS WHERE ID = ?")
        );
        // `query` may be omitted when `read_query` carries the read.
        assert!(spec.query.is_empty());
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn read_query_defaults_to_none() {
        let spec: HanaBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "query": "SELECT 1 AS ONE FROM DUMMY",
        }))
        .unwrap();
        assert!(spec.read_query.is_none());
    }

    #[test]
    fn validate_list_query_enforces_bounds_and_cursor() {
        let mut cfg = ListQueryConfig {
            sql: "SELECT ID AS URI FROM T".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(
            validate_list_query(&cfg).is_err(),
            "keyset needs cursor_column"
        );
        cfg.cursor_column = Some("ID".into());
        assert!(validate_list_query(&cfg).is_ok());
        cfg.cursor_column = Some("ID; DROP TABLE T".into());
        assert!(
            validate_list_query(&cfg).is_err(),
            "unsafe cursor identifier"
        );
        cfg.cursor_column = Some("ID".into());
        cfg.page_size = 0;
        assert!(validate_list_query(&cfg).is_err(), "page_size out of range");
        cfg.page_size = 100;
        cfg.sql = "  ".into();
        assert!(validate_list_query(&cfg).is_err(), "empty sql");
    }

    #[test]
    fn validate_list_query_offset_mode_skips_cursor() {
        let cfg = ListQueryConfig {
            sql: "SELECT ID AS URI FROM T LIMIT ? OFFSET ?".into(),
            mode: ListQueryMode::Offset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(validate_list_query(&cfg).is_ok());
    }

    #[test]
    fn validate_completion_requires_single_placeholder() {
        let mut cc = CompletionConfig {
            sql: "SELECT NAME FROM T WHERE NAME LIKE ? || '%'".into(),
            max_results: None,
        };
        assert!(validate_completion("name", &cc).is_ok());
        cc.sql = "SELECT NAME FROM T".into();
        assert!(validate_completion("name", &cc).is_err(), "needs one ?");
        cc.sql = "SELECT NAME FROM T WHERE A = ? AND B = ?".into();
        assert!(validate_completion("name", &cc).is_err(), "exactly one ?");
        cc.sql = "  ".into();
        assert!(validate_completion("name", &cc).is_err(), "empty sql");
    }

    #[test]
    fn count_bind_placeholders_counts_each_question_mark() {
        assert_eq!(count_bind_placeholders("SELECT ? FROM DUMMY"), 1);
        assert_eq!(count_bind_placeholders("A = ? AND B = ?"), 2);
        assert_eq!(count_bind_placeholders("SELECT 1 FROM DUMMY"), 0);
    }
}
