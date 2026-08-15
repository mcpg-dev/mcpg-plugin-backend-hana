//! SAP HANA transport: a lazy bb8-pooled async statement runner over the
//! pure-Rust `hdbconnect_async` driver, the read-only keyword guard, and the
//! `HdbValue` → JSON marshaller.
//!
//! The bb8 `Pool<ConnectionManager>` is built once at `register_profile` via
//! `build_unchecked` with `min_idle = 0` — that opens NO socket (registration
//! stays offline-testable); the first `pool.get()` establishes a connection.
//! Each call gets a pooled `Connection`, prepares the operator-fixed statement,
//! binds the scalar params as a single `execute_row(Vec<HdbValue>)` (server-side
//! prepared parameters — injection-safe), then materializes capped JSON rows.
//! TLS is rustls; the connection verifies the server certificate unless the
//! binding opts out (`tls_verify_peer = false`).

use std::time::Duration;

use bb8::Pool;
use hdbconnect_async::{
    ConnectParamsBuilder, ConnectionManager, HdbValue, ServerCerts, types::DayDate,
};
use serde_json::{Value, json};

use crate::params::HanaBind;

/// The bb8 pool type the profile holds.
pub type HanaPool = Pool<ConnectionManager>;

/// Outcome of a completed query: the JSON rows (capped at `max_rows` /
/// `max_result_bytes`) plus whether more rows existed beyond the cap.
#[derive(Debug)]
pub struct QueryOutcome {
    pub rows: Vec<Value>,
    pub truncated: bool,
    pub row_count: usize,
}

/// Reject a statement that is not read-only. Delegates to the shared hardened
/// guard, which keeps the leading-keyword allowlist and also rejects write/DDL
/// keywords anywhere (write-CTEs), `EXPLAIN ANALYZE`, and stacked statements.
pub fn enforce_read_only(statement: &str) -> Result<(), String> {
    mcpg_plugin_sdk::sql_guard::enforce_read_only(statement)
}

/// Resolved catalog-introspection filters for one `list_tables` /
/// `list_columns` call. Each filter (when non-empty) becomes a `WHERE col = ?`
/// clause whose value is BOUND — never interpolated. An empty filter is omitted
/// (matches all). The column names in the clauses are code-fixed `SYS.*` view
/// columns, so the SQL skeleton carries no caller-derived text.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CatalogFilters {
    pub schema: String,
    pub table: String,
    pub table_type: String,
    pub column: String,
}

/// Build the `SYS.TABLES` discovery query for `operation: list_tables`. Returns
/// the SQL plus the ordered binds for its `?` placeholders. Each present filter
/// adds a `WHERE … = ?` predicate over a fixed `SYS.TABLES` column; the trailing
/// `LIMIT ?` bounds the row count. No filter value ever reaches the SQL text.
pub fn build_list_tables_query(
    filters: &CatalogFilters,
    max_rows: usize,
) -> (String, Vec<HanaBind>) {
    let mut sql = String::from("SELECT SCHEMA_NAME, TABLE_NAME, TABLE_TYPE FROM SYS.TABLES");
    let mut binds: Vec<HanaBind> = Vec::new();
    let mut clauses: Vec<&str> = Vec::new();
    if !filters.schema.is_empty() {
        clauses.push("SCHEMA_NAME = ?");
        binds.push(HanaBind::Str(filters.schema.clone()));
    }
    if !filters.table.is_empty() {
        clauses.push("TABLE_NAME = ?");
        binds.push(HanaBind::Str(filters.table.clone()));
    }
    if !filters.table_type.is_empty() {
        clauses.push("TABLE_TYPE = ?");
        binds.push(HanaBind::Str(filters.table_type.clone()));
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY SCHEMA_NAME, TABLE_NAME LIMIT ?");
    binds.push(HanaBind::Int(max_rows as i64));
    (sql, binds)
}

/// Build the `SYS.TABLE_COLUMNS` discovery query for `operation: list_columns`.
/// Same bound-filter discipline as [`build_list_tables_query`]; the `table_type`
/// filter is not applicable to columns and is ignored. Ordered by table then
/// `POSITION` so columns come back in declaration order.
pub fn build_list_columns_query(
    filters: &CatalogFilters,
    max_rows: usize,
) -> (String, Vec<HanaBind>) {
    let mut sql = String::from(
        "SELECT SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, DATA_TYPE_NAME, LENGTH, \
         IS_NULLABLE, POSITION FROM SYS.TABLE_COLUMNS",
    );
    let mut binds: Vec<HanaBind> = Vec::new();
    let mut clauses: Vec<&str> = Vec::new();
    if !filters.schema.is_empty() {
        clauses.push("SCHEMA_NAME = ?");
        binds.push(HanaBind::Str(filters.schema.clone()));
    }
    if !filters.table.is_empty() {
        clauses.push("TABLE_NAME = ?");
        binds.push(HanaBind::Str(filters.table.clone()));
    }
    if !filters.column.is_empty() {
        clauses.push("COLUMN_NAME = ?");
        binds.push(HanaBind::Str(filters.column.clone()));
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY SCHEMA_NAME, TABLE_NAME, POSITION LIMIT ?");
    binds.push(HanaBind::Int(max_rows as i64));
    (sql, binds)
}

/// Per-binding TLS choice resolved from the spec.
pub enum TlsChoice {
    /// Plaintext connection (no TLS).
    None,
    /// TLS, verifying the server chain against the webpki roots.
    SystemRoots,
    /// TLS, verifying the server chain against this PEM trust anchor.
    Ca(String),
    /// TLS with NO server verification (self-signed dev only).
    NoVerify,
}

/// Build the per-binding bb8 [`HanaPool`]. This is I/O-free: `build_unchecked`
/// with `min_idle = 0` spawns no connection task that opens a socket, so
/// `register_profile` stays offline. The first `pool.get()` connects.
///
/// `connection_timeout` bounds how long a `pool.get()` waits for a connection.
#[allow(clippy::too_many_arguments)]
pub fn build_pool(
    host: &str,
    port: u16,
    user: &str,
    password: Option<&str>,
    database: Option<&str>,
    tls: TlsChoice,
    pool_max_size: u32,
    connection_timeout: Duration,
) -> Result<HanaPool, String> {
    let mut builder = ConnectParamsBuilder::new();
    builder.hostname(host).port(port).dbuser(user);
    if let Some(pw) = password {
        builder.password(pw);
    }
    if let Some(db) = database {
        builder.dbname(db);
    }
    match tls {
        TlsChoice::None => {}
        TlsChoice::SystemRoots => {
            builder.tls_with(ServerCerts::RootCertificates);
        }
        TlsChoice::Ca(pem) => {
            builder.tls_with(ServerCerts::Direct(pem));
        }
        TlsChoice::NoVerify => {
            builder.tls_without_server_verification();
        }
    }

    let manager = ConnectionManager::new(builder)
        .map_err(|e| format!("HANA connect-params build failed: {e}"))?;
    let pool = Pool::builder()
        .max_size(pool_max_size.max(1))
        .connection_timeout(connection_timeout)
        .build_unchecked(manager);
    Ok(pool)
}

/// Lower a scalar bind onto an owned [`HdbValue`]. The value reaches HANA as a
/// server-side prepared-statement parameter — never interpolated into the
/// statement text — so it can never alter the operator-fixed SQL.
fn to_hdb_value(value: &HanaBind) -> HdbValue<'static> {
    match value {
        HanaBind::Null => HdbValue::NULL,
        HanaBind::Int(i) => HdbValue::BIGINT(*i),
        HanaBind::Float(f) => HdbValue::DOUBLE(*f),
        HanaBind::Bool(b) => HdbValue::BOOLEAN(*b),
        HanaBind::Str(s) => HdbValue::STRING(s.clone()),
    }
}

/// Run a prepared statement against a pooled connection, binding `bound` to the
/// `?` placeholders, and marshalling the result set into capped JSON rows.
///
/// Statements that return no result set (e.g. a write under `read_only=false`)
/// yield zero rows. The caller wraps this in an outer tokio timeout (the hard
/// per-call ceiling).
pub async fn run_query(
    pool: &HanaPool,
    statement: &str,
    bound: Vec<HanaBind>,
    max_rows: usize,
    max_result_bytes: usize,
) -> Result<QueryOutcome, String> {
    let conn = pool
        .get()
        .await
        .map_err(|e| format!("HANA pool connection failed: {e}"))?;

    let mut stmt = conn
        .prepare(statement)
        .await
        .map_err(|e| format!("HANA prepare failed: {e}"))?;

    let params: Vec<HdbValue<'static>> = bound.iter().map(to_hdb_value).collect();
    let response = stmt
        .execute_row(params)
        .await
        .map_err(|e| format!("HANA execute failed: {e}"))?;

    // A statement with no result set (DML / CALL with no cursor) materializes
    // zero rows — the affected-row count is not part of the row envelope.
    let result_set = match response.into_result_set() {
        Ok(rs) => rs,
        Err(_) => {
            return Ok(QueryOutcome {
                rows: Vec::new(),
                truncated: false,
                row_count: 0,
            });
        }
    };

    marshal_result_set(result_set, max_rows, max_result_bytes).await
}

/// Materialize a [`ResultSet`] into capped JSON object-rows. Column names come
/// from the result-set metadata; each `HdbValue` is mapped to JSON via
/// [`hdb_value_to_json`]. The cap is on materialized rows AND serialized bytes;
/// `row_count` reflects every row seen, `truncated` is set when rows beyond a
/// cap existed.
async fn marshal_result_set(
    mut result_set: hdbconnect_async::ResultSet,
    max_rows: usize,
    max_result_bytes: usize,
) -> Result<QueryOutcome, String> {
    let column_names = column_names(&result_set);

    let mut rows: Vec<Value> = Vec::new();
    let mut truncated = false;
    let mut row_count = 0usize;
    let mut byte_budget = max_result_bytes;

    while let Some(mut row) = result_set
        .next_row()
        .await
        .map_err(|e| format!("HANA row fetch failed: {e}"))?
    {
        row_count += 1;
        if rows.len() >= max_rows || truncated {
            truncated = true;
            continue;
        }
        let mut obj = serde_json::Map::with_capacity(column_names.len());
        let mut idx = 0usize;
        while let Some(hv) = row.next_value() {
            let name = column_names
                .get(idx)
                .cloned()
                .unwrap_or_else(|| format!("col{idx}"));
            obj.insert(name, hdb_value_to_json(hv));
            idx += 1;
        }
        let value = Value::Object(obj);
        let approx = serde_json::to_string(&value).map(|s| s.len()).unwrap_or(0);
        if approx > byte_budget {
            truncated = true;
            continue;
        }
        byte_budget -= approx;
        rows.push(value);
    }

    Ok(QueryOutcome {
        rows,
        truncated,
        row_count,
    })
}

/// Extract the display column names from a result set's metadata, in column
/// order. `ResultSetMetadata` derefs to `Vec<FieldMetadata>`.
fn column_names(result_set: &hdbconnect_async::ResultSet) -> Vec<String> {
    result_set
        .metadata()
        .iter()
        .map(|fm| fm.displayname().to_owned())
        .collect()
}

/// Map one [`HdbValue`] to a JSON value. Numeric types become JSON numbers,
/// booleans/strings map directly, NULL → JSON null, dates/times → their string
/// rendering, binary → base64. LOBs render as their string form (the marshaller
/// does not stream LOB bodies into the row envelope).
pub fn hdb_value_to_json(hv: HdbValue<'_>) -> Value {
    match hv {
        HdbValue::NULL => Value::Null,
        HdbValue::TINYINT(v) => json!(v),
        HdbValue::SMALLINT(v) => json!(v),
        HdbValue::INT(v) => json!(v),
        HdbValue::BIGINT(v) => json!(v),
        HdbValue::REAL(v) => serde_json::Number::from_f64(v as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        HdbValue::DOUBLE(v) => serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        HdbValue::DECIMAL(ref d) => {
            // A DECIMAL renders losslessly as a string; downstream consumers
            // that need a number can parse it without precision loss.
            Value::String(d.to_string())
        }
        HdbValue::BOOLEAN(b) => Value::Bool(b),
        HdbValue::STRING(s) => Value::String(s),
        HdbValue::STR(s) => Value::String(s.to_owned()),
        HdbValue::DBSTRING(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Value::String(s),
            Err(e) => encode_binary(e.as_bytes()),
        },
        HdbValue::BINARY(bytes) | HdbValue::GEOMETRY(bytes) | HdbValue::POINT(bytes) => {
            encode_binary(&bytes)
        }
        HdbValue::LONGDATE(ref d) => Value::String(d.to_string()),
        HdbValue::SECONDDATE(ref d) => Value::String(d.to_string()),
        HdbValue::DAYDATE(d) => Value::String(daydate_string(&d)),
        HdbValue::SECONDTIME(ref t) => Value::String(t.to_string()),
        HdbValue::ARRAY(items) => Value::Array(items.into_iter().map(hdb_value_to_json).collect()),
        // LOBs + lob-streams are rendered as their Display form (length marker)
        // rather than streamed into the row envelope.
        other => Value::String(other.to_string()),
    }
}

/// DayDate has no public accessor besides its `Display`, which is what we want.
fn daydate_string(d: &DayDate) -> String {
    d.to_string()
}

fn encode_binary(bytes: &[u8]) -> Value {
    use base64::Engine as _;
    Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_only_guard_allows_reads() {
        for s in [
            "SELECT 1 FROM DUMMY",
            "  with x as (select 1 from dummy) select * from x",
            "-- comment\nSELECT 2 FROM DUMMY",
            "/* hi */ SELECT 1 FROM DUMMY",
        ] {
            assert!(enforce_read_only(s).is_ok(), "should allow: {s}");
        }
    }

    #[test]
    fn read_only_guard_rejects_writes_and_calls() {
        for s in [
            "INSERT INTO T VALUES (1)",
            "UPDATE T SET X = 1",
            "DELETE FROM T",
            "CREATE TABLE T (X INT)",
            "DROP TABLE T",
            "CALL MY_PROC(?)",
            "   ",
            "",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    /// The delegated shared guard hardens beyond the old leading-keyword check:
    /// write-CTEs, `EXPLAIN ANALYZE`, and stacked statements are all rejected
    /// while a plain read still passes.
    #[test]
    fn read_only_guard_delegates_to_hardened_shared_guard() {
        for s in [
            "WITH x AS (INSERT INTO t SELECT 1) SELECT * FROM x",
            "EXPLAIN ANALYZE SELECT 1",
            "SELECT 1; DROP TABLE t",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
        assert!(enforce_read_only("SELECT 1").is_ok());
    }

    #[test]
    fn scalar_binds_lower_to_hdb_values() {
        assert!(matches!(to_hdb_value(&HanaBind::Null), HdbValue::NULL));
        assert!(matches!(
            to_hdb_value(&HanaBind::Int(7)),
            HdbValue::BIGINT(7)
        ));
        assert!(matches!(
            to_hdb_value(&HanaBind::Bool(true)),
            HdbValue::BOOLEAN(true)
        ));
        match to_hdb_value(&HanaBind::Str("x".into())) {
            HdbValue::STRING(s) => assert_eq!(s, "x"),
            other => panic!("expected STRING, got {other:?}"),
        }
        match to_hdb_value(&HanaBind::Float(1.5)) {
            HdbValue::DOUBLE(f) => assert!((f - 1.5).abs() < f64::EPSILON),
            other => panic!("expected DOUBLE, got {other:?}"),
        }
    }

    #[test]
    fn hdb_value_marshals_scalars() {
        assert_eq!(hdb_value_to_json(HdbValue::NULL), Value::Null);
        assert_eq!(hdb_value_to_json(HdbValue::INT(42)), json!(42));
        assert_eq!(hdb_value_to_json(HdbValue::BIGINT(99)), json!(99));
        assert_eq!(hdb_value_to_json(HdbValue::TINYINT(7)), json!(7));
        assert_eq!(hdb_value_to_json(HdbValue::SMALLINT(-3)), json!(-3));
        assert_eq!(hdb_value_to_json(HdbValue::BOOLEAN(true)), json!(true));
        assert_eq!(
            hdb_value_to_json(HdbValue::STRING("hello".into())),
            json!("hello")
        );
        assert_eq!(hdb_value_to_json(HdbValue::STR("hi")), json!("hi"));
        assert_eq!(hdb_value_to_json(HdbValue::DOUBLE(2.5)), json!(2.5));
    }

    #[test]
    fn hdb_value_binary_is_base64() {
        let v = hdb_value_to_json(HdbValue::BINARY(vec![1, 2, 3]));
        assert_eq!(v, json!("AQID"));
    }

    #[test]
    fn list_tables_query_no_filters_selects_all_with_limit() {
        let (sql, binds) = build_list_tables_query(&CatalogFilters::default(), 500);
        assert_eq!(
            sql,
            "SELECT SCHEMA_NAME, TABLE_NAME, TABLE_TYPE FROM SYS.TABLES \
             ORDER BY SCHEMA_NAME, TABLE_NAME LIMIT ?"
        );
        assert!(!sql.contains("WHERE"));
        // Only the LIMIT bind.
        assert_eq!(binds, vec![HanaBind::Int(500)]);
    }

    #[test]
    fn list_tables_query_binds_filters_never_interpolates() {
        let filters = CatalogFilters {
            schema: "SALES".into(),
            table: "ORDERS".into(),
            table_type: "VIEW".into(),
            column: String::new(),
        };
        let (sql, binds) = build_list_tables_query(&filters, 100);
        // Predicates reference fixed SYS columns + `?`; no filter value appears
        // in the SQL text (injection-safe).
        assert!(sql.contains("SCHEMA_NAME = ? AND TABLE_NAME = ? AND TABLE_TYPE = ?"));
        assert!(!sql.contains("SALES"));
        assert!(!sql.contains("ORDERS"));
        assert!(!sql.contains("VIEW"));
        assert_eq!(
            binds,
            vec![
                HanaBind::Str("SALES".into()),
                HanaBind::Str("ORDERS".into()),
                HanaBind::Str("VIEW".into()),
                HanaBind::Int(100),
            ]
        );
    }

    #[test]
    fn list_tables_query_rejects_sql_metacharacters_as_data() {
        // A hostile filter value is carried as a bound parameter — it lands in
        // `binds`, never in the SQL skeleton.
        let filters = CatalogFilters {
            schema: "X'; DROP TABLE SYS.TABLES;--".into(),
            ..Default::default()
        };
        let (sql, binds) = build_list_tables_query(&filters, 10);
        assert!(!sql.contains("DROP"));
        assert!(sql.contains("SCHEMA_NAME = ?"));
        assert_eq!(
            binds[0],
            HanaBind::Str("X'; DROP TABLE SYS.TABLES;--".into())
        );
    }

    #[test]
    fn list_columns_query_binds_filters_and_orders_by_position() {
        let filters = CatalogFilters {
            schema: "SALES".into(),
            table: "ORDERS".into(),
            table_type: "ignored".into(),
            column: "ID".into(),
        };
        let (sql, binds) = build_list_columns_query(&filters, 200);
        assert!(sql.starts_with(
            "SELECT SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, DATA_TYPE_NAME, LENGTH, \
             IS_NULLABLE, POSITION FROM SYS.TABLE_COLUMNS"
        ));
        // table_type is not a column predicate here.
        assert!(!sql.contains("TABLE_TYPE"));
        assert!(sql.contains("SCHEMA_NAME = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?"));
        assert!(sql.ends_with("ORDER BY SCHEMA_NAME, TABLE_NAME, POSITION LIMIT ?"));
        assert_eq!(
            binds,
            vec![
                HanaBind::Str("SALES".into()),
                HanaBind::Str("ORDERS".into()),
                HanaBind::Str("ID".into()),
                HanaBind::Int(200),
            ]
        );
    }

    /// The catalog cells marshal through the same `HdbValue` → JSON path as a
    /// normal query — strings stay strings, integers stay numbers, NULL → null.
    #[test]
    fn catalog_cells_marshal_via_row_to_json() {
        assert_eq!(
            hdb_value_to_json(HdbValue::STRING("SALES".into())),
            json!("SALES")
        );
        assert_eq!(hdb_value_to_json(HdbValue::INT(1)), json!(1));
        assert_eq!(
            hdb_value_to_json(HdbValue::STRING("TRUE".into())),
            json!("TRUE")
        );
        assert_eq!(hdb_value_to_json(HdbValue::NULL), Value::Null);
    }

    #[test]
    fn build_pool_is_offline_and_lazy() {
        // build_unchecked with min_idle=0 opens no socket; this must return a
        // pool without connecting (it runs inside a tokio runtime in the
        // integration path; here we only require it not to error/connect).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let pool = build_pool(
                "hana.invalid",
                39015,
                "MCPG",
                Some("pw"),
                Some("HXE"),
                TlsChoice::SystemRoots,
                6,
                Duration::from_millis(50),
            )
            .expect("pool builds offline");
            assert_eq!(pool.state().connections, 0);
        });
    }
}
