//! SAP HANA structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is the
//! gateway's `is_error` signal (same contract as the clickhouse/oracle/sql
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn hana_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_hana.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_server_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a query error string. Transient network / timeout / pool-exhaustion
/// failures are retryable transport errors; parser / type / permission
/// rejections are caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    // Non-retryable first: a syntax/type/permission error must not be masked as
    // transport just because its text happens to mention "connection".
    let non_retryable = lower.contains("syntax error")
        || lower.contains("sql syntax")
        || lower.contains("invalid identifier")
        || lower.contains("invalid column")
        || lower.contains("invalid table name")
        || lower.contains("could not find table")
        || lower.contains("insufficient privilege")
        || lower.contains("not authorized")
        || lower.contains("type mismatch")
        || lower.contains("inconsistent datatype")
        || lower.contains("read-only")
        || lower.contains("readonly")
        || lower.contains("cannot modify");
    let retryable = !non_retryable
        && (lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("connection")
            || lower.contains("connect")
            || lower.contains("network")
            || lower.contains("broken")
            || lower.contains("pool")
            || lower.contains("socket")
            || lower.contains("temporarily")
            || lower.contains("unavailable")
            || lower.contains("too many"));
    let kind = if retryable {
        "transport_error"
    } else {
        "hana_error"
    };
    hana_downstream_error(kind, message, retryable)
}

/// JSON Schema (draft 2020-12) for the fixed envelope wrapper
/// [`build_result_envelope`] produces. Describes the stable top-level shape;
/// per-query `response.rows` items are intentionally left untyped (`{}`) so any
/// row shape validates.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "toolName": { "type": "string" },
            "profile": { "type": "string" },
            "request": {
                "type": "object",
                "properties": {
                    "database": { "type": "string" }
                },
                "additionalProperties": true
            },
            "response": {
                "type": ["object", "null"],
                "properties": {
                    "rows": { "type": ["array", "null"], "items": {} },
                    "count": { "type": ["integer", "null"] },
                    "truncated": { "type": "boolean" },
                    "durationMs": { "type": "integer" }
                },
                "additionalProperties": true
            },
            "downstreamError": { "type": ["object", "null"] },
            "downstreamErrors": { "type": "array", "items": {} },
            "error": { "type": ["string", "null"] }
        },
        "additionalProperties": true
    })
}

/// Envelope schema specialized for a catalog-introspection operation: the same
/// wrapper as [`result_envelope_schema`] but with `response.rows` items typed to
/// the `SYS.TABLES` / `SYS.TABLE_COLUMNS` column set. `columns` are the column
/// names the select projects (object stays open).
pub fn catalog_envelope_schema(columns: &[&str]) -> Value {
    let mut schema = result_envelope_schema();
    let mut props = serde_json::Map::new();
    for col in columns {
        // Catalog cells marshal to a JSON string, number, or null depending on
        // the SYS column type; keep the per-cell type open.
        props.insert((*col).to_owned(), json!({}));
    }
    schema["properties"]["response"]["properties"]["rows"]["items"] = json!({
        "type": "object",
        "properties": Value::Object(props),
        "additionalProperties": true,
    });
    schema
}

/// Column names a `list_tables` (`SYS.TABLES`) result yields.
pub const LIST_TABLES_COLUMNS: &[&str] = &["SCHEMA_NAME", "TABLE_NAME", "TABLE_TYPE"];

/// Column names a `list_columns` (`SYS.TABLE_COLUMNS`) result yields.
pub const LIST_COLUMNS_COLUMNS: &[&str] = &[
    "SCHEMA_NAME",
    "TABLE_NAME",
    "COLUMN_NAME",
    "DATA_TYPE_NAME",
    "LENGTH",
    "IS_NULLABLE",
    "POSITION",
];

/// Build the HANA structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    database: &str,
    rows: Option<&[Value]>,
    row_count: Option<usize>,
    truncated: bool,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": row_count.or_else(|| rows.map(<[Value]>::len)),
            "truncated": truncated,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "database": database,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_retryable_transport_error() {
        let e = classify_error("HANA call timed out");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn network_failure_is_retryable() {
        let e = classify_error("connection broken: connect refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn syntax_error_is_not_retryable() {
        let e = classify_error("SAP DBTech JDBC: [257]: sql syntax error: incorrect syntax near");
        assert_eq!(e["kind"], json!("hana_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn privilege_denial_is_not_retryable() {
        let e = classify_error("[258]: insufficient privilege: Not authorized");
        assert_eq!(e["kind"], json!("hana_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_and_count() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "HXE",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["id"], json!(1));
        assert_eq!(env["response"]["truncated"], json!(false));
        assert_eq!(env["request"]["database"], json!("HXE"));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn truncated_flag_is_carried() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "HXE",
            Some(&rows),
            Some(1),
            true,
            3,
            None,
            None,
        );
        assert_eq!(env["response"]["truncated"], json!(true));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("[259]: invalid table name: BOGUS");
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "HXE",
            None,
            None,
            false,
            2,
            Some(&d),
            Some("table missing"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("hana_error"));
    }

    #[test]
    fn catalog_envelope_schema_types_rows_to_columns() {
        let schema = catalog_envelope_schema(LIST_TABLES_COLUMNS);
        let row_props =
            &schema["properties"]["response"]["properties"]["rows"]["items"]["properties"];
        assert!(row_props["SCHEMA_NAME"].is_object());
        assert!(row_props["TABLE_NAME"].is_object());
        assert!(row_props["TABLE_TYPE"].is_object());
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"]["additionalProperties"],
            json!(true)
        );

        let cols = catalog_envelope_schema(LIST_COLUMNS_COLUMNS);
        let col_props =
            &cols["properties"]["response"]["properties"]["rows"]["items"]["properties"];
        assert!(col_props["COLUMN_NAME"].is_object());
        assert!(col_props["DATA_TYPE_NAME"].is_object());
        assert!(col_props["POSITION"].is_object());
    }

    #[test]
    fn output_schema_matches_envelope_shape() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "HXE",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"],
            json!({})
        );
    }
}
