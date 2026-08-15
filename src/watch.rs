//! `watch_strategy` entity (`hana_poll`) — the POLLING change-watch path.
//!
//! SAP HANA has no native change-push channel for this binding, so this strategy
//! polls a cheap read-only scalar "high-water" query (`SELECT max(UPDATED_AT)
//! FROM EVENTS`, `SELECT count(*) FROM …`, a monotonic sequence, …) on a cadence
//! and signals a change whenever that scalar advances. The poll
//! thread, the cursor diff, the stop signal and the opaque handle round-trip all
//! live in the shared [`mcpg_plugin_sdk::watch`] helper — this entity only
//! supplies the per-tick `poll` closure over its own engine.
//!
//! The helper's loop is synchronous and [`engine::run_query`] is async, so a
//! single current-thread tokio runtime is built once in [`watch`] and moved into
//! the closure; each tick `block_on`s one query (sequential ticks, so a
//! single-thread runtime is enough). Connect / query failures map to the
//! closure's `Err(String)` — the helper logs and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::engine::{self, QueryOutcome, TlsChoice};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.hana";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "hana_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick query budget when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_tls_verify_peer() -> bool {
    true
}

fn default_use_tls() -> bool {
    true
}

fn default_pool_max_size() -> u32 {
    1
}

/// Per-watch spec: the HANA connection fields needed to build a pool (reusing
/// the backend's connection shape) plus the read-only scalar high-water
/// `tracking_query` and the poll cadence. The connection is carried per-watch
/// (not at plugin level), so a watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// HANA host (operator-fixed, never caller-templated). REQUIRED.
    host: String,
    /// HDB SQL port (e.g. 39015). REQUIRED.
    port: u16,
    /// HANA dbuser. REQUIRED.
    user: String,
    /// HANA password (resolved from `${cred://…}` / `${env.X}` at config load).
    #[serde(default)]
    password: Option<String>,
    /// Optional explicit tenant database name (HANA MDC).
    #[serde(default)]
    database: Option<String>,
    /// Verify the server's TLS certificate chain. Default true; `false` opts
    /// into a no-verify connection (self-signed dev only).
    #[serde(default = "default_tls_verify_peer")]
    tls_verify_peer: bool,
    /// Optional trust-anchor PEM for TLS (resolved from `${file://…}` at config
    /// load). When set the server chain is verified against this CA.
    #[serde(default)]
    tls_ca_cert: Option<String>,
    /// Whether to connect over TLS at all. Default true; `false` → plaintext.
    #[serde(default = "default_use_tls")]
    use_tls: bool,
    /// bb8 pool max size for the watcher (default 1 — one polling connection).
    #[serde(default = "default_pool_max_size")]
    pool_max_size: u32,
    /// The read-only scalar high-water query whose first-row first-column value
    /// is the cursor (e.g. `SELECT max(UPDATED_AT) FROM EVENTS`). REQUIRED.
    tracking_query: String,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick server-side + wall-clock query budget in milliseconds
    /// (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + tracking query arrive on the per-watch spec.
pub struct HanaWatchCdylib {
    manifest: PluginManifest,
}

impl HanaWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + `tracking_query` arrive
    /// via the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.hana",
                name: "SAP HANA Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Extract the cursor scalar from a high-water query outcome: the first column
/// of the first row, stringified (numbers / bools / strings alike). `None` when
/// the query returned zero rows (no signal this tick) or the first row has no
/// columns. JSON-string values yield the bare string; everything else its JSON
/// rendering, so the cursor comparison is stable across ticks.
fn cursor_from_outcome(outcome: &QueryOutcome) -> Option<String> {
    let first = outcome.rows.first()?;
    let scalar = first.as_object()?.values().next()?;
    Some(match scalar {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

impl SyncWatchStrategyPlugin for HanaWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid hana_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.port == 0 {
            return Err(invalid("port must be greater than 0".into()));
        }
        if parsed.user.trim().is_empty() {
            return Err(invalid("user must not be empty".into()));
        }
        if parsed.tracking_query.trim().is_empty() {
            return Err(invalid("tracking_query must not be empty".into()));
        }
        // The tracking query is read-only by contract — reuse the engine guard so
        // a polling watcher can never mutate the server.
        engine::enforce_read_only(&parsed.tracking_query).map_err(invalid)?;

        // Resolve the TLS choice, mirroring the backend's register path:
        // plaintext when `use_tls=false`; otherwise a CA PEM (verified) / system
        // roots (verified) / no-verify (opt-out).
        let tls = if !parsed.use_tls {
            TlsChoice::None
        } else if !parsed.tls_verify_peer {
            TlsChoice::NoVerify
        } else if let Some(ca) = parsed
            .tls_ca_cert
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            TlsChoice::Ca(ca.to_owned())
        } else {
            TlsChoice::SystemRoots
        };

        let timeout = Duration::from_millis(parsed.timeout_ms);

        // The lazy bb8 pool (no socket opened here): `build_unchecked` with
        // `min_idle = 0` connects on the first `pool.get()` inside the closure.
        let pool = engine::build_pool(
            &parsed.host,
            parsed.port,
            &parsed.user,
            parsed.password.as_deref(),
            parsed.database.as_deref(),
            tls,
            parsed.pool_max_size.max(1),
            timeout,
        )
        .map_err(|message| WatchError::Subscribe { message })?;

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` each
        // async query.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("hana_poll: tokio runtime init failed: {e}"),
            })?;

        let tracking_query = parsed.tracking_query;
        let pool = Arc::new(pool);

        let poll = move || -> Result<Option<String>, String> {
            // The tracking query is a scalar high-water read — one row, one
            // column. The outer per-tick budget is the hard ceiling.
            let fut = engine::run_query(&pool, &tracking_query, Vec::new(), 1, usize::MAX);
            let outcome = rt.block_on(async {
                match tokio::time::timeout(timeout, fut).await {
                    Ok(inner) => inner,
                    Err(_) => Err("hana_poll: tracking query timed out".to_owned()),
                }
            })?;
            Ok(cursor_from_outcome(&outcome))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> HanaWatchCdylib {
        HanaWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "tracking_query": "SELECT max(UPDATED_AT) FROM EVENTS",
        }))
        .unwrap();
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
        assert_eq!(parsed.pool_max_size, 1);
        assert!(parsed.tls_verify_peer);
        assert!(parsed.use_tls);
        assert!(parsed.password.is_none());
        assert!(parsed.database.is_none());
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "hana.example",
            "port": 30015,
            "user": "READER",
            "password": "pw",
            "database": "HXE",
            "tls_verify_peer": false,
            "use_tls": false,
            "pool_max_size": 4,
            "tracking_query": "SELECT count(*) FROM EVENTS",
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.database.as_deref(), Some("HXE"));
        assert_eq!(parsed.password.as_deref(), Some("pw"));
        assert!(!parsed.tls_verify_peer);
        assert!(!parsed.use_tls);
        assert_eq!(parsed.pool_max_size, 4);
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "hana://events",
                &json!({
                    "host": "hana.example",
                    "port": 39015,
                    "user": "MCPG",
                    "tracking_query": "SELECT 1 FROM DUMMY",
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "hana://events",
                &json!({
                    "host": "hana.example",
                    "port": 39015,
                    "user": "MCPG",
                    "tracking_query": "   ",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn non_read_only_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "hana://events",
                &json!({
                    "host": "hana.example",
                    "port": 39015,
                    "user": "MCPG",
                    "tracking_query": "INSERT INTO EVENTS VALUES (now())",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cursor_from_outcome_extracts_first_scalar() {
        // A monotonic timestamp string.
        let outcome = QueryOutcome {
            rows: vec![json!({ "MAX(UPDATED_AT)": "2026-06-23 10:00:00" })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(
            cursor_from_outcome(&outcome).as_deref(),
            Some("2026-06-23 10:00:00")
        );

        // A numeric high-water value stringifies to its JSON rendering.
        let outcome = QueryOutcome {
            rows: vec![json!({ "COUNT(*)": 42 })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&outcome).as_deref(), Some("42"));
    }

    #[test]
    fn cursor_from_outcome_none_on_zero_rows_or_null() {
        let empty = QueryOutcome {
            rows: vec![],
            truncated: false,
            row_count: 0,
        };
        assert_eq!(cursor_from_outcome(&empty), None);

        let null = QueryOutcome {
            rows: vec![json!({ "MAX(T)": Value::Null })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&null), None);
    }
}
