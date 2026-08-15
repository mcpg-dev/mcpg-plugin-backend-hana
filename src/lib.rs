//! SAP HANA backend binding plugin for mcpg.
//!
//! Implements [`HanaBackendPlugin`] — `BackendPlugin` for `kind: "hana"`. Runs
//! an operator-fixed SQL statement whose `?` placeholders are bound from CEL
//! expressions evaluated against the tool arguments (server-side
//! prepared-statement parameters, never interpolated — injection-safe), against
//! a SAP HANA database over its native HDB SQL protocol. A read-only keyword
//! guard fences the statement. Structurally mirrors the clickhouse/oracle
//! backends; HANA-specific machinery lives in [`engine`] + [`params`] +
//! [`envelope`] + [`surface`].
//!
//! The bb8 connection pool is built once at `register_profile` via
//! `build_unchecked` (`min_idle = 0`) — that opens NO socket until the first
//! call, so registration stays offline-testable. TLS verifies the server
//! certificate by default; `tls_verify_peer = false` opts into an insecure
//! no-verify connection (self-signed dev only).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;
mod engine;
mod envelope;
mod params;
mod surface;
mod types;
pub mod watch;

use engine::{
    CatalogFilters, HanaPool, QueryOutcome, TlsChoice, build_list_columns_query,
    build_list_tables_query, build_pool, enforce_read_only, run_query,
};
use envelope::{build_result_envelope, classify_error};
use params::{CompiledParam, HanaBind, compile_params, evaluate_params, json_to_hana_bind};
pub use types::{
    CompletionConfig as HanaCompletionConfig, HanaBackendSpec, HanaOperation, ListQueryConfig,
    ListQueryMode, validate_completion, validate_list_query,
};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.hana.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.hana.request_failed"),
        "hana_error" => Some("dev.mcpg.backend.hana.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.hana.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.hana".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("HANA plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

/// Reject a bare `cred://` URI in an operator-fixed string. Secrets reach the
/// server through `${cred://…}` resolved at config load (the dbuser password);
/// a bare `cred://` left in a statement would be sent to HANA verbatim, which is
/// always an operator mistake.
fn reject_bare_cred(field: &str, value: &str) -> Result<(), String> {
    if value.contains("cred://") {
        return Err(format!(
            "{field} must not contain a bare cred:// URI — use ${{cred://…}} (resolved at config load)"
        ));
    }
    Ok(())
}

/// Per-binding catalog-introspection filter config: an operator-pinned static
/// value plus an optional tool-argument name for each `SYS.TABLES` /
/// `SYS.TABLE_COLUMNS` filter. Resolved per call into [`CatalogFilters`]; the
/// per-call argument (when configured AND present as a string in the call
/// arguments) overrides the static value. Every resolved filter is bound as a
/// `?` parameter — never interpolated into SQL — so caller input can only narrow
/// the metadata. Only consulted for the `list_tables` / `list_columns` ops.
#[derive(Debug, Default, Clone)]
struct CatalogFilterConfig {
    schema: Option<String>,
    table: Option<String>,
    table_type: Option<String>,
    column: Option<String>,
    schema_arg: Option<String>,
    table_arg: Option<String>,
    table_type_arg: Option<String>,
    column_arg: Option<String>,
}

impl CatalogFilterConfig {
    /// Resolve the four filters for one call. For each, the per-call argument
    /// (when configured and present as a JSON string) wins over the static
    /// value; otherwise the static value (or empty = no filter) is used. The
    /// resolved strings are bound as `?` parameters by the query builders.
    fn resolve(&self, arguments: &Value) -> CatalogFilters {
        CatalogFilters {
            schema: resolve_one(
                self.schema.as_deref(),
                self.schema_arg.as_deref(),
                arguments,
            ),
            table: resolve_one(self.table.as_deref(), self.table_arg.as_deref(), arguments),
            table_type: resolve_one(
                self.table_type.as_deref(),
                self.table_type_arg.as_deref(),
                arguments,
            ),
            column: resolve_one(
                self.column.as_deref(),
                self.column_arg.as_deref(),
                arguments,
            ),
        }
    }

    /// The distinct tool-argument names this config reads from call arguments,
    /// in filter order — surfaced as the catalog op's `input_schema` properties.
    fn argument_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for arg in [
            &self.schema_arg,
            &self.table_arg,
            &self.table_type_arg,
            &self.column_arg,
        ]
        .into_iter()
        .flatten()
        {
            if !names.contains(arg) {
                names.push(arg.clone());
            }
        }
        names
    }
}

/// Resolve a single catalog filter: a caller-supplied string argument (when the
/// `arg_name` is configured and the argument is a JSON string) overrides the
/// operator-pinned `static_value`; absent both, the empty string = match all.
fn resolve_one(static_value: Option<&str>, arg_name: Option<&str>, arguments: &Value) -> String {
    if let Some(name) = arg_name
        && let Some(v) = arguments.get(name).and_then(Value::as_str)
    {
        return v.to_owned();
    }
    static_value.unwrap_or("").to_owned()
}

// ------------------------------------------------------------------ plugin

/// Per-binding HANA runtime — the lazy bb8 pool plus the compiled statement and
/// query bounds. The pool / statement / params / completions sit behind `Arc`
/// so the whole profile is cheap to clone per call.
#[derive(Clone)]
struct HanaProfile {
    pool: HanaPool,
    /// Database label for the envelope `request.database`.
    database: String,
    operation: HanaOperation,
    read_only: bool,
    statement: String,
    compiled_params: Arc<[CompiledParam]>,
    /// Catalog-introspection filter config (static + per-call argument names).
    /// Only consulted for the `list_tables` / `list_columns` operations.
    catalog_filters: Arc<CatalogFilterConfig>,
    max_rows: usize,
    max_result_bytes: usize,
    timeout: Duration,
    surface: surface::Surface,
    surface_uri: Option<String>,
    list_query: Option<ListQueryConfig>,
    /// Per-`{id}` single-row read statement for a `resource_templates[]` binding.
    /// Bound from the same `compiled_params` as `statement`; when None the
    /// resource-read branch falls back to `statement`.
    read_query: Option<String>,
    variable_completions: Arc<BTreeMap<String, HanaCompletionConfig>>,
}

/// `BackendPlugin` implementation for `kind: "hana"`.
pub struct HanaBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, HanaProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for HanaBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl HanaBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.hana",
                name: "SAP HANA Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_hana_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_hana_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("hana-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("hana-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::hana::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (param-eval failures), emit the triad, and return
    /// it as a normal payload — matching the clickhouse/oracle backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &HanaProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.database,
            None,
            None,
            false,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    /// Run a statement for `profile`: get a pooled connection, prepare + bind +
    /// fetch capped rows. The outer tokio timeout is the hard ceiling.
    async fn run_query(
        &self,
        profile: &HanaProfile,
        statement: &str,
        bound: Vec<HanaBind>,
        max_rows: usize,
    ) -> Result<QueryOutcome, String> {
        // Defense-in-depth: the read-only guard already ran at register, but a
        // guarded binding re-asserts it per call so a write can never reach the
        // server even if a profile is ever mutated in place.
        if profile.read_only {
            enforce_read_only(statement)?;
        }
        let fut = run_query(
            &profile.pool,
            statement,
            bound,
            max_rows,
            profile.max_result_bytes,
        );
        match tokio::time::timeout(profile.timeout, fut).await {
            Ok(inner) => inner,
            Err(_) => Err("HANA call timed out".to_owned()),
        }
    }

    /// Run a catalog-introspection operation: build the code-fixed `SYS.*`
    /// select with the resolved filters bound as `?` parameters, then run it
    /// through the same prepared-statement + row-marshal path as a query. No
    /// read-only guard is needed — the select never mutates.
    async fn run_catalog(
        &self,
        profile: &HanaProfile,
        operation: HanaOperation,
        filters: &CatalogFilters,
    ) -> Result<QueryOutcome, String> {
        let (sql, binds) = match operation {
            HanaOperation::ListTables => build_list_tables_query(filters, profile.max_rows),
            HanaOperation::ListColumns => build_list_columns_query(filters, profile.max_rows),
            // The catalog runner is only reached for catalog operations.
            HanaOperation::Query => return Err("not a catalog operation".to_owned()),
        };
        let fut = run_query(
            &profile.pool,
            &sql,
            binds,
            profile.max_rows,
            profile.max_result_bytes,
        );
        match tokio::time::timeout(profile.timeout, fut).await {
            Ok(inner) => inner,
            Err(_) => Err("HANA call timed out".to_owned()),
        }
    }
}

impl std::fmt::Debug for HanaBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HanaBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for HanaBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "hana"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: HanaBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("HANA binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.port == 0 {
            return Err(invalid("port must be greater than 0".into()));
        }
        if parsed.user.trim().is_empty() {
            return Err(invalid("user must not be empty".into()));
        }
        // HANA always authenticates with a password (resolved from `${cred://…}`
        // at config load). Reject a missing one at register with a clear hint
        // rather than letting the driver surface a cryptic build error.
        if parsed.password.as_deref().unwrap_or("").is_empty() {
            return Err(invalid(
                "password must be set (resolve it from ${cred://…} at config load)".into(),
            ));
        }
        // The `query` statement is required only for `operation: query`; the
        // catalog operations drive `SYS.TABLES` / `SYS.TABLE_COLUMNS` and ignore
        // it. `list_columns` needs a table to scope to (static or per-call) so a
        // call never enumerates every column in the database.
        match parsed.operation {
            HanaOperation::Query => {
                // A resource_template binding may supply only `read_query` (the
                // per-`{id}` single-row read) and omit `query`; otherwise the
                // operator-fixed `query` statement is required.
                if parsed.query.trim().is_empty()
                    && parsed
                        .read_query
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "query must not be empty (or set `read_query` for a resource_template read binding)".into(),
                    ));
                }
            }
            HanaOperation::ListColumns => {
                let has_table = !parsed
                    .table
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty();
                let has_table_arg = !parsed
                    .table_arg
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty();
                if !has_table && !has_table_arg {
                    return Err(invalid(
                        "operation: list_columns requires a `table` filter or a `table_arg` (the table whose columns to list)".into(),
                    ));
                }
            }
            HanaOperation::ListTables => {}
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.max_rows == 0 {
            return Err(invalid("max_rows must be greater than 0".into()));
        }
        if parsed.max_result_bytes == 0 {
            return Err(invalid("max_result_bytes must be greater than 0".into()));
        }
        if parsed.pool_max_size == 0 {
            return Err(invalid("pool_max_size must be greater than 0".into()));
        }
        reject_bare_cred("host", &parsed.host).map_err(invalid)?;

        // Read-only guard + bare-cred check apply to the `query` operation only:
        // the catalog operations run a code-fixed `SYS.*` select that never
        // mutates and carries no operator query text. The guard runs on a present
        // `query`; a resource_template read binding may omit it (the per-`{id}`
        // read lives in `read_query`, guarded below).
        if parsed.operation == HanaOperation::Query {
            reject_bare_cred("query", &parsed.query).map_err(invalid)?;
            if parsed.read_only && !parsed.query.trim().is_empty() {
                enforce_read_only(&parsed.query).map_err(invalid)?;
            }
        }

        // Surface coherence: `uri` is only meaningful on the resource surface.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }

        // `read_query` is the per-`{id}` single-row read for a resource_template
        // binding; like `query` it is operator-fixed, must be read-only under the
        // guard, and must not carry a bare cred://. It only makes sense on the
        // resource surface — fail-closed elsewhere so a misplaced field is never a
        // silent no-op.
        if let Some(rq) = &parsed.read_query {
            if rq.trim().is_empty() {
                return Err(invalid("`read_query` must not be empty".into()));
            }
            if parsed.surface != surface::Surface::Resource {
                return Err(invalid(format!(
                    "`read_query` is only valid with `surface: resource` (this binding is `surface: {}`)",
                    parsed.surface.as_str()
                )));
            }
            reject_bare_cred("read_query", rq).map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(rq).map_err(invalid)?;
            }
        }

        // Listing + completion are operator-fixed read surfaces; fail-closed at
        // register so a misconfigured `list_query` / `variable_completions`
        // never reaches a `resources/list` or `completion/complete` call.
        if let Some(lq) = &parsed.list_query {
            validate_list_query(lq).map_err(invalid)?;
            reject_bare_cred("list_query.sql", &lq.sql).map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(&lq.sql).map_err(invalid)?;
            }
        }
        for (name, cc) in &parsed.variable_completions {
            validate_completion(name, cc).map_err(invalid)?;
            reject_bare_cred(&format!("variable_completions.{name}.sql"), &cc.sql)
                .map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(&cc.sql).map_err(invalid)?;
            }
        }

        let compiled_params: Arc<[CompiledParam]> =
            compile_params(&parsed.params).map_err(invalid)?.into();

        // Resolve the TLS choice: plaintext when `use_tls=false`; otherwise a CA
        // PEM (verified) / system roots (verified) / no-verify (opt-out).
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

        // Build the lazy bb8 pool (no socket opened here, so register stays
        // offline). The first `pool.get()` connects.
        let pool = build_pool(
            &parsed.host,
            parsed.port,
            &parsed.user,
            parsed.password.as_deref(),
            parsed.database.as_deref(),
            tls,
            parsed.pool_max_size,
            Duration::from_millis(parsed.timeout_ms),
        )
        .map_err(invalid)?;

        let database = parsed
            .database
            .clone()
            .unwrap_or_else(|| format!("{}:{}", parsed.host, parsed.port));

        debug!(
            backend = %backend_name,
            host = %parsed.host,
            port = parsed.port,
            read_only = parsed.read_only,
            params = compiled_params.len(),
            "registered SAP HANA binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            HanaProfile {
                pool,
                database,
                operation: parsed.operation,
                read_only: parsed.read_only,
                statement: parsed.query,
                compiled_params,
                catalog_filters: Arc::new(CatalogFilterConfig {
                    schema: parsed.schema,
                    table: parsed.table,
                    table_type: parsed.table_type,
                    column: parsed.column,
                    schema_arg: parsed.schema_arg,
                    table_arg: parsed.table_arg,
                    table_type_arg: parsed.table_type_arg,
                    column_arg: parsed.column_arg,
                }),
                max_rows: parsed.max_rows,
                max_result_bytes: parsed.max_result_bytes,
                timeout: Duration::from_millis(parsed.timeout_ms),
                surface: parsed.surface,
                surface_uri: parsed.uri,
                list_query: parsed.list_query,
                read_query: parsed.read_query,
                variable_completions: Arc::new(parsed.variable_completions),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "hana_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("HANA plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Catalog-introspection ops bypass CEL params entirely: they resolve the
        // (optionally caller-supplied) filters and run a code-fixed `SYS.*`
        // select that binds each filter as a `?` parameter (never SQL).
        let result: Result<QueryOutcome, String> = if profile.operation.is_catalog() {
            let filters = profile.catalog_filters.resolve(&arguments);
            self.run_catalog(&profile, profile.operation, &filters)
                .await
        } else {
            // Evaluate the CEL parameter expressions, then lower each to a scalar
            // HANA bind (rejecting arrays/objects) — all connection-free.
            let bound = match evaluate_params(&profile.compiled_params, &arguments) {
                Ok(values) => {
                    let mut binds = Vec::with_capacity(values.len());
                    let mut err: Option<String> = None;
                    for v in values {
                        match json_to_hana_bind(v) {
                            Ok(b) => binds.push(b),
                            Err(e) => {
                                err = Some(format!("binding params: {e}"));
                                break;
                            }
                        }
                    }
                    if let Some(message) = err {
                        return self
                            .finish_error(
                                &profile,
                                backend_name,
                                &tool_name,
                                &message,
                                "invalid_spec",
                                identity.as_ref(),
                                &request_id,
                                started,
                                host_span,
                            )
                            .await;
                    }
                    binds
                }
                Err(e) => {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            &format!("evaluating params: {e}"),
                            "invalid_spec",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
            };

            // On the resource surface a per-`{id}` `read_query` (when configured)
            // is the single-row read for a `resource_templates[]` binding; it
            // binds the same `params` (the gateway-extracted template vars reach
            // it as `arguments.<var>`). Every other surface — and a resource
            // binding without `read_query` — runs the operator-fixed `statement`.
            let effective_statement = match (profile.surface, profile.read_query.as_deref()) {
                (surface::Surface::Resource, Some(rq)) => rq,
                _ => &profile.statement,
            };
            self.run_query(&profile, effective_statement, bound, profile.max_rows)
                .await
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => {
                    // On the resource/prompt surfaces the gateway decoder
                    // requires a surface-shaped body; the tool surface keeps the
                    // historical envelope. A resource read with no resolvable URI
                    // falls back to the tool error envelope (carries
                    // `downstreamError`) so the decoder sees a clean error.
                    match profile.surface {
                        surface::Surface::Tool => (
                            build_result_envelope(
                                &tool_name,
                                backend_name,
                                &profile.database,
                                Some(&outcome.rows),
                                Some(outcome.row_count),
                                outcome.truncated,
                                started.elapsed().as_millis(),
                                None,
                                None,
                            ),
                            "ok",
                            None,
                        ),
                        surface::Surface::Resource => {
                            match surface::resolve_resource_uri(
                                profile.surface_uri.as_deref(),
                                &arguments,
                            ) {
                                Some(uri) => (
                                    surface::resource_contents_body(uri, &outcome.rows),
                                    "ok",
                                    None,
                                ),
                                None => {
                                    let message = "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)".to_owned();
                                    let downstream = classify_error(&message);
                                    let env = build_result_envelope(
                                        &tool_name,
                                        backend_name,
                                        &profile.database,
                                        None,
                                        None,
                                        false,
                                        started.elapsed().as_millis(),
                                        Some(&downstream),
                                        Some(&message),
                                    );
                                    (env, "hana_error", Some(message))
                                }
                            }
                        }
                        surface::Surface::Prompt => {
                            (surface::prompt_messages_body(&outcome.rows), "ok", None)
                        }
                    }
                }
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "hana_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.database,
                        None,
                        None,
                        false,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("hana.transport".to_owned(), json!("plugin"));
        map
    }

    /// JSON Schema for the result envelope this binding emits. For the catalog
    /// operations the `response.rows` items are typed to the known `SYS.TABLES` /
    /// `SYS.TABLE_COLUMNS` column set; the `query` op leaves rows untyped.
    fn output_schema(&self, backend_name: &str) -> Option<Value> {
        let op = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| g.get(backend_name).map(|p| p.operation))
            .unwrap_or(HanaOperation::Query);
        Some(match op {
            HanaOperation::Query => envelope::result_envelope_schema(),
            HanaOperation::ListTables => {
                envelope::catalog_envelope_schema(envelope::LIST_TABLES_COLUMNS)
            }
            HanaOperation::ListColumns => {
                envelope::catalog_envelope_schema(envelope::LIST_COLUMNS_COLUMNS)
            }
        })
    }

    /// JSON Schema for the tool arguments. The binding's positional `params`
    /// are CEL expressions over `arguments.*`; the referenced argument names
    /// are surfaced as untyped, optional properties. The object stays open
    /// (`additionalProperties: true`) so the schema never rejects valid args.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        // `try_read` (sync, non-blocking): `input_schema` is called from the
        // gateway's registration path with no concurrent writer.
        let names: Vec<String> = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| {
                g.get(backend_name).map(|p| {
                    if p.operation.is_catalog() {
                        // Catalog ops take no CEL params; their callable args are
                        // the configured `*_arg` filter argument names.
                        p.catalog_filters.argument_names()
                    } else {
                        arguments_referenced_by_params(&p.compiled_params)
                    }
                })
            })
            .unwrap_or_default();
        Some(params_input_schema(&names))
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query`. Bindings without one inherit the empty page. The
    /// pagination `?cursor` / `?page_size` are the only non-operator binds:
    /// keyset binds the prior page's last `cursor_column` (NULL first page),
    /// offset binds page_size then the running offset — HANA binds both, so the
    /// cursor is data, never interpolated.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(list_cfg) = profile.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };

        let prior_offset = match (list_cfg.mode, cursor) {
            (ListQueryMode::Offset, Some(c)) => {
                c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                    message: format!("offset-mode cursor '{c}' is not a non-negative integer"),
                })?
            }
            _ => 0,
        };
        let binds: Vec<HanaBind> = match list_cfg.mode {
            ListQueryMode::Keyset => vec![
                match cursor {
                    Some(c) => HanaBind::Str(c.to_owned()),
                    None => HanaBind::Null,
                },
                HanaBind::Int(list_cfg.page_size as i64),
            ],
            ListQueryMode::Offset => vec![
                HanaBind::Int(list_cfg.page_size as i64),
                HanaBind::Int(prior_offset as i64),
            ],
        };

        let outcome = self
            .run_query(&profile, &list_cfg.sql, binds, list_cfg.page_size as usize)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        Ok(surface::rows_to_resource_page(
            &outcome.rows,
            &list_cfg,
            prior_offset,
        ))
    }

    /// Return completion candidates for a resource-template variable via the
    /// operator-fixed `variable_completions[<variable_name>]` query. The single
    /// `?` is bound to the caller's typed `prefix` value — never interpolated
    /// (injection-safe). Unconfigured variables inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(cc) = profile.variable_completions.get(variable_name).cloned() else {
            return Ok(vec![]);
        };

        let max = cc.max_results.unwrap_or(100) as usize;
        let binds = vec![HanaBind::Str(prefix.to_owned())];
        let outcome = self
            .run_query(&profile, &cc.sql, binds, max)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        let first_col = outcome
            .rows
            .first()
            .and_then(Value::as_object)
            .and_then(|m| m.keys().next().cloned());
        Ok(surface::rows_to_completion_values(
            &outcome.rows,
            first_col.as_deref(),
            max,
        ))
    }
}

/// Collect the distinct `arguments.<ident>` names referenced across a
/// binding's compiled CEL params, preserving first-seen order.
fn arguments_referenced_by_params(params: &[CompiledParam]) -> Vec<String> {
    let mut names = Vec::new();
    for p in params {
        for name in extract_argument_idents(&p.source) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Build an open object schema from the referenced argument names. With no
/// known names this is the permissive `{type:object, additionalProperties:true}`.
fn params_input_schema(names: &[String]) -> Value {
    let mut properties = serde_json::Map::new();
    for name in names {
        properties.insert(name.clone(), json!({}));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "additionalProperties": true,
    })
}

/// Extract identifiers appearing as `arguments.<ident>` in a CEL source string.
/// Pure string scan (no CEL deps) — a best-effort hint, never a rejection
/// surface.
fn extract_argument_idents(source: &str) -> Vec<String> {
    const MARKER: &str = "arguments.";
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(MARKER) {
        let start = search_from + rel + MARKER.len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            out.push(source[start..end].to_owned());
        }
        search_from = end.max(search_from + rel + MARKER.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        mcpg_plugin_protocol::noop_backend_host()
    }

    fn minimal_spec() -> Value {
        json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "query": "SELECT 1 AS ONE FROM DUMMY WHERE 1 = ?",
            "params": ["arguments.id"],
        })
    }

    #[test]
    fn kind_is_hana() {
        assert_eq!(HanaBackendPlugin::new().kind(), "hana");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            HanaBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.hana"
        );
    }

    #[test]
    fn extract_argument_idents_finds_names() {
        let got = extract_argument_idents("arguments.user_id + size(arguments.tags)");
        assert_eq!(got, vec!["user_id".to_owned(), "tags".to_owned()]);
        assert!(extract_argument_idents("1 + 2").is_empty());
    }

    #[tokio::test]
    async fn output_schema_is_object() {
        let plugin = HanaBackendPlugin::new();
        let schema = BackendPlugin::output_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
    }

    #[tokio::test]
    async fn input_schema_lists_referenced_params() {
        let plugin = HanaBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["additionalProperties"], json!(true));
        assert!(schema["properties"]["id"].is_object());
    }

    /// The pool builds at register without opening a socket — registration
    /// stays offline and returns without connecting.
    #[tokio::test]
    async fn register_builds_pool_lazily() {
        let plugin = HanaBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register stays offline");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("an").unwrap();
        assert!(p.read_only);
        assert_eq!(p.compiled_params.len(), 1);
        // No connection has been established by registration.
        assert_eq!(p.pool.state().connections, 0);
    }

    #[tokio::test]
    async fn register_default_database_label_is_host_port() {
        let plugin = HanaBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert_eq!(profiles.get("an").unwrap().database, "hana.example:39015");
    }

    #[tokio::test]
    async fn register_carries_explicit_database_label() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["database"] = json!("HXE");
        plugin
            .register_profile("an", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert_eq!(profiles.get("an").unwrap().database, "HXE");
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_when_guarded() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("INSERT INTO T VALUES (1)");
        spec["params"] = json!([]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-select under read_only");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_allows_write_when_read_only_off() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("INSERT INTO T VALUES (?)");
        spec["read_only"] = json!(false);
        plugin
            .register_profile("w", &spec, no_op_host())
            .await
            .expect("write under read_only=false");
        assert!(!plugin.profiles.read().await.get("w").unwrap().read_only);
    }

    #[tokio::test]
    async fn register_accepts_verify_peer_false() {
        // Unlike clickhouse, HANA supports an explicit no-verify TLS connection
        // (self-signed dev). The flag is honored, not rejected.
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["tls_verify_peer"] = json!(false);
        plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect("verify_peer=false is accepted");
    }

    #[tokio::test]
    async fn register_rejects_bare_cred() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("SELECT 1 FROM DUMMY WHERE SECRET = 'cred://aws/x#id'");
        spec["params"] = json!([]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_missing_password() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec.as_object_mut().unwrap().remove("password");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("missing password");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("password"), "{message}")
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_empty_query() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["uri"] = json!("hana://x");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_keyset_list_query_without_cursor() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({ "sql": "SELECT ID AS URI FROM T" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("missing cursor_column");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = HanaBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    /// A bad-param call (CEL references a missing path) returns a tool-error
    /// envelope (downstreamError set), not a transport `Err` — and never opens
    /// a connection (the failure is before any I/O).
    #[tokio::test]
    async fn execute_param_failure_yields_error_envelope() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "query": "SELECT ? AS X FROM DUMMY",
            "params": ["arguments.missing.deeply"],
        });
        plugin
            .register_profile("q", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({})).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "q".into())],
            request_id: "rq".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("q", req).await.expect("execute");
        let env: Value = serde_json::from_slice(&resp.payload).expect("envelope json");
        assert!(!env["downstreamError"].is_null(), "{env}");
        assert!(env["response"].is_null());
    }

    #[test]
    fn resolve_one_prefers_present_string_argument() {
        let args = json!({ "schema": "SALES" });
        // Per-call argument overrides the static value.
        assert_eq!(resolve_one(Some("STATIC"), Some("schema"), &args), "SALES");
        // Static value when no argument is configured / present.
        assert_eq!(resolve_one(Some("STATIC"), None, &args), "STATIC");
        assert_eq!(
            resolve_one(Some("STATIC"), Some("missing"), &args),
            "STATIC"
        );
        // Empty (= match all) when neither is set.
        assert_eq!(resolve_one(None, Some("missing"), &args), "");
        // A non-string argument does not override.
        let n = json!({ "schema": 7 });
        assert_eq!(resolve_one(Some("STATIC"), Some("schema"), &n), "STATIC");
    }

    #[test]
    fn catalog_filter_config_argument_names_distinct_in_order() {
        let cfg = CatalogFilterConfig {
            schema_arg: Some("schema".into()),
            table_arg: Some("table".into()),
            // a duplicate name is collapsed
            column_arg: Some("table".into()),
            ..Default::default()
        };
        assert_eq!(
            cfg.argument_names(),
            vec!["schema".to_owned(), "table".to_owned()]
        );
    }

    #[tokio::test]
    async fn register_list_columns_requires_table_or_arg() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "operation": "list_columns",
        });
        let err = plugin
            .register_profile("c", &spec, no_op_host())
            .await
            .expect_err("list_columns without table");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("list_columns"), "{message}")
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_list_tables_allows_omitted_query() {
        // Catalog operations ignore `query` — it may be omitted entirely.
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "operation": "list_tables",
            "schema": "SALES",
            "schema_arg": "schema",
        });
        plugin
            .register_profile("t", &spec, no_op_host())
            .await
            .expect("list_tables registers without a query");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("t").unwrap();
        assert_eq!(p.operation, HanaOperation::ListTables);
        assert_eq!(p.catalog_filters.schema.as_deref(), Some("SALES"));
    }

    #[tokio::test]
    async fn catalog_output_schema_types_rows() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "operation": "list_columns",
            "table": "ORDERS",
        });
        plugin
            .register_profile("c", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::output_schema(&plugin, "c").unwrap();
        let row_props =
            &schema["properties"]["response"]["properties"]["rows"]["items"]["properties"];
        assert!(row_props["COLUMN_NAME"].is_object());
        assert!(row_props["DATA_TYPE_NAME"].is_object());
    }

    #[tokio::test]
    async fn catalog_input_schema_surfaces_filter_args() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "operation": "list_tables",
            "schema_arg": "schema",
            "table_type_arg": "kind",
        });
        plugin
            .register_profile("t", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "t").unwrap();
        assert!(schema["properties"]["schema"].is_object());
        assert!(schema["properties"]["kind"].is_object());
        assert_eq!(schema["additionalProperties"], json!(true));
    }

    #[tokio::test]
    async fn list_resources_empty_when_unconfigured() {
        let plugin = HanaBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "q", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    /// A resource_template binding may declare a per-`{id}` `read_query` and omit
    /// `query`; the profile stores it and stays read-only-guarded.
    #[tokio::test]
    async fn register_resource_template_read_query() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "surface": "resource",
            "read_query": "SELECT * FROM ORDERS WHERE ID = ?",
            "params": ["arguments.id"],
        });
        plugin
            .register_profile("rt", &spec, no_op_host())
            .await
            .expect("read_query registers without a query");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rt").unwrap();
        assert_eq!(
            p.read_query.as_deref(),
            Some("SELECT * FROM ORDERS WHERE ID = ?")
        );
        assert!(p.statement.is_empty());
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_read_query_on_tool_surface() {
        let plugin = HanaBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["read_query"] = json!("SELECT * FROM T WHERE ID = ?");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("read_query on tool surface");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("read_query"), "{message}");
                assert!(message.contains("surface: resource"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_read_query() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "surface": "resource",
            "read_query": "DELETE FROM ORDERS WHERE ID = ?",
            "params": ["arguments.id"],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-read-only read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bare_cred_read_query() {
        let plugin = HanaBackendPlugin::new();
        let spec = json!({
            "host": "hana.example",
            "port": 39015,
            "user": "MCPG",
            "password": "pw",
            "surface": "resource",
            "read_query": "SELECT * FROM T WHERE K = 'cred://aws/x#id'",
            "params": [],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred in read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// The gateway delivers the extracted template variable as `arguments.<var>`;
    /// the binding's `params` CEL bind it to the `read_query`'s `?` placeholder.
    /// A value crafted to look like SQL is carried verbatim as a single scalar
    /// bind (a `HanaBind::Str`) — it is data for the driver to escape, never
    /// spliced into the statement text.
    #[test]
    fn template_var_binds_as_param_not_interpolated() {
        let compiled = params::compile_params(&["arguments.id".to_owned()]).unwrap();
        // What the gateway hands the backend for `hana://orders/{id}` on a read of
        // `hana://orders/1 OR 1=1; DROP TABLE x`.
        let injection = "1 OR 1=1; DROP TABLE x";
        let args = json!({
            "uri": format!("hana://orders/{injection}"),
            "id": injection,
            "template_vars": { "id": injection },
        });
        let values = params::evaluate_params(&compiled, &args).unwrap();
        assert_eq!(values, vec![json!(injection)]);
        let bind = params::json_to_hana_bind(values.into_iter().next().unwrap()).unwrap();
        // The whole injection string is one opaque scalar bind — the driver
        // escapes it as a HANA string literal; it never reaches SQL as text.
        assert_eq!(bind, params::HanaBind::Str(injection.to_owned()));
    }

    /// The resource-read branch shapes a single fabricated row into the
    /// `resources/read` contract body keyed on the concrete (gateway-supplied)
    /// URI.
    #[test]
    fn resource_template_read_shapes_single_row_contents() {
        let uri = "hana://orders/42";
        let row = json!({ "ID": 42, "TOTAL": 19.99 });
        let body = surface::resource_contents_body(uri, std::slice::from_ref(&row));
        let contents = body["contents"].as_array().expect("contents");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(uri));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Vec<Value> =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, vec![row]);
    }

    #[tokio::test]
    async fn complete_template_variable_empty_when_unconfigured() {
        let plugin = HanaBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "q",
            "v",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }
}
