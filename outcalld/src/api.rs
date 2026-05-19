use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use outcall_api::{
    ActiveRule, AllowRuleRequest, AllowRuleResult, ApiResponse, BridgeStatus, CaBundleResult,
    CaConfig, CaStatus, ContainerCreateRequest, ContainerCreateResult, ContainerInfo,
    ContainerInspectResult, ContainerRemoveRequest, ContainerRemoveResult, ContainerStopRequest,
    ContainerStopResult, DnsCacheDetail, DnsCacheFlushResult, DnsFilterStatus, EvaluateRequest,
    EvaluateResult, FlushDynamicResult, ImagePullRequest, ImagePullResult, NetworkCreateRequest,
    NetworkCreateResult, NetworkDestroyRequest, NetworkDestroyResult, NetworkStatus, ProxyStatus,
    ReloadResult, RuleDetail, RuleSummary, TestExpressionRequest, TestExpressionResult,
};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::bridge::BridgeManager;
use crate::dns::DnsServer;
use crate::docker::DockerManager;
use crate::dynamic::DynamicRuleManager;
use crate::network::NetworkManager;
use crate::proxy::ProxyServer;
use crate::rules::RuleEngine;

// ── Host socket peer credentials ──────────────────────────────────────────────

/// Unix peer credentials extracted at connection time for the host control socket.
/// Carries uid/gid so the access-control middleware can enforce UID policy.
#[derive(Clone, Debug)]
pub struct HostPeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<u32>,
}

impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, tokio::net::UnixListener>,
    > for HostPeerCred
{
    fn connect_info(target: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        match target.io().peer_cred() {
            Ok(cred) => HostPeerCred {
                uid: cred.uid(),
                gid: cred.gid(),
                pid: cred.pid().map(|p| p as u32),
            },
            Err(_) => {
                // Deny-by-default: use a sentinel that no real process has.
                HostPeerCred {
                    uid: u32::MAX,
                    gid: u32::MAX,
                    pid: None,
                }
            }
        }
    }
}

/// Axum middleware factory enforcing host-socket UID policy.
///
/// Allowed UIDs: UID 0 (root) **or** `daemon_uid` (the effective UID of the
/// daemon process, i.e. the operator user that started `outcalld`). Any other
/// caller receives 403 Forbidden. If peer credentials are unavailable the
/// connection is also rejected.
///
/// `daemon_uid` is captured once at startup so this module avoids any `unsafe`
/// libc calls (the lib crate enforces `#![forbid(unsafe_code)]`); main.rs is
/// the binary crate where the libc call lives.
pub fn require_operator_uid(
    daemon_uid: u32,
) -> impl Fn(
    ConnectInfo<HostPeerCred>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone
       + Send
       + Sync
       + 'static {
    move |ConnectInfo(peer), req, next| {
        Box::pin(async move {
            let allowed = peer.uid == 0 || peer.uid == daemon_uid;
            if !allowed {
                tracing::warn!(
                    peer_uid = peer.uid,
                    daemon_uid = daemon_uid,
                    "host API: connection rejected — foreign UID"
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(outcall_api::ApiResponse::<()>::err(
                        "forbidden: host API requires root or daemon UID",
                    )),
                )
                    .into_response();
            }
            next.run(req).await
        })
    }
}

pub type SharedBridge = Arc<Mutex<BridgeManager>>;
pub type SharedRules = Arc<RuleEngine>;
pub type SharedDns = Arc<DnsServer>;
pub type SharedProxy = Arc<ProxyServer>;
pub type SharedDocker = Arc<DockerManager>;
pub type SharedDynamic = Arc<DynamicRuleManager>;
pub type SharedNetwork = Arc<NetworkManager>;

#[derive(Clone)]
pub struct AppState {
    pub bridge: SharedBridge,
    pub rules: SharedRules,
    pub dns: SharedDns,
    pub proxy: SharedProxy,
    pub docker: SharedDocker,
    pub dynamic: SharedDynamic,
    pub network: SharedNetwork,
    pub ca: Arc<CaState>,
}

#[derive(Clone, Default)]
pub struct CaState {
    pub config: Option<CaConfig>,
    pub interception_enabled: bool,
    pub pem_bundle: Option<String>,
}

pub fn router(
    bridge: SharedBridge,
    rules: SharedRules,
    dns: SharedDns,
    proxy: SharedProxy,
    docker: SharedDocker,
    dynamic: SharedDynamic,
    network: SharedNetwork,
    ca: CaState,
    daemon_uid: u32,
) -> Router {
    let state = AppState {
        bridge,
        rules,
        dns,
        proxy,
        docker,
        dynamic,
        network,
        ca: Arc::new(ca),
    };
    Router::new()
        // Bridge endpoints
        .route("/api/v1/bridge", get(bridge_status))
        .route("/api/v1/bridge/up", post(bridge_up))
        .route("/api/v1/bridge/down", post(bridge_down))
        // Rule engine endpoints (S003)
        .route("/api/v1/rule/evaluate", post(rule_evaluate))
        .route("/api/v1/rules", get(rules_list))
        .route("/api/v1/rule/{id}", get(rule_show))
        .route("/api/v1/rules/reload", post(rules_reload))
        .route("/api/v1/rule/test", post(rule_test))
        // DNS filter endpoints (S007)
        .route("/api/v1/dns", get(dns_status))
        .route("/api/v1/dns/cache", get(dns_cache))
        .route("/api/v1/dns/cache/flush", post(dns_cache_flush))
        // HTTP proxy endpoint (S006)
        .route("/api/v1/proxy", get(proxy_status))
        // Docker Manager endpoints (S008)
        .route("/api/v1/containers", get(containers_list))
        .route("/api/v1/container", get(container_inspect))
        .route("/api/v1/container/create", post(container_create))
        .route("/api/v1/container/stop", post(container_stop))
        .route("/api/v1/container/remove", post(container_remove))
        .route("/api/v1/container/pull", post(container_pull))
        // Dynamic Rules endpoints (S009)
        .route("/api/v1/rules/active", get(dynamic_rules_list))
        .route("/api/v1/rules/flush", post(dynamic_rules_flush))
        .route("/api/v1/rule/allow", post(dynamic_rule_allow))
        // Network Management endpoints (S002)
        .route("/api/v1/network/create", post(network_create))
        .route("/api/v1/network", get(network_inspect))
        .route("/api/v1/networks", get(network_list))
        .route("/api/v1/network/destroy", post(network_destroy))
        .route("/api/v1/network/config", get(network_config))
        // CA / TLS interception endpoints (S011)
        .route("/api/v1/ca/status", get(ca_status))
        .route("/api/v1/ca/bundle", get(ca_bundle))
        .with_state(state)
        // Enforce host-socket UID policy on all API routes (defence in depth;
        // primary protection is the 0600 socket file mode set in main.rs).
        .layer(axum::middleware::from_fn(require_operator_uid(daemon_uid)))
        // Dashboard (S010) — stateless, merged after state is bound.
        // The UI routes are intentionally exempt from UID gating since the
        // dashboard serves only static assets and has no privileged operations.
        .merge(outcall_ui::router())
}

// ── Bridge handlers ────────────────────────────────────────────────────────

async fn bridge_status(State(state): State<AppState>) -> Json<ApiResponse<BridgeStatus>> {
    let mgr = state.bridge.lock().await;
    Json(ApiResponse::ok(mgr.status().await))
}

async fn bridge_up(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    let mut mgr = state.bridge.lock().await;
    match mgr.init().await {
        Ok(()) => Json(ApiResponse::ok(())),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

async fn bridge_down(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    let mgr = state.bridge.lock().await;
    match mgr.teardown().await {
        Ok(()) => Json(ApiResponse::ok(())),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

// ── Rule engine handlers ───────────────────────────────────────────────────

/// POST /api/v1/rule/evaluate — evaluate a request context against loaded rules.
async fn rule_evaluate(
    State(state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> Json<ApiResponse<EvaluateResult>> {
    // FR-033: check bridge is up before evaluating
    let bridge_up = state.bridge.lock().await.status().await.up;
    if !bridge_up {
        return Json(ApiResponse::err(
            "rule evaluation unavailable: bridge is not up",
        ));
    }
    let result = state.rules.evaluate(&req.context).await;
    Json(ApiResponse::ok(result))
}

/// GET /api/v1/rules — list all loaded rules in evaluation order.
async fn rules_list(State(state): State<AppState>) -> Json<ApiResponse<Vec<RuleSummary>>> {
    Json(ApiResponse::ok(state.rules.list_rules().await))
}

/// GET /api/v1/rule/:id — get details for a specific rule.
async fn rule_show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<RuleDetail>> {
    match state.rules.get_rule(&id).await {
        Some(detail) => Json(ApiResponse::ok(detail)),
        None => Json(ApiResponse::err(format!("rule not found: \"{id}\""))),
    }
}

/// POST /api/v1/rules/reload — reload rules from disk atomically.
async fn rules_reload(State(state): State<AppState>) -> Json<ApiResponse<ReloadResult>> {
    match state.rules.reload().await {
        Ok((files, rules, warnings)) => Json(ApiResponse::ok(ReloadResult {
            files_loaded: files,
            rules_loaded: rules,
            warnings,
        })),
        Err(e) => Json(ApiResponse::err(format!(
            "reload failed: {e}. Previous rules remain active."
        ))),
    }
}

/// POST /api/v1/rule/test — test a CEL expression against a context.
async fn rule_test(
    Json(req): Json<TestExpressionRequest>,
) -> Json<ApiResponse<TestExpressionResult>> {
    let (result, error) = RuleEngine::test_expression(&req.expression, &req.context);
    Json(ApiResponse::ok(TestExpressionResult { result, error }))
}

// ── DNS filter handlers ────────────────────────────────────────────────────

/// GET /api/v1/dns — DNS filter status.
async fn dns_status(State(state): State<AppState>) -> Json<ApiResponse<DnsFilterStatus>> {
    Json(ApiResponse::ok(state.dns.status().await))
}

/// Query parameters for GET /api/v1/dns/cache.
#[derive(Deserialize)]
struct CacheQuery {
    entries: Option<bool>,
}

/// GET /api/v1/dns/cache — cache statistics (and optionally entries).
async fn dns_cache(
    State(state): State<AppState>,
    Query(q): Query<CacheQuery>,
) -> Json<ApiResponse<DnsCacheDetail>> {
    let stats = state.dns.cache_stats().await;
    let entries = if q.entries.unwrap_or(false) {
        state.dns.cache_entries_list().await
    } else {
        vec![]
    };
    Json(ApiResponse::ok(DnsCacheDetail { stats, entries }))
}

/// POST /api/v1/dns/cache/flush — flush the DNS cache.
async fn dns_cache_flush(State(state): State<AppState>) -> Json<ApiResponse<DnsCacheFlushResult>> {
    let entries_flushed = state.dns.flush_cache().await;
    Json(ApiResponse::ok(DnsCacheFlushResult { entries_flushed }))
}

// ── HTTP proxy handler ─────────────────────────────────────────────────────

/// GET /api/v1/proxy — HTTP proxy status.
async fn proxy_status(State(state): State<AppState>) -> Json<ApiResponse<ProxyStatus>> {
    let (active, total_req, total_blocked) = state.proxy.stats();
    Json(ApiResponse::ok(ProxyStatus {
        running: state.proxy.is_running(),
        listen_address: state.proxy.listen_addr.to_string(),
        proxy_url: state.proxy.proxy_url(),
        active_connections: active,
        total_requests: total_req,
        total_blocked,
    }))
}

// ── Docker Manager handlers (S008) ─────────────────────────────────────────

/// GET /api/v1/containers — list all outcall-managed containers.
async fn containers_list(State(state): State<AppState>) -> Json<ApiResponse<Vec<ContainerInfo>>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    match state.docker.list_containers().await {
        Ok(list) => Json(ApiResponse::ok(list)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// Query parameters for GET /api/v1/container?name=<name>.
#[derive(Deserialize)]
struct ContainerNameQuery {
    name: String,
}

/// GET /api/v1/container?name=<name> — inspect a single container.
async fn container_inspect(
    State(state): State<AppState>,
    Query(q): Query<ContainerNameQuery>,
) -> Json<ApiResponse<ContainerInspectResult>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    match state.docker.inspect_container(&q.name).await {
        Ok(detail) => Json(ApiResponse::ok(detail)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /api/v1/container/create — create and start an agent container.
async fn container_create(
    State(state): State<AppState>,
    Json(req): Json<ContainerCreateRequest>,
) -> Json<ApiResponse<ContainerCreateResult>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    // Derive proxy and DNS addresses from the running subsystems.
    let proxy_addr = state.proxy.listen_addr.to_string();
    let dns_addr = {
        let status = state.dns.status().await;
        format!("{}:{}", status.listen_address, status.listen_port)
    };
    match state
        .docker
        .create_container(req, &proxy_addr, &dns_addr)
        .await
    {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /api/v1/container/stop — stop a running container.
async fn container_stop(
    State(state): State<AppState>,
    Json(req): Json<ContainerStopRequest>,
) -> Json<ApiResponse<ContainerStopResult>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    match state.docker.stop_container(&req.name, req.timeout).await {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /api/v1/container/remove — remove a stopped container.
async fn container_remove(
    State(state): State<AppState>,
    Json(req): Json<ContainerRemoveRequest>,
) -> Json<ApiResponse<ContainerRemoveResult>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    match state
        .docker
        .remove_container(&req.name, req.force.unwrap_or(false))
        .await
    {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /api/v1/container/pull — pull an image from a registry.
async fn container_pull(
    State(state): State<AppState>,
    Json(req): Json<ImagePullRequest>,
) -> Json<ApiResponse<ImagePullResult>> {
    if state.docker.is_unavailable() {
        return Json(ApiResponse::err("Docker manager unavailable"));
    }
    match state.docker.pull_image(&req.image).await {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

// ── Dynamic Rules handlers (S009) ──────────────────────────────────────────

/// GET /api/v1/rules/active — list all active dynamic nftables rules.
async fn dynamic_rules_list(State(state): State<AppState>) -> Json<ApiResponse<Vec<ActiveRule>>> {
    Json(ApiResponse::ok(state.dynamic.list_rules().await))
}

/// POST /api/v1/rules/flush — remove all dynamic rules.
async fn dynamic_rules_flush(
    State(state): State<AppState>,
) -> Json<ApiResponse<FlushDynamicResult>> {
    Json(ApiResponse::ok(state.dynamic.flush_all().await))
}

/// POST /api/v1/rule/allow — insert a dynamic allow rule for a container.
async fn dynamic_rule_allow(
    State(state): State<AppState>,
    Json(req): Json<AllowRuleRequest>,
) -> Json<ApiResponse<AllowRuleResult>> {
    match state.dynamic.insert_rule(req).await {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

// ── Network Management handlers (S002) ─────────────────────────────────────

/// POST /api/v1/network/create — create or reuse an outcall network.
async fn network_create(
    State(state): State<AppState>,
    Json(req): Json<NetworkCreateRequest>,
) -> Json<ApiResponse<NetworkCreateResult>> {
    match state.network.create_network(req).await {
        Ok(r) => Json(ApiResponse::ok(r)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

#[derive(Deserialize)]
struct NetworkNameQuery {
    name: Option<String>,
}

/// GET /api/v1/network[?name=<name>] — inspect a single network.
async fn network_inspect(
    State(state): State<AppState>,
    Query(q): Query<NetworkNameQuery>,
) -> Json<ApiResponse<NetworkStatus>> {
    match state.network.inspect_network(q.name.as_deref()).await {
        Ok(r) => Json(ApiResponse::ok(r)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// GET /api/v1/networks — list all outcall-managed networks.
async fn network_list(State(state): State<AppState>) -> Json<ApiResponse<Vec<NetworkStatus>>> {
    match state.network.list_networks().await {
        Ok(r) => Json(ApiResponse::ok(r)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /api/v1/network/destroy — remove a network (refuses if containers connected).
async fn network_destroy(
    State(state): State<AppState>,
    Json(req): Json<NetworkDestroyRequest>,
) -> Json<ApiResponse<NetworkDestroyResult>> {
    match state.network.destroy_network(req.name.as_deref()).await {
        Ok(r) => Json(ApiResponse::ok(r)),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

#[derive(serde::Serialize)]
struct NetworkConfig {
    subnet_block: String,
}

/// GET /api/v1/network/config — return the configured subnet block (FR-031).
async fn network_config(State(state): State<AppState>) -> Json<ApiResponse<NetworkConfig>> {
    Json(ApiResponse::ok(NetworkConfig {
        subnet_block: state.network.subnet_block_cidr(),
    }))
}

// ── CA / TLS interception handlers (S011) ─────────────────────────────────

/// GET /api/v1/ca/status — return CA loading status (S011-IF-009).
async fn ca_status(State(state): State<AppState>) -> Json<ApiResponse<CaStatus>> {
    let loaded = state.ca.config.is_some();
    let (cert_path, key_path, subject_serial, interception_enabled) =
        if let Some(ref cfg) = state.ca.config {
            let serial = read_ca_serial(cfg);
            (
                Some(cfg.cert_path.to_string_lossy().to_string()),
                Some(cfg.key_path.to_string_lossy().to_string()),
                serial,
                state.ca.interception_enabled,
            )
        } else {
            (None, None, None, false)
        };
    Json(ApiResponse::ok(CaStatus {
        loaded,
        cert_path,
        key_path,
        subject_serial,
        interception_enabled,
    }))
}

/// GET /api/v1/ca/bundle — return CA PEM bundle (S011-FR-018).
async fn ca_bundle(State(state): State<AppState>) -> Json<ApiResponse<CaBundleResult>> {
    match &state.ca.pem_bundle {
        Some(bundle) => Json(ApiResponse::ok(CaBundleResult {
            pem_bundle: bundle.clone(),
        })),
        None => Json(ApiResponse::err("no CA loaded".to_string())),
    }
}

fn read_ca_serial(_cfg: &CaConfig) -> Option<String> {
    // TODO: Parse PEM, extract SubjectSerial from X509 cert
    None
}
