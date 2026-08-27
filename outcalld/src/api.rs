use std::fmt::Display;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{Json, Router};
use outcall_api::{ApiResponse, CaConfig};
use tokio::sync::{Mutex, RwLock};

use crate::agent_api::RuleRequestManager;
use crate::bridge::BridgeManager;
use crate::dns::DnsServer;
use crate::docker::DockerManager;
use crate::dynamic::DynamicRuleManager;
use crate::network::NetworkManager;
use crate::proxy::ProxyServer;
use crate::rules::RuleEngine;

mod access;
mod bridge_rules;
mod containers;
mod dynamic;
mod network;
mod policy_reload;
mod rule_requests;
mod services;

pub use access::{require_operator_uid, HostPeerCred};

const HOST_API_BODY_LIMIT: usize = 1024 * 1024;

pub type SharedBridge = Arc<Mutex<BridgeManager>>;
pub type SharedRules = Arc<RuleEngine>;
pub type SharedDns = Arc<DnsServer>;
pub type SharedProxy = Arc<ProxyServer>;
pub type SharedDocker = Arc<DockerManager>;
pub type SharedDynamic = Arc<DynamicRuleManager>;
pub type SharedNetwork = Arc<NetworkManager>;
pub type SharedLifecycle = Arc<Mutex<()>>;
pub type SharedPolicyBarrier = Arc<RwLock<()>>;

#[derive(Clone)]
pub struct AppState {
    pub bridge: SharedBridge,
    pub rules: SharedRules,
    pub dns: SharedDns,
    pub proxy: SharedProxy,
    pub docker: SharedDocker,
    pub dynamic: SharedDynamic,
    pub network: SharedNetwork,
    pub lifecycle: SharedLifecycle,
    pub policy_barrier: SharedPolicyBarrier,
    pub policy_update: SharedLifecycle,
    pub ca: Arc<CaState>,
    pub rule_requests: RuleRequestManager,
    pub rules_dir: String,
}

#[derive(Clone, Default)]
pub struct CaState {
    pub config: Option<CaConfig>,
    pub interception_enabled: bool,
    pub pem_bundle: Option<String>,
}

pub fn router(state: AppState, daemon_uid: u32, operator_uid: u32) -> Router {
    Router::new()
        .route("/api/v1/bridge", get(bridge_rules::bridge_status))
        .route("/api/v1/bridge/up", post(bridge_rules::bridge_up))
        .route("/api/v1/bridge/down", post(bridge_rules::bridge_down))
        .route("/api/v1/rule/evaluate", post(bridge_rules::rule_evaluate))
        .route("/api/v1/rules", get(bridge_rules::rules_list))
        .route("/api/v1/rule/{id}", get(bridge_rules::rule_show))
        .route("/api/v1/rules/reload", post(bridge_rules::rules_reload))
        .route("/api/v1/rule/test", post(bridge_rules::rule_test))
        .route("/api/v1/dns", get(services::dns_status))
        .route("/api/v1/dns/cache", get(services::dns_cache))
        .route("/api/v1/dns/cache/flush", post(services::dns_cache_flush))
        .route("/api/v1/proxy", get(services::proxy_status))
        .route("/api/v1/containers", get(containers::list))
        .route("/api/v1/container", get(containers::inspect))
        .route("/api/v1/container/create", post(containers::create))
        .route("/api/v1/container/stop", post(containers::stop))
        .route("/api/v1/container/remove", post(containers::remove))
        .route("/api/v1/container/pull", post(containers::pull))
        .route("/api/v1/rules/active", get(dynamic::list))
        .route("/api/v1/rules/flush", post(dynamic::flush))
        .route("/api/v1/rule/allow", post(dynamic::allow))
        .route("/api/v1/network/create", post(network::create))
        .route("/api/v1/network", get(network::inspect))
        .route("/api/v1/networks", get(network::list))
        .route("/api/v1/network/destroy", post(network::destroy))
        .route("/api/v1/network/config", get(network::config))
        .route("/api/v1/ca/status", get(services::ca_status))
        .route("/api/v1/ca/bundle", get(services::ca_bundle))
        .route("/api/v1/requests/rules", get(rule_requests::list))
        .route(
            "/api/v1/requests/rules/{id}/approve",
            post(rule_requests::approve),
        )
        .route(
            "/api/v1/requests/rules/{id}/reject",
            post(rule_requests::reject),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(HOST_API_BODY_LIMIT))
        .layer(axum::middleware::from_fn(require_operator_uid(
            daemon_uid,
            operator_uid,
        )))
        // Static UI assets have no privileged operations and remain outside
        // the host-socket UID middleware.
        .merge(outcall_ui::router())
}

fn result_json<T, E>(result: Result<T, E>) -> Json<ApiResponse<T>>
where
    E: Display,
{
    match result {
        Ok(value) => Json(ApiResponse::ok(value)),
        Err(error) => Json(ApiResponse::err(error.to_string())),
    }
}
