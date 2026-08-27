use axum::extract::{Query, State};
use axum::Json;
use outcall_api::{
    ApiResponse, CaBundleResult, CaStatus, DnsCacheDetail, DnsCacheFlushResult, DnsFilterStatus,
    ProxyStatus,
};
use serde::Deserialize;

use super::AppState;

pub(super) async fn dns_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<DnsFilterStatus>> {
    Json(ApiResponse::ok(state.dns.status().await))
}

#[derive(Deserialize)]
pub(super) struct CacheQuery {
    entries: Option<bool>,
}

pub(super) async fn dns_cache(
    State(state): State<AppState>,
    Query(query): Query<CacheQuery>,
) -> Json<ApiResponse<DnsCacheDetail>> {
    let stats = state.dns.cache_stats().await;
    let entries = if query.entries.unwrap_or(false) {
        state.dns.cache_entries_list().await
    } else {
        vec![]
    };
    Json(ApiResponse::ok(DnsCacheDetail { stats, entries }))
}

pub(super) async fn dns_cache_flush(
    State(state): State<AppState>,
) -> Json<ApiResponse<DnsCacheFlushResult>> {
    Json(ApiResponse::ok(DnsCacheFlushResult {
        entries_flushed: state.dns.flush_cache().await,
    }))
}

pub(super) async fn proxy_status(State(state): State<AppState>) -> Json<ApiResponse<ProxyStatus>> {
    let (active_connections, total_requests, total_blocked) = state.proxy.stats();
    Json(ApiResponse::ok(ProxyStatus {
        running: state.proxy.is_running(),
        listen_address: state.proxy.listen_addr.to_string(),
        proxy_url: state.proxy.proxy_url(),
        active_connections,
        total_requests,
        total_blocked,
    }))
}

pub(super) async fn ca_status(State(state): State<AppState>) -> Json<ApiResponse<CaStatus>> {
    let loaded = state.ca.config.is_some();
    let (cert_path, key_path, subject_serial, interception_enabled) = match &state.ca.config {
        Some(config) => {
            let serial = match crate::ca::read_certificate_serial(&config.cert_path) {
                Ok(serial) => Some(serial),
                Err(error) => return Json(ApiResponse::err(error.to_string())),
            };
            (
                Some(config.cert_path.to_string_lossy().to_string()),
                Some(config.key_path.to_string_lossy().to_string()),
                serial,
                state.ca.interception_enabled,
            )
        }
        None => (None, None, None, false),
    };
    Json(ApiResponse::ok(CaStatus {
        loaded,
        cert_path,
        key_path,
        subject_serial,
        interception_enabled,
    }))
}

pub(super) async fn ca_bundle(State(state): State<AppState>) -> Json<ApiResponse<CaBundleResult>> {
    match &state.ca.pem_bundle {
        Some(bundle) => Json(ApiResponse::ok(CaBundleResult {
            pem_bundle: bundle.clone(),
        })),
        None => Json(ApiResponse::err("no CA loaded")),
    }
}
