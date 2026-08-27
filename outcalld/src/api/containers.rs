use axum::extract::{Query, State};
use axum::Json;
use outcall_api::{
    ApiResponse, ContainerCreateRequest, ContainerCreateResult, ContainerInfo,
    ContainerInspectResult, ContainerRemoveRequest, ContainerRemoveResult, ContainerStopRequest,
    ContainerStopResult, ImagePullRequest, ImagePullResult,
};
use serde::Deserialize;

use super::AppState;

fn unavailable<T>(state: &AppState) -> Option<Json<ApiResponse<T>>> {
    state
        .docker
        .is_unavailable()
        .then(|| Json(ApiResponse::err("Docker manager unavailable")))
}

pub(super) async fn list(State(state): State<AppState>) -> Json<ApiResponse<Vec<ContainerInfo>>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    super::result_json(state.docker.list_containers().await)
}

#[derive(Deserialize)]
pub(super) struct NameQuery {
    name: String,
}

pub(super) async fn inspect(
    State(state): State<AppState>,
    Query(query): Query<NameQuery>,
) -> Json<ApiResponse<ContainerInspectResult>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    super::result_json(state.docker.inspect_container(&query.name).await)
}

pub(super) async fn create(
    State(state): State<AppState>,
    Json(request): Json<ContainerCreateRequest>,
) -> Json<ApiResponse<ContainerCreateResult>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    let _lifecycle = state.lifecycle.lock().await;
    if let Err(error) = state
        .bridge
        .lock()
        .await
        .require_netfilter_enforceable()
        .await
    {
        return Json(ApiResponse::err(error.to_string()));
    }
    let proxy_address = state
        .proxy
        .is_running()
        .then(|| state.proxy.listen_addr.to_string());
    let dns_address = state.dns.status().await.listen_address;
    match state
        .docker
        .create_container(request, proxy_address.as_deref(), &dns_address)
        .await
    {
        Ok(result) => Json(ApiResponse::ok(result)),
        Err(error) => Json(ApiResponse::err(format!("{error:#}"))),
    }
}

pub(super) async fn stop(
    State(state): State<AppState>,
    Json(request): Json<ContainerStopRequest>,
) -> Json<ApiResponse<ContainerStopResult>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    super::result_json(
        state
            .docker
            .stop_container(&request.name, request.timeout)
            .await,
    )
}

pub(super) async fn remove(
    State(state): State<AppState>,
    Json(request): Json<ContainerRemoveRequest>,
) -> Json<ApiResponse<ContainerRemoveResult>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    super::result_json(
        state
            .docker
            .remove_container(&request.name, request.force.unwrap_or(false))
            .await,
    )
}

pub(super) async fn pull(
    State(state): State<AppState>,
    Json(request): Json<ImagePullRequest>,
) -> Json<ApiResponse<ImagePullResult>> {
    if let Some(response) = unavailable(&state) {
        return response;
    }
    super::result_json(state.docker.pull_image(&request.image).await)
}
