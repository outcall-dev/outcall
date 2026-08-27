use axum::extract::{Query, State};
use axum::Json;
use outcall_api::{
    ApiResponse, NetworkCreateRequest, NetworkCreateResult, NetworkDestroyRequest,
    NetworkDestroyResult, NetworkStatus,
};
use serde::{Deserialize, Serialize};

use super::AppState;

pub(super) async fn create(
    State(state): State<AppState>,
    Json(request): Json<NetworkCreateRequest>,
) -> Json<ApiResponse<NetworkCreateResult>> {
    let _lifecycle = state.lifecycle.lock().await;
    super::result_json(state.network.create_network(request).await)
}

#[derive(Deserialize)]
pub(super) struct NameQuery {
    name: Option<String>,
}

pub(super) async fn inspect(
    State(state): State<AppState>,
    Query(query): Query<NameQuery>,
) -> Json<ApiResponse<NetworkStatus>> {
    super::result_json(state.network.inspect_network(query.name.as_deref()).await)
}

pub(super) async fn list(State(state): State<AppState>) -> Json<ApiResponse<Vec<NetworkStatus>>> {
    super::result_json(state.network.list_networks().await)
}

pub(super) async fn destroy(
    State(state): State<AppState>,
    Json(request): Json<NetworkDestroyRequest>,
) -> Json<ApiResponse<NetworkDestroyResult>> {
    let _lifecycle = state.lifecycle.lock().await;
    super::result_json(state.network.destroy_network(request.name.as_deref()).await)
}

#[derive(Serialize)]
pub(super) struct Config {
    subnet_block: String,
}

pub(super) async fn config(State(state): State<AppState>) -> Json<ApiResponse<Config>> {
    Json(ApiResponse::ok(Config {
        subnet_block: state.network.subnet_block_cidr(),
    }))
}
