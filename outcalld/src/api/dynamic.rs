use axum::extract::State;
use axum::Json;
use outcall_api::{ActiveRule, AllowRuleRequest, AllowRuleResult, ApiResponse, FlushDynamicResult};

use super::AppState;

pub(super) async fn list(State(state): State<AppState>) -> Json<ApiResponse<Vec<ActiveRule>>> {
    Json(ApiResponse::ok(state.dynamic.list_rules().await))
}

pub(super) async fn flush(State(state): State<AppState>) -> Json<ApiResponse<FlushDynamicResult>> {
    super::result_json(state.dynamic.flush_all().await)
}

pub(super) async fn allow(
    State(state): State<AppState>,
    Json(request): Json<AllowRuleRequest>,
) -> Json<ApiResponse<AllowRuleResult>> {
    let _policy = state.policy_barrier.read().await;
    super::result_json(state.dynamic.insert_rule(request).await)
}
