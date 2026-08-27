use axum::extract::{Path, State};
use axum::Json;
use outcall_api::{
    ApiResponse, BridgeStatus, EvaluateRequest, EvaluateResult, ReloadResult, RuleDetail,
    RuleSummary, TestExpressionRequest, TestExpressionResult,
};

use super::AppState;
use crate::rules::RuleEngine;

pub(super) async fn bridge_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<BridgeStatus>> {
    super::result_json(state.bridge.lock().await.status().await)
}

pub(super) async fn bridge_up(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    let _lifecycle = state.lifecycle.lock().await;
    super::result_json(state.bridge.lock().await.init().await)
}

pub(super) async fn bridge_down(State(state): State<AppState>) -> Json<ApiResponse<()>> {
    let _lifecycle = state.lifecycle.lock().await;
    let containers = match state.docker.list_containers().await {
        Ok(containers) => containers,
        Err(error) => {
            return Json(ApiResponse::err(format!(
                "cannot verify bridge teardown safety: {error}"
            )));
        }
    };
    if !containers.is_empty() {
        let names = containers
            .iter()
            .map(|container| container.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Json(ApiResponse::err(format!(
            "cannot tear down bridge while managed containers exist: {names}"
        )));
    }
    let networks = match state.network.list_networks().await {
        Ok(networks) => networks,
        Err(error) => {
            return Json(ApiResponse::err(format!(
                "cannot verify bridge teardown safety: {error}"
            )));
        }
    };
    if !networks.is_empty() {
        let names = networks
            .iter()
            .map(|network| network.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Json(ApiResponse::err(format!(
            "cannot tear down bridge while managed networks exist: {names}"
        )));
    }
    super::result_json(state.bridge.lock().await.teardown().await)
}

pub(super) async fn rule_evaluate(
    State(state): State<AppState>,
    Json(request): Json<EvaluateRequest>,
) -> Json<ApiResponse<EvaluateResult>> {
    let bridge_up = match state.bridge.lock().await.status().await {
        Ok(status) => status.up,
        Err(error) => return Json(ApiResponse::err(error.to_string())),
    };
    if !bridge_up {
        return Json(ApiResponse::err(
            "rule evaluation unavailable: bridge is not up",
        ));
    }
    Json(ApiResponse::ok(
        state.rules.evaluate(&request.context).await,
    ))
}

pub(super) async fn rules_list(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<RuleSummary>>> {
    Json(ApiResponse::ok(state.rules.list_rules().await))
}

pub(super) async fn rule_show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<RuleDetail>> {
    match state.rules.get_rule(&id).await {
        Some(detail) => Json(ApiResponse::ok(detail)),
        None => Json(ApiResponse::err(format!("rule not found: \"{id}\""))),
    }
}

pub(super) async fn rules_reload(State(state): State<AppState>) -> Json<ApiResponse<ReloadResult>> {
    match super::policy_reload::reload(&state).await {
        Ok((files_loaded, rules_loaded, warnings)) => Json(ApiResponse::ok(ReloadResult {
            files_loaded,
            rules_loaded,
            warnings,
        })),
        Err(error) => Json(ApiResponse::err(format!(
            "reload failed: {error}. Previous rules remain active."
        ))),
    }
}

pub(super) async fn rule_test(
    Json(request): Json<TestExpressionRequest>,
) -> Json<ApiResponse<TestExpressionResult>> {
    let (result, error) = RuleEngine::test_expression(&request.expression, &request.context);
    Json(ApiResponse::ok(TestExpressionResult { result, error }))
}
