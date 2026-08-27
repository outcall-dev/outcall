use std::collections::HashMap;

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use outcall_api::{
    AgentRuleSubmitRequest, ApiResponse, CheckinData, Decision, PermissionRequest,
    RuleRequestResponse, RuleRequestStatus, Verdict,
};

use super::context::build_eval_context;
use super::evaluation::EvaluationError;
use super::identity::{resolve_peer_container, resolve_session, UnixPeerCred};
use super::limiter::{reap_stale, retry_after_seconds, SlidingWindow};
use super::rule_requests::generate_request_id;
use super::sessions::generate_token;
use super::{valid_request_id, AgentApiError, AgentState, RateLimitConfig, RuleRequestEntry};
use crate::rules::RuleEngine;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckinRequest {}

pub(super) async fn checkin(
    ConnectInfo(peer): ConnectInfo<UnixPeerCred>,
    State(state): State<AgentState>,
    payload: Result<Json<CheckinRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = json_payload(payload) {
        return error.into_response();
    }
    let container = match resolve_peer_container(&state, &peer).await {
        Ok(container) => container,
        Err(error) => return error.into_response(),
    };

    let mut sessions = state.sessions.lock().await;
    if let Some((token, existing)) = sessions.existing_for_container(&container.id) {
        info!(container_id = %container.id, "check-in: returning existing session");
        return (
            StatusCode::OK,
            Json(ApiResponse::ok(CheckinData {
                container_id: existing.id,
                session_token: token,
                context_keys: default_context_keys(),
            })),
        )
            .into_response();
    }

    let token = match generate_token() {
        Ok(token) => token,
        Err(error) => {
            error!(%error, "check-in: secure token generation failed");
            return AgentApiError::Internal("secure token generation unavailable").into_response();
        }
    };
    let response = CheckinData {
        container_id: container.id.clone(),
        session_token: token.clone(),
        context_keys: default_context_keys(),
    };
    if let Err(error) = sessions.insert(token, container.clone()) {
        error!(%error, "check-in: session registry unavailable");
        return AgentApiError::SessionCapacity.into_response();
    }

    info!(container_id = %container.id, peer_pid = ?peer.pid, "check-in: new session");
    (StatusCode::OK, Json(ApiResponse::ok(response))).into_response()
}

fn default_context_keys() -> Vec<String> {
    ["action_type", "target", "metadata"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(super) async fn permissions_check(
    ConnectInfo(peer): ConnectInfo<UnixPeerCred>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    payload: Result<Json<PermissionRequest>, JsonRejection>,
) -> Response {
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let container = match resolve_session(&state, &peer, &headers).await {
        Ok(container) => container,
        Err(error) => return error.into_response(),
    };

    if let Some(response) = check_rate_limit(
        &state.permission_rates,
        &container.id,
        state.permission_rate,
        "permission check",
    )
    .await
    {
        return response;
    }

    let context = match build_eval_context(&request, &container.name) {
        Ok(context) => context,
        Err(error) => {
            return AgentApiError::InvalidRequest(format!("permission request: {error}"))
                .into_response();
        }
    };

    let verdict = match state.evaluations.evaluate(&state.rules, context).await {
        Ok(result) => Verdict {
            allowed: matches!(result.decision, Decision::Allow),
            matched_rule: result.matched_rule.clone(),
            reason: matches!(result.decision, Decision::Block)
                .then(|| "blocked by policy".to_string()),
        },
        Err(EvaluationError::Timeout) => {
            warn!(container_id = %container.id, "permission check: evaluation timeout");
            Verdict {
                allowed: false,
                matched_rule: None,
                reason: Some(AgentApiError::EvaluationTimeout.to_string()),
            }
        }
        Err(EvaluationError::Worker(error)) => {
            error!(container_id = %container.id, %error, "permission check: evaluation failed");
            Verdict {
                allowed: false,
                matched_rule: None,
                reason: Some(AgentApiError::EvaluationUnavailable.to_string()),
            }
        }
    };

    info!(
        container_id = %container.id,
        action_type = ?request.action_type,
        target = %request.target,
        allowed = verdict.allowed,
        "permission check"
    );
    (StatusCode::OK, Json(ApiResponse::ok(verdict))).into_response()
}

pub(super) async fn rule_request_submit(
    ConnectInfo(peer): ConnectInfo<UnixPeerCred>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    payload: Result<Json<AgentRuleSubmitRequest>, JsonRejection>,
) -> Response {
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let container = match resolve_session(&state, &peer, &headers).await {
        Ok(container) => container,
        Err(error) => return error.into_response(),
    };

    if let Some(response) = check_rate_limit(
        &state.rule_rates,
        &container.id,
        state.rule_rate,
        "rule submit",
    )
    .await
    {
        return response;
    }

    if let Err(error) = RuleEngine::validate_rule_file(&request.rule_file) {
        return AgentApiError::InvalidRequest(format!("rule file: {error}")).into_response();
    }
    let request_id = match generate_request_id() {
        Ok(request_id) => request_id,
        Err(error) => {
            error!(%error, "rule submit: secure request ID generation failed");
            return AgentApiError::Internal("secure request ID generation unavailable")
                .into_response();
        }
    };
    let response = RuleRequestResponse {
        id: request_id.clone(),
        status: RuleRequestStatus::Pending,
        reason: None,
    };
    let entry = RuleRequestEntry {
        container_id: container.id.clone(),
        rule_file: request.rule_file,
        status: RuleRequestStatus::Pending,
        reason: None,
    };

    if let Err(error) = state.rule_requests.insert(request_id, entry).await {
        error!(%error, "rule submit: failed to persist request");
        return AgentApiError::Internal("failed to persist rule request").into_response();
    }

    info!(container_id = %container.id, "rule request submitted");
    (StatusCode::CREATED, Json(ApiResponse::ok(response))).into_response()
}

pub(super) async fn rule_request_status(
    ConnectInfo(peer): ConnectInfo<UnixPeerCred>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let container = match resolve_session(&state, &peer, &headers).await {
        Ok(container) => container,
        Err(error) => return error.into_response(),
    };
    if !valid_request_id(&id) {
        return AgentApiError::RuleRequestNotFound.into_response();
    }

    match state.rule_requests.get(&id).await {
        Some(entry) if entry.container_id == container.id => {
            info!(
                container_id = %container.id,
                request_id = %id,
                status = ?entry.status,
                "rule request status"
            );
            (
                StatusCode::OK,
                Json(ApiResponse::ok(RuleRequestResponse {
                    id,
                    status: entry.status,
                    reason: entry.reason,
                })),
            )
                .into_response()
        }
        _ => AgentApiError::RuleRequestNotFound.into_response(),
    }
}

async fn check_rate_limit(
    rates: &Mutex<HashMap<String, SlidingWindow>>,
    container_id: &str,
    config: RateLimitConfig,
    operation: &'static str,
) -> Option<Response> {
    let retry_after = {
        let mut rates = rates.lock().await;
        reap_stale(&mut rates);
        rates
            .entry(container_id.to_string())
            .or_insert_with(|| SlidingWindow::new(config.limit, config.window))
            .check()
            .err()
    }?;

    warn!(%container_id, operation, "agent API request rate limited");
    Some(
        AgentApiError::RateLimited {
            container_id: container_id.to_string(),
            retry_after_seconds: retry_after_seconds(retry_after),
        }
        .into_response(),
    )
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, AgentApiError> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AgentApiError::RequestBodyTooLarge
        } else {
            AgentApiError::MalformedRequest("malformed JSON body")
        }
    })
}
