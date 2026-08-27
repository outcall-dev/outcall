use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use outcall_api::{
    ApiResponse, ApproveRuleResult, PendingRuleRequest, RejectRuleRequest, RejectRuleResult,
    RuleRequestStatus,
};

use super::AppState;
use crate::agent_api::valid_request_id;

const REJECTION_REASON_LIMIT: usize = 1024;

pub(super) async fn list(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<PendingRuleRequest>>> {
    let entries = state.rule_requests.list_pending().await;
    let mut list: Vec<PendingRuleRequest> = entries
        .into_iter()
        .map(|(id, entry)| PendingRuleRequest {
            id,
            container_id: entry.container_id,
            rule_file: entry.rule_file,
            status: entry.status,
            reason: entry.reason,
        })
        .collect();
    list.sort_by(|left, right| left.id.cmp(&right.id));
    Json(ApiResponse::ok(list))
}

pub(super) async fn approve(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if !valid_request_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<ApproveRuleResult>::err(
                "invalid rule request ID",
            )),
        )
            .into_response();
    }
    let _transition = state.rule_requests.lock_transition().await;
    let entry = match state.rule_requests.get(&id).await {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<ApproveRuleResult>::err(format!(
                    "rule request \"{id}\" not found"
                ))),
            )
                .into_response();
        }
    };

    if entry.status == RuleRequestStatus::Approved {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<ApproveRuleResult>::err(format!(
                "rule request \"{id}\" is already approved"
            ))),
        )
            .into_response();
    }
    if entry.status == RuleRequestStatus::Rejected {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<ApproveRuleResult>::err(format!(
                "rule request \"{id}\" has already been rejected"
            ))),
        )
            .into_response();
    }

    let _policy_update = state.policy_update.lock().await;
    let rollback_snapshot = state.rules.rollback_snapshot().await;

    let filename = format!("agent-{id}.yaml");
    let file_path = std::path::Path::new(&state.rules_dir).join(&filename);
    if let Err(error) =
        crate::state_file::write_new_atomic(&file_path, entry.rule_file.as_bytes(), 0o600)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<ApproveRuleResult>::err(format!(
                "failed to write rule file \"{filename}\": {error}"
            ))),
        )
            .into_response();
    }

    let rules_loaded = match super::policy_reload::reload_locked(&state).await {
        Ok((_, rules_loaded, _)) => {
            tracing::info!(
                id = %id,
                file = %filename,
                rules_loaded,
                "rule request approved and rules reloaded"
            );
            rules_loaded
        }
        Err(error) => {
            let remove_error = crate::state_file::remove_if_exists(&file_path).err();
            tracing::error!(
                id = %id,
                error = %error,
                ?remove_error,
                "rule engine reload failed; approved policy was not activated"
            );
            let cleanup = remove_error.map_or_else(
                || "".to_string(),
                |cleanup| format!("; failed to remove staged rule file: {cleanup}"),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<ApproveRuleResult>::err(format!(
                    "rule engine reload failed after writing \"{filename}\"{cleanup}"
                ))),
            )
                .into_response();
        }
    };

    if let Err(persist_error) = state.rule_requests.approve(&id).await {
        let remove_error = crate::state_file::remove_if_exists(&file_path).err();
        let restore_error = super::policy_reload::restore_locked(&state, rollback_snapshot)
            .await
            .err();
        tracing::error!(
            id = %id,
            error = %persist_error,
            ?remove_error,
            ?restore_error,
            "rule approval persistence failed; restored previous policy snapshot"
        );
        let cleanup_complete = remove_error.is_none() && restore_error.is_none();
        let message = if cleanup_complete {
            "failed to persist rule approval; previous policy was restored"
        } else {
            "failed to persist rule approval and cleanup was incomplete; inspect daemon logs before retrying"
        };
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<ApproveRuleResult>::err(message)),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(ApiResponse::ok(ApproveRuleResult { id, rules_loaded })),
    )
        .into_response()
}

pub(super) async fn reject(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<RejectRuleRequest>,
) -> Response {
    if !valid_request_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<RejectRuleResult>::err(
                "invalid rule request ID",
            )),
        )
            .into_response();
    }
    if let Err(error) = validate_rejection_reason(body.reason.as_deref()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::<RejectRuleResult>::err(error)),
        )
            .into_response();
    }
    let _transition = state.rule_requests.lock_transition().await;
    let entry = match state.rule_requests.get(&id).await {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<RejectRuleResult>::err(format!(
                    "rule request \"{id}\" not found"
                ))),
            )
                .into_response();
        }
    };

    if entry.status != RuleRequestStatus::Pending {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<RejectRuleResult>::err(format!(
                "rule request \"{id}\" is not pending (status: {:?})",
                entry.status
            ))),
        )
            .into_response();
    }

    if let Err(persist_error) = state.rule_requests.reject(&id, body.reason.clone()).await {
        tracing::error!(id = %id, error = %persist_error, "failed to persist rule rejection");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<RejectRuleResult>::err(
                "failed to persist rule rejection",
            )),
        )
            .into_response();
    }

    tracing::info!(id = %id, reason = ?body.reason, "rule request rejected");
    (
        StatusCode::OK,
        Json(ApiResponse::ok(RejectRuleResult { id })),
    )
        .into_response()
}

fn validate_rejection_reason(reason: Option<&str>) -> Result<(), &'static str> {
    let Some(reason) = reason else {
        return Ok(());
    };
    if reason.trim().is_empty() {
        return Err("rejection reason must not be empty");
    }
    if reason.len() > REJECTION_REASON_LIMIT {
        return Err("rejection reason exceeds 1024 bytes");
    }
    if reason.chars().any(char::is_control) {
        return Err("rejection reason must not contain control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_rejection_reason;

    #[test]
    fn rejection_reason_is_bounded_and_log_safe() {
        assert!(validate_rejection_reason(None).is_ok());
        assert!(validate_rejection_reason(Some("not needed")).is_ok());
        assert!(validate_rejection_reason(Some("  ")).is_err());
        assert!(validate_rejection_reason(Some("line one\nline two")).is_err());
        assert!(validate_rejection_reason(Some(&"x".repeat(1025))).is_err());
    }
}
