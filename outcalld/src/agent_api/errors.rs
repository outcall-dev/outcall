use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use outcall_api::ApiResponse;

#[derive(Debug, thiserror::Error)]
pub enum AgentApiError {
    #[error("failed to bind agent socket at {path}: {source}")]
    SocketBind {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("peer identity could not be verified")]
    PeerIdentification,
    #[error("peer identity lookup timed out")]
    PeerIdentificationTimeout,
    #[error("peer identity lookup capacity exhausted")]
    PeerIdentificationBusy,
    #[error("check-in rejected: peer is not a managed container")]
    CheckinRejected,
    #[error("evaluation timeout")]
    EvaluationTimeout,
    #[error("policy evaluation unavailable")]
    EvaluationUnavailable,
    #[error("rate limit exceeded for container {container_id}")]
    RateLimited {
        container_id: String,
        retry_after_seconds: u64,
    },
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid request: {0}")]
    MalformedRequest(&'static str),
    #[error("request body exceeds 65536 bytes")]
    RequestBodyTooLarge,
    #[error("invalid or missing session token")]
    InvalidSession,
    #[error("session is not valid for this container")]
    SessionContainerMismatch,
    #[error("agent session capacity reached")]
    SessionCapacity,
    #[error("rule request not found")]
    RuleRequestNotFound,
    #[error("{0}")]
    Internal(&'static str),
}

impl AgentApiError {
    pub fn socket_bind(path: &std::path::Path, source: std::io::Error) -> Self {
        Self::SocketBind {
            path: path.display().to_string(),
            source,
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::PeerIdentification | Self::CheckinRejected | Self::SessionContainerMismatch => {
                StatusCode::FORBIDDEN
            }
            Self::InvalidSession => StatusCode::UNAUTHORIZED,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::InvalidRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::RuleRequestNotFound => StatusCode::NOT_FOUND,
            Self::PeerIdentificationTimeout
            | Self::PeerIdentificationBusy
            | Self::SessionCapacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::SocketBind { .. }
            | Self::EvaluationTimeout
            | Self::EvaluationUnavailable
            | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let retry_after = match &self {
            Self::RateLimited {
                retry_after_seconds,
                ..
            } => Some(*retry_after_seconds),
            _ => None,
        };
        let mut response = (status, Json(ApiResponse::<()>::err(self.to_string()))).into_response();
        if let Some(seconds) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_errors_map_to_stable_http_statuses() {
        assert_eq!(
            AgentApiError::InvalidSession.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AgentApiError::RequestBodyTooLarge.into_response().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            AgentApiError::PeerIdentificationBusy
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let rate_limited = AgentApiError::RateLimited {
            container_id: "container-a".to_string(),
            retry_after_seconds: 3,
        }
        .into_response();
        assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rate_limited.headers()["retry-after"], "3");
    }
}
