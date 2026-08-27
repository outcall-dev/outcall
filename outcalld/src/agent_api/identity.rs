use std::time::Duration;

use axum::http::HeaderMap;
use tokio::sync::TryAcquireError;
use tracing::warn;

use crate::docker::ManagedContainerIdentity;

use super::sessions::valid_session_token;
use super::{AgentApiError, AgentState};

const IDENTITY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Unix socket peer credentials captured when the connection is accepted.
#[derive(Clone, Debug)]
pub struct UnixPeerCred {
    /// Host-namespace PID of the connecting process. `None` if unavailable.
    pub pid: Option<u32>,
}

impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, tokio::net::UnixListener>,
    > for UnixPeerCred
{
    fn connect_info(target: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        #[cfg(target_os = "linux")]
        let pid = target
            .io()
            .peer_cred()
            .ok()
            .and_then(|credentials| credentials.pid())
            .map(|pid| pid as u32);
        #[cfg(not(target_os = "linux"))]
        let pid = {
            let _ = target;
            None
        };
        Self { pid }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

pub(super) async fn resolve_peer_container(
    state: &AgentState,
    peer: &UnixPeerCred,
) -> Result<ManagedContainerIdentity, AgentApiError> {
    let Some(pid) = peer.pid else {
        warn!("agent API: peer credentials unavailable");
        return Err(AgentApiError::PeerIdentification);
    };
    let _permit = state
        .identity_lookups
        .try_acquire()
        .map_err(identity_capacity_error)?;

    match tokio::time::timeout(
        IDENTITY_LOOKUP_TIMEOUT,
        state.docker.lookup_container_by_pid(pid),
    )
    .await
    {
        Ok(Ok(Some(container))) => Ok(container),
        Ok(Ok(None)) => {
            warn!(peer_pid = pid, "agent API: peer is not a managed container");
            Err(AgentApiError::CheckinRejected)
        }
        Ok(Err(error)) => {
            warn!(peer_pid = pid, %error, "agent API: peer identity lookup failed");
            Err(AgentApiError::PeerIdentification)
        }
        Err(_) => {
            warn!(peer_pid = pid, "agent API: peer identity lookup timed out");
            Err(AgentApiError::PeerIdentificationTimeout)
        }
    }
}

fn identity_capacity_error(_: TryAcquireError) -> AgentApiError {
    warn!("agent API: peer identity lookup capacity exhausted");
    AgentApiError::PeerIdentificationBusy
}

pub(super) async fn resolve_session(
    state: &AgentState,
    peer: &UnixPeerCred,
    headers: &HeaderMap,
) -> Result<ManagedContainerIdentity, AgentApiError> {
    let Some(token) = bearer_token(headers).filter(|token| valid_session_token(token)) else {
        return Err(AgentApiError::InvalidSession);
    };
    let peer_container = resolve_peer_container(state, peer).await?;
    let sessions = state.sessions.lock().await;
    match sessions.container_for_token(token) {
        Some(session_container) if session_container.id == peer_container.id => Ok(peer_container),
        Some(_) => {
            warn!(peer_container_id = %peer_container.id, "agent API: session token used by a different container");
            Err(AgentApiError::SessionContainerMismatch)
        }
        None => Err(AgentApiError::InvalidSession),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_scheme_is_case_insensitive_and_token_is_not_normalized() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("bEaReR tok-0123456789abcdef0123456789abcdef"),
        );
        assert_eq!(
            bearer_token(&headers),
            Some("tok-0123456789abcdef0123456789abcdef")
        );

        headers.insert(
            "authorization",
            HeaderValue::from_static("Basic tok-0123456789abcdef0123456789abcdef"),
        );
        assert_eq!(bearer_token(&headers), None);
    }
}
