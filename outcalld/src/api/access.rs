use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Unix peer credentials captured when accepting a host control connection.
#[derive(Clone, Debug)]
pub struct HostPeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<u32>,
}

impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, tokio::net::UnixListener>,
    > for HostPeerCred
{
    fn connect_info(target: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        match target.io().peer_cred() {
            Ok(credentials) => Self {
                uid: credentials.uid(),
                gid: credentials.gid(),
                pid: credentials.pid().map(|pid| pid as u32),
            },
            Err(_) => Self {
                uid: u32::MAX,
                gid: u32::MAX,
                pid: None,
            },
        }
    }
}

/// Permit root, the daemon user, and the host operator that owns the socket.
pub fn require_operator_uid(
    daemon_uid: u32,
    operator_uid: u32,
) -> impl Fn(
    ConnectInfo<HostPeerCred>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone
       + Send
       + Sync
       + 'static {
    move |ConnectInfo(peer), request, next| {
        Box::pin(async move {
            let allowed = peer.uid == 0 || peer.uid == daemon_uid || peer.uid == operator_uid;
            if !allowed {
                tracing::warn!(
                    peer_uid = peer.uid,
                    daemon_uid,
                    operator_uid,
                    "host API connection rejected: foreign UID"
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(outcall_api::ApiResponse::<()>::err(
                        "forbidden: host API requires root, daemon UID, or operator UID",
                    )),
                )
                    .into_response();
            }
            next.run(request).await
        })
    }
}
