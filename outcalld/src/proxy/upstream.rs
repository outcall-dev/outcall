use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::CONNECT_TIMEOUT_SECS;

#[derive(Debug, thiserror::Error)]
pub(super) enum UpstreamError {
    #[error("target resolved only to restricted addresses")]
    RestrictedAddress,
    #[error("upstream name resolution failed")]
    Resolution,
    #[error("upstream operation timed out")]
    Timeout,
    #[error("upstream connection failed")]
    Connection,
}

pub(super) async fn resolve_upstream(
    host: &str,
    port: u16,
    allow_private_ips: bool,
) -> Result<Vec<SocketAddr>, UpstreamError> {
    const MAX_UPSTREAM_ADDRESSES: usize = 64;

    let candidates = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        match tokio::time::timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            tokio::net::lookup_host((host, port)),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses.take(MAX_UPSTREAM_ADDRESSES).collect(),
            Ok(Err(_)) => return Err(UpstreamError::Resolution),
            Err(_) => return Err(UpstreamError::Timeout),
        }
    };
    if candidates.is_empty() {
        return Err(UpstreamError::Resolution);
    }

    let mut allowed = Vec::new();
    for address in candidates {
        if !allow_private_ips && crate::address_policy::is_restricted(address.ip()) {
            warn!(%host, %address, "proxy discarded restricted upstream address");
            continue;
        }
        if !allowed.contains(&address) {
            allowed.push(address);
        }
    }
    if allowed.is_empty() {
        return Err(UpstreamError::RestrictedAddress);
    }
    Ok(allowed)
}

pub(super) async fn connect_upstream(addresses: &[SocketAddr]) -> Result<TcpStream, UpstreamError> {
    tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => debug!(%address, %error, "proxy upstream address failed"),
            }
        }
        Err(UpstreamError::Connection)
    })
    .await
    .map_err(|_| UpstreamError::Timeout)?
}

pub(super) async fn connect(
    host: &str,
    port: u16,
    allow_private_ips: bool,
) -> Result<TcpStream, UpstreamError> {
    let addresses = resolve_upstream(host, port, allow_private_ips).await?;
    connect_upstream(&addresses).await
}

pub(super) fn error_response(error: &UpstreamError) -> (u16, &'static str, &'static str) {
    match error {
        UpstreamError::RestrictedAddress => (
            403,
            "Forbidden",
            "Upstream resolved to a restricted address",
        ),
        UpstreamError::Timeout => (504, "Gateway Timeout", "Upstream operation timed out"),
        UpstreamError::Resolution | UpstreamError::Connection => {
            (502, "Bad Gateway", "Upstream connection failed")
        }
    }
}
