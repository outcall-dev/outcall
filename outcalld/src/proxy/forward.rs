use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use outcall_api::Decision;

use crate::rules::RuleEngine;

use super::context::http_context;
use super::http::{
    connection_header_tokens, parse_absolute_http_uri, policy_headers, request_body_length,
    require_matching_host, ParsedRequest, RequestError,
};
use super::io::{copy_with_idle_timeout, write_error_logged, TransferError};
use super::upstream::{self, UpstreamError};
use super::{IDLE_TIMEOUT_SECS, MAX_HTTP_BODY_BYTES};

pub(super) async fn handle(
    mut client: TcpStream,
    request: ParsedRequest,
    body_prefix: Vec<u8>,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
    source_ip: IpAddr,
) {
    let ParsedRequest {
        method,
        uri,
        headers,
    } = request;
    let target = match parse_absolute_http_uri(&uri) {
        Ok(target) => target,
        Err(_) => {
            write_error_logged(client, 400, "Bad Request", "Invalid absolute-form URI").await;
            return;
        }
    };
    let host = target.host;
    let port = target.port;
    let path = target.path;

    if require_matching_host(&headers, &host, port, 80).is_err() {
        warn!(%source_ip, uri_host = %host, port, "BLOCK HTTP: invalid or mismatched Host header");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        write_error_logged(
            client,
            400,
            "Bad Request",
            "Host header does not match request URI authority",
        )
        .await;
        return;
    }
    let body_length = match request_body_length(&headers, MAX_HTTP_BODY_BYTES) {
        Ok(length) => length,
        Err(error) => {
            debug!(%error, "proxy rejected ambiguous HTTP body framing");
            let (status, reason, body) = match error {
                RequestError::BodyTooLarge(_) => {
                    (413, "Payload Too Large", "HTTP request body is too large")
                }
                _ => (400, "Bad Request", "Unsupported HTTP body framing"),
            };
            write_error_logged(client, status, reason, body).await;
            return;
        }
    };
    if body_prefix.len() as u64 > body_length {
        write_error_logged(
            client,
            400,
            "Bad Request",
            "HTTP request contains trailing data",
        )
        .await;
        return;
    }
    let header_map = policy_headers(&headers);
    let evaluation = rule_engine
        .evaluate_with_egress(&http_context(
            &method,
            &host,
            &path,
            &header_map,
            port,
            body_length,
            agent_name.as_deref(),
        ))
        .await;
    let result = &evaluation.result;

    if result.decision == Decision::Block {
        let reason = result.matched_rule.as_deref().unwrap_or("default policy");
        warn!(%source_ip, %method, %host, port, rule = %reason, "BLOCK HTTP");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        let body = format!("Blocked by outcall: {reason}");
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Outcall-Block-Reason: {reason}\r\n\r\n{body}",
            body.len()
        );
        if let Err(error) = client.write_all(response.as_bytes()).await {
            debug!(%error, "proxy HTTP block response was not delivered");
        }
        return;
    }

    let allow_private_ips = evaluation
        .egress
        .as_ref()
        .is_some_and(|egress| egress.allow_private_ips);
    debug!(%source_ip, %method, %host, port, rule = ?result.matched_rule, "ALLOW HTTP");
    let mut upstream = match upstream::connect(&host, port, allow_private_ips).await {
        Ok(stream) => stream,
        Err(error) => {
            warn!(%source_ip, %host, port, %error, "HTTP upstream connection rejected or failed");
            let (status, reason, body) = upstream::error_response(&error);
            if matches!(error, UpstreamError::RestrictedAddress) {
                total_blocked.fetch_add(1, Ordering::Relaxed);
            }
            write_error_logged(client, status, reason, body).await;
            return;
        }
    };

    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    let connection_tokens = connection_header_tokens(&headers);
    let mut outbound = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in &headers {
        let normalized = name.to_ascii_lowercase();
        if !HOP_BY_HOP.contains(&normalized.as_str()) && !connection_tokens.contains(&normalized) {
            outbound.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    outbound.push_str("Connection: close\r\n\r\n");

    if let Err(error) = upstream.write_all(outbound.as_bytes()).await {
        debug!(%error, "proxy failed to write HTTP headers upstream");
        write_error_logged(
            client,
            502,
            "Bad Gateway",
            "Failed to write request to upstream",
        )
        .await;
        return;
    }
    if !body_prefix.is_empty() {
        if let Err(error) = upstream.write_all(&body_prefix).await {
            debug!(%error, "proxy failed to write buffered HTTP body upstream");
            return;
        }
    }

    let remaining = body_length.saturating_sub(body_prefix.len() as u64);
    if remaining > 0 {
        let mut limited_client = (&mut client).take(remaining);
        let copied = copy_with_idle_timeout(
            &mut limited_client,
            &mut upstream,
            Duration::from_secs(IDLE_TIMEOUT_SECS),
        )
        .await;
        match copied {
            Ok(bytes) if bytes == remaining => {}
            Ok(bytes) => {
                debug!(
                    bytes,
                    expected = remaining,
                    "proxy received a truncated HTTP body"
                );
                return;
            }
            Err(TransferError::Io(error)) => {
                debug!(%error, "proxy failed while forwarding the HTTP body");
                return;
            }
            Err(TransferError::IdleTimeout) => {
                debug!("proxy HTTP request body reached its idle timeout");
                return;
            }
        }
    }
    if let Err(error) = upstream.shutdown().await {
        debug!(%error, "proxy failed to finish the upstream HTTP request");
        return;
    }

    match copy_with_idle_timeout(
        &mut upstream,
        &mut client,
        Duration::from_secs(IDLE_TIMEOUT_SECS),
    )
    .await
    {
        Ok(_) => {}
        Err(TransferError::Io(error)) => {
            debug!(%error, "proxy HTTP response closed with an I/O error");
        }
        Err(TransferError::IdleTimeout) => {
            debug!("proxy HTTP response reached its idle timeout");
        }
    }
}
