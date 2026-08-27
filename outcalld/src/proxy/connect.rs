use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use outcall_api::Decision;

use crate::rules::RuleEngine;

use super::context::http_context;
use super::http::{
    parse_connect_target, request_body_length, require_matching_host, ParsedRequest,
};
use super::io::{read_client_hello_record, relay_with_idle_timeout, write_error_logged};
use super::tls::extract_sni;
use super::upstream::{connect_upstream, error_response, resolve_upstream};
use super::{DEFAULT_CONNECT_BLOCKED_PORTS, IDLE_TIMEOUT_SECS};

pub(super) async fn handle(
    mut client: TcpStream,
    request: ParsedRequest,
    body_prefix: Vec<u8>,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
    source_ip: IpAddr,
) {
    let target = match parse_connect_target(&request.uri) {
        Ok(target) => target,
        Err(_) => {
            write_error_logged(client, 400, "Bad Request", "Invalid CONNECT target").await;
            return;
        }
    };
    let host = target.host;
    let port = target.port;
    if require_matching_host(&request.headers, &host, port, 443).is_err()
        || request_body_length(&request.headers, 0).is_err()
        || !body_prefix.is_empty()
    {
        write_error_logged(
            client,
            400,
            "Bad Request",
            "Invalid CONNECT headers or body framing",
        )
        .await;
        return;
    }

    if DEFAULT_CONNECT_BLOCKED_PORTS.contains(&port) {
        warn!(%source_ip, host = %host, port, "BLOCK CONNECT: known non-HTTPS service port rejected");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        write_error_logged(client, 403, "Forbidden", "CONNECT port is not allowed").await;
        return;
    }

    let rule_set = rule_engine.snapshot().await;
    let prelim = RuleEngine::evaluate_snapshot_with_egress(
        &rule_set,
        &http_context(
            "CONNECT",
            &host,
            "/",
            &HashMap::new(),
            port,
            0,
            agent_name.as_deref(),
        ),
    );
    let prelim_result = &prelim.result;

    if prelim_result.decision == Decision::Block {
        let reason = prelim_result
            .matched_rule
            .as_deref()
            .unwrap_or("default policy");
        warn!(%source_ip, %host, port, rule = %reason, "BLOCK CONNECT before SNI");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        let body = format!("Blocked by outcall: {reason}");
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Outcall-Block-Reason: {reason}\r\n\r\n{body}",
            body.len()
        );
        if let Err(error) = client.write_all(response.as_bytes()).await {
            debug!(%error, "proxy CONNECT block response was not delivered");
        }
        return;
    }

    let allow_private_ips = prelim
        .egress
        .as_ref()
        .is_some_and(|egress| egress.allow_private_ips);
    let upstream_addresses = match resolve_upstream(&host, port, allow_private_ips).await {
        Ok(addresses) => addresses,
        Err(error) => {
            warn!(%source_ip, host = %host, port, %error, "BLOCK CONNECT: upstream target is unavailable or restricted");
            total_blocked.fetch_add(1, Ordering::Relaxed);
            let (status, reason, body) = error_response(&error);
            write_error_logged(client, status, reason, body).await;
            return;
        }
    };

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }

    let client_hello = match read_client_hello_record(&mut client).await {
        Ok(record) => record,
        Err(error) => {
            warn!(security_event = true, %source_ip, host = %host, port, %error, "BLOCK CONNECT: invalid TLS ClientHello");
            total_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let eval_host = match extract_sni(&client_hello) {
        Ok(Some(sni)) => sni,
        Ok(None) => host.clone(),
        Err(error) => {
            warn!(security_event = true, %source_ip, host = %host, port, %error, "BLOCK CONNECT: malformed TLS ClientHello");
            total_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if eval_host != host {
        let sni_result = RuleEngine::evaluate_snapshot(
            &rule_set,
            &http_context(
                "CONNECT",
                &eval_host,
                "/",
                &HashMap::new(),
                port,
                0,
                agent_name.as_deref(),
            ),
        );
        if sni_result.decision == Decision::Block {
            let reason = sni_result
                .matched_rule
                .as_deref()
                .unwrap_or("default policy");
            error!(
                security_event = true,
                %source_ip,
                host = %eval_host,
                port,
                matched_rule = %reason,
                "BLOCK CONNECT after SNI"
            );
            total_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    debug!(%source_ip, host = %eval_host, port, "ALLOW CONNECT");
    let mut upstream = match connect_upstream(&upstream_addresses).await {
        Ok(stream) => stream,
        Err(error) => {
            warn!(%source_ip, %host, port, %error, "CONNECT upstream failed");
            total_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    if let Err(error) = upstream.write_all(&client_hello).await {
        debug!(%error, "proxy failed to forward TLS ClientHello");
        return;
    }

    if let Err(error) =
        relay_with_idle_timeout(client, upstream, Duration::from_secs(IDLE_TIMEOUT_SECS)).await
    {
        debug!(%error, "proxy CONNECT tunnel closed");
    }
}
