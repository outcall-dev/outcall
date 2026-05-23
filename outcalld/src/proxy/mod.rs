//! HTTP proxy with SNI peeking for CONNECT tunneling (S006).
//!
//! Flow for CONNECT (HTTPS):
//!   1. Evaluate on CONNECT hostname → 403 if BLOCK (before 200).
//!   2. Send 200 Connection Established.
//!   3. Peek TLS ClientHello → extract SNI.
//!   4. Re-evaluate on SNI if different from CONNECT host.
//!   5. If BLOCK → close (cannot send 403 after 200 is already sent).
//!   6. If ALLOW → connect upstream, forward peeked bytes, tunnel.
//!
//! Flow for plain HTTP:
//!   1. Evaluate on target hostname extracted from absolute-form URI.
//!   2. If BLOCK → 403.
//!   3. If ALLOW → connect upstream, forward request, relay response.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};

use crate::rules::RuleEngine;
use outcall_api::{AgentContext, Decision, EvalContext, HttpContext, NetworkContext};

#[cfg(target_os = "linux")]
use crate::agent_api::derive_agent_name;
use crate::docker::DockerManager;

const MAX_CONNECTIONS: usize = 1024;
const CONNECT_TIMEOUT_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_HEADER_BYTES: usize = 8192;
const DEFAULT_CONNECT_BLOCKED_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 110, 119, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5672, 5900, 6379, 9200, 9300, 11211, 27017,
];
/// Bytes to read for SNI peeking — one read() normally covers an entire TLS ClientHello.
const SNI_PEEK_BYTES: usize = 4096;
const GRACE_PERIOD_SECS: u64 = 5;

// ── Error categories for read_through_headers ─────────────────────────────

enum HeaderReadError {
    TooLarge,
    Io,
}

// ── Public API ─────────────────────────────────────────────────────────────

pub struct ProxyServer {
    pub listen_addr: SocketAddr,
    /// Filled in once `start()` has bound the listener — the OS-assigned
    /// port if `listen_addr` had port 0. None until `start()` returns.
    bound_addr: Mutex<Option<SocketAddr>>,
    /// Optional resolver for peer-IP → container-name lookups.
    /// When present, the proxy populates `agent.name` on EvalContext so
    /// CEL rules referencing `agent.name` can match real HTTP/HTTPS traffic
    /// (S013). When None (typically in tests), `agent` is left unset.
    docker: Option<Arc<DockerManager>>,
    active_connections: Arc<AtomicU64>,
    total_requests: Arc<AtomicU64>,
    total_blocked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr, docker: Option<Arc<DockerManager>>) -> Arc<Self> {
        Arc::new(Self {
            listen_addr,
            bound_addr: Mutex::new(None),
            docker,
            active_connections: Arc::new(AtomicU64::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            total_blocked: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: Mutex::new(None),
        })
    }

    pub async fn start(self: &Arc<Self>, rule_engine: Arc<RuleEngine>) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| anyhow::anyhow!("proxy: failed to bind {}: {e}", self.listen_addr))?;

        // Capture the actually-bound address — when listen_addr's port is 0
        // (the OS-assigned-port idiom used in tests), self.listen_addr alone
        // does not reflect the real port.
        if let Ok(addr) = listener.local_addr() {
            *self.bound_addr.lock().await = Some(addr);
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.shutdown_tx.lock().await = Some(tx);
        self.running.store(true, Ordering::SeqCst);

        let this = self.clone();
        tokio::spawn(async move { this.accept_loop(listener, rule_engine, rx).await });

        Ok(())
    }

    pub async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.listen_addr)
    }

    /// Address the listener is actually bound to. None until `start()` has
    /// completed. Use this in tests where `listen_addr.port() == 0`.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().await
    }

    /// Returns (active_connections, total_requests, total_blocked).
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.active_connections.load(Ordering::Relaxed),
            self.total_requests.load(Ordering::Relaxed),
            self.total_blocked.load(Ordering::Relaxed),
        )
    }

    async fn accept_loop(
        self: Arc<Self>,
        listener: TcpListener,
        rule_engine: Arc<RuleEngine>,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) {
        let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            let (stream, peer) = tokio::select! {
                result = listener.accept() => match result {
                    Ok(pair) => pair,
                    Err(e) => { error!("proxy accept error: {e}"); continue; }
                },
                _ = &mut shutdown => break,
            };

            let permit = match sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tokio::spawn(async move {
                        let _ =
                            write_error(stream, 503, "Service Unavailable", "Too many connections")
                                .await;
                    });
                    continue;
                }
            };

            self.active_connections.fetch_add(1, Ordering::Relaxed);
            self.total_requests.fetch_add(1, Ordering::Relaxed);

            let rule_engine = rule_engine.clone();
            let active = self.active_connections.clone();
            let blocked = self.total_blocked.clone();
            let docker = self.docker.clone();

            tokio::spawn(async move {
                let agent_name = resolve_agent_name(&docker, peer).await;
                handle_connection(stream, rule_engine, &blocked, agent_name).await;
                active.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            });
        }

        // Grace period: wait for active connections to drain.
        let _ = tokio::time::timeout(
            Duration::from_secs(GRACE_PERIOD_SECS),
            sem.acquire_many(MAX_CONNECTIONS as u32),
        )
        .await;

        self.running.store(false, Ordering::SeqCst);
        info!("proxy stopped");
    }
}

// ── Connection dispatcher ─────────────────────────────────────────────────

/// Resolves a peer SocketAddr to an outcall-managed agent name (if any).
/// Returns None when the docker manager is unavailable, the peer IP is not
/// a managed container, or the lookup fails.
#[cfg(target_os = "linux")]
async fn resolve_agent_name(
    docker: &Option<Arc<DockerManager>>,
    peer: SocketAddr,
) -> Option<String> {
    let docker = docker.as_ref()?;
    let ip = peer.ip().to_string();
    let name = docker.lookup_container_name_by_ip(&ip).await?;
    Some(derive_agent_name(&name))
}

async fn handle_connection(
    mut stream: TcpStream,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
) {
    let mut buf = Vec::with_capacity(2048);

    let header_end = match read_through_headers(&mut stream, &mut buf, MAX_HEADER_BYTES).await {
        Ok(n) => n,
        Err(HeaderReadError::TooLarge) => {
            let _ = write_error(
                stream,
                431,
                "Request Header Fields Too Large",
                "Headers exceed the maximum allowed size",
            )
            .await;
            return;
        }
        Err(HeaderReadError::Io) => return,
    };

    let (method, raw_uri, headers) = match parse_request_line_headers(&buf[..header_end]) {
        Some(r) => r,
        None => {
            let _ = write_error(stream, 400, "Bad Request", "Malformed request line").await;
            return;
        }
    };

    // Health check — not forwarded upstream.
    if method.eq_ignore_ascii_case("GET") && raw_uri == "/outcall-health" {
        handle_health(stream).await;
        return;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(stream, &raw_uri, rule_engine, total_blocked, agent_name).await;
    } else {
        let body_prefix = buf[header_end..].to_vec();
        handle_http(
            stream,
            &method,
            &raw_uri,
            headers,
            body_prefix,
            rule_engine,
            total_blocked,
            agent_name,
        )
        .await;
    }
}

// ── Health check ──────────────────────────────────────────────────────────

async fn handle_health(mut stream: TcpStream) {
    let body = r#"{"status":"ok"}"#;
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

// ── CONNECT (HTTPS tunneling) ─────────────────────────────────────────────

async fn handle_connect(
    mut client: TcpStream,
    host_port: &str,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
) {
    let (host, port) = match parse_host_port(host_port) {
        Some(hp) => hp,
        None => {
            let _ = write_error(client, 400, "Bad Request", "Invalid CONNECT target").await;
            return;
        }
    };

    if DEFAULT_CONNECT_BLOCKED_PORTS.contains(&port) {
        warn!(host = %host, port, "BLOCK CONNECT: known non-HTTPS service port rejected");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        let _ = write_error(client, 403, "Forbidden", "CONNECT port is not allowed").await;
        return;
    }

    // Pre-SNI evaluation on the CONNECT hostname — allows sending 403 before 200.
    let prelim_result = rule_engine
        .evaluate(&build_http_ctx(
            "CONNECT",
            &host,
            "/",
            &HashMap::new(),
            port,
            agent_name.as_deref(),
        ))
        .await;

    if prelim_result.decision == Decision::Block {
        let reason = prelim_result
            .matched_rule
            .as_deref()
            .unwrap_or("default policy");
        warn!("BLOCK CONNECT {host}:{port} (pre-SNI) rule={reason}");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        let body = format!("Blocked by outcall: {reason}");
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Outcall-Block-Reason: {reason}\r\n\r\n{body}",
            body.len()
        );
        let _ = client.write_all(resp.as_bytes()).await;
        return;
    }

    // Send 200 to trigger TLS handshake from client.
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }

    // Peek TLS ClientHello for SNI extraction.
    let mut peek_buf = vec![0u8; SNI_PEEK_BYTES];
    let n = match tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        client.read(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
        Ok(Ok(n)) => n,
    };
    peek_buf.truncate(n);

    let eval_host = extract_sni(&peek_buf).unwrap_or_else(|| host.clone());
    debug!("CONNECT {host}:{port} eval_host={eval_host}");

    // Re-evaluate if SNI differs from CONNECT hostname.
    if eval_host != host {
        let sni_result = rule_engine
            .evaluate(&build_http_ctx(
                "CONNECT",
                &eval_host,
                "/",
                &HashMap::new(),
                port,
                agent_name.as_deref(),
            ))
            .await;
        if sni_result.decision == Decision::Block {
            let reason = sni_result
                .matched_rule
                .as_deref()
                .unwrap_or("default policy");
            error!(
                security_event = true,
                host = %eval_host,
                port = %port,
                matched_rule = %reason,
                "BLOCK CONNECT (SNI): connection dropped — reason: {reason}"
            );
            total_blocked.fetch_add(1, Ordering::Relaxed);
            // 200 already sent — close the connection; client sees a reset.
            return;
        }
    }

    debug!("ALLOW CONNECT {eval_host}:{port}");

    let mut upstream = match upstream_connect(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            warn!("CONNECT upstream failed {host}:{port}: {e}");
            return;
        }
    };

    // Forward the peeked bytes (TLS ClientHello) to upstream before tunneling.
    if upstream.write_all(&peek_buf).await.is_err() {
        return;
    }

    let _ = tokio::time::timeout(
        Duration::from_secs(IDLE_TIMEOUT_SECS),
        tokio::io::copy_bidirectional(&mut client, &mut upstream),
    )
    .await;
}

// ── Plain HTTP forwarding ─────────────────────────────────────────────────

async fn handle_http(
    mut client: TcpStream,
    method: &str,
    raw_uri: &str,
    headers: Vec<(String, String)>,
    body_prefix: Vec<u8>,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
) {
    let (host, port, path) = match parse_absolute_uri(raw_uri) {
        Some(r) => r,
        None => {
            let _ = write_error(client, 400, "Bad Request", "Invalid absolute-form URI").await;
            return;
        }
    };

    let header_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    if let Some(header_host) = header_map.get("host") {
        if !host_header_matches_authority(header_host, &host, port) {
            warn!(uri_host = %host, port, host_header = %header_host, "BLOCK HTTP: Host header does not match absolute-form URI authority");
            total_blocked.fetch_add(1, Ordering::Relaxed);
            let _ = write_error(
                client,
                400,
                "Bad Request",
                "Host header does not match request URI authority",
            )
            .await;
            return;
        }
    }

    debug!("HTTP {method} {host}:{port}{path}");

    let result = rule_engine
        .evaluate(&build_http_ctx(
            method,
            &host,
            &path,
            &header_map,
            port,
            agent_name.as_deref(),
        ))
        .await;

    if result.decision == Decision::Block {
        let reason = result.matched_rule.as_deref().unwrap_or("default policy");
        warn!("BLOCK HTTP {method} {host}:{port}{path} rule={reason}");
        total_blocked.fetch_add(1, Ordering::Relaxed);
        let body = format!("Blocked by outcall: {reason}");
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Outcall-Block-Reason: {reason}\r\n\r\n{body}",
            body.len()
        );
        let _ = client.write_all(resp.as_bytes()).await;
        return;
    }

    debug!("ALLOW HTTP {method} {host}:{port}{path}");

    let mut upstream = match upstream_connect(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            let (status, reason) = if e.contains("timed out") {
                (504u16, "Gateway Timeout")
            } else {
                (502u16, "Bad Gateway")
            };
            let body = format!("Upstream connection failed: {e}");
            let _ = write_error(client, status, reason, &body).await;
            return;
        }
    };

    // Rewrite to origin form and strip hop-by-hop headers.
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

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in &headers {
        if !HOP_BY_HOP.contains(&k.to_lowercase().as_str()) {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    req.push_str("Connection: close\r\n\r\n");

    if upstream.write_all(req.as_bytes()).await.is_err() {
        let _ = write_error(
            client,
            502,
            "Bad Gateway",
            "Failed to write request to upstream",
        )
        .await;
        return;
    }

    if !body_prefix.is_empty() && upstream.write_all(&body_prefix).await.is_err() {
        return;
    }

    let _ = tokio::time::timeout(
        Duration::from_secs(IDLE_TIMEOUT_SECS),
        tokio::io::copy_bidirectional(&mut client, &mut upstream),
    )
    .await;
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn build_http_ctx(
    method: &str,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    port: u16,
    agent_name: Option<&str>,
) -> EvalContext {
    EvalContext {
        http: Some(HttpContext {
            method: method.to_uppercase(),
            path: path.to_string(),
            host: host.to_string(),
            headers: headers.clone(),
            body_size: 0,
        }),
        network: Some(NetworkContext {
            hostname: Some(host.to_string()),
            ip: String::new(),
            port,
            protocol: "tcp".into(),
        }),
        agent: agent_name.map(|n| AgentContext {
            name: n.to_string(),
        }),
        ..Default::default()
    }
}

/// Connect to upstream with a timeout. Returns a descriptive error on failure.
async fn upstream_connect(host: &str, port: u16) -> std::result::Result<TcpStream, String> {
    let addr = format!("{host}:{port}");
    match tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("{e}")),
        Err(_) => Err(format!("timed out connecting to {addr}")),
    }
}

/// Read from `stream` until "\r\n\r\n", appending to `buf`.
/// Returns byte offset of first byte after "\r\n\r\n".
async fn read_through_headers(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limit: usize,
) -> std::result::Result<usize, HeaderReadError> {
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| HeaderReadError::Io)?;
        if n == 0 {
            return Err(HeaderReadError::Io);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > limit {
            return Err(HeaderReadError::TooLarge);
        }
        if let Some(pos) = find_double_crlf(buf) {
            return Ok(pos);
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse "METHOD URI HTTP/1.x\r\nHeader: Value\r\n…\r\n" from raw bytes.
fn parse_request_line_headers(bytes: &[u8]) -> Option<(String, String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.trim().to_string();
    let uri = parts.next()?.trim().to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Some((method, uri, headers))
}

/// Parse "host:port" → (host, port). Defaults to port 443 if absent.
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((s.to_string(), 443)),
    }
}

/// Parse "http[s]://host[:port]/path…" → (host, port, path).
fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, after_scheme) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        return None;
    };

    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], after_scheme[idx..].to_string()),
        None => (after_scheme, "/".to_string()),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), default_port),
    };

    Some((host, port, path))
}

fn host_header_matches_authority(header_host: &str, uri_host: &str, uri_port: u16) -> bool {
    let header = header_host.trim().trim_end_matches('.').to_lowercase();
    let uri_host = uri_host.trim().trim_end_matches('.').to_lowercase();

    match header.rsplit_once(':') {
        Some((host, port)) => {
            host.eq_ignore_ascii_case(&uri_host) && port.parse::<u16>().is_ok_and(|p| p == uri_port)
        }
        None => header == uri_host && (uri_port == 80 || uri_port == 443),
    }
}

/// Extract the SNI hostname from a raw TLS ClientHello buffer.
///
/// Walks the TLS record and handshake headers, then scans extensions
/// for the SNI extension (type 0x0000).
fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record: content_type(1) + version(2) + record_len(2) = 5 bytes
    if buf.len() < 6 || buf[0] != 0x16 {
        return None; // not a TLS handshake record
    }
    // Handshake: msg_type(1) + length(3) — msg_type == 0x01 for ClientHello
    if buf[5] != 0x01 {
        return None;
    }
    // ClientHello body starts at byte 9 (5-byte TLS header + 4-byte handshake header)
    let mut pos: usize = 9;
    pos = pos.checked_add(2)?; // legacy_version (2)
    if buf.len() < pos {
        return None;
    }
    pos = pos.checked_add(32)?; // random (32)
    if buf.len() < pos + 1 {
        return None;
    }
    let sid_len = buf[pos] as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?; // session_id
    if buf.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?; // cipher_suites
    if buf.len() < pos + 1 {
        return None;
    }
    let cm_len = buf[pos] as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?; // compression_methods
    if buf.len() < pos + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?;

    while pos + 4 <= ext_end && pos + 4 <= buf.len() {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            // SNI extension: list_len(2) + name_type(1) + name_len(2) + name
            if pos + 5 > buf.len() {
                return None;
            }
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            let name_start = pos + 5;
            if name_start + name_len > buf.len() {
                return None;
            }
            return std::str::from_utf8(&buf[name_start..name_start + name_len])
                .ok()
                .map(|s| s.trim_end_matches('.').to_lowercase());
        }
        pos = pos.checked_add(ext_len)?;
    }
    None
}

/// Write a plain-text HTTP error response.
async fn write_error(mut stream: TcpStream, status: u16, reason: &str, body: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_empty_returns_none() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn sni_non_tls_returns_none() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1"), None);
    }

    #[test]
    fn parse_host_port_with_port() {
        assert_eq!(
            parse_host_port("example.com:8443"),
            Some(("example.com".into(), 8443))
        );
    }

    #[test]
    fn parse_host_port_no_port_defaults_443() {
        assert_eq!(
            parse_host_port("example.com"),
            Some(("example.com".into(), 443))
        );
    }

    #[test]
    fn parse_host_port_rejects_non_numeric_port() {
        assert_eq!(parse_host_port("example.com:notaport"), None);
    }

    #[test]
    fn parse_host_port_rejects_out_of_range_port() {
        // 99999 > u16::MAX, parse fails.
        assert_eq!(parse_host_port("example.com:99999"), None);
    }

    #[test]
    fn parse_host_port_rejects_trailing_colon() {
        // "host:" has an empty port string — parse() fails on empty input.
        assert_eq!(parse_host_port("example.com:"), None);
    }

    #[test]
    fn connect_blocked_ports_include_common_non_https_services() {
        assert!(DEFAULT_CONNECT_BLOCKED_PORTS.contains(&22));
        assert!(DEFAULT_CONNECT_BLOCKED_PORTS.contains(&25));
        assert!(DEFAULT_CONNECT_BLOCKED_PORTS.contains(&6379));
    }

    #[test]
    fn connect_blocked_ports_allow_custom_tls_ports() {
        assert!(!DEFAULT_CONNECT_BLOCKED_PORTS.contains(&443));
        assert!(!DEFAULT_CONNECT_BLOCKED_PORTS.contains(&8443));
        assert!(!DEFAULT_CONNECT_BLOCKED_PORTS.contains(&9443));
    }

    #[test]
    fn parse_absolute_uri_http_default_port() {
        assert_eq!(
            parse_absolute_uri("http://example.com/path"),
            Some(("example.com".into(), 80, "/path".into()))
        );
    }

    #[test]
    fn parse_absolute_uri_with_port() {
        assert_eq!(
            parse_absolute_uri("http://example.com:9090/api/v1"),
            Some(("example.com".into(), 9090, "/api/v1".into()))
        );
    }

    #[test]
    fn parse_absolute_uri_no_path() {
        assert_eq!(
            parse_absolute_uri("http://example.com"),
            Some(("example.com".into(), 80, "/".into()))
        );
    }

    #[test]
    fn parse_absolute_uri_https() {
        assert_eq!(
            parse_absolute_uri("https://secure.example.com/data"),
            Some(("secure.example.com".into(), 443, "/data".into()))
        );
    }

    #[test]
    fn host_header_match_accepts_same_host_default_port() {
        assert!(host_header_matches_authority(
            "example.com",
            "example.com",
            80
        ));
        assert!(host_header_matches_authority(
            "example.com",
            "example.com",
            443
        ));
    }

    #[test]
    fn host_header_match_accepts_same_host_explicit_port() {
        assert!(host_header_matches_authority(
            "example.com:8080",
            "example.com",
            8080
        ));
    }

    #[test]
    fn host_header_match_rejects_mismatched_host_or_port() {
        assert!(!host_header_matches_authority(
            "evil.com",
            "example.com",
            80
        ));
        assert!(!host_header_matches_authority(
            "example.com:8080",
            "example.com",
            80
        ));
    }

    #[test]
    fn find_double_crlf_present() {
        // The 4-byte CRLF-CRLF terminator starts at byte 23 in this input;
        // find_double_crlf returns the position right after it (where the
        // body begins), which is 27.
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_double_crlf(buf), Some(27));
    }

    #[test]
    fn find_double_crlf_absent() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(find_double_crlf(buf), None);
    }

    #[test]
    fn parse_request_line_headers_basic() {
        let raw =
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let r = parse_request_line_headers(raw);
        assert!(r.is_some());
        let (method, uri, hdrs) = r.unwrap();
        assert_eq!(method, "GET");
        assert_eq!(uri, "http://example.com/path");
        assert_eq!(hdrs.len(), 2);
    }

    #[test]
    fn parse_request_line_connect() {
        let raw = b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let r = parse_request_line_headers(raw);
        assert!(r.is_some());
        let (method, uri, _) = r.unwrap();
        assert_eq!(method, "CONNECT");
        assert_eq!(uri, "api.github.com:443");
    }

    // ─── negative paths ────────────────────────────────────────────────────

    #[test]
    fn parse_request_line_headers_rejects_non_utf8() {
        // 0xff is never valid UTF-8 — the early `from_utf8` must reject this.
        let raw: &[u8] = &[0xff, 0xfe, b'G', b'E', b'T'];
        assert!(parse_request_line_headers(raw).is_none());
    }

    #[test]
    fn parse_request_line_headers_rejects_empty_input() {
        // Empty input parses as UTF-8, but has no method/uri tokens.
        assert!(parse_request_line_headers(b"").is_none());
    }

    #[test]
    fn parse_request_line_headers_rejects_request_line_without_uri() {
        // Method present, URI missing — the second `parts.next()?` returns None.
        assert!(parse_request_line_headers(b"GET\r\n\r\n").is_none());
    }

    #[test]
    fn parse_request_line_headers_keeps_empty_value_headers() {
        // `X-Empty:` with no value is still a valid header line — should appear
        // in the output with an empty value, not be dropped.
        let raw = b"GET / HTTP/1.1\r\nX-Empty:\r\nHost: x\r\n\r\n";
        let (_, _, hdrs) = parse_request_line_headers(raw).expect("parse");
        let empty = hdrs
            .iter()
            .find(|(k, _)| k == "X-Empty")
            .expect("X-Empty header preserved");
        assert_eq!(empty.1, "");
    }

    #[test]
    fn parse_request_line_headers_silently_skips_malformed_headers() {
        // A header line without a colon is currently dropped silently. Lock in
        // that behaviour — surfacing it as an error would be a breaking change
        // that we'd want to make deliberately.
        let raw = b"GET / HTTP/1.1\r\nNoColonHere\r\nHost: x\r\n\r\n";
        let (_, _, hdrs) = parse_request_line_headers(raw).expect("parse");
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].0, "Host");
    }

    // ── Agent context enrichment (S013 proxy path) ────────────────────────

    #[test]
    fn build_http_ctx_without_agent_leaves_agent_unset() {
        let ctx = build_http_ctx("GET", "example.com", "/", &HashMap::new(), 443, None);
        assert!(
            ctx.agent.is_none(),
            "agent should be unset when name is None"
        );
        assert!(ctx.http.is_some());
        assert_eq!(ctx.http.as_ref().unwrap().method, "GET");
        assert_eq!(ctx.http.as_ref().unwrap().host, "example.com");
    }

    #[test]
    fn build_http_ctx_with_agent_populates_name() {
        let ctx = build_http_ctx(
            "POST",
            "api.example.com",
            "/v1",
            &HashMap::new(),
            443,
            Some("ci"),
        );
        let agent = ctx.agent.expect("agent should be set");
        assert_eq!(agent.name, "ci");
        assert_eq!(ctx.http.as_ref().unwrap().method, "POST");
    }

    #[test]
    fn build_http_ctx_uppercases_method() {
        // Lock in the uppercase normalization — CEL rules use canonical
        // uppercase methods (`http.method == "GET"`).
        let ctx = build_http_ctx("get", "x.example", "/", &HashMap::new(), 443, None);
        assert_eq!(ctx.http.unwrap().method, "GET");
    }

    #[tokio::test]
    async fn resolve_agent_name_returns_none_when_docker_absent() {
        // No DockerManager → no resolution. Verifies the Option<Arc<...>> path.
        let docker: Option<Arc<DockerManager>> = None;
        let peer: SocketAddr = "10.200.0.5:54321".parse().unwrap();
        assert_eq!(resolve_agent_name(&docker, peer).await, None);
    }
}
