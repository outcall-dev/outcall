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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};

#[cfg(target_os = "linux")]
use crate::agent_api::derive_agent_name;
use crate::docker::DockerManager;
use crate::rules::RuleEngine;

const MAX_CONNECTIONS: usize = 1024;
const CONNECT_TIMEOUT_SECS: u64 = 10;
const IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_HEADER_BYTES: usize = 8192;
const MAX_HTTP_BODY_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_CONNECT_BLOCKED_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 110, 119, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5672, 5900, 6379, 9200, 9300, 11211, 27017,
];
const GRACE_PERIOD_SECS: u64 = 5;

mod connect;
mod context;
mod forward;
mod http;
mod io;
mod tls;
mod upstream;

use http::parse_request;
use io::{read_through_headers, write_error, write_error_logged, HeaderReadError};
#[cfg(test)]
mod tests;

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
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
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
            accept_task: Mutex::new(None),
        })
    }

    pub async fn start(self: &Arc<Self>, rule_engine: Arc<RuleEngine>) -> Result<()> {
        let mut shutdown_slot = self.shutdown_tx.lock().await;
        if shutdown_slot.is_some() || self.running.load(Ordering::SeqCst) {
            anyhow::bail!("proxy is already running");
        }
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
        *shutdown_slot = Some(tx);
        self.running.store(true, Ordering::SeqCst);

        let this = self.clone();
        let task = tokio::spawn(async move { this.accept_loop(listener, rule_engine, rx).await });
        *self.accept_task.lock().await = Some(task);

        Ok(())
    }

    pub async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            if tx.send(()).is_err() {
                debug!("proxy accept task had already stopped before shutdown signal");
            }
        }
        let Some(mut task) = self.accept_task.lock().await.take() else {
            self.running.store(false, Ordering::SeqCst);
            return;
        };
        match tokio::time::timeout(Duration::from_secs(GRACE_PERIOD_SECS + 1), &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "proxy accept task failed during shutdown"),
            Err(_) => {
                warn!("proxy accept task exceeded shutdown deadline; aborting it");
                task.abort();
                if let Err(error) = task.await {
                    if !error.is_cancelled() {
                        warn!(%error, "proxy accept task failed after abort");
                    }
                }
            }
        }
        self.running.store(false, Ordering::SeqCst);
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
        let mut connections = tokio::task::JoinSet::new();

        loop {
            let accepted = tokio::select! {
                result = listener.accept() => Some(result),
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        warn!(%error, "proxy connection task failed");
                    }
                    continue;
                }
                _ = &mut shutdown => None,
            };
            let Some(accepted) = accepted else { break };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    error!(%error, "proxy accept error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            let permit = match sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    match tokio::time::timeout(
                        Duration::from_secs(1),
                        write_error(stream, 503, "Service Unavailable", "Too many connections"),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            debug!(%error, "proxy capacity response was not delivered");
                        }
                        Err(error) => debug!(%error, "proxy capacity response timed out"),
                    }
                    continue;
                }
            };

            self.active_connections.fetch_add(1, Ordering::Relaxed);
            self.total_requests.fetch_add(1, Ordering::Relaxed);

            let rule_engine = rule_engine.clone();
            let active = self.active_connections.clone();
            let blocked = self.total_blocked.clone();
            let docker = self.docker.clone();

            connections.spawn(async move {
                match resolve_agent_name(&docker, peer).await {
                    Ok(agent_name) => {
                        handle_connection(stream, rule_engine, &blocked, agent_name, peer).await;
                    }
                    Err(error) => {
                        blocked.fetch_add(1, Ordering::Relaxed);
                        warn!(source = %peer.ip(), %error, "proxy rejected unidentified peer");
                        write_error_logged(
                            stream,
                            403,
                            "Forbidden",
                            "Managed container identity required",
                        )
                        .await;
                    }
                }
                active.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            });
        }

        drop(listener);
        let drained = tokio::time::timeout(Duration::from_secs(GRACE_PERIOD_SECS), async {
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "proxy connection task failed while draining");
                }
            }
        })
        .await;
        if drained.is_err() {
            let remaining = connections.len();
            warn!(
                remaining,
                "proxy grace period expired; aborting connections"
            );
            connections.shutdown().await;
        }
        self.active_connections.store(0, Ordering::SeqCst);

        self.running.store(false, Ordering::SeqCst);
        info!("proxy stopped");
    }
}

// ── Connection dispatcher ─────────────────────────────────────────────────

/// Resolves a peer SocketAddr to an outcall-managed agent name. A missing
/// Docker manager explicitly disables attribution for protocol-level tests;
/// production always supplies one and therefore fails closed on unknown peers.
#[cfg(target_os = "linux")]
async fn resolve_agent_name(
    docker: &Option<Arc<DockerManager>>,
    peer: SocketAddr,
) -> Result<Option<String>> {
    let Some(docker) = docker.as_ref() else {
        return Ok(None);
    };
    let ip = peer.ip().to_string();
    let name = docker
        .lookup_container_name_by_ip(&ip)
        .await?
        .with_context(|| format!("peer {ip} is not an outcall-managed container"))?;
    Ok(Some(derive_agent_name(&name)))
}

#[cfg(not(target_os = "linux"))]
async fn resolve_agent_name(
    docker: &Option<Arc<DockerManager>>,
    peer: SocketAddr,
) -> Result<Option<String>> {
    if docker.is_none() {
        Ok(None)
    } else {
        anyhow::bail!("peer {} cannot be attributed on this platform", peer.ip())
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    rule_engine: Arc<RuleEngine>,
    total_blocked: &AtomicU64,
    agent_name: Option<String>,
    peer: SocketAddr,
) {
    let mut buf = Vec::with_capacity(2048);

    let header_read = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        read_through_headers(&mut stream, &mut buf, MAX_HEADER_BYTES),
    )
    .await;
    let header_end = match header_read {
        Err(_) => {
            write_error_logged(stream, 408, "Request Timeout", "Request headers timed out").await;
            return;
        }
        Ok(result) => match result {
            Ok(n) => n,
            Err(HeaderReadError::TooLarge) => {
                write_error_logged(
                    stream,
                    431,
                    "Request Header Fields Too Large",
                    "Headers exceed the maximum allowed size",
                )
                .await;
                return;
            }
            Err(HeaderReadError::Io) => return,
        },
    };

    let request = match parse_request(&buf[..header_end]) {
        Ok(request) => request,
        Err(error) => {
            debug!(%error, "proxy rejected malformed HTTP request");
            write_error_logged(stream, 400, "Bad Request", "Malformed HTTP request").await;
            return;
        }
    };
    let body_prefix = buf[header_end..].to_vec();

    // Health check — not forwarded upstream.
    if request.method.eq_ignore_ascii_case("GET") && request.uri == "/outcall-health" {
        if !body_prefix.is_empty() {
            write_error_logged(stream, 400, "Bad Request", "Unexpected health-check body").await;
            return;
        }
        handle_health(stream).await;
        return;
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        connect::handle(
            stream,
            request,
            body_prefix,
            rule_engine,
            total_blocked,
            agent_name,
            peer.ip(),
        )
        .await;
    } else {
        forward::handle(
            stream,
            request,
            body_prefix,
            rule_engine,
            total_blocked,
            agent_name,
            peer.ip(),
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
    if let Err(error) = stream.write_all(resp.as_bytes()).await {
        debug!(%error, "proxy health response was not delivered");
    }
}
