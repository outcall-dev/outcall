//! Deny-by-default DNS filter for managed agent containers (S007).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hickory_server::server::Server;
use outcall_api::{DnsCacheEntry, DnsCacheStats, DnsFilterStatus};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use self::cache::{DnsCache, MAX_ENTRIES};
use self::handler::DnsHandler;
use crate::dynamic::DynamicRuleManager;
use crate::rules::RuleEngine;

mod cache;
mod handler;
mod resolver;
mod response;

pub use resolver::{container_resolv_conf, parse_upstream_arg};

pub struct DnsCounters {
    pub queries_total: AtomicU64,
    pub queries_allowed: AtomicU64,
    pub queries_blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_evictions: AtomicU64,
}

impl DnsCounters {
    fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_allowed: AtomicU64::new(0),
            queries_blocked: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
        }
    }
}

/// Public lifecycle and status handle for the DNS filter.
pub struct DnsServer {
    listen_addr: Mutex<SocketAddr>,
    pub upstreams: Vec<SocketAddr>,
    cache: Arc<Mutex<DnsCache>>,
    pub counters: Arc<DnsCounters>,
    pub running: Arc<AtomicBool>,
    require_managed_peer: bool,
    policy_barrier: Arc<RwLock<()>>,
    lifecycle: Mutex<()>,
    shutdown_token: Mutex<Option<CancellationToken>>,
    server_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DnsServer {
    pub fn new(listen_addr: SocketAddr, upstreams: Vec<SocketAddr>) -> Arc<Self> {
        Self::with_peer_identity_requirement(listen_addr, upstreams, true)
    }

    /// Construct a protocol test server without Docker peer attribution.
    /// Production daemon code must use [`DnsServer::new`].
    #[doc(hidden)]
    pub fn new_for_tests(listen_addr: SocketAddr, upstreams: Vec<SocketAddr>) -> Arc<Self> {
        Self::with_peer_identity_requirement(listen_addr, upstreams, false)
    }

    fn with_peer_identity_requirement(
        listen_addr: SocketAddr,
        upstreams: Vec<SocketAddr>,
        require_managed_peer: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            listen_addr: Mutex::new(listen_addr),
            upstreams,
            cache: Arc::new(Mutex::new(DnsCache::new())),
            counters: Arc::new(DnsCounters::new()),
            running: Arc::new(AtomicBool::new(false)),
            require_managed_peer,
            policy_barrier: Arc::new(RwLock::new(())),
            lifecycle: Mutex::new(()),
            shutdown_token: Mutex::new(None),
            server_task: Mutex::new(None),
        })
    }

    /// Bind UDP and TCP sockets and start serving.
    pub async fn start(
        self: &Arc<Self>,
        rule_engine: Arc<RuleEngine>,
        dynamic: Arc<DynamicRuleManager>,
    ) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.running.load(Ordering::SeqCst) {
            bail!("DNS filter is already running");
        }
        if let Some(task) = self.server_task.lock().await.take() {
            if let Err(error) = task.await {
                warn!(%error, "previous DNS server task failed");
            }
        }
        self.shutdown_token.lock().await.take();

        let resolver = resolver::build(&self.upstreams)?;
        let handler = DnsHandler::new(
            rule_engine,
            dynamic,
            self.require_managed_peer,
            resolver,
            self.cache.clone(),
            self.counters.clone(),
            self.policy_barrier.clone(),
        );

        let requested_addr = *self.listen_addr.lock().await;
        let udp = UdpSocket::bind(requested_addr)
            .await
            .with_context(|| format!("DNS: failed to bind UDP {requested_addr}"))?;
        let bound_addr = udp.local_addr().context("DNS: inspect bound UDP address")?;
        let tcp_addr = tcp_bind_address(requested_addr, bound_addr);
        let tcp = TcpListener::bind(tcp_addr)
            .await
            .with_context(|| format!("DNS: failed to bind TCP {tcp_addr}"))?;

        *self.listen_addr.lock().await = bound_addr;
        info!(addr = %bound_addr, "DNS filter started");

        let mut server = Server::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5), 4096);

        let shutdown_token = server.shutdown_token().clone();
        *self.shutdown_token.lock().await = Some(shutdown_token);
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = server.block_until_done().await {
                error!(%error, "DNS server failed");
            }
            running.store(false, Ordering::SeqCst);
            info!("DNS server stopped");
        });
        *self.server_task.lock().await = Some(task);

        Ok(())
    }

    pub async fn shutdown(&self) {
        let _lifecycle = self.lifecycle.lock().await;
        if let Some(token) = self.shutdown_token.lock().await.take() {
            debug!("requesting graceful DNS server shutdown");
            token.cancel();
        }
        if let Some(mut task) = self.server_task.lock().await.take() {
            match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "DNS server task failed during shutdown"),
                Err(_) => {
                    warn!("DNS server exceeded shutdown deadline; aborting it");
                    task.abort();
                    if let Err(error) = task.await {
                        if !error.is_cancelled() {
                            warn!(%error, "DNS server task failed after abort");
                        }
                    }
                }
            }
        }
        self.running.store(false, Ordering::SeqCst);
    }

    pub async fn local_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().await
    }

    pub async fn flush_cache(&self) -> usize {
        self.cache.lock().await.clear()
    }

    /// Shared barrier used by the daemon's policy-reload coordinator.
    #[doc(hidden)]
    pub fn policy_barrier(&self) -> Arc<RwLock<()>> {
        self.policy_barrier.clone()
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn seed_cache_for_tests(&self) {
        use std::net::Ipv4Addr;

        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};

        let record = Record::from_rdata(
            Name::from_ascii("policy.test.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
        );
        self.cache.lock().await.insert(
            "policy.test".to_string(),
            RecordType::A,
            "A".to_string(),
            vec![record],
        );
    }

    pub async fn status(&self) -> DnsFilterStatus {
        let cache_entries = self.cache.lock().await.len();
        let listen_addr = self.listen_addr.lock().await;
        DnsFilterStatus {
            running: self.running.load(Ordering::Relaxed),
            listen_address: listen_addr.ip().to_string(),
            listen_port: listen_addr.port(),
            upstreams: self.upstreams.iter().map(ToString::to_string).collect(),
            cache_entries,
            queries_total: self.counters.queries_total.load(Ordering::Relaxed),
            queries_allowed: self.counters.queries_allowed.load(Ordering::Relaxed),
            queries_blocked: self.counters.queries_blocked.load(Ordering::Relaxed),
        }
    }

    pub async fn cache_stats(&self) -> DnsCacheStats {
        let entries = self.cache.lock().await.len();
        DnsCacheStats {
            entries,
            max_entries: MAX_ENTRIES,
            hits: self.counters.cache_hits.load(Ordering::Relaxed),
            misses: self.counters.cache_misses.load(Ordering::Relaxed),
            evictions: self.counters.cache_evictions.load(Ordering::Relaxed),
        }
    }

    pub async fn cache_entries_list(&self) -> Vec<DnsCacheEntry> {
        self.cache.lock().await.snapshot()
    }
}

fn tcp_bind_address(requested: SocketAddr, udp_bound: SocketAddr) -> SocketAddr {
    if requested.port() == 0 {
        udp_bound
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_uses_udp_selected_ephemeral_port() {
        let requested: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let udp_bound: SocketAddr = "127.0.0.1:43123".parse().unwrap();
        assert_eq!(tcp_bind_address(requested, udp_bound), udp_bound);
    }

    #[test]
    fn configured_port_is_preserved() {
        let requested: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let udp_bound: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert_eq!(tcp_bind_address(requested, udp_bound), requested);
    }

    #[tokio::test]
    async fn shutdown_waits_for_server_and_supports_restart() {
        let rules_dir = tempfile::tempdir().unwrap();
        let rules = Arc::new(RuleEngine::load(rules_dir.path().to_str().unwrap()).unwrap());
        let docker = Arc::new(crate::docker::DockerManager::new_unavailable());
        let dynamic = DynamicRuleManager::new_without_policy_reset_for_tests(docker);
        let server = DnsServer::new_for_tests("127.0.0.1:0".parse().unwrap(), vec![]);

        server.start(rules.clone(), dynamic.clone()).await.unwrap();
        assert!(server.running.load(Ordering::SeqCst));
        server.shutdown().await;
        assert!(!server.running.load(Ordering::SeqCst));

        server.start(rules, dynamic).await.unwrap();
        assert!(server.running.load(Ordering::SeqCst));
        server.shutdown().await;
        assert!(!server.running.load(Ordering::SeqCst));
    }
}
