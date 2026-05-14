//! DNS filter server — S007.
//!
//! Intercepts all DNS queries from agent containers, evaluates them against
//! the rule engine, and either forwards to upstream or returns NXDOMAIN.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_net::runtime::{RuntimeProvider, Time, TokioRuntimeProvider, TokioTime};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, Server,
};
use lru::LruCache;
use outcall_api::{
    AllowRuleRequest, Decision, DnsCacheEntry, DnsCacheStats, DnsContext, DnsFilterStatus,
    EvalContext,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::dynamic::DynamicRuleManager;
use crate::rules::RuleEngine;
use crate::rules::model::EgressMode;

// ── Constants ──────────────────────────────────────────────────────────────

const DNS_CACHE_MAX_ENTRIES: usize = 10_000;
const DNS_CACHE_MAX_TTL_SECS: u32 = 300;

// ── Cache types ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CacheEntry {
    records: Vec<Record>,
    effective_ttl: u32,
    inserted_at: Instant,
    record_type_str: String,
}

type DnsLruCache = LruCache<(String, RecordType), CacheEntry>;

// ── Counters ───────────────────────────────────────────────────────────────

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

// ── RequestHandler ─────────────────────────────────────────────────────────

struct DnsHandler {
    rule_engine: Arc<RuleEngine>,
    dynamic: Arc<DynamicRuleManager>,
    resolver: TokioResolver,
    cache: Arc<Mutex<DnsLruCache>>,
    counters: Arc<DnsCounters>,
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "invalid DNS request");
                let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
                metadata.response_code = ResponseCode::ServFail;
                return ResponseInfo::from(Header { metadata, counts: HeaderCounts::default() });
            }
        };

        let query = request_info.query;
        let raw_name = query.name().to_string();
        let hostname = raw_name.trim_end_matches('.').to_lowercase();
        let record_type = query.query_type();
        let record_type_str = record_type_to_str(record_type);
        let src = request_info.src;

        self.counters.queries_total.fetch_add(1, Ordering::Relaxed);

        // mDNS (.local) → NXDOMAIN without rule evaluation (FR-033)
        if hostname.ends_with(".local") {
            debug!(%hostname, "mDNS query → NXDOMAIN (no rule evaluation)");
            return self.send_nxdomain(request, response_handle).await;
        }

        // Build evaluation context
        let ctx = EvalContext {
            dns: Some(DnsContext {
                query: hostname.clone(),
                record_type: record_type_str.clone(),
            }),
            ..Default::default()
        };

        let eval_start = Instant::now();
        let eval_result = self.rule_engine.evaluate(&ctx).await;
        let eval_ms = eval_start.elapsed().as_millis();
        if eval_ms > 10 {
            warn!(
                elapsed_ms = eval_ms,
                %hostname,
                "DNS rule evaluation exceeded 10ms budget"
            );
        }

        let rule_id = eval_result
            .matched_rule
            .as_deref()
            .unwrap_or("default-block");
        let matched_egress = if let Some(rule_id) = eval_result.matched_rule.as_deref() {
            self.rule_engine.rule_egress(rule_id).await
        } else {
            None
        };

        match eval_result.decision {
            Decision::Block => {
                self.counters
                    .queries_blocked
                    .fetch_add(1, Ordering::Relaxed);
                info!(
                    %src, %hostname, record_type = %record_type_str,
                    decision = "block", rule = rule_id, from_cache = false,
                    "DNS query blocked"
                );
                self.send_nxdomain(request, response_handle).await
            }

            Decision::Allow => {
                self.counters
                    .queries_allowed
                    .fetch_add(1, Ordering::Relaxed);

                let cache_key = (hostname.clone(), record_type);

                // Check cache
                let cached = {
                    let mut cache = self.cache.lock().await;
                    if let Some(entry) = cache.get(&cache_key) {
                        let elapsed = entry.inserted_at.elapsed().as_secs() as u32;
                        if elapsed < entry.effective_ttl {
                            let remaining = entry.effective_ttl.saturating_sub(elapsed);
                            let mut records = entry.records.clone();
                            for r in &mut records {
                                r.ttl = remaining;
                            }
                            Some(records)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some(records) = cached {
                    self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                    info!(
                        %src, %hostname, record_type = %record_type_str,
                        decision = "allow", rule = rule_id, from_cache = true,
                        "DNS query allowed (cached)"
                    );
                    return self
                        .send_answer(request, &records, response_handle)
                        .await;
                }

                self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);

                // Forward to upstream
                let upstream_start = Instant::now();
                match self.resolver.lookup(hostname.as_str(), record_type).await {
                    Ok(lookup) => {
                        let upstream_ms = upstream_start.elapsed().as_millis();
                        let records: Vec<Record> = lookup.answers().to_vec();

                        check_rebinding(&hostname, &records);

                        // Cache the result
                        if !records.is_empty() {
                            let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(60);
                            let effective_ttl = min_ttl.min(DNS_CACHE_MAX_TTL_SECS);
                            let entry = CacheEntry {
                                records: records.clone(),
                                effective_ttl,
                                inserted_at: Instant::now(),
                                record_type_str: record_type_str.clone(),
                            };
                            let mut cache = self.cache.lock().await;
                            let is_new = cache.peek(&cache_key).is_none();
                            let was_full = cache.len() >= DNS_CACHE_MAX_ENTRIES;
                            cache.put(cache_key, entry);
                            if is_new && was_full {
                                self.counters
                                    .cache_evictions
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        info!(
                            %src, %hostname, record_type = %record_type_str,
                            decision = "allow", rule = rule_id, from_cache = false,
                            upstream_ms,
                            "DNS query allowed"
                        );

                        self.apply_egress_policy(src, &hostname, &matched_egress, &records)
                            .await;

                        self.send_answer(request, &records, response_handle)
                            .await
                    }
                    Err(e) => {
                        warn!(%hostname, error = %e, "upstream DNS resolution failed → SERVFAIL");
                        self.send_servfail(request, response_handle).await
                    }
                }
            }
        }
    }
}

impl DnsHandler {
    async fn apply_egress_policy(
        &self,
        src: SocketAddr,
        hostname: &str,
        egress: &Option<crate::rules::model::EgressSpec>,
        records: &[Record],
    ) {
        let Some(egress) = egress else {
            return;
        };

        match egress.mode {
            EgressMode::Proxy => {
                debug!(%hostname, "egress mode is proxy; no direct nft allow rules inserted");
            }
            EgressMode::DirectIp => {
                let src_ip = src.ip().to_string();
                let container = self
                    .dynamic
                    .container_name_for_ip(&src_ip)
                    .await
                    .unwrap_or_else(|| src_ip.clone());

                let ports: Vec<u16> = if egress.ports.is_empty() {
                    vec![80, 443]
                } else {
                    egress.ports.clone()
                };

                let ipv4_destinations = extract_ipv4_destinations(records);
                let ipv6_destinations = extract_ipv6_destinations(records);

                if ipv4_destinations.is_empty() && ipv6_destinations.is_empty() {
                    debug!(%hostname, "direct_ip egress requested but no DNS A or AAAA answers found");
                    return;
                }

                for dst in ipv4_destinations {
                    for port in &ports {
                        let req = AllowRuleRequest {
                            container: container.clone(),
                            src_ip: src_ip.clone(),
                            destination: dst.clone(),
                            protocol: Some("tcp".to_string()),
                            port: Some(*port),
                        };

                        if let Err(e) = self.dynamic.insert_rule(req).await {
                            warn!(%hostname, src = %src_ip, dst = %dst, port = *port, "failed to insert direct_ip allow rule (IPv4): {e}");
                        }
                    }
                }

                for dst in ipv6_destinations {
                    for port in &ports {
                        let req = AllowRuleRequest {
                            container: container.clone(),
                            src_ip: src_ip.clone(),
                            destination: dst.clone(),
                            protocol: Some("tcp".to_string()),
                            port: Some(*port),
                        };

                        if let Err(e) = self.dynamic.insert_rule(req).await {
                            warn!(%hostname, src = %src_ip, dst = %dst, port = *port, "failed to insert direct_ip allow rule (IPv6): {e}");
                        }
                    }
                }
            }
        }
    }

async fn send_nxdomain<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let soa = soa_record();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&(&*request).metadata);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::NXDomain;
        metadata.authoritative = true;
        metadata.recursion_available = true;
        let resp = builder.build(
            metadata,
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::once(&soa),
            std::iter::empty::<&Record>(),
        );
        response_handle
            .send_response(resp)
            .await
            .unwrap_or_else(|_| ResponseInfo::from(self.nxdomain_header(&(&*request).metadata)))
    }

    async fn send_servfail<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&(&*request).metadata);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::ServFail;
        metadata.recursion_available = true;
        let resp = builder.build_no_records(metadata);
        response_handle
            .send_response(resp)
            .await
            .unwrap_or_else(|_| ResponseInfo::from(self.servfail_header(&(&*request).metadata)))
    }

    async fn send_answer<R: ResponseHandler>(
        &self,
        request: &Request,
        records: &[Record],
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&(&*request).metadata);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::NoError;
        metadata.recursion_available = true;
        let resp = builder.build(
            metadata,
            records.iter(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
            std::iter::empty::<&Record>(),
        );
        response_handle
            .send_response(resp)
            .await
            .unwrap_or_else(|_| ResponseInfo::from(self.noerror_header(&(&*request).metadata)))
    }
}

// ── Response helpers ───────────────────────────────────────────────────────

impl DnsHandler {
    fn nxdomain_header(&self, original: &Metadata) -> Header {
        let mut metadata = Metadata::response_from_request(original);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::NXDomain;
        metadata.authoritative = true;
        metadata.recursion_available = true;
        Header {
            metadata,
            counts: HeaderCounts::default(),
        }
    }

    fn servfail_header(&self, original: &Metadata) -> Header {
        let mut metadata = Metadata::response_from_request(original);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::ServFail;
        metadata.recursion_available = true;
        Header {
            metadata,
            counts: HeaderCounts::default(),
        }
    }

    fn noerror_header(&self, original: &Metadata) -> Header {
        let mut metadata = Metadata::response_from_request(original);
        metadata.message_type = MessageType::Response;
        metadata.response_code = ResponseCode::NoError;
        metadata.recursion_available = true;
        Header {
            metadata,
            counts: HeaderCounts::default(),
        }
    }
}

fn soa_record() -> Record {
    let name = Name::from_str("outcall.invalid.").unwrap_or_else(|_| Name::root());
    let mname = Name::from_str("ns.outcall.invalid.").unwrap_or_else(|_| Name::root());
    let rname = Name::from_str("hostmaster.outcall.invalid.").unwrap_or_else(|_| Name::root());
    let soa = SOA::new(mname, rname, 1, 3600, 600, 86400, 60);
    Record::from_rdata(name, 60, RData::SOA(soa))
}

fn record_type_to_str(rt: RecordType) -> String {
    format!("{rt:?}").to_ascii_uppercase()
}

/// Warn on potential DNS rebinding (FR-034).
fn check_rebinding(hostname: &str, records: &[Record]) {
    for r in records {
        let maybe_addr: Option<IpAddr> = match &r.data {
            RData::A(ip) => Some(IpAddr::V4(ip.0)),
            RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
            _ => None,
        };
        if let Some(addr) = maybe_addr {
            let private = match addr {
                IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_loopback(),
            };
            if private {
                warn!(
                    %hostname, %addr,
                    "potential DNS rebinding: public hostname resolved to private/loopback IP"
                );
            }
        }
    }
}

fn extract_ipv4_destinations(records: &[Record]) -> Vec<String> {
    let mut out = Vec::new();
    for r in records {
        if let RData::A(ip) = &r.data {
            out.push(ip.0.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn extract_ipv6_destinations(records: &[Record]) -> Vec<String> {
    let mut out = Vec::new();
    for r in records {
        if let RData::AAAA(ip) = &r.data {
            out.push(ip.0.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

// ── DnsServer ──────────────────────────────────────────────────────────────

/// Public handle for the running DNS filter.
pub struct DnsServer {
    listen_addr: Mutex<SocketAddr>,
    pub upstreams: Vec<SocketAddr>,
    pub cache: Arc<Mutex<DnsLruCache>>,
    pub counters: Arc<DnsCounters>,
    pub running: Arc<AtomicBool>,
    shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl DnsServer {
    pub fn new(listen_addr: SocketAddr, upstreams: Vec<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            listen_addr: Mutex::new(listen_addr),
            upstreams,
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DNS_CACHE_MAX_ENTRIES).unwrap(),
            ))),
            counters: Arc::new(DnsCounters::new()),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: Mutex::new(None),
        })
    }

    /// Bind sockets and start serving. Returns when the server is running.
    pub async fn start(
        self: &Arc<Self>,
        rule_engine: Arc<RuleEngine>,
        dynamic: Arc<DynamicRuleManager>,
    ) -> Result<()> {
        let resolver = build_resolver(&self.upstreams)?;
        let handler = DnsHandler {
            rule_engine,
            dynamic,
            resolver,
            cache: self.cache.clone(),
            counters: self.counters.clone(),
        };

        // Lock to get the address for binding (only locked briefly here).
        let bind_addr = *self.listen_addr.lock().await;
        let udp = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("DNS: failed to bind UDP {}", bind_addr))?;
        let tcp = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("DNS: failed to bind TCP {}", bind_addr))?;

        // Store the actual bound address (handles ephemeral port 0 case).
        *self.listen_addr.lock().await = udp.local_addr().expect("UDP local_addr");
        info!(addr = %udp.local_addr().expect("UDP local_addr"), "DNS filter started");

        let mut server = Server::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(5), 4096);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *self.shutdown_tx.lock().await = Some(tx);
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = server.block_until_done() => {
                    if let Err(e) = result {
                        error!("DNS server error: {e}");
                    }
                }
                _ = rx => {
                    info!("DNS server received shutdown signal");
                }
            }
            running.store(false, Ordering::SeqCst);
            info!("DNS server stopped");
        });

        Ok(())
    }

    /// Gracefully stop the DNS server.
    pub async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// Returns the actual address the DNS server is listening on.
    /// Useful for tests that bind on port 0 (ephemeral).
    pub async fn local_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().await
    }

    /// Flush the DNS cache. Returns the number of entries cleared.
    pub async fn flush_cache(&self) -> usize {
        let mut cache = self.cache.lock().await;
        let count = cache.len();
        cache.clear();
        count
    }

    /// Build a DnsFilterStatus snapshot.
    pub async fn status(&self) -> DnsFilterStatus {
        let cache_entries = self.cache.lock().await.len();
        let listen_addr = self.listen_addr.lock().await;
        DnsFilterStatus {
            running: self.running.load(Ordering::Relaxed),
            listen_address: listen_addr.ip().to_string(),
            listen_port: listen_addr.port(),
            upstreams: self.upstreams.iter().map(|a| a.to_string()).collect(),
            cache_entries,
            queries_total: self.counters.queries_total.load(Ordering::Relaxed),
            queries_allowed: self.counters.queries_allowed.load(Ordering::Relaxed),
            queries_blocked: self.counters.queries_blocked.load(Ordering::Relaxed),
        }
    }

    /// Build a DnsCacheStats snapshot.
    pub async fn cache_stats(&self) -> DnsCacheStats {
        let cache = self.cache.lock().await;
        DnsCacheStats {
            entries: cache.len(),
            max_entries: DNS_CACHE_MAX_ENTRIES,
            hits: self.counters.cache_hits.load(Ordering::Relaxed),
            misses: self.counters.cache_misses.load(Ordering::Relaxed),
            evictions: self.counters.cache_evictions.load(Ordering::Relaxed),
        }
    }

    /// Build a list of cache entries.
    pub async fn cache_entries_list(&self) -> Vec<DnsCacheEntry> {
        let cache = self.cache.lock().await;
        cache
            .iter()
            .map(|((hostname, _rt), entry)| {
                let elapsed = entry.inserted_at.elapsed().as_secs() as u32;
                let remaining = entry.effective_ttl.saturating_sub(elapsed);
                DnsCacheEntry {
                    hostname: hostname.clone(),
                    record_type: entry.record_type_str.clone(),
                    ttl_remaining_secs: remaining,
                }
            })
            .collect()
    }
}

// ── Resolver construction ──────────────────────────────────────────────────

fn build_resolver(upstreams: &[SocketAddr]) -> Result<TokioResolver> {
    let effective = if upstreams.is_empty() {
        let parsed = parse_resolv_conf();
        if parsed.is_empty() {
            // Last-resort fallback
            warn!("No DNS upstreams configured and /etc/resolv.conf empty — using 8.8.8.8");
            vec!["8.8.8.8:53".parse().unwrap()]
        } else {
            parsed
        }
    } else {
        upstreams.to_vec()
    };

    let name_servers: Vec<NameServerConfig> = effective
        .iter()
        .map(|addr| NameServerConfig::udp(addr.ip()))
        .collect();

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut opts = ResolverOpts::default();
    opts.cache_size = 0; // We maintain our own cache
    opts.ndots = 0;

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| anyhow::anyhow!("DNS resolver build failed: {}", e))
}

/// Parse nameserver lines from /etc/resolv.conf.
fn parse_resolv_conf() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("nameserver")
                .and_then(|rest| rest.trim().parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

/// Parse `--dns-upstream` argument: comma-separated `IP[:port]` values.
pub fn parse_upstream_arg(arg: &str) -> Vec<SocketAddr> {
    if arg.is_empty() {
        return vec![];
    }
    arg.split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.contains(':') {
                s.parse().ok()
            } else {
                s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
            }
        })
        .collect()
}

/// Build the resolv.conf content to inject into containers (FR-006, IF-007).
pub fn container_resolv_conf(gateway_ip: &str) -> String {
    format!("# Generated by outcalld -- do not edit\nnameserver {gateway_ip}\noptions ndots:0\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn extract_ipv4_destinations_dedups_and_ignores_non_a_records() {
        let name = Name::from_ascii("ports.ubuntu.com.").expect("name");
        let rec1 = Record::from_rdata(
            name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(91, 189, 91, 104))),
        );
        let rec2 = Record::from_rdata(
            name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(91, 189, 92, 19))),
        );
        let rec3 = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(91, 189, 91, 104))),
        );

        let got = extract_ipv4_destinations(&[rec1, rec2, rec3]);
        assert_eq!(got, vec!["91.189.91.104", "91.189.92.19"]);
    }

    #[test]
    fn extract_ipv6_destinations_dedups_and_ignores_non_aaaa_records() {
        let name = Name::from_ascii("example.com.").expect("name");
        let rec1 = Record::from_rdata(
            name.clone(),
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::LOCALHOST)),
        );
        let rec2 = Record::from_rdata(
            name.clone(),
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
            ))),
        );
        let rec3 = Record::from_rdata(
            name,
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(Ipv6Addr::LOCALHOST)),
        );

        let got = extract_ipv6_destinations(&[rec1, rec2, rec3]);
        // The function sorts lexicographically before dedup. ASCII '2' (0x32)
        // sorts before ':' (0x3A), so "2001:db8::1" precedes "::1".
        assert_eq!(got, vec!["2001:db8::1", "::1"]);
    }

    #[test]
    fn extract_ipv6_destinations_ignores_a_records() {
        let name = Name::from_ascii("example.com.").expect("name");
        let rec = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 215, 14))),
        );

        let got = extract_ipv6_destinations(&[rec]);
        assert!(got.is_empty());
    }
}
