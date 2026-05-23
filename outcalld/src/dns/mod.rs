//! DNS filter server — S007.
//!
//! Intercepts all DNS queries from agent containers, evaluates them against
//! the rule engine, and either forwards to upstream or returns NXDOMAIN.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_net::runtime::{RuntimeProvider, Time, TokioRuntimeProvider, TokioTime};
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;
use lru::LruCache;
use outcall_api::{
    AllowRuleRequest, Decision, DnsCacheEntry, DnsCacheStats, DnsContext, DnsFilterStatus,
    EvalContext,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::dynamic::DynamicRuleManager;
use crate::rules::model::EgressMode;
use crate::rules::RuleEngine;

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
                return ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                });
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
                    return self.send_answer(request, &records, response_handle).await;
                }

                self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);

                // Forward to upstream
                let upstream_start = Instant::now();
                match self.resolver.lookup(hostname.as_str(), record_type).await {
                    Ok(lookup) => {
                        let upstream_ms = upstream_start.elapsed().as_millis();
                        let records: Vec<Record> = lookup.answers().to_vec();

                        // Block DNS rebinding responses (FR-034)
                        let rebinding = check_rebinding(&hostname, &records);
                        if rebinding {
                            self.counters
                                .queries_blocked
                                .fetch_add(1, Ordering::Relaxed);
                            info!(
                                %src, %hostname,
                                decision = "block", rule = "dns-rebinding",
                                "DNS query blocked — rebinding detected"
                            );
                            return self.send_nxdomain(request, response_handle).await;
                        }

                        // Strip private/loopback/link-local/ULA/multicast IPs from the
                        // upstream response (BYPASS-03a/03b, PAYLOAD-03). An attacker who
                        // controls upstream DNS could resolve a hostname to an RFC1918
                        // address and reach services Outcall was supposed to block.
                        //
                        // Per-rule opt-out: if the matched rule sets `allow_private_ips: true`
                        // we pass private IPs through (e.g. internal-VLAN registries).
                        let allow_private = matched_egress
                            .as_ref()
                            .map(|e| e.allow_private_ips)
                            .unwrap_or(false);
                        let records = if allow_private {
                            records
                        } else {
                            filter_private_ips(&hostname, records)
                        };

                        // If filtering emptied the answer set, return SERVFAIL. NXDOMAIN
                        // is negatively cacheable and would incorrectly claim the domain
                        // does not exist if policy later allows private answers.
                        if records.is_empty() {
                            info!(
                                %src, %hostname,
                                decision = "block", rule = "private-ip-filter",
                                "DNS answer set empty after private-IP stripping → SERVFAIL"
                            );
                            return self.send_servfail(request, response_handle).await;
                        }

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

                        self.send_answer(request, &records, response_handle).await
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
            EgressMode::Intercept => {
                // Intercept mode terminates TLS at the proxy — no direct nft allow
                // rules are inserted. The proxy handles the TLS termination and
                // forwards the (now decrypted) request to the upstream.
                debug!(%hostname, "egress mode is intercept; TLS termination via proxy; no direct nft allow rules");
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

// ── Private-IP filter (BYPASS-03a/03b, PAYLOAD-03) ────────────────────────

/// Returns `true` if `addr` falls within any address range that must not be
/// forwarded to agent containers as a DNS answer:
///
/// IPv4 blocked ranges:
///   10.0.0.0/8        — RFC1918 private
///   172.16.0.0/12     — RFC1918 private
///   192.168.0.0/16    — RFC1918 private
///   127.0.0.0/8       — loopback
///   169.254.0.0/16    — link-local (APIPA)
///   100.64.0.0/10     — Shared Address (CGNAT, RFC6598)
///   0.0.0.0/8         — "this" network
///   224.0.0.0/4       — multicast
///
/// IPv6 blocked ranges:
///   ::1/128           — loopback
///   fe80::/10         — link-local
///   fc00::/7          — ULA (unique-local, covers fc00:: and fd00::)
///   ff00::/8          — multicast
///   ::ffff:0:0/96     — IPv4-mapped (equivalent to filtering the IPv4 form)
fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            o[0] == 10
            // 172.16.0.0/12  (172.16.x.x – 172.31.x.x)
            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            // 192.168.0.0/16
            || (o[0] == 192 && o[1] == 168)
            // 127.0.0.0/8
            || o[0] == 127
            // 169.254.0.0/16
            || (o[0] == 169 && o[1] == 254)
            // 100.64.0.0/10  (100.64.x.x – 100.127.x.x)
            || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
            // 0.0.0.0/8
            || o[0] == 0
            // 224.0.0.0/4  (224.x.x.x – 239.x.x.x)
            || o[0] >= 224 && o[0] <= 239
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // ::1/128 — loopback
            v6.is_loopback()
            // fe80::/10 — link-local (fe80:: – febf::)
            || (segs[0] & 0xffc0) == 0xfe80
            // fc00::/7  — ULA (fc00:: – fdff::)
            || (segs[0] & 0xfe00) == 0xfc00
            // ff00::/8  — multicast
            || (segs[0] & 0xff00) == 0xff00
            // ::ffff:0:0/96 — IPv4-mapped  (::ffff:x.x.x.x)
            || (segs[0] == 0 && segs[1] == 0 && segs[2] == 0
                && segs[3] == 0 && segs[4] == 0 && segs[5] == 0xffff)
        }
    }
}

/// Remove any A/AAAA records whose IP is private/loopback/link-local/multicast.
/// Non-address records (CNAME, TXT, …) are always kept.
/// Each dropped record is logged at INFO with structured fields for operator
/// debugging: `host`, `dropped_ip`, `reason`.
fn filter_private_ips(hostname: &str, records: Vec<Record>) -> Vec<Record> {
    records
        .into_iter()
        .filter(|r| {
            let maybe_addr: Option<IpAddr> = match &r.data {
                RData::A(ip) => Some(IpAddr::V4(ip.0)),
                RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                _ => return true, // keep non-address records unconditionally
            };
            if let Some(addr) = maybe_addr {
                if is_private_ip(addr) {
                    info!(
                        host = %hostname,
                        dropped_ip = %addr,
                        reason = "private_ip",
                        "DNS answer record stripped — private/loopback/link-local IP"
                    );
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Check for potential DNS rebinding (FR-034).
/// Returns true if rebinding was detected (private IP returned for public hostname).
fn check_rebinding(hostname: &str, records: &[Record]) -> bool {
    let mut rebinding_detected = false;
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
                    "DNS rebinding detected: public hostname resolved to private/loopback IP → blocking"
                );
                rebinding_detected = true;
            }
        }
    }
    rebinding_detected
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
                // PRIVATE_INVARIANT_OK: DNS_CACHE_MAX_ENTRIES is a non-zero compile-time constant.
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
        // STARTUP_OK: udp was just bound successfully above; local_addr() cannot fail here.
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
            // PRIVATE_INVARIANT_OK: hardcoded literal "8.8.8.8:53" always parses successfully.
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

    // ── Private-IP filter tests ────────────────────────────────────────────

    /// A public IPv4 address (1.1.1.1) must pass through the filter unchanged.
    #[test]
    fn filter_private_ips_passes_public_ipv4() {
        let name = Name::from_ascii("example.com.").expect("name");
        let rec = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        );
        let out = filter_private_ips("example.com", vec![rec]);
        assert_eq!(out.len(), 1, "public IP should not be filtered");
    }

    /// RFC1918 10.x.x.x must be stripped (BYPASS-03a: internal service resolution).
    #[test]
    fn filter_private_ips_drops_rfc1918_10_slash_8() {
        let name = Name::from_ascii("myservice.internal.").expect("name");
        let rec = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(10, 200, 0, 5))),
        );
        let out = filter_private_ips("myservice.internal", vec![rec]);
        assert!(out.is_empty(), "10.x private IP must be dropped");
    }

    /// IPv4 loopback 127.0.0.1 must be stripped.
    #[test]
    fn filter_private_ips_drops_loopback_127() {
        let name = Name::from_ascii("localhost.").expect("name");
        let rec = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(127, 0, 0, 1))),
        );
        let out = filter_private_ips("localhost", vec![rec]);
        assert!(out.is_empty(), "loopback 127.0.0.1 must be dropped");
    }

    /// IPv6 link-local fe80::1 must be stripped.
    #[test]
    fn filter_private_ips_drops_ipv6_link_local() {
        let name = Name::from_ascii("fe80-host.example.com.").expect("name");
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let rec = Record::from_rdata(name, 60, RData::AAAA(hickory_proto::rr::rdata::AAAA(addr)));
        let out = filter_private_ips("fe80-host.example.com", vec![rec]);
        assert!(out.is_empty(), "fe80::/10 link-local must be dropped");
    }

    /// Mixed response: one private (10.x) and one public (93.184.x) A record.
    /// The private one must be stripped; the public one must survive.
    #[test]
    fn filter_private_ips_strips_private_keeps_public_in_mixed_response() {
        let name = Name::from_ascii("mixed.example.com.").expect("name");
        let priv_rec = Record::from_rdata(
            name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 168, 1, 100))),
        );
        let pub_rec = Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 215, 14))),
        );
        let out = filter_private_ips("mixed.example.com", vec![priv_rec, pub_rec]);
        assert_eq!(out.len(), 1, "only the public IP should remain");
        if let RData::A(ip) = &out[0].data {
            assert_eq!(ip.0, Ipv4Addr::new(93, 184, 215, 14));
        } else {
            panic!("expected an A record");
        }
    }

    /// Additional ranges: CGNAT (100.64.x), 172.16/12, 169.254/16 must all be blocked.
    #[test]
    fn filter_private_ips_drops_additional_private_ranges() {
        let name = Name::from_ascii("test.example.com.").expect("name");
        let cases = vec![
            Ipv4Addr::new(100, 64, 0, 1),   // CGNAT 100.64.0.0/10
            Ipv4Addr::new(172, 16, 5, 1),   // 172.16.0.0/12
            Ipv4Addr::new(172, 31, 255, 1), // top of 172.16.0.0/12
            Ipv4Addr::new(169, 254, 1, 1),  // link-local APIPA
        ];
        for addr in cases {
            let rec = Record::from_rdata(
                name.clone(),
                60,
                RData::A(hickory_proto::rr::rdata::A(addr)),
            );
            let out = filter_private_ips("test.example.com", vec![rec]);
            assert!(out.is_empty(), "{addr} should be filtered as private");
        }
    }
}
