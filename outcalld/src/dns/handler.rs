use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hickory_net::runtime::Time;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::Record;
use hickory_resolver::TokioResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use outcall_api::{AgentContext, AllowRuleRequest, Decision, DnsContext, EvalContext};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use super::cache::{DnsCache, MAX_TTL_SECS};
use super::response;
use super::DnsCounters;
use crate::agent_api::derive_agent_name;
use crate::dns_records::{
    apply_address_policy, extract_ipv4_destinations, extract_ipv6_destinations,
    AddressPolicyOutcome,
};
use crate::dynamic::DynamicRuleManager;
use crate::rules::model::{EgressMode, EgressSpec};
use crate::rules::RuleEngine;

pub(super) struct DnsHandler {
    rule_engine: Arc<RuleEngine>,
    dynamic: Arc<DynamicRuleManager>,
    require_managed_peer: bool,
    resolver: TokioResolver,
    cache: Arc<Mutex<DnsCache>>,
    counters: Arc<DnsCounters>,
    policy_barrier: Arc<RwLock<()>>,
}

struct AnswerContext<'a> {
    source: SocketAddr,
    hostname: &'a str,
    record_type: &'a str,
    rule_id: &'a str,
    egress: Option<&'a EgressSpec>,
    from_cache: bool,
    upstream_ms: u128,
    container_name: Option<&'a str>,
}

impl DnsHandler {
    pub(super) fn new(
        rule_engine: Arc<RuleEngine>,
        dynamic: Arc<DynamicRuleManager>,
        require_managed_peer: bool,
        resolver: TokioResolver,
        cache: Arc<Mutex<DnsCache>>,
        counters: Arc<DnsCounters>,
        policy_barrier: Arc<RwLock<()>>,
    ) -> Self {
        Self {
            rule_engine,
            dynamic,
            require_managed_peer,
            resolver,
            cache,
            counters,
            policy_barrier,
        }
    }

    async fn enforce_and_send<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        records: Vec<Record>,
        context: AnswerContext<'_>,
    ) -> ResponseInfo {
        let allow_private_ips = context
            .egress
            .is_some_and(|egress| egress.allow_private_ips);
        let records = match apply_address_policy(context.hostname, records, allow_private_ips) {
            AddressPolicyOutcome::Allowed(records) => records,
            AddressPolicyOutcome::RestrictedOnly => {
                self.counters
                    .queries_blocked
                    .fetch_add(1, Ordering::Relaxed);
                info!(
                    src = %context.source,
                    hostname = %context.hostname,
                    decision = "block",
                    rule = "restricted-address-filter",
                    from_cache = context.from_cache,
                    "DNS answer contained no permitted addresses; returning SERVFAIL"
                );
                return response::send_servfail(request, response_handle).await;
            }
        };

        self.counters
            .queries_allowed
            .fetch_add(1, Ordering::Relaxed);
        info!(
            src = %context.source,
            hostname = %context.hostname,
            record_type = %context.record_type,
            decision = "allow",
            rule = context.rule_id,
            from_cache = context.from_cache,
            upstream_ms = context.upstream_ms,
            "DNS query allowed"
        );
        self.apply_egress_policy(
            context.source,
            context.hostname,
            context.egress,
            &records,
            context.container_name,
        )
        .await;
        response::send_answer(request, &records, response_handle).await
    }

    async fn apply_egress_policy(
        &self,
        source: SocketAddr,
        hostname: &str,
        egress: Option<&EgressSpec>,
        records: &[Record],
        container_name: Option<&str>,
    ) {
        let Some(egress) = egress else {
            return;
        };

        match egress.mode {
            EgressMode::Proxy => {
                debug!(%hostname, "proxy egress needs no direct nft allow rule");
            }
            EgressMode::Intercept => {
                debug!(%hostname, "intercept egress needs no direct nft allow rule");
            }
            EgressMode::DirectIp => {
                self.apply_direct_ip_policy(source, hostname, egress, records, container_name)
                    .await;
            }
        }
    }

    async fn apply_direct_ip_policy(
        &self,
        source: SocketAddr,
        hostname: &str,
        egress: &EgressSpec,
        records: &[Record],
        container_name: Option<&str>,
    ) {
        let source_ip = source.ip().to_string();
        let Some(container) = container_name else {
            warn!(%hostname, src = %source_ip, "direct_ip egress denied for unmanaged source IP");
            return;
        };
        let ports = if egress.ports.is_empty() {
            vec![80, 443]
        } else {
            egress.ports.clone()
        };
        let Some(expires_in_secs) = direct_rule_ttl(records) else {
            debug!(%hostname, "direct_ip egress requested with no positive answer TTL");
            return;
        };
        let (destinations, ignored_count) = matching_direct_destinations(source.ip(), records);
        if destinations.is_empty() && ignored_count == 0 {
            debug!(%hostname, "direct_ip egress requested without A or AAAA answers");
            return;
        }
        if ignored_count > 0 {
            debug!(
                %hostname,
                ignored_count,
                source_family = if source.ip().is_ipv4() { "IPv4" } else { "IPv6" },
                "ignored direct_ip destinations from a different address family"
            );
        }

        for destination in destinations {
            self.insert_direct_rules(
                hostname,
                container,
                &source_ip,
                &destination,
                &ports,
                expires_in_secs,
            )
            .await;
        }
    }

    async fn insert_direct_rules(
        &self,
        hostname: &str,
        container: &str,
        source_ip: &str,
        destination: &str,
        ports: &[u16],
        expires_in_secs: u64,
    ) {
        let address_family = if destination.contains(':') {
            "IPv6"
        } else {
            "IPv4"
        };
        for port in ports {
            let request = AllowRuleRequest {
                container: container.to_string(),
                src_ip: source_ip.to_string(),
                destination: destination.to_string(),
                protocol: Some("tcp".to_string()),
                port: Some(*port),
                expires_in_secs: Some(expires_in_secs),
            };
            if let Err(error) = self.dynamic.insert_managed_rule(request).await {
                warn!(
                    %hostname,
                    src = %source_ip,
                    dst = %destination,
                    port = *port,
                    family = address_family,
                    "failed to insert direct_ip allow rule: {error}"
                );
            }
        }
    }
}

fn direct_rule_ttl(records: &[Record]) -> Option<u64> {
    records
        .iter()
        .map(|record| record.ttl)
        .min()
        .map(|ttl| ttl.min(MAX_TTL_SECS))
        .filter(|ttl| *ttl > 0)
        .map(u64::from)
}

fn matching_direct_destinations(source: IpAddr, records: &[Record]) -> (Vec<String>, usize) {
    let ipv4 = extract_ipv4_destinations(records);
    let ipv6 = extract_ipv6_destinations(records);
    if source.is_ipv4() {
        (ipv4, ipv6.len())
    } else {
        (ipv6, ipv4.len())
    }
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
            Err(error) => {
                warn!(%error, "invalid DNS request");
                let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
                metadata.response_code = ResponseCode::ServFail;
                return ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                });
            }
        };

        let query = request_info.query;
        let hostname = query
            .name()
            .to_string()
            .trim_end_matches('.')
            .to_lowercase();
        let record_type = query.query_type();
        let record_type_name = format!("{record_type:?}").to_ascii_uppercase();
        let source = request_info.src;
        let source_ip = source.ip().to_string();
        self.counters.queries_total.fetch_add(1, Ordering::Relaxed);

        let container_name = match self.dynamic.container_name_for_ip(&source_ip).await {
            Ok(Some(name)) => Some(name),
            Ok(None) | Err(_) if !self.require_managed_peer => None,
            Ok(None) => {
                self.counters
                    .queries_blocked
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%source, "DNS query rejected from unmanaged peer");
                return response::send_refused(request, response_handle).await;
            }
            Err(error) => {
                self.counters
                    .queries_blocked
                    .fetch_add(1, Ordering::Relaxed);
                warn!(%source, %error, "DNS peer identity lookup failed; rejecting query");
                return response::send_refused(request, response_handle).await;
            }
        };

        if hostname.ends_with(".local") {
            debug!(%hostname, "mDNS query returns NXDOMAIN without rule evaluation");
            return response::send_nxdomain(request, response_handle).await;
        }

        // Hold a read lease through evaluation, resolution, and any derived
        // direct-IP insertion. Reload takes the write lease, so an old-policy
        // request cannot recreate a grant after revocation cleanup.
        let _policy_lease = self.policy_barrier.read().await;

        let context = EvalContext {
            dns: Some(DnsContext {
                query: hostname.clone(),
                record_type: record_type_name.clone(),
            }),
            agent: container_name
                .as_deref()
                .map(derive_agent_name)
                .map(|name| AgentContext { name }),
            ..Default::default()
        };

        let evaluation_started = Instant::now();
        let evaluated = self.rule_engine.evaluate_with_egress(&context).await;
        let evaluation = evaluated.result;
        let evaluation_ms = evaluation_started.elapsed().as_millis();
        if evaluation_ms > 10 {
            warn!(elapsed_ms = evaluation_ms, %hostname, "DNS rule evaluation exceeded 10ms budget");
        }
        let rule_id = evaluation
            .matched_rule
            .as_deref()
            .unwrap_or("default-block");
        let matched_egress = evaluated.egress;

        if evaluation.decision == Decision::Block {
            self.counters
                .queries_blocked
                .fetch_add(1, Ordering::Relaxed);
            info!(
                %source,
                %hostname,
                record_type = %record_type_name,
                decision = "block",
                rule = rule_id,
                from_cache = false,
                "DNS query blocked"
            );
            return response::send_nxdomain(request, response_handle).await;
        }

        if let Some(records) = self.cache.lock().await.get(&hostname, record_type) {
            self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
            return self
                .enforce_and_send(
                    request,
                    response_handle,
                    records,
                    AnswerContext {
                        source,
                        hostname: &hostname,
                        record_type: &record_type_name,
                        rule_id,
                        egress: matched_egress.as_ref(),
                        from_cache: true,
                        upstream_ms: 0,
                        container_name: container_name.as_deref(),
                    },
                )
                .await;
        }

        self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        let upstream_started = Instant::now();
        match self.resolver.lookup(hostname.as_str(), record_type).await {
            Ok(lookup) => {
                let upstream_ms = upstream_started.elapsed().as_millis();
                let records = lookup.answers().to_vec();
                let evicted = self.cache.lock().await.insert(
                    hostname.clone(),
                    record_type,
                    record_type_name.clone(),
                    records.clone(),
                );
                if evicted {
                    self.counters
                        .cache_evictions
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.enforce_and_send(
                    request,
                    response_handle,
                    records,
                    AnswerContext {
                        source,
                        hostname: &hostname,
                        record_type: &record_type_name,
                        rule_id,
                        egress: matched_egress.as_ref(),
                        from_cache: false,
                        upstream_ms,
                        container_name: container_name.as_deref(),
                    },
                )
                .await
            }
            Err(error) => {
                warn!(%hostname, %error, "upstream DNS resolution failed; returning SERVFAIL");
                response::send_servfail(request, response_handle).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData};

    use super::*;

    fn record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
        )
    }

    fn ipv6_record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        )
    }

    #[test]
    fn direct_rule_ttl_uses_minimum_cache_capped_ttl() {
        assert_eq!(direct_rule_ttl(&[record(600), record(120)]), Some(120));
        assert_eq!(direct_rule_ttl(&[record(600)]), Some(300));
    }

    #[test]
    fn direct_rule_ttl_rejects_empty_or_zero_ttl_answers() {
        assert_eq!(direct_rule_ttl(&[]), None);
        assert_eq!(direct_rule_ttl(&[record(60), record(0)]), None);
    }

    #[test]
    fn direct_destinations_must_match_the_source_address_family() {
        let records = [record(60), ipv6_record(60)];

        let (ipv4, ignored) = matching_direct_destinations(Ipv4Addr::LOCALHOST.into(), &records);
        assert_eq!(ipv4, ["203.0.113.10"]);
        assert_eq!(ignored, 1);

        let (ipv6, ignored) = matching_direct_destinations(Ipv6Addr::LOCALHOST.into(), &records);
        assert_eq!(ipv6, ["::1"]);
        assert_eq!(ignored, 1);
    }
}
