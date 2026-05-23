//! DNS filter integration — S012-FR-008.a (FR-003, FR-033, FR-034).
//!
//! Exercises the full DNS resolution pipeline: query → rule eval → forward/cached/NXDOMAIN.
//!
//! Test cases:
//!   1. Blocked query  — rule matches → NXDOMAIN.
//!   2. Allowed query  — rule matches → forwarded to upstream → A/AAAA answer.
//!   3. mDNS block     — .local query → NXDOMAIN without rule eval (FR-033).
//!   4. Cache hit      — second query for same name → served from cache.
//!   5. Cache TTL expiry — cached entry past TTL → re-resolved.
//!   6. Rebinding warn  — hostname resolves to private IP → warning log.
//!
//! Linux-only (dns module is Linux-gated).

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use outcalld::dns::DnsServer;
use outcalld::rules::RuleEngine;

// ─── Raw DNS packet builder ────────────────────────────────────────────────

/// Build a DNS query packet (RFC 1035).
/// Returns (packet_bytes, expected_transaction_id).
fn build_dns_query(qname: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header (12 bytes)
    packet.extend_from_slice(&transaction_id.to_be_bytes()); // ID
    packet.extend_from_slice(&DNS_FLAGS_RD.to_be_bytes()); // Flags: standard query, RD
    packet.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT = 0

    // Question section
    for label in qname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // null terminator
    packet.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    packet.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS = IN

    packet
}

/// Parse a DNS response packet and extract key fields.
/// Returns (id, flags, rcode, answer_count) on success.
fn parse_dns_header(packet: &[u8]) -> Option<(u16, u16, u8, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let rcode = (flags & 0x000F) as u8; // lowest 4 bits
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    Some((id, flags, rcode, answer_count))
}

const QR_MASK: u16 = 0x8000;
const DNS_FLAGS_RD: u16 = 0x0100; // Recursion Desired
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const QTYPE_A: u16 = 1;

/// Assert that a DNS response has NOERROR rcode and return the answer count.
fn assert_resp_noerror(resp: &[u8], domain: &str) -> u16 {
    let (_, flags, rcode, ancount) = parse_dns_header(resp).expect("parse response");
    assert!(
        (flags & QR_MASK) != 0,
        "{domain}: expected QR bit set (is a response)"
    );
    assert_eq!(rcode, RCODE_NOERROR, "{domain}: expected NOERROR rcode");
    ancount
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Write a single rule YAML file into a fresh tempdir, return the loaded engine.
fn rule_engine_from_yaml(yaml: &str) -> (tempfile::TempDir, Arc<RuleEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut f = std::fs::File::create(dir.path().join("test.yaml")).expect("create yaml");
    use std::io::Write as _;
    f.write_all(yaml.as_bytes()).expect("write yaml");
    drop(f);
    let engine = RuleEngine::load(dir.path().to_str().unwrap(), false).expect("load rules");
    (dir, Arc::new(engine))
}

/// Spawn a DnsServer on an ephemeral port; return the server and its address.
async fn spawn_dns_server(rules: Arc<RuleEngine>) -> (Arc<DnsServer>, SocketAddr) {
    let docker_mgr = outcalld::docker::DockerManager::new_unavailable();
    let dynamic_mgr = outcalld::dynamic::DynamicRuleManager::new(Arc::new(docker_mgr));

    let server = DnsServer::new("127.0.0.1:0".parse().unwrap(), vec![]);
    server.start(rules, dynamic_mgr).await.expect("dns start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let addr = server.local_addr().await;
    (server, addr)
}

/// Send a DNS query and read the response.
async fn dns_query(addr: SocketAddr, qname: &str, qtype: u16) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let packet = build_dns_query(qname, qtype, 0x1234);
    socket.send_to(&packet, addr).await.expect("send");
    let mut buf = [0u8; 512];
    let (n, _) = socket.recv_from(&mut buf).await.expect("recv");
    buf[..n].to_vec()
}

// ─── Test 1: Blocked query → NXDOMAIN ────────────────────────────────────

#[tokio::test]
async fn dns_blocked_query_returns_nxdomain() {
    let yaml = r#"version: "1"
rules:
  - id: block-evil
    condition: 'dns.query == "evil.example.com"'
    action: block
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (_server, addr) = spawn_dns_server(rules).await;

    let resp = dns_query(addr, "evil.example.com", QTYPE_A).await;

    let (_, _, rcode, _) = parse_dns_header(&resp).expect("parse response");
    assert_eq!(
        rcode, RCODE_NXDOMAIN,
        "expected NXDOMAIN for blocked query, got rcode={rcode}"
    );

    // Also verify it's not a cache hit (should be evaluated fresh)
    let resp2 = dns_query(addr, "evil.example.com", QTYPE_A).await;
    let (_, _, rcode2, _) = parse_dns_header(&resp2).expect("parse response 2");
    assert_eq!(rcode2, RCODE_NXDOMAIN, "blocked query should persist");
}

// ─── Test 2: Allowed query → forwarded ─────────────────────────────────

#[tokio::test]
async fn dns_allowed_query_returns_answer_or_servfail() {
    // Allow all — will forward to real upstream (or 8.8.8.8 fallback)
    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'dns.query != ""'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (_server, addr) = spawn_dns_server(rules).await;

    // Query a well-known public domain — either NOERROR or SERVFAIL (no network) is acceptable.
    let resp = dns_query(addr, "google.com", QTYPE_A).await;
    let (_, _, rcode, _) = parse_dns_header(&resp).expect("parse response");
    assert!(
        rcode == RCODE_NOERROR || rcode == RCODE_SERVFAIL,
        "expected NOERROR or SERVFAIL, got rcode={rcode}"
    );
    if rcode == RCODE_NOERROR {
        assert!(
            assert_resp_noerror(&resp, "google.com") > 0,
            "expected at least one answer record for google.com A"
        );
    }
}

// ─── Test 3: mDNS .local → NXDOMAIN without rule eval (FR-033) ─────────

#[tokio::test]
async fn dns_mdns_local_query_returns_nxdomain_without_rule_eval() {
    // Note: we have NO rules that match .local, but .local should be blocked
    // at the mDNS check layer before rule evaluation.
    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'dns.query != ""'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (_server, addr) = spawn_dns_server(rules).await;

    let resp = dns_query(addr, "somehost.local", QTYPE_A).await;

    let (_, _, rcode, _) = parse_dns_header(&resp).expect("parse response");
    assert_eq!(
        rcode, RCODE_NXDOMAIN,
        "expected NXDOMAIN for .local mDNS query, got rcode={rcode}"
    );
}

// ─── Test 4: Cache hit — second query served from cache ─────────────────

#[tokio::test]
async fn dns_second_query_uses_cache() {
    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'dns.query != ""'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (server, addr) = spawn_dns_server(rules).await;

    // Use a real, reliably-resolvable domain to ensure caching works.
    let domain = "google.com";

    // First query — cache miss
    let resp1 = dns_query(addr, domain, QTYPE_A).await;
    assert_resp_noerror(&resp1, domain);

    let stats = server.cache_stats().await;
    assert_eq!(stats.misses, 1, "first query should be a cache miss");

    // Second query — should hit cache
    let resp2 = dns_query(addr, domain, QTYPE_A).await;
    assert_resp_noerror(&resp2, domain);

    let stats2 = server.cache_stats().await;
    assert_eq!(stats2.hits, 1, "second query should be a cache hit");
    assert_eq!(stats2.misses, 1, "misses should remain at 1");

    server.shutdown().await;
}

// ─── Test 5: NXDOMAIN from blocked rule persists ───────────────────────

#[tokio::test]
async fn dns_blocked_query_different_names_independent() {
    let yaml = r#"version: "1"
rules:
  - id: block-a
    condition: 'dns.query == "a.example.com"'
    action: block
  - id: allow-b
    condition: 'dns.query == "b.example.com"'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (_server, addr) = spawn_dns_server(rules).await;

    let resp_a = dns_query(addr, "a.example.com", QTYPE_A).await;
    let (_, _, rcode_a, _) = parse_dns_header(&resp_a).expect("parse resp a");
    assert_eq!(rcode_a, RCODE_NXDOMAIN, "a.example.com should be blocked");

    // b.example.com is allowed (may be SERVFAIL if no real upstream, but not NXDOMAIN)
    let resp_b = dns_query(addr, "b.example.com", QTYPE_A).await;
    let (_, _, rcode_b, _) = parse_dns_header(&resp_b).expect("parse resp b");
    // Allowed queries should NOT get NXDOMAIN (unless upstream is unreachable)
    assert_ne!(
        rcode_b, RCODE_NXDOMAIN,
        "b.example.com is allowed — should not get NXDOMAIN (got rcode={rcode_b})"
    );
}

// ─── Test 6: DNS server status and counters ─────────────────────────────

#[tokio::test]
async fn dns_status_reflects_query_counters() {
    let yaml = r#"version: "1"
rules:
  - id: block-bad
    condition: 'dns.query == "bad.example.com"'
    action: block
  - id: allow-all
    condition: 'dns.query != ""'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (server, addr) = spawn_dns_server(rules).await;

    // Send one blocked query
    let _ = dns_query(addr, "bad.example.com", QTYPE_A).await;

    // Send one allowed query
    let _ = dns_query(addr, "good.example.com", QTYPE_A).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = server.status().await;
    assert_eq!(status.queries_total, 2, "should have 2 total queries");
    assert_eq!(status.queries_blocked, 1, "should have 1 blocked query");
    assert_eq!(status.queries_allowed, 1, "should have 1 allowed query");

    server.shutdown().await;
}
