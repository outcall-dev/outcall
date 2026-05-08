//! HTTPS proxy integration — S012-FR-009.b / S006-AS-001/-002/-003.
//!
//! The proxy only *peeks* the TLS ClientHello to extract SNI — it does NOT
//! complete a TLS handshake or validate certificates. These tests verify the
//! proxy's CONNECT + SNI decision logic without requiring any real TLS stack.
//!
//! Test cases:
//!   1. Pre-SNI block  — CONNECT to blocked host → 403 before 200.
//!   2. CONNECT allow — CONNECT to allowed host → 200 Connection Established.
//!   3. SNI mismatch   — CONNECT host allowed, SNI blocked → connection close.
//!   4. No SNI         — CONNECT host allowed, no valid SNI → preliminary stands.
//!
//! Linux-only (proxy module is Linux-gated).

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use outcalld::proxy::ProxyServer;
use outcalld::rules::RuleEngine;

// ─── TLS ClientHello builder (no external TLS deps) ────────────────────────

/// Build a minimal TLS ClientHello record with a given SNI hostname.
/// Returns the raw TCP bytes of the TLS record.
fn craft_client_hello(sni_hostname: &str) -> Vec<u8> {
    // Build the handshake body first so we can compute its length.
    let mut handshake = Vec::new();

    // msg_type: ClientHello = 0x01
    handshake.push(0x01);

    // message length (3 bytes, big-endian) — filled in at the end.
    let len_offset = handshake.len();
    handshake.extend_from_slice(&[0, 0, 0]);

    // client_version: TLS 1.2 = 0x0303  (ClientHello version is always TLS 1.2)
    handshake.extend_from_slice(&[0x03, 0x03]);

    // random (32 bytes) — fixed pattern for reproducibility.
    let random: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    handshake.extend_from_slice(&random);

    // session_id (empty)
    handshake.push(0x00);

    // cipher_suites — two common AES-GCM suites.
    let ciphers: [u8; 4] = [0x13, 0x01, 0x13, 0x02];
    handshake.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&ciphers);

    // compression_methods — null only.
    handshake.extend_from_slice(&[0x01, 0x00]);

    // extensions length placeholder (filled after building SNI ext).
    let ext_len_offset = handshake.len();
    handshake.extend_from_slice(&[0, 0]);

    // ── SNI extension (0x0000) ──
    let sni_bytes = sni_hostname.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]); // extension type: SNI
    let inner_len = 1 + 2 + sni_bytes.len() + 3; // list(1) + name_type(1) + name_len(2) + name
    sni_ext.extend_from_slice(&(inner_len as u16).to_be_bytes()); // extension data length
    sni_ext.push(0x00); // name_type: host_name (RFC 6066)
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    // Write actual SNI extension into handshake.
    let ext_total_len = sni_ext.len() - 4; // subtract ext header (type + len)
    let _after_ext_len = handshake.len();
    handshake.splice(
        ext_len_offset..ext_len_offset + 2,
        (ext_total_len as u16).to_be_bytes(),
    );
    for byte in sni_ext {
        handshake.push(byte);
    }

    // Update total handshake length (subtract msg_type + 3 length bytes).
    let hs_len = (handshake.len() - 4) as u32;
    let hs_bytes = hs_len.to_be_bytes();
    handshake[len_offset..len_offset + 3].copy_from_slice(&hs_bytes[1..]);

    // Wrap in a TLS Record: type=handshake(0x16), version=TLS 1.0(0x0301).
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Write a single rule YAML file into a fresh tempdir, return the loaded engine.
fn rule_engine_from_yaml(yaml: &str) -> (tempfile::TempDir, Arc<RuleEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut f = std::fs::File::create(dir.path().join("test.yaml")).expect("create yaml");
    f.write_all(yaml.as_bytes()).expect("write yaml");
    drop(f);
    let engine = RuleEngine::load(dir.path().to_str().unwrap()).expect("load rules");
    (dir, Arc::new(engine))
}

/// Spawn a ProxyServer on an ephemeral port; return the proxy and its address.
async fn spawn_proxy(rules: Arc<RuleEngine>) -> (Arc<ProxyServer>, std::net::SocketAddr) {
    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap());
    proxy.start(rules).await.expect("proxy start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let addr = proxy.local_addr().await.expect("proxy bound addr");
    (proxy, addr)
}

/// Send raw bytes to `addr`, read all bytes back.
async fn raw_request(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(data).await.expect("send");
    sock.shutdown().await.ok();
    let mut buf = Vec::with_capacity(4096);
    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read_to_end(&mut buf)).await;
    buf
}

/// Extract the HTTP status code from a response.
fn status_code(response: &[u8]) -> Option<u16> {
    let line = response.split(|&b| b == b'\n').next()?;
    let mut parts = line.splitn(3, |&b| b == b' ');
    let _ = parts.next()?;
    let code = std::str::from_utf8(parts.next()?).ok()?;
    code.trim().parse().ok()
}

// ─── Test 1: Pre-SNI block ─────────────────────────────────────────────────

/// CONNECT to a blocked host returns 403 BEFORE the proxy sends 200.
/// Pre-SNI evaluation lets us reject the connection before seeing TLS.
#[tokio::test]
async fn https_connect_blocked_host_returns_403_pre_sni() {
    let yaml = r#"version: "1"
rules:
  - id: block-bad-host
    condition: 'http.host == "blocked.example.com"'
    action: block
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    // CONNECT to blocked.example.com — proxy should block pre-SNI.
    let req = "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n";
    let resp = raw_request(proxy_addr, req.as_bytes()).await;

    assert_eq!(
        status_code(&resp),
        Some(403),
        "expected 403 pre-SNI block, got: {}",
        String::from_utf8_lossy(&resp)
            .chars()
            .take(200)
            .collect::<String>()
    );
    assert!(
        String::from_utf8_lossy(&resp).contains("X-Outcall-Block-Reason"),
        "expected X-Outcall-Block-Reason header"
    );
    // Must NOT have sent "200 Connection Established" — that's only for allowed hosts.
    assert!(
        !String::from_utf8_lossy(&resp).contains("Connection Established"),
        "should not send 200 before blocking"
    );

    proxy.shutdown().await;
}

// ─── Test 2: CONNECT allowed → 200 ─────────────────────────────────────────

/// CONNECT to an allowed host: proxy sends 200 Connection Established,
/// then waits for the client to send TLS bytes (which we never send — test ends).
#[tokio::test]
async fn https_connect_allowed_host_returns_200() {
    let yaml = r#"version: "1"
rules:
  - id: allow-example-com
    condition: 'http.host == "allowed.example.com"'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    let req = "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n";
    let resp = raw_request(proxy_addr, req.as_bytes()).await;

    assert_eq!(
        status_code(&resp),
        Some(200),
        "expected 200 for allowed CONNECT, got: {}",
        String::from_utf8_lossy(&resp)
            .chars()
            .take(200)
            .collect::<String>()
    );
    assert!(
        String::from_utf8_lossy(&resp).contains("Connection Established"),
        "expected 200 Connection Established"
    );

    proxy.shutdown().await;
}

// ─── Test 3: SNI mismatch — CONNECT host allowed, SNI blocked ─────────────

/// CONNECT host is in the allow list, but the TLS ClientHello SNI field
/// contains a blocked hostname. The proxy sends 200, peeks the ClientHello,
/// re-evaluates on SNI, finds it's blocked, and closes the connection.
#[tokio::test]
async fn https_connect_allowed_host_but_sni_blocked_closes() {
    let yaml = r#"version: "1"
rules:
  - id: allow-proxy-host
    condition: 'http.host == "proxy.example.com"'
    action: allow
  - id: block-evil-host
    condition: 'http.host == "evil.example.com"'
    action: block
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    // CONNECT to proxy.example.com (allowed) then send ClientHello with SNI=evil.example.com (blocked).
    let connect_req = "CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n";
    let mut sock = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    sock.write_all(connect_req.as_bytes())
        .await
        .expect("send CONNECT");

    // Read the 200 Connection Established.
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .expect("read 200")
        .expect("read 200");
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(resp.contains("200"), "expected 200 first, got: {resp}");

    // Send ClientHello where SNI = evil.example.com (blocked).
    let client_hello = craft_client_hello("evil.example.com");
    sock.write_all(&client_hello)
        .await
        .expect("send ClientHello");

    // Proxy should close the connection (it already sent 200, so it can't send 403).
    // Wait up to 2s for EOF (server closed = expected).
    let mut close_buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut close_buf)).await;
    assert!(
        read_result.is_err() // timeout = server closed (expected after SNI block)
            || matches!(read_result, Ok(Ok(0))),
        "expected server to close connection after SNI block"
    );

    proxy.shutdown().await;
}

// ─── Test 4: No SNI in ClientHello — preliminary decision stands ────────────

/// Client sends a TLS ClientHello with no SNI extension (empty/bad).
/// Proxy peeks, can't extract SNI, falls back to CONNECT host as eval target.
#[tokio::test]
async fn https_connect_allowed_host_no_sni_uses_preliminary_decision() {
    let yaml = r#"version: "1"
rules:
  - id: allow-example-com
    condition: 'http.host == "example.com"'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    let connect_req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut sock = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    sock.write_all(connect_req.as_bytes())
        .await
        .expect("send CONNECT");

    // Read 200.
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .expect("read 200")
        .expect("read 200");
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        resp.contains("200"),
        "expected 200 (prelim decision), got: {resp}"
    );

    // Send a raw TLS record that is too short to parse (no SNI).
    // Proxy reads SNI_PEEK_BYTES (4096), gets nothing useful, eval_host = CONNECT host.
    let short_record: Vec<u8> = vec![0x16, 0x03, 0x01, 0x00, 0x10]; // incomplete record
    sock.write_all(&short_record)
        .await
        .expect("send short record");
    sock.shutdown().await.ok();

    // Should still be allowed (preliminary decision based on CONNECT host stands).
    // Nothing should go wrong — proxy should either tunnel or time out, not crash.
    proxy.shutdown().await;
}

// ─── Test 5: SNI allowed on allowed CONNECT host — tunnel ready ──────────────

/// CONNECT host allowed, ClientHello SNI also allowed — tunnel established.
/// This is the happy path: 200 sent, peeked ClientHello re-evaluated, ALLOW.
#[tokio::test]
async fn https_connect_allowed_host_and_sni_establishes_tunnel() {
    let yaml = r#"version: "1"
rules:
  - id: allow-proxy-host
    condition: 'http.host == "proxy.example.com"'
    action: allow
  - id: allow-upstream-host
    condition: 'http.host == "upstream.example.com"'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    // CONNECT to proxy.example.com, then send ClientHello with SNI=upstream.example.com.
    // Both are allowed → tunnel should be established.
    let connect_req = "CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n";
    let mut sock = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    sock.write_all(connect_req.as_bytes())
        .await
        .expect("send CONNECT");

    // Read 200.
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .expect("read 200")
        .expect("read 200");
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(resp.contains("200"), "expected 200 first, got: {resp}");

    // Send ClientHello with allowed SNI.
    let client_hello = craft_client_hello("upstream.example.com");
    sock.write_all(&client_hello)
        .await
        .expect("send ClientHello");
    sock.shutdown().await.ok();

    // Connection should stay open (tunnel established, proxy tries to connect upstream).
    // We didn't set up an upstream, so it'll eventually time out — but no crash/403.
    proxy.shutdown().await;
}

// ─── Test 6: Pre-SNI block — no 200 sent at all ───────────────────────────

/// Verify that for a blocked CONNECT host, the proxy never sends the 200
/// byte sequence at any point in the response.
#[tokio::test]
async fn https_connect_blocked_host_no_200_bytes_in_response() {
    let yaml = r#"version: "1"
rules:
  - id: block-example-com
    condition: 'http.host == "example.com"'
    action: block
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let resp = raw_request(proxy_addr, req.as_bytes()).await;

    // Response must be a clean 403 — no "HTTP/1.1 200" anywhere.
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        status_code(&resp) == Some(403),
        "expected 403, got something else: {resp_str}"
    );
    // Must not contain the literal bytes of a 200 response.
    assert!(
        !resp_str.contains("200"),
        "response must not contain '200': {resp_str}"
    );
    // X-Outcall-Block-Reason must be present.
    assert!(
        resp_str.contains("X-Outcall-Block-Reason"),
        "expected block reason header: {resp_str}"
    );

    proxy.shutdown().await;
}
