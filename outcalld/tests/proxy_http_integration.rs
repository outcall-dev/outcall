//! End-to-end test for the HTTP proxy on plaintext HTTP — S012-FR-009.a / S006-AS-001/-002.
//!
//! Flow per test:
//!   1. Spin up a 127.0.0.1 upstream HTTP server on an OS-assigned port.
//!   2. Load a RuleEngine from a tempdir containing one allow/block rule.
//!   3. Spin up a ProxyServer on a separate OS-assigned port.
//!   4. Open a raw TcpStream to the proxy, send an absolute-URI GET request
//!      pointing at the upstream, read the response.
//!   5. Assert on status line + reason header.
//!
//! No reqwest/hyper involvement — everything is raw bytes so the test
//! exercises the proxy's parsing path explicitly.
//!
//! Linux-only because the proxy module is gated to Linux.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use outcalld::proxy::ProxyServer;
use outcalld::rules::RuleEngine;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Spawn a trivial HTTP server that replies "200 OK\r\n…\r\nhello-upstream"
/// to every request. Returns its bound address. Stops when the test ends —
/// the listener future is dropped along with the JoinHandle.
async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Read the request line + headers; we don't bother parsing.
                let _ = sock.read(&mut buf).await;
                let body = b"hello-upstream";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    addr
}

/// Write a single rule YAML file into a fresh tempdir, return the loaded engine.
fn rule_engine_from_yaml(yaml: &str) -> (tempfile::TempDir, Arc<RuleEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut f = std::fs::File::create(dir.path().join("test.yaml")).expect("create yaml");
    f.write_all(yaml.as_bytes()).expect("write yaml");
    drop(f);
    let engine = RuleEngine::load(dir.path().to_str().unwrap(), false).expect("load rules");
    (dir, Arc::new(engine))
}

/// Spawn a ProxyServer on an ephemeral port; return the proxy and its address.
async fn spawn_proxy(rules: Arc<RuleEngine>) -> (Arc<ProxyServer>, std::net::SocketAddr) {
    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap(), None);
    proxy.start(rules).await.expect("proxy start");
    // Give the accept loop a tick to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let addr = proxy.local_addr().await.expect("proxy bound addr");
    (proxy, addr)
}

/// Send `request` to `addr`, read all bytes back (until EOF or 1s timeout).
async fn request(addr: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(request).await.expect("send");
    sock.shutdown().await.ok();

    let mut buf = Vec::with_capacity(4096);
    let read = tokio::time::timeout(Duration::from_secs(1), sock.read_to_end(&mut buf)).await;
    let _ = read; // we accept partial reads; test asserts only on the prefix.
    buf
}

fn status_code(response: &[u8]) -> Option<u16> {
    // Status line: "HTTP/1.x SSS reason\r\n…"
    let line = response.split(|&b| b == b'\n').next()?;
    let mut parts = line.splitn(3, |&b| b == b' ');
    let _ = parts.next()?; // version
    let code = std::str::from_utf8(parts.next()?).ok()?;
    code.trim().parse().ok()
}

fn header_value<'a>(response: &'a [u8], name: &str) -> Option<&'a str> {
    let needle = format!("{name}: ");
    let body = std::str::from_utf8(response).ok()?;
    let line = body.lines().find(|l| l.starts_with(&needle))?;
    Some(line[needle.len()..].trim_end())
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_request_to_allowed_host_is_forwarded() {
    let upstream = spawn_upstream().await;

    // Allow anything to 127.0.0.1 — covers both http.host and dns.query.
    let yaml = format!(
        r#"version: "1"
rules:
  - id: allow-loopback
    condition: 'http.host == "127.0.0.1" || http.host.startsWith("127.0.0.1")'
    action: allow
"#,
    );
    let (_keep_dir, rules) = rule_engine_from_yaml(&yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    let req = format!(
        "GET http://{}/hello HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        upstream, upstream
    );
    let resp = request(proxy_addr, req.as_bytes()).await;

    assert_eq!(
        status_code(&resp),
        Some(200),
        "expected 200 from upstream, got: {}",
        String::from_utf8_lossy(&resp)
            .chars()
            .take(200)
            .collect::<String>()
    );
    assert!(
        resp.windows(b"hello-upstream".len())
            .any(|w| w == b"hello-upstream"),
        "expected upstream body in response"
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn http_request_to_blocked_host_returns_403() {
    let upstream = spawn_upstream().await;

    // No allow rule that matches → default-block hits.
    let yaml = r#"version: "1"
rules:
  - id: allow-only-example-com
    condition: 'http.host == "example.com"'
    action: allow
"#;
    let (_keep_dir, rules) = rule_engine_from_yaml(yaml);
    let (proxy, proxy_addr) = spawn_proxy(rules).await;

    let req = format!(
        "GET http://{}/hello HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        upstream, upstream
    );
    let resp = request(proxy_addr, req.as_bytes()).await;

    assert_eq!(
        status_code(&resp),
        Some(403),
        "expected 403 (blocked), got: {}",
        String::from_utf8_lossy(&resp)
            .chars()
            .take(200)
            .collect::<String>()
    );
    assert!(
        header_value(&resp, "X-Outcall-Block-Reason").is_some(),
        "expected X-Outcall-Block-Reason header in 403 response"
    );

    proxy.shutdown().await;
}
