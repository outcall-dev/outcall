use std::collections::HashMap;

use super::context::http_context;
use super::upstream::{resolve_upstream, UpstreamError};
use tokio::io::AsyncReadExt;

use super::*;

fn rule_engine(yaml: Option<&str>) -> (tempfile::TempDir, Arc<RuleEngine>) {
    let directory = tempfile::tempdir().unwrap();
    if let Some(yaml) = yaml {
        std::fs::write(directory.path().join("proxy-test.yaml"), yaml).unwrap();
    }
    let engine = RuleEngine::load(directory.path().to_str().unwrap()).unwrap();
    (directory, Arc::new(engine))
}

async fn start_test_proxy(rules: Arc<RuleEngine>) -> (Arc<ProxyServer>, SocketAddr) {
    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap(), None);
    proxy.start(rules).await.unwrap();
    let address = proxy.local_addr().await.unwrap();
    (proxy, address)
}

async fn send_proxy_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
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
fn http_context_without_agent_leaves_agent_unset() {
    let ctx = http_context("GET", "example.com", "/", &HashMap::new(), 443, 12, None);
    assert!(
        ctx.agent.is_none(),
        "agent should be unset when name is None"
    );
    assert!(ctx.http.is_some());
    assert_eq!(ctx.http.as_ref().unwrap().method, "GET");
    assert_eq!(ctx.http.as_ref().unwrap().host, "example.com");
    assert_eq!(ctx.http.as_ref().unwrap().body_size, 12);
}

#[test]
fn http_context_with_agent_populates_name() {
    let ctx = http_context(
        "POST",
        "api.example.com",
        "/v1",
        &HashMap::new(),
        443,
        0,
        Some("ci"),
    );
    let agent = ctx.agent.expect("agent should be set");
    assert_eq!(agent.name, "ci");
    assert_eq!(ctx.http.as_ref().unwrap().method, "POST");
}

#[test]
fn http_context_uppercases_method() {
    let ctx = http_context("get", "x.example", "/", &HashMap::new(), 443, 0, None);
    assert_eq!(ctx.http.unwrap().method, "GET");
}

#[tokio::test]
async fn resolve_agent_name_returns_none_when_docker_absent() {
    let docker: Option<Arc<DockerManager>> = None;
    let peer: SocketAddr = "10.200.0.5:54321".parse().unwrap();
    assert_eq!(resolve_agent_name(&docker, peer).await.unwrap(), None);
}

#[tokio::test]
async fn resolve_agent_name_fails_closed_when_docker_is_unavailable() {
    let docker = Some(Arc::new(DockerManager::new_unavailable()));
    let peer: SocketAddr = "10.200.0.5:54321".parse().unwrap();
    assert!(resolve_agent_name(&docker, peer).await.is_err());
}

#[tokio::test]
async fn startup_is_single_instance_and_shutdown_waits_for_listener_exit() {
    let (_directory, rules) = rule_engine(None);
    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap(), None);

    proxy.start(rules.clone()).await.unwrap();
    assert!(proxy.is_running());
    assert!(proxy.start(rules).await.is_err());

    proxy.shutdown().await;
    assert!(!proxy.is_running());
    proxy.shutdown().await;
}

#[tokio::test]
async fn rejects_ambiguous_or_pipelined_plain_http_before_connecting_upstream() {
    let (_directory, rules) = rule_engine(None);
    let (proxy, address) = start_test_proxy(rules).await;

    let pipelined = b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 0\r\n\r\nGET http://example.com/ HTTP/1.1\r\n\r\n";
    let response = send_proxy_request(address, pipelined).await;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

    let chunked = b"POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nTransfer-Encoding: chunked\r\n\r\n";
    let response = send_proxy_request(address, chunked).await;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

    proxy.shutdown().await;
}

#[tokio::test]
async fn rejects_oversized_declared_http_body_with_413() {
    let (_directory, rules) = rule_engine(None);
    let (proxy, address) = start_test_proxy(rules).await;
    let request = b"POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 16777217\r\n\r\n";

    let response = send_proxy_request(address, request).await;

    assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large\r\n"));
    proxy.shutdown().await;
}

#[tokio::test]
async fn local_health_endpoint_is_not_forwarded() {
    let (_directory, rules) = rule_engine(None);
    let (proxy, address) = start_test_proxy(rules).await;

    let response = send_proxy_request(
        address,
        b"GET /outcall-health HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
    )
    .await;

    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"\r\n\r\n{\"status\":\"ok\"}"));
    proxy.shutdown().await;
}

#[tokio::test]
async fn forwards_exact_body_and_exposes_declared_size_to_policy() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert!(request.ends_with(b"\r\n\r\ndata"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let yaml = r#"version: "1"
rules:
  - id: allow-four-byte-local-post
    condition: 'http.host == "127.0.0.1" && http.method == "POST" && http.body_size == 4'
    action: allow
    egress:
      mode: proxy
      allow_private_ips: true
"#;
    let (_directory, rules) = rule_engine(Some(yaml));
    let (proxy, address) = start_test_proxy(rules).await;
    let request = format!(
        "POST http://{upstream_address}/ HTTP/1.1\r\nHost: {upstream_address}\r\nContent-Length: 4\r\n\r\ndata"
    );

    let response = send_proxy_request(address, request.as_bytes()).await;

    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"\r\n\r\nok"));
    upstream_task.await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn restricted_upstream_addresses_require_explicit_opt_in() {
    assert!(matches!(
        resolve_upstream("127.0.0.1", 443, false).await,
        Err(UpstreamError::RestrictedAddress)
    ));
    assert_eq!(
        resolve_upstream("127.0.0.1", 443, true).await.unwrap(),
        vec!["127.0.0.1:443".parse().unwrap()]
    );
}
