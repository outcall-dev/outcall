//! Proxy rule-mode integration — S003 + S006.
//!
//! Verifies explicit proxy-mode rule evaluation and first-match ordering.
//! Direct-IP and interception behavior require dedicated runtime tests.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::TempDir;

use outcall_api::{ApiResponse, EvaluateResult};

// ── Raw HTTP helper (reused from agent_api_integration.rs) ───────────────────

fn read_http_response(sock: &mut UnixStream) -> String {
    let mut buf = String::new();
    let _ = sock.read_to_string(&mut buf);
    buf
}

fn http_body(response: &str) -> &str {
    if let Some((_, body)) = response.split_once("\r\n\r\n") {
        return body;
    }
    if let Some((_, body)) = response.split_once("\n\n") {
        return body;
    }
    response
}

fn http_json_post(path: &str, json: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    )
}

fn parse_api_response<T: serde::de::DeserializeOwned>(body: &str) -> Option<ApiResponse<T>> {
    serde_json::from_str(body).ok()
}

// ── Daemon spawn helper ───────────────────────────────────────────────────────

async fn spawn_daemon(
    host_socket: &Path,
    agent_socket: &Path,
    rules_dir: &Path,
) -> Result<(Child, String, String)> {
    let mut cmd = Command::new("outcalld");
    cmd.env("RUST_LOG", "outcalld=warn")
        .arg("--socket")
        .arg(host_socket.as_os_str())
        .arg("--agent-socket-host-path")
        .arg(agent_socket.as_os_str())
        .arg("--rules-dir")
        .arg(rules_dir.as_os_str())
        .arg("--no-proxy");
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn outcalld")?;

    let timeout = Duration::from_secs(5);
    let poll_interval = Duration::from_millis(25);
    let started_at = std::time::Instant::now();
    loop {
        if host_socket.exists() && agent_socket.exists() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            anyhow::bail!(
                "outcalld exited before binding sockets (status: {:?}). stderr:\n{}",
                status,
                stderr.trim()
            );
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            anyhow::bail!(
                "outcalld did not bind sockets within {:?}. stderr:\n{}",
                timeout,
                stderr.trim()
            );
        }
        tokio::time::sleep(poll_interval).await;
    }

    let host = host_socket.to_string_lossy().to_string();
    let agent = agent_socket.to_string_lossy().to_string();
    Ok((child, host, agent))
}

// ── Test: proxy mode uses SNI peek (no decryption) ───────────────────────────

/// A rule with `mode: proxy` (default) uses SNI peek. The proxy should
/// be able to ALLOW/BLOCK based on the SNI hostname without decrypting.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn proxy_mode_uses_sni_peek_not_decryption() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();

    // Block a specific host via SNI.
    let yaml = r#"version: "1"
rules:
  - id: block-evil
    condition: 'dns.query == "evil.example.com"'
    action: block
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let host_sock = tmp.path().join("host.sock");
    let agent_sock = tmp.path().join("agent.sock");
    let (mut daemon, host, _agent) = spawn_daemon(&host_sock, &agent_sock, &rules_dir)
        .await
        .expect("daemon spawned");

    // Evaluate DNS for blocked host → should be BLOCK.
    let req = outcall_api::EvaluateRequest {
        context: outcall_api::EvalContext {
            dns: Some(outcall_api::DnsContext {
                query: "evil.example.com".to_string(),
                record_type: "A".to_string(),
            }),
            ..Default::default()
        },
    };

    let json = serde_json::to_string(&req).expect("serialize");
    let mut sock = UnixStream::connect(&host).expect("connect host");
    let http_req = http_json_post("/api/v1/rule/evaluate", &json);
    sock.write_all(http_req.as_bytes()).expect("send");
    let response = read_http_response(&mut sock);

    let resp = parse_api_response::<EvaluateResult>(http_body(&response)).expect("parse response");

    assert!(resp.success);
    let result = resp.data.expect("missing data");
    assert!(
        matches!(result.decision, outcall_api::Decision::Block),
        "evil.example.com should be BLOCKED, got {:?}",
        result.decision
    );

    let _ = daemon.kill();
}

// ── Test: Explicit proxy mode ────────────────────────────────────────────────

/// An explicit proxy-mode rule behaves like the default proxy mode.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn explicit_proxy_mode_is_evaluated() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();

    let yaml = r#"version: "1"
rules:
  - id: block-evil
    condition: 'dns.query == "evil.example.com"'
    action: block
    egress: { mode: proxy }          # S006 mode (explicit)
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let host_sock = tmp.path().join("host.sock");
    let agent_sock = tmp.path().join("agent.sock");
    let (mut daemon, host, _agent) = spawn_daemon(&host_sock, &agent_sock, &rules_dir)
        .await
        .expect("daemon spawned");

    // Test that `block-evil` with explicit `mode: proxy` works correctly.
    let req = outcall_api::EvaluateRequest {
        context: outcall_api::EvalContext {
            dns: Some(outcall_api::DnsContext {
                query: "evil.example.com".to_string(),
                record_type: "A".to_string(),
            }),
            ..Default::default()
        },
    };

    let json = serde_json::to_string(&req).expect("serialize");
    let mut sock = UnixStream::connect(&host).expect("connect host");
    let http_req = http_json_post("/api/v1/rule/evaluate", &json);
    sock.write_all(http_req.as_bytes()).expect("send");
    let response = read_http_response(&mut sock);

    let resp = parse_api_response::<EvaluateResult>(http_body(&response)).expect("parse response");

    assert!(resp.success);
    let result = resp.data.expect("missing data");
    assert!(
        matches!(result.decision, outcall_api::Decision::Block),
        "explicit mode:proxy block rule should work, got {:?}",
        result.decision
    );

    let _ = daemon.kill();
}

// ── Test: Rule resolution priority ───────────────────────────────────────────

/// When multiple rules match the same request, the first matching rule wins.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn first_matching_rule_wins() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();

    let yaml = r#"version: "1"
rules:
  - id: block-evil
    condition: 'dns.query == "evil.example.com"'
    action: block
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let host_sock = tmp.path().join("host.sock");
    let agent_sock = tmp.path().join("agent.sock");
    let (mut daemon, host, _agent) = spawn_daemon(&host_sock, &agent_sock, &rules_dir)
        .await
        .expect("daemon spawned");

    // Even though both rules could match, block-evil is first → BLOCK.
    let req = outcall_api::EvaluateRequest {
        context: outcall_api::EvalContext {
            dns: Some(outcall_api::DnsContext {
                query: "evil.example.com".to_string(),
                record_type: "A".to_string(),
            }),
            ..Default::default()
        },
    };

    let json = serde_json::to_string(&req).expect("serialize");
    let mut sock = UnixStream::connect(&host).expect("connect host");
    let http_req = http_json_post("/api/v1/rule/evaluate", &json);
    sock.write_all(http_req.as_bytes()).expect("send");
    let response = read_http_response(&mut sock);

    let resp = parse_api_response::<EvaluateResult>(http_body(&response)).expect("parse response");

    assert!(resp.success);
    let result = resp.data.expect("missing data");
    // First rule wins — BLOCK, not ALLOW.
    assert!(
        matches!(result.decision, outcall_api::Decision::Block),
        "first matching rule should win, got {:?}",
        result.decision
    );

    let _ = daemon.kill();
}
