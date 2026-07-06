//! Dynamic rules integration — S012-FR-012.a / S009.
//!
//! Verifies that dynamic nftables allow rules can be submitted via the
//! host API, are tracked in memory, appear in the active rules list,
//! and are removed by flush.  Tests run against a live outcalld process
//! with ephemeral Unix sockets.
//!
//! Linux-only — nftables is Linux-gated.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::TempDir;

use outcall_api::{ActiveRule, AllowRuleRequest, AllowRuleResult, ApiResponse, FlushDynamicResult};

// ── Helpers ──────────────────────────────────────────────────────────────────

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

fn parse_api_response<T: serde::de::DeserializeOwned>(body: &str) -> Option<ApiResponse<T>> {
    serde_json::from_str(body).ok()
}

fn http_post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    sock: &mut UnixStream,
    path: &str,
    body: &T,
) -> Option<ApiResponse<R>> {
    let json = serde_json::to_string(body).ok()?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    );
    sock.write_all(request.as_bytes()).ok()?;
    let response = read_http_response(sock);
    parse_api_response(http_body(&response))
}

fn http_get<R: serde::de::DeserializeOwned>(
    sock: &mut UnixStream,
    path: &str,
) -> Option<ApiResponse<R>> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    sock.write_all(request.as_bytes()).ok()?;
    let response = read_http_response(sock);
    parse_api_response(http_body(&response))
}

async fn spawn_daemon(socket: &PathBuf, rules_dir: &PathBuf) -> Result<(Child, String)> {
    let mut cmd = Command::new("outcalld");
    cmd.env("RUST_LOG", "outcalld=warn")
        .arg("--socket")
        .arg(socket.as_os_str())
        .arg("--rules-dir")
        .arg(rules_dir.as_os_str())
        .arg("--no-proxy");
    let mut daemon = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn outcalld")?;

    let timeout = Duration::from_secs(5);
    let poll_interval = Duration::from_millis(25);
    let started_at = std::time::Instant::now();
    loop {
        if socket.exists() {
            break;
        }
        if let Ok(Some(status)) = daemon.try_wait() {
            let mut stderr = String::new();
            if let Some(mut s) = daemon.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            anyhow::bail!(
                "outcalld exited before binding socket (status: {:?}). stderr:\n{}",
                status,
                stderr.trim()
            );
        }
        if started_at.elapsed() >= timeout {
            let _ = daemon.kill();
            let mut stderr = String::new();
            if let Some(mut s) = daemon.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            anyhow::bail!(
                "outcalld did not bind socket within {:?}. stderr:\n{}",
                timeout,
                stderr.trim()
            );
        }
        tokio::time::sleep(poll_interval).await;
    }

    Ok((daemon, socket.to_string_lossy().to_string()))
}

fn make_allow_all_rules(dir: &PathBuf) -> Result<()> {
    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(dir.join("test.yaml"), yaml)?;
    Ok(())
}

// ── Test 1: Flush on empty state returns zero removed ─────────────────────

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn dynamic_flush_empty_returns_zero_removed() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir).await.expect("daemon");

    let mut s = UnixStream::connect(&sock).expect("connect");
    let resp = http_post_json::<_, FlushDynamicResult>(&mut s, "/api/v1/rules/flush", &());
    let resp = resp.expect("flush response");

    assert!(
        resp.success,
        "flush should succeed: {}",
        resp.error.unwrap_or_default()
    );
    let data = resp.data.expect("no data");
    assert_eq!(data.removed, 0, "nothing to remove, should be 0");

    daemon.kill().expect("daemon kill");
}

// ── Test 2: Insert a dynamic allow rule returns a valid nft handle ───────

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn dynamic_insert_rule_returns_valid_handle() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir).await.expect("daemon");

    let req = AllowRuleRequest {
        container: "test-container-1".to_string(),
        src_ip: "10.60.0.2".to_string(),
        destination: "1.2.3.4".to_string(),
        protocol: Some("tcp".to_string()),
        port: Some(443),
    };

    let mut s = UnixStream::connect(&sock).expect("connect");
    let resp = http_post_json::<_, AllowRuleResult>(&mut s, "/api/v1/rule/allow", &req);
    let resp = resp.expect("allow response");

    assert!(
        resp.success,
        "insert should succeed: {}",
        resp.error.unwrap_or_default()
    );
    let data = resp.data.expect("no data");
    assert!(
        data.nft_handle > 0,
        "nftables handle must be non-zero, got {}",
        data.nft_handle
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 3: After insert, rule appears in active list ─────────────────────

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn dynamic_insert_then_list_includes_new_rule() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir).await.expect("daemon");

    let req = AllowRuleRequest {
        container: "test-container-2".to_string(),
        src_ip: "10.60.0.3".to_string(),
        destination: "github.com".to_string(),
        protocol: Some("tcp".to_string()),
        port: Some(443),
    };

    // Insert
    {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_post_json::<_, AllowRuleResult>(&mut s, "/api/v1/rule/allow", &req);
        assert!(resp.expect("insert").success, "insert should succeed");
    }

    // List
    let rules: Vec<ActiveRule> = {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_get::<Vec<ActiveRule>>(&mut s, "/api/v1/rules/active");
        let resp = resp.expect("list response");
        assert!(resp.success, "list should succeed");
        resp.data.expect("no data")
    };

    assert!(
        rules.iter().any(|r| r.container == "test-container-2"),
        "inserted rule should appear in active list: {:?}",
        rules
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 4: Inserting the same rule twice returns same handle (idempotent) ─

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn dynamic_insert_idempotent_returns_same_handle() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir).await.expect("daemon");

    let req = AllowRuleRequest {
        container: "test-container-3".to_string(),
        src_ip: "10.60.0.4".to_string(),
        destination: "1.1.1.1".to_string(),
        protocol: None,
        port: None,
    };

    let handle1 = {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_post_json::<_, AllowRuleResult>(&mut s, "/api/v1/rule/allow", &req);
        let resp = resp.expect("first insert");
        assert!(resp.success);
        resp.data.expect("no data").nft_handle
    };

    let handle2 = {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_post_json::<_, AllowRuleResult>(&mut s, "/api/v1/rule/allow", &req);
        let resp = resp.expect("second insert (idempotent)");
        assert!(resp.success);
        resp.data.expect("no data").nft_handle
    };

    assert_eq!(
        handle1, handle2,
        "inserting the same rule twice should return the same nft handle"
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 5: Flush removes all dynamic rules and reports count ─────────────

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn dynamic_flush_removes_all_rules_reports_count() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir).await.expect("daemon");

    // Insert two rules
    for i in 0..2 {
        let req = AllowRuleRequest {
            container: format!("test-container-flush-{i}"),
            src_ip: format!("10.60.0.{}", 10 + i),
            destination: format!("10.60.0.{}", 10 + i),
            protocol: Some("tcp".to_string()),
            port: Some(443),
        };
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_post_json::<_, AllowRuleResult>(&mut s, "/api/v1/rule/allow", &req);
        assert!(resp.expect("insert").success, "insert rule {i}");
    }

    // Flush
    let removed = {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_post_json::<_, FlushDynamicResult>(&mut s, "/api/v1/rules/flush", &());
        let resp = resp.expect("flush response");
        assert!(resp.success);
        resp.data.expect("no data").removed
    };

    assert_eq!(removed, 2, "flush should report 2 rules removed");

    // List should be empty
    let rules: Vec<ActiveRule> = {
        let mut s = UnixStream::connect(&sock).expect("connect");
        let resp = http_get::<Vec<ActiveRule>>(&mut s, "/api/v1/rules/active");
        let resp = resp.expect("list after flush");
        assert!(resp.success);
        resp.data.unwrap_or_default()
    };

    assert!(
        rules.is_empty(),
        "active rules should be empty after flush, got {}",
        rules.len()
    );

    daemon.kill().expect("daemon kill");
}
