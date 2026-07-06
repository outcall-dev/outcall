//! CLI integration — S012-FR-007.a / S003-FR-004.
//!
//! Spawns `outcalld` on an ephemeral Unix socket, then runs the `outcall`
//! binary against it. Asserts on exit codes and stdout for every subcommand
//! group (bridge, dns, proxy, container, network).
//!
//! Linux-only — requires actual nftables/bridge, not mockable in a container.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────────

/// Start `outcalld` as a background child process.
/// Returns the socket path and the Child handle (caller must kill).
async fn spawn_daemon(socket: &PathBuf, rules_dir: &PathBuf) -> Result<(Child, String)> {
    let mut cmd = Command::new("outcalld");
    cmd.env("RUST_LOG", "outcalld=warn")
        .arg("--socket")
        .arg(socket.as_os_str())
        .arg("--rules-dir")
        .arg(rules_dir.as_os_str())
        .arg("--no-proxy");
    let mut daemon = cmd
        // Disable Docker so we don't need a running Docker daemon
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
                use std::io::Read;
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
                use std::io::Read;
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

    let socket_str = socket.to_string_lossy().to_string();
    Ok((daemon, socket_str))
}

/// Write a minimal allow-all rule YAML into a temp dir.
fn make_allow_all_rules(dir: &PathBuf) -> Result<()> {
    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    fs::write(dir.join("test.yaml"), yaml)?;
    Ok(())
}

/// Run `outcall` with the given subcommand against the socket.
/// Returns the output (combined stdout + stderr).
fn outcall_exec(socket: &str, subcommand: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("outcall");
    cmd.arg("--socket").arg(socket);
    for arg in subcommand {
        cmd.arg(*arg);
    }
    cmd.output().expect("outcall exec failed")
}

fn assert_success(output: &std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}: exit {}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(200)
            .collect::<String>()
    );
}

fn assert_failure(output: &std::process::Output, context: &str) {
    assert!(
        !output.status.success(),
        "{context}: expected failure, got exit 0",
    );
}

// ── Test 1: Bridge subcommand group ──────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_bridge_status_reports_bridge_state() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["bridge", "status"]);
    assert_success(&out, "bridge status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Bridge:") || s.contains("Status:"),
        "bridge status output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_bridge_up_and_down_cycle() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let up = outcall_exec(&sock, &["bridge", "up"]);
    assert_success(&up, "bridge up");

    let down = outcall_exec(&sock, &["bridge", "down"]);
    assert_success(&down, "bridge down");

    daemon.kill().expect("daemon kill");
}

// ── Test 2: DNS subcommand group ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_dns_status_reports_filter_state() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["dns", "status"]);
    assert_success(&out, "dns status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("DNS") || s.contains("active"),
        "dns status output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_dns_test_blocked_host_shows_block_decision() {
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
    fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["dns", "test", "evil.example.com"]);
    assert_success(&out, "dns test blocked");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("BLOCK"),
        "expected BLOCK for blocked host, got: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_dns_test_allowed_host_shows_allow_decision() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["dns", "test", "google.com"]);
    assert_success(&out, "dns test allowed");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("ALLOW"),
        "expected ALLOW for allowed host, got: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_dns_cache_shows_entries_after_queries() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let _ = outcall_exec(&sock, &["dns", "test", "google.com"]);
    let _ = outcall_exec(&sock, &["dns", "test", "google.com"]);

    let out = outcall_exec(&sock, &["dns", "cache"]);
    assert_success(&out, "dns cache");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Hits:") || s.contains("entries"),
        "cache output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_dns_flush_reports_cleared_entries() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let _ = outcall_exec(&sock, &["dns", "test", "google.com"]);

    let out = outcall_exec(&sock, &["dns", "flush"]);
    assert_success(&out, "dns flush");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("flushed") || s.contains("cleared"),
        "flush output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 3: Proxy subcommand group ────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_proxy_status_reports_proxy_state() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["proxy", "status"]);
    assert_success(&out, "proxy status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("HTTP") || s.contains("Proxy") || s.contains("active"),
        "proxy status output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 4: Network subcommand group ─────────────────────────────────────────

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_network_list_returns_table_or_empty() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["network", "list"]);
    assert_success(&out, "network list");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("NAME") || s.contains("Subnet") || s.is_empty(),
        "network list output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_network_create_succeeds_or_already_exists() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["network", "create"]);
    assert_success(&out, "network create");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("created") || s.contains("already exists"),
        "network create output: {s}",
    );

    daemon.kill().expect("daemon kill");
}

// ── Test 5: Unknown subcommand exits non-zero ─────────────────────────────────

#[tokio::test]
async fn cli_unknown_subcommand_exits_nonzero() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("outcalld.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["foobar"]);
    assert_failure(&out, "unknown subcommand");

    daemon.kill().expect("daemon kill");
}

// ── Test 6: Custom socket path is respected ─────────────────────────────────

#[tokio::test]
#[ignore = "requires a running outcalld with CAP_NET_ADMIN; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn cli_custom_socket_path_is_respected() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();
    make_allow_all_rules(&rules_dir).expect("write rules");

    let socket = tmp.path().join("custom.sock");
    let (mut daemon, sock) = spawn_daemon(&socket, &rules_dir)
        .await
        .expect("daemon spawned");

    let out = outcall_exec(&sock, &["bridge", "status"]);
    assert_success(&out, "custom socket bridge status");

    daemon.kill().expect("daemon kill");
}

// ── Test 7: CLI fails cleanly when daemon is unreachable ───────────────────

#[tokio::test]
async fn cli_fails_cleanly_when_daemon_unreachable() {
    let tmp = TempDir::new().expect("tempdir");
    let dead_socket = tmp.path().join("not-running.sock");

    let out = Command::new("outcall")
        .arg("--socket")
        .arg(dead_socket.to_str().unwrap())
        .arg("bridge")
        .arg("status")
        .output()
        .expect("outcall exec");

    assert_failure(&out, "daemon unreachable");
    let s = String::from_utf8_lossy(&out.stderr);
    assert!(
        s.contains("cannot connect") || s.contains("running"),
        "expected connection error, got: {s}",
    );
}
