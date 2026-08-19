//! TLS interception configuration — S011-AS-003/-004.
//!
//! Verifies daemon startup behavior for rule sets that do and do not require
//! a configured interception CA. Full TLS interception is not implemented.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;

// ── Test: Intercept mode rejects when no CA loaded ─────────────────────────

/// S011-AS-003: A rule with `mode: intercept` is rejected when daemon has no CA.
/// We verify that starting the daemon with no CA flag fails if a rule requests
/// intercept mode.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn intercept_rule_rejected_when_no_ca() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();

    // Write a rule with intercept mode (without a CA, this should be rejected).
    let yaml = r#"version: "1"
rules:
  - id: intercept-rule
    condition: 'http.host == "localhost"'
    action: allow
    egress: { mode: intercept }
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let host_sock = tmp.path().join("host.sock");
    let agent_sock = tmp.path().join("agent.sock");

    // Spawn daemon without CA flags.
    let mut cmd = Command::new("outcalld");
    cmd.env("RUST_LOG", "outcalld=warn")
        .arg("--socket")
        .arg(host_sock.as_os_str())
        .arg("--agent-socket-host-path")
        .arg(agent_sock.as_os_str())
        .arg("--rules-dir")
        .arg(rules_dir.as_os_str())
        .arg("--no-proxy");
    let mut child = cmd.spawn().expect("daemon spawn");

    tokio::time::sleep(Duration::from_millis(500)).await;
    match child.try_wait().expect("daemon status") {
        Some(status) => assert!(
            !status.success(),
            "daemon unexpectedly accepted intercept rule"
        ),
        None => {
            child.kill().expect("daemon kill");
            child.wait().expect("daemon wait");
            panic!("daemon stayed running without a CA for an intercept rule");
        }
    }
}

// ── Test: Daemon starts healthy with no CA and no intercept rules ────────────

/// S011-AS-004: Daemon starts cleanly without CA when no rules use intercept.
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN to bring up the outcall0 bridge; run with sudo and `cargo test -- --ignored` on a privileged host"]
async fn daemon_starts_without_ca_when_no_intercept_rules() {
    let tmp = TempDir::new().expect("tempdir");
    let rules_dir = tmp.path().to_path_buf();

    let yaml = r#"version: "1"
rules:
  - id: allow-all
    condition: 'true'
    action: allow
"#;
    std::fs::write(rules_dir.join("test.yaml"), yaml).expect("write rules");

    let host_sock = tmp.path().join("host.sock");
    let agent_sock = tmp.path().join("agent.sock");

    let mut cmd = Command::new("outcalld");
    cmd.env("RUST_LOG", "outcalld=warn")
        .arg("--socket")
        .arg(host_sock.as_os_str())
        .arg("--agent-socket-host-path")
        .arg(agent_sock.as_os_str())
        .arg("--rules-dir")
        .arg(rules_dir.as_os_str())
        .arg("--no-proxy");
    let mut child = cmd.spawn().expect("daemon spawn");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        child.try_wait().expect("daemon status").is_none(),
        "daemon exited even though no rule required an interception CA"
    );
    child.kill().expect("daemon kill");
    child.wait().expect("daemon wait");
}
