//! Network bridge integration — S001 / S012-FR-001.a.
//!
#![cfg(target_os = "linux")]
//!
//! Must be run as root (or with CAP_NET_ADMIN):
//!     sudo cargo test -p outcalld --test bridge_integration -- --nocapture
//!
//! On macOS this test is skipped because netlink/nftables are Linux-only.

use std::process::Command;

fn default_gateway() -> (std::net::Ipv4Addr, u8) {
    let gateway = outcall_api::DEFAULT_GATEWAY
        .parse()
        .expect("DEFAULT_GATEWAY should be a valid IPv4 address");
    (gateway, 24)
}

fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn ip_link_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn nft_table_exists(family: &str, table: &str) -> bool {
    Command::new("nft")
        .args(["list", "table", family, table])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ip_addr_exists(name: &str, cidr: &str) -> bool {
    Command::new("ip")
        .args(["addr", "show", "dev", name])
        .output()
        .map(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains(cidr)
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn bridge_lifecycle() {
    if !is_linux() {
        eprintln!("SKIP: bridge tests require Linux (netlink + nftables)");
        return;
    }
    if !is_root() {
        eprintln!("SKIP: bridge tests require root (run with sudo)");
        return;
    }

    let bridge_name = "outcall_test0";

    // -- Clean up any leftover state from a previous failed run --
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "outcall"])
        .output();
    let _ = Command::new("ip")
        .args(["link", "del", bridge_name])
        .output();

    // -- Create and initialize --
    let (gateway_ip, gateway_prefix_len) = default_gateway();
    let mut mgr = outcalld::bridge::BridgeManager::new(
        Some(bridge_name),
        gateway_ip,
        gateway_prefix_len,
    )
        .await
        .expect("BridgeManager::new");

    mgr.init().await.expect("bridge init");

    // -- Verify bridge exists --
    assert!(
        ip_link_exists(bridge_name),
        "bridge {bridge_name} should exist after init"
    );
    assert!(
        ip_addr_exists(bridge_name, &format!("{gateway_ip}/{gateway_prefix_len}")),
        "bridge {bridge_name} should own gateway {gateway_ip}/{gateway_prefix_len}"
    );

    // -- Verify nftables table exists --
    assert!(
        nft_table_exists("inet", "outcall"),
        "nftables table 'inet outcall' should exist after init"
    );

    // -- Verify the ruleset contains our drop rules --
    let nft_output = Command::new("nft")
        .args(["list", "table", "inet", "outcall"])
        .output()
        .expect("nft list table");
    let ruleset = String::from_utf8_lossy(&nft_output.stdout);
    assert!(
        ruleset.contains(bridge_name),
        "ruleset should reference bridge name:\n{ruleset}"
    );
    assert!(
        ruleset.contains("drop"),
        "ruleset should contain drop rules:\n{ruleset}"
    );
    assert!(
        ruleset.contains("established"),
        "ruleset should allow established connections:\n{ruleset}"
    );

    // -- Idempotence: init again should not fail --
    let mut mgr2 = outcalld::bridge::BridgeManager::new(
        Some(bridge_name),
        gateway_ip,
        gateway_prefix_len,
    )
        .await
        .expect("BridgeManager::new (second)");
    mgr2.init().await.expect("bridge init (idempotent)");

    // -- Teardown --
    mgr2.teardown().await.expect("bridge teardown");

    // -- Verify clean state --
    assert!(
        !ip_link_exists(bridge_name),
        "bridge {bridge_name} should not exist after teardown"
    );
    assert!(
        !nft_table_exists("inet", "outcall"),
        "nftables table should not exist after teardown"
    );
}
