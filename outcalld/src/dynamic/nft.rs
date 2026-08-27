use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use tokio::process::Command;
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use crate::bridge::BridgeManager;
use crate::system_command::{output_with_timeout, SYSTEM_COMMAND_TIMEOUT};

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "outcall";
const NFT_CHAIN: &str = "forward";

#[async_trait]
pub(super) trait NftController: Send + Sync {
    async fn insert(
        &self,
        src_ip: IpAddr,
        dst_ip: &str,
        protocol: Option<&str>,
        port: Option<u16>,
    ) -> Result<u64>;

    async fn delete(&self, handle: u64) -> Result<()>;

    async fn reset_to_base_policy(&self) -> Result<()>;
}

#[cfg(target_os = "linux")]
pub(super) struct SystemNftController {
    pub(super) bridge: Arc<Mutex<BridgeManager>>,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl NftController for SystemNftController {
    async fn insert(
        &self,
        src_ip: IpAddr,
        dst_ip: &str,
        protocol: Option<&str>,
        port: Option<u16>,
    ) -> Result<u64> {
        nft_insert(src_ip, dst_ip, protocol, port).await
    }

    async fn delete(&self, handle: u64) -> Result<()> {
        nft_delete(handle).await
    }

    async fn reset_to_base_policy(&self) -> Result<()> {
        self.bridge
            .lock()
            .await
            .reset_policy()
            .await
            .context("failed to restore base nftables policy")
    }
}

pub(super) struct TestNftController;

#[async_trait]
impl NftController for TestNftController {
    async fn insert(
        &self,
        src_ip: IpAddr,
        dst_ip: &str,
        protocol: Option<&str>,
        port: Option<u16>,
    ) -> Result<u64> {
        nft_insert(src_ip, dst_ip, protocol, port).await
    }

    async fn delete(&self, handle: u64) -> Result<()> {
        nft_delete(handle).await
    }

    async fn reset_to_base_policy(&self) -> Result<()> {
        anyhow::bail!("base-policy reset is unavailable in the test-only constructor")
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct NoopNftController;

#[cfg(all(test, target_os = "linux"))]
#[async_trait]
impl NftController for NoopNftController {
    async fn insert(
        &self,
        _src_ip: IpAddr,
        _dst_ip: &str,
        _protocol: Option<&str>,
        _port: Option<u16>,
    ) -> Result<u64> {
        Ok(1)
    }

    async fn delete(&self, _handle: u64) -> Result<()> {
        Ok(())
    }

    async fn reset_to_base_policy(&self) -> Result<()> {
        Ok(())
    }
}

async fn nft_insert(
    src_ip: IpAddr,
    dst_ip: &str,
    protocol: Option<&str>,
    port: Option<u16>,
) -> Result<u64> {
    let is_ipv6 = is_ipv6_addr(dst_ip);
    if src_ip.is_ipv6() != is_ipv6 {
        anyhow::bail!(
            "source address {src_ip} and destination {dst_ip} use different address families"
        );
    }
    let ip_prefix = if is_ipv6 { "ip6" } else { "ip" };
    let src_ip = src_ip.to_string();

    let mut expression = vec![
        format!("{ip_prefix} saddr {src_ip}"),
        format!("{ip_prefix} daddr {dst_ip}"),
    ];
    match (protocol, port) {
        (Some(protocol), Some(port)) => expression.push(format!("{protocol} dport {port}")),
        (Some(protocol), None) => expression.push(format!("meta l4proto {protocol}")),
        _ => {}
    }
    expression.push("accept".to_string());

    let mut command = Command::new("nft");
    command
        .arg("--handle")
        .arg("--echo")
        .arg("insert")
        .arg("rule")
        .arg(NFT_FAMILY)
        .arg(NFT_TABLE)
        .arg(NFT_CHAIN)
        .args(&expression);
    let output = output_with_timeout(
        &mut command,
        SYSTEM_COMMAND_TIMEOUT,
        "insert dynamic nftables rule",
    )
    .await?;
    if !output.status.success() {
        anyhow::bail!(
            "nft insert failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nft_handle(&stdout).with_context(|| format!("could not parse nft handle from: {stdout}"))
}

async fn nft_delete(handle: u64) -> Result<()> {
    let mut command = Command::new("nft");
    command
        .arg("delete")
        .arg("rule")
        .arg(NFT_FAMILY)
        .arg(NFT_TABLE)
        .arg(NFT_CHAIN)
        .arg("handle")
        .arg(handle.to_string());
    let output = output_with_timeout(
        &mut command,
        SYSTEM_COMMAND_TIMEOUT,
        "delete dynamic nftables rule",
    )
    .await?;
    if !output.status.success() {
        anyhow::bail!(
            "nft delete handle {handle} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn parse_nft_handle(output: &str) -> Option<u64> {
    output.lines().find_map(|line| {
        let tail = line.split_once("# handle ")?.1.trim();
        tail.split_whitespace().next()?.parse().ok()
    })
}

fn is_ipv6_addr(value: &str) -> bool {
    value
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
        || value
            .parse::<IpNet>()
            .is_ok_and(|network| network.addr().is_ipv6())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nft_handle_from_echo_output() {
        let output = "ip saddr 10.0.0.1 ip daddr 1.2.3.4 accept # handle 42\n";
        assert_eq!(parse_nft_handle(output), Some(42));
        assert_eq!(parse_nft_handle("no handle here\n"), None);
    }

    #[test]
    fn identifies_ipv6_literals_and_networks() {
        assert!(is_ipv6_addr("::1"));
        assert!(is_ipv6_addr("2001:db8::/64"));
        assert!(!is_ipv6_addr("fe80::1%eth0"));
        assert!(!is_ipv6_addr("10.0.0.1"));
        assert!(!is_ipv6_addr("example.com"));
    }

    #[tokio::test]
    async fn rejects_mixed_source_and_destination_families_before_nft() {
        let result = nft_insert(
            "10.200.0.2".parse().unwrap(),
            "2001:db8::1",
            Some("tcp"),
            Some(443),
        )
        .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("different address families"));
    }
}
