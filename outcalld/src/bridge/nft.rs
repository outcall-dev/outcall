use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::info;

use super::{BridgeError, HostServiceAccess};
use crate::system_command::{output_with_timeout, wait_with_output, SYSTEM_COMMAND_TIMEOUT};

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "outcall";

pub(super) async fn apply_base(
    bridge_name: &str,
    host_services: HostServiceAccess,
) -> Result<(), BridgeError> {
    let table_exists = table_active().await?;
    run_policy(&render_transaction(
        bridge_name,
        host_services,
        table_exists,
    ))
    .await?;
    info!("base nftables rules applied");
    Ok(())
}

pub(super) async fn table_active() -> Result<bool, BridgeError> {
    let mut command = Command::new("nft");
    command.args(["list", "table", NFT_FAMILY, NFT_TABLE]);
    let output = output_with_timeout(
        &mut command,
        SYSTEM_COMMAND_TIMEOUT,
        "inspect Outcall nftables table",
    )
    .await
    .map_err(|error| BridgeError::Nftables(error.to_string()))?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if table_missing(&stderr) {
        Ok(false)
    } else {
        Err(BridgeError::Nftables(format!(
            "inspect nftables table failed: {}",
            stderr.trim()
        )))
    }
}

pub(super) async fn delete_table() -> Result<(), BridgeError> {
    let mut command = Command::new("nft");
    command.args(["delete", "table", NFT_FAMILY, NFT_TABLE]);
    let output = output_with_timeout(
        &mut command,
        SYSTEM_COMMAND_TIMEOUT,
        "delete Outcall nftables table",
    )
    .await
    .map_err(|error| BridgeError::Nftables(error.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if table_missing(&stderr) {
        Ok(())
    } else {
        Err(BridgeError::Nftables(format!(
            "delete nftables table failed: {}",
            stderr.trim()
        )))
    }
}

async fn run_policy(ruleset: &str) -> Result<(), BridgeError> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| BridgeError::Nftables(spawn_error(error)))?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(BridgeError::Nftables(
            "nft stdin pipe was unavailable".to_string(),
        ));
    };
    stdin
        .write_all(ruleset.as_bytes())
        .await
        .map_err(|error| BridgeError::Nftables(format!("write nft stdin: {error}")))?;
    drop(stdin);

    let output = wait_with_output(child, SYSTEM_COMMAND_TIMEOUT, "apply nftables policy")
        .await
        .map_err(|error| BridgeError::Nftables(error.to_string()))?;
    if !output.status.success() {
        return Err(BridgeError::Nftables(format!(
            "nft exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn spawn_error(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "nft command not found; install nftables".to_string(),
        std::io::ErrorKind::PermissionDenied => {
            "permission denied running nft; root or CAP_NET_ADMIN is required".to_string()
        }
        _ => format!("spawn nft: {error}"),
    }
}

fn table_missing(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("does not exist")
        || stderr.contains("not found")
}

fn render_base(bridge_name: &str, host_services: HostServiceAccess) -> String {
    let dns = host_services.dns;
    let proxy_rule = host_services
        .proxy
        .map(|proxy| {
            format!(
                "        iifname \"{bridge_name}\" ip daddr {} tcp dport {} accept\n",
                proxy.address, proxy.port
            )
        })
        .unwrap_or_default();

    format!(
        r#"table inet outcall {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
        iifname != "{bridge_name}" oifname != "{bridge_name}" accept
        iifname "{bridge_name}" ct state invalid drop
        oifname "{bridge_name}" ct state invalid drop
        iifname "{bridge_name}" meta nfproto ipv6 drop
        oifname "{bridge_name}" meta nfproto ipv6 drop
        iifname "{bridge_name}" ct state established,related accept
        oifname "{bridge_name}" ct state established,related accept
    }}

    chain input_from_agents {{
        type filter hook input priority filter; policy accept;
        iifname "{bridge_name}" ct state invalid drop
        iifname "{bridge_name}" ip daddr {dns_address} udp dport {dns_port} accept
        iifname "{bridge_name}" ip daddr {dns_address} tcp dport {dns_port} accept
{proxy_rule}        iifname "{bridge_name}" meta nfproto ipv4 drop
        iifname "{bridge_name}" meta nfproto ipv6 drop
    }}

    chain output_ipv6_block {{
        type filter hook output priority filter; policy accept;
        oifname "{bridge_name}" meta nfproto ipv6 drop
    }}
}}"#,
        dns_address = dns.address,
        dns_port = dns.port,
    )
}

fn render_transaction(
    bridge_name: &str,
    host_services: HostServiceAccess,
    table_exists: bool,
) -> String {
    let replacement = render_base(bridge_name, host_services);
    if table_exists {
        format!("delete table inet outcall\n{replacement}")
    } else {
        replacement
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::bridge::HostServiceEndpoint;

    #[test]
    fn base_policy_allows_only_declared_host_services() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let ruleset = render_base("outcall0", HostServiceAccess::default_for_gateway(gateway));
        assert!(ruleset.contains("ip daddr 10.200.0.1 udp dport 53 accept"));
        assert!(ruleset.contains("ip daddr 10.200.0.1 tcp dport 8080 accept"));
        assert!(ruleset.contains("iifname \"outcall0\" meta nfproto ipv4 drop"));
        assert!(ruleset.contains("oifname \"outcall0\" meta nfproto ipv6 drop"));
        assert!(ruleset.lines().any(|line| {
            line.trim() == "oifname \"outcall0\" ct state established,related accept"
        }));
        assert!(!ruleset
            .lines()
            .any(|line| line.trim() == "oifname \"outcall0\" accept"));
        assert!(!ruleset.contains("dport 22 accept"));

        let without_proxy = render_base(
            "outcall0",
            HostServiceAccess {
                dns: HostServiceEndpoint {
                    address: gateway,
                    port: 53,
                },
                proxy: None,
            },
        );
        assert!(!without_proxy.contains("tcp dport 8080 accept"));
    }

    #[test]
    fn replacement_is_one_transaction() {
        let ruleset = render_transaction(
            "outcall0",
            HostServiceAccess::default_for_gateway(Ipv4Addr::new(10, 200, 0, 1)),
            true,
        );
        assert!(ruleset.starts_with("delete table inet outcall\ntable inet outcall"));
    }

    #[test]
    fn distinguishes_missing_table_from_operational_errors() {
        assert!(table_missing("Error: No such file or directory"));
        assert!(table_missing("table does not exist"));
        assert!(!table_missing("Operation not permitted"));
    }
}
