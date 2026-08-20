use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::{Handle, LinkBridge, LinkUnspec};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

const BRIDGE_NF_IPV4: &str = "/proc/sys/net/bridge/bridge-nf-call-iptables";
const BRIDGE_NF_IPV6: &str = "/proc/sys/net/bridge/bridge-nf-call-ip6tables";

use outcall_api::BridgeStatus;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("netlink connection failed: {0}")]
    Connection(#[source] std::io::Error),

    #[error("bridge operation failed: {0:#}")]
    Operation(#[source] anyhow::Error),

    #[error("nftables operation failed: {0}")]
    Nftables(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostServiceEndpoint {
    pub address: Ipv4Addr,
    pub port: u16,
}

impl HostServiceEndpoint {
    fn from_listener(listener: SocketAddr, gateway_ip: Ipv4Addr, label: &str) -> Result<Self> {
        if listener.port() == 0 {
            anyhow::bail!("{label} listener must use a fixed, non-zero port");
        }
        let address = match listener.ip() {
            IpAddr::V4(address) if address.is_unspecified() => gateway_ip,
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => anyhow::bail!(
                "{label} listener {listener} is IPv6, but the managed bridge only permits IPv4 host services"
            ),
        };
        Ok(Self {
            address,
            port: listener.port(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostServiceAccess {
    pub dns: HostServiceEndpoint,
    pub proxy: Option<HostServiceEndpoint>,
}

impl HostServiceAccess {
    pub fn from_listeners(
        gateway_ip: Ipv4Addr,
        dns_listener: SocketAddr,
        proxy_listener: Option<SocketAddr>,
    ) -> Result<Self> {
        Ok(Self {
            dns: HostServiceEndpoint::from_listener(dns_listener, gateway_ip, "DNS")?,
            proxy: proxy_listener
                .map(|listener| HostServiceEndpoint::from_listener(listener, gateway_ip, "proxy"))
                .transpose()?,
        })
    }

    pub fn default_for_gateway(gateway_ip: Ipv4Addr) -> Self {
        Self {
            dns: HostServiceEndpoint {
                address: gateway_ip,
                port: 53,
            },
            proxy: Some(HostServiceEndpoint {
                address: gateway_ip,
                port: 8080,
            }),
        }
    }
}

/// Manages the outcall network bridge and its associated nftables rules.
///
/// Every agent container attaches to this bridge. The base nftables ruleset
/// drops all forwarded traffic by default — rules are dynamically inserted
/// later to allow specific flows.
pub struct BridgeManager {
    name: String,
    gateway_ip: Ipv4Addr,
    gateway_prefix_len: u8,
    host_services: HostServiceAccess,
    handle: Handle,
    index: Option<u32>,
}

impl BridgeManager {
    /// Create a new bridge manager. Does not touch the kernel yet.
    pub async fn new(
        name: Option<&str>,
        gateway_ip: Ipv4Addr,
        gateway_prefix_len: u8,
        host_services: HostServiceAccess,
    ) -> Result<Self, BridgeError> {
        let (conn, handle, _) = rtnetlink::new_connection().map_err(BridgeError::Connection)?;
        tokio::spawn(conn);

        Ok(Self {
            name: name.unwrap_or(outcall_api::DEFAULT_BRIDGE_NAME).to_string(),
            gateway_ip,
            gateway_prefix_len,
            host_services,
            handle,
            index: None,
        })
    }

    /// Create (or attach to) the bridge and apply the base nftables ruleset.
    pub async fn init(&mut self) -> Result<(), BridgeError> {
        self.ensure_bridge().await?;
        self.ensure_gateway_address().await?;
        self.enable_bridge_netfilter().await;
        self.apply_base_rules().await?;
        Ok(())
    }

    /// Ensure bridged traffic traverses the nftables `forward` hook.
    ///
    /// Without `net.bridge.bridge-nf-call-iptables=1`, the kernel delivers
    /// frames between two veths on the same bridge at L2, completely
    /// bypassing the nftables hooks where our drop rules live. That makes
    /// T-2 (agent-to-agent isolation) silently unenforceable: a pre-shared
    /// rule meant to drop iifname=outcall0 traffic never even sees the
    /// packet. Block tests against external destinations still appear to
    /// pass — those traverse routing, which goes through FORWARD — so this
    /// failure mode is exactly the kind that ships unnoticed.
    ///
    /// Steps:
    ///   1. `modprobe br_netfilter` — the `bridge-nf-*` sysctls only exist
    ///      when this module is loaded (or built into the kernel).
    ///   2. Write `1` to both bridge IPv4 and IPv6 netfilter sysctls.
    ///
    /// Both steps are best-effort: we warn but don't fail. The reasoning
    /// is operational — if the module can't load or the sysctl can't be
    /// written, the daemon is still useful for proxy-mediated egress
    /// rules; only L2-bridged container-to-container enforcement degrades.
    /// A loud `warn!` makes the gap discoverable instead of silent. Managed
    /// container creation separately calls `require_netfilter_enforceable`, so
    /// this best-effort setup cannot turn into a fail-open runtime.
    async fn enable_bridge_netfilter(&self) {
        // 1) Module load. Ignore output; if it's already loaded or built
        // in, modprobe returns 0 anyway. If we lack CAP_SYS_MODULE, this
        // fails and we just check the sysctl below.
        let _ = Command::new("modprobe").arg("br_netfilter").output().await;

        // 2) Sysctl writes via direct procfs paths — sysctl(1) isn't always
        // installed in minimal containers, while procfs is. Docker Desktop
        // exposes these as read-only when already enabled, so read first.
        for path in [BRIDGE_NF_IPV4, BRIDGE_NF_IPV6] {
            if matches!(tokio::fs::read_to_string(path).await, Ok(value) if value.trim() == "1") {
                info!(sysctl = path, "bridge netfilter already enabled");
                continue;
            }
            match tokio::fs::write(path, b"1").await {
                Ok(()) => info!(sysctl = path, "bridge netfilter enabled"),
                Err(error) => warn!(
                    sysctl = path,
                    error = %error,
                    "could not enable bridge netfilter; managed container creation will be refused"
                ),
            }
        }
    }

    /// Refuse managed workloads unless both bridge netfilter hooks are active.
    /// This check lives in the daemon so callers cannot bypass it by invoking
    /// the container API directly instead of using the host CLI preflight.
    pub async fn require_netfilter_enforceable(&self) -> Result<(), BridgeError> {
        let ipv4 = read_netfilter_setting(BRIDGE_NF_IPV4).await;
        let ipv6 = read_netfilter_setting(BRIDGE_NF_IPV6).await;
        if netfilter_settings_enforceable(&ipv4, &ipv6) {
            return Ok(());
        }

        Err(BridgeError::Operation(anyhow::anyhow!(
            "Secure unattended mode requires bridge netfilter enforcement; \
             bridge-nf-call-iptables={ipv4}, bridge-nf-call-ip6tables={ipv6} (expected both to be 1)"
        )))
    }

    /// Idempotent bridge setup: create if missing, then bring up.
    async fn ensure_bridge(&mut self) -> Result<(), BridgeError> {
        let existing = self
            .find_link_index()
            .await
            .map_err(BridgeError::Operation)?;

        if let Some(idx) = existing {
            info!(bridge = %self.name, index = idx, "attaching to existing bridge");
            self.index = Some(idx);
        } else {
            info!(bridge = %self.name, "creating bridge");
            self.handle
                .link()
                .add(LinkBridge::new(&self.name).build())
                .execute()
                .await
                .context("create bridge")
                .map_err(BridgeError::Operation)?;

            let idx = self
                .find_link_index()
                .await
                .map_err(BridgeError::Operation)?
                .context("bridge not found after creation")
                .map_err(BridgeError::Operation)?;
            self.index = Some(idx);
        }

        // Bring the bridge up (idempotent — safe even if already up)
        let idx = self.index.expect("set above");
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await
            .context("bring bridge up")
            .map_err(BridgeError::Operation)?;

        info!(bridge = %self.name, index = idx, "bridge is up");
        Ok(())
    }

    /// Ensure the bridge owns the gateway IP used by the default DNS and proxy listeners.
    async fn ensure_gateway_address(&self) -> Result<(), BridgeError> {
        let idx = self.index.expect("bridge index set during ensure_bridge");
        self.handle
            .address()
            .add(idx, IpAddr::V4(self.gateway_ip), self.gateway_prefix_len)
            .replace()
            .execute()
            .await
            .context("assign bridge gateway address")
            .map_err(BridgeError::Operation)?;
        info!(
            bridge = %self.name,
            gateway = %self.gateway_ip,
            prefix_len = self.gateway_prefix_len,
            "bridge gateway address configured"
        );
        Ok(())
    }

    /// Look up the bridge by name, returning its interface index if it exists.
    async fn find_link_index(&self) -> Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(self.name.clone())
            .execute();

        match links.try_next().await {
            Ok(Some(msg)) => Ok(Some(msg.header.index)),
            Ok(None) => Ok(None),
            Err(e) => {
                // ENODEV (errno 19) means the device doesn't exist
                if e.to_string().contains("No such device") {
                    Ok(None)
                } else {
                    Err(anyhow::Error::from(e).context("query link by name"))
                }
            }
        }
    }

    /// Apply the base nftables ruleset: drop all forwarded traffic on the
    /// bridge except established/related connections.
    async fn apply_base_rules(&self) -> Result<(), BridgeError> {
        // Keep replacement in one nft transaction. If parsing or applying the
        // new policy fails, nft retains the previous fail-closed table.
        let table_exists = Command::new("nft")
            .args(["list", "table", "inet", "outcall"])
            .output()
            .await
            .is_ok_and(|output| output.status.success());
        let ruleset = render_ruleset_transaction(&self.name, self.host_services, table_exists);
        self.run_nft(&ruleset).await?;

        info!("base nftables rules applied");
        Ok(())
    }

    /// Execute an nftables ruleset via `nft -f -`.
    async fn run_nft(&self, ruleset: &str) -> Result<(), BridgeError> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                let detail = if e.kind() == std::io::ErrorKind::NotFound {
                    "nft command not found — is nftables installed?".to_string()
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission denied running nft — are you root or have CAP_NET_ADMIN?"
                        .to_string()
                } else {
                    format!("spawn nft: {e}")
                };
                BridgeError::Nftables(detail)
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .await
                .map_err(|e| BridgeError::Nftables(format!("write stdin: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| BridgeError::Nftables(format!("wait: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BridgeError::Nftables(format!(
                "nft exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Tear down: delete the nftables table, bring the bridge down, remove it.
    pub async fn teardown(&self) -> Result<(), BridgeError> {
        info!(bridge = %self.name, "tearing down");

        // Delete nftables table
        match Command::new("nft")
            .args(["delete", "table", "inet", "outcall"])
            .output()
            .await
        {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("nft table delete (may not exist): {}", stderr.trim());
            }
            Err(e) => warn!("nft command failed: {e}"),
            _ => {}
        }

        // Bring down and delete the bridge
        if let Some(idx) = self.index {
            let _ = self
                .handle
                .link()
                .set(LinkUnspec::new_with_index(idx).down().build())
                .execute()
                .await;
            self.handle
                .link()
                .del(idx)
                .execute()
                .await
                .context("delete bridge link")
                .map_err(BridgeError::Operation)?;
        }

        info!(bridge = %self.name, "teardown complete");
        Ok(())
    }

    /// Query current bridge and nftables state (fresh check every call).
    pub async fn status(&self) -> BridgeStatus {
        let link_up = self.find_link_index().await.ok().flatten().is_some();

        let nft_active = Command::new("nft")
            .args(["list", "table", "inet", "outcall"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        BridgeStatus {
            name: self.name.clone(),
            up: link_up,
            index: self.index,
            nftables_active: nft_active,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

fn render_base_ruleset(name: &str, host_services: HostServiceAccess) -> String {
    let dns = host_services.dns;
    let proxy_rule = host_services
        .proxy
        .map(|proxy| {
            format!(
                "        iifname \"{name}\" ip daddr {} tcp dport {} accept\n",
                proxy.address, proxy.port
            )
        })
        .unwrap_or_default();

    format!(
        r#"table inet outcall {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
        # Preserve forwarding that does not touch the managed bridge.
        iifname != "{name}" oifname != "{name}" accept
        iifname "{name}" ct state invalid drop
        oifname "{name}" ct state invalid drop
        # Dynamic allow rules are inserted at the chain head. Everything else
        # from or to an agent remains denied, including all IPv6 forwarding.
        iifname "{name}" meta nfproto ipv6 drop
        oifname "{name}" meta nfproto ipv6 drop
        iifname "{name}" ct state established,related accept
        oifname "{name}" ct state established,related accept
    }}

    # Agents may reach only the daemon-owned DNS and proxy listeners on the
    # host. Host tools and files must be exposed through the authenticated
    # broker rather than arbitrary host TCP/UDP services.
    chain input_from_agents {{
        type filter hook input priority filter; policy accept;
        iifname "{name}" ct state invalid drop
        iifname "{name}" ip daddr {dns_address} udp dport {dns_port} accept
        iifname "{name}" ip daddr {dns_address} tcp dport {dns_port} accept
{proxy_rule}        iifname "{name}" meta nfproto ipv4 drop
        iifname "{name}" meta nfproto ipv6 drop
    }}

    # Block IPv6 frames that avoid the forward hook through direct on-link
    # delivery, link-local addressing, or multicast.
    chain output_ipv6_block {{
        type filter hook output priority filter; policy accept;
        oifname "{name}" meta nfproto ipv6 drop
    }}
}}"#,
        dns_address = dns.address,
        dns_port = dns.port,
    )
}

fn render_ruleset_transaction(
    name: &str,
    host_services: HostServiceAccess,
    table_exists: bool,
) -> String {
    let replacement = render_base_ruleset(name, host_services);
    if table_exists {
        format!("delete table inet outcall\n{replacement}")
    } else {
        replacement
    }
}

async fn read_netfilter_setting(path: &str) -> String {
    match tokio::fs::read_to_string(path).await {
        Ok(value) => value.trim().to_string(),
        Err(error) => format!("unavailable ({error})"),
    }
}

fn netfilter_settings_enforceable(ipv4: &str, ipv6: &str) -> bool {
    ipv4.trim() == "1" && ipv6.trim() == "1"
}

pub fn first_gateway_from_subnet_block(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid subnet block \"{cidr}\": missing prefix"))?;
    let base: Ipv4Addr = ip_str
        .parse()
        .with_context(|| format!("invalid IP in subnet block \"{cidr}\""))?;
    let prefix: u8 = prefix_str
        .parse()
        .with_context(|| format!("invalid prefix in subnet block \"{cidr}\""))?;
    if prefix > 24 {
        anyhow::bail!("subnet block must be /24 or larger (got /{prefix})");
    }

    let total = u32::from_be_bytes(base.octets());
    let first_24 = total & !0xff;
    let mut gateway_octets = Ipv4Addr::from(first_24.to_be_bytes()).octets();
    gateway_octets[3] = 1;
    Ok((Ipv4Addr::from(gateway_octets), 24))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::{
        first_gateway_from_subnet_block, netfilter_settings_enforceable, render_base_ruleset,
        render_ruleset_transaction, BridgeError, HostServiceAccess, HostServiceEndpoint,
    };

    #[test]
    fn derives_first_gateway_for_default_block() {
        let (gateway, prefix_len) =
            first_gateway_from_subnet_block("10.200.0.0/16").expect("gateway");
        assert_eq!(gateway.to_string(), "10.200.0.1");
        assert_eq!(prefix_len, 24);
    }

    #[test]
    fn derives_first_gateway_for_non_default_block() {
        let (gateway, prefix_len) =
            first_gateway_from_subnet_block("172.30.8.0/20").expect("gateway");
        assert_eq!(gateway.to_string(), "172.30.8.1");
        assert_eq!(prefix_len, 24);
    }

    #[test]
    fn listener_access_maps_unspecified_addresses_to_the_bridge_gateway() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let access = HostServiceAccess::from_listeners(
            gateway,
            "0.0.0.0:5353".parse().unwrap(),
            Some("0.0.0.0:8181".parse().unwrap()),
        )
        .unwrap();

        assert_eq!(
            access,
            HostServiceAccess {
                dns: HostServiceEndpoint {
                    address: gateway,
                    port: 5353,
                },
                proxy: Some(HostServiceEndpoint {
                    address: gateway,
                    port: 8181,
                }),
            }
        );
    }

    #[test]
    fn listener_access_rejects_ipv6_endpoints() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let dns: SocketAddr = "[::1]:53".parse().unwrap();
        let error = HostServiceAccess::from_listeners(gateway, dns, None).unwrap_err();
        assert!(error.to_string().contains("DNS listener"));
    }

    #[test]
    fn listener_access_rejects_ephemeral_ports() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let dns: SocketAddr = "10.200.0.1:0".parse().unwrap();
        let error = HostServiceAccess::from_listeners(gateway, dns, None).unwrap_err();
        assert!(error.to_string().contains("fixed, non-zero port"));
    }

    #[test]
    fn base_rules_allow_only_declared_host_services() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let ruleset =
            render_base_ruleset("outcall0", HostServiceAccess::default_for_gateway(gateway));

        assert!(ruleset.contains("iifname \"outcall0\" ip daddr 10.200.0.1 udp dport 53 accept"));
        assert!(ruleset.contains("iifname \"outcall0\" ip daddr 10.200.0.1 tcp dport 8080 accept"));
        assert!(ruleset.contains("iifname \"outcall0\" meta nfproto ipv4 drop"));
        assert!(ruleset.contains("iifname \"outcall0\" meta nfproto ipv6 drop"));
        assert!(!ruleset.contains("dport 22 accept"));
    }

    #[test]
    fn base_rules_omit_proxy_exception_when_proxy_is_disabled() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let access = HostServiceAccess {
            dns: HostServiceEndpoint {
                address: gateway,
                port: 53,
            },
            proxy: None,
        };

        let ruleset = render_base_ruleset("outcall0", access);
        assert!(!ruleset.contains("tcp dport 8080 accept"));
        assert!(ruleset.contains("meta nfproto ipv4 drop"));
    }

    #[test]
    fn existing_policy_is_replaced_in_one_nft_transaction() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let ruleset = render_ruleset_transaction(
            "outcall0",
            HostServiceAccess::default_for_gateway(gateway),
            true,
        );

        assert!(ruleset.starts_with("delete table inet outcall\ntable inet outcall"));
        assert_eq!(ruleset.matches("table inet outcall").count(), 2);
    }

    #[test]
    fn both_bridge_netfilter_hooks_are_required() {
        assert!(netfilter_settings_enforceable("1\n", "1"));
        assert!(!netfilter_settings_enforceable("0", "1"));
        assert!(!netfilter_settings_enforceable("1", "0"));
        assert!(!netfilter_settings_enforceable("missing", "1"));
    }

    #[test]
    fn bridge_operation_errors_preserve_the_source_message() {
        let error = BridgeError::Operation(anyhow::anyhow!("security preflight failed"));
        assert_eq!(
            error.to_string(),
            "bridge operation failed: security preflight failed"
        );
    }
}
