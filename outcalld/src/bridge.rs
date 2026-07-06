use std::net::Ipv4Addr;
use std::process::Stdio;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::{Handle, LinkBridge, LinkUnspec};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

use outcall_api::BridgeStatus;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("netlink connection failed")]
    Connection(#[source] std::io::Error),

    #[error("bridge operation failed")]
    Operation(#[source] anyhow::Error),

    #[error("nftables operation failed: {0}")]
    Nftables(String),
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
    handle: Handle,
    index: Option<u32>,
}

impl BridgeManager {
    /// Create a new bridge manager. Does not touch the kernel yet.
    pub async fn new(
        name: Option<&str>,
        gateway_ip: Ipv4Addr,
        gateway_prefix_len: u8,
    ) -> Result<Self, BridgeError> {
        let (conn, handle, _) = rtnetlink::new_connection().map_err(BridgeError::Connection)?;
        tokio::spawn(conn);

        Ok(Self {
            name: name.unwrap_or(outcall_api::DEFAULT_BRIDGE_NAME).to_string(),
            gateway_ip,
            gateway_prefix_len,
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
    ///   2. Write `1` to `/proc/sys/net/bridge/bridge-nf-call-iptables`.
    ///
    /// Both steps are best-effort: we warn but don't fail. The reasoning
    /// is operational — if the module can't load or the sysctl can't be
    /// written, the daemon is still useful for proxy-mediated egress
    /// rules; only L2-bridged container-to-container enforcement degrades.
    /// A loud `warn!` makes the gap discoverable instead of silent.
    async fn enable_bridge_netfilter(&self) {
        // 1) Module load. Ignore output; if it's already loaded or built
        // in, modprobe returns 0 anyway. If we lack CAP_SYS_MODULE, this
        // fails and we just check the sysctl below.
        let _ = Command::new("modprobe").arg("br_netfilter").output().await;

        // 2) Sysctl write via direct procfs path — sysctl(1) isn't always
        // installed in minimal containers, procfs always is.
        const PATH: &str = "/proc/sys/net/bridge/bridge-nf-call-iptables";
        match tokio::fs::write(PATH, b"1").await {
            Ok(()) => info!(sysctl = PATH, "bridge netfilter enabled (T-2 enforceable)"),
            Err(e) => warn!(
                sysctl = PATH,
                error = %e,
                "could not enable bridge-nf-call-iptables; container-to-container traffic on \
                 the same bridge will bypass nftables hooks (T-2 silently unenforced). \
                 Load the br_netfilter module on the host or set this sysctl manually."
            ),
        }
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
            .add(idx, self.gateway_ip, self.gateway_prefix_len)
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
        // Clean slate — remove table if it already exists (ignore errors)
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "outcall"])
            .output()
            .await;

        let ruleset = self.base_ruleset();
        self.run_nft(&ruleset).await?;

        info!("base nftables rules applied");
        Ok(())
    }

    /// Generate the base nftables ruleset.
    ///
    /// Policy: the chain default is `drop` — the deepest enforcement layer
    /// must fail closed. We allow all forwarded traffic that does NOT
    /// transit our bridge so we don't break unrelated networking on the
    /// host. Anything that does transit the bridge must be either
    /// established/related (handled here) or explicitly allowed by a
    /// dynamic rule inserted at higher priority. Audit C-3.
    ///
    /// IPv6 defence-in-depth (BYPASS-11):
    ///
    /// The `inet` family covers both IPv4 and IPv6, so the FORWARD chain
    /// policy drop applies to both. However, certain IPv6 traffic — notably
    /// link-local multicast (ff02::/16) and packets that exit via a directly-
    /// connected route on the agent veth rather than being forwarded through
    /// the bridge — can bypass the FORWARD hook entirely. To close this:
    ///
    ///   1. In the `forward` chain we add an explicit `meta nfproto ipv6 drop`
    ///      before the established/related rules so any IPv6 packet that *does*
    ///      reach FORWARD with established state is also dropped (defence against
    ///      IPv6 sessions opened before a rule was revoked).  Dynamic allow rules
    ///      are inserted at the chain head (position 0, higher priority) and use
    ///      `ip6 saddr … ip6 daddr … accept`, so legitimately allowed IPv6 flows
    ///      are still accepted before they hit this explicit drop.
    ///
    ///   2. An `output` chain (type filter hook output) drops all IPv6 packets
    ///      exiting a non-loopback interface *from* the agent — this catches
    ///      link-local/multicast packets that never traverse the FORWARD hook.
    ///
    ///   3. An `input` chain drops all unsolicited IPv6 arriving *on* the bridge
    ///      interface that weren't established by the host (RA, NS, multicast
    ///      listener queries etc.) that could otherwise be used to inject routes.
    fn base_ruleset(&self) -> String {
        format!(
            r#"table inet outcall {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
        # Allow non-outcall0 traffic through (unrelated interfaces)
        iifname != "{name}" oifname != "{name}" accept
        # Drop invalid state packets (prevents inkernel tracking exploits)
        iifname "{name}" ct state invalid drop
        oifname "{name}" ct state invalid drop
        # Explicitly block all IPv6 forwarded through the bridge (BYPASS-11).
        # Dynamic allow rules for IPv6 destinations are inserted at chain head
        # (position 0) with higher priority and use `ip6 saddr/daddr accept`,
        # so they are evaluated before this rule.
        iifname "{name}" meta nfproto ipv6 drop
        oifname "{name}" meta nfproto ipv6 drop
        # Accept established/related IPv4 connections
        iifname "{name}" ct state established,related accept
        oifname "{name}" ct state established,related accept
    }}

    # BYPASS-11: catch link-local / multicast IPv6 that leaves the agent veth
    # without being forwarded through the bridge (direct on-link delivery).
    # The output hook fires for every packet leaving any local process OR
    # forwarded out of the host — matching on oifname scopes this to the bridge.
    chain output_ipv6_block {{
        type filter hook output priority filter; policy accept;
        oifname "{name}" meta nfproto ipv6 drop
    }}

    # BYPASS-11: drop unsolicited inbound IPv6 arriving on the bridge
    # (Router Advertisements, Neighbour Solicitations, MLD queries) that
    # could be used to inject a default IPv6 route into an agent namespace.
    chain input_ipv6_block {{
        type filter hook input priority filter; policy accept;
        iifname "{name}" meta nfproto ipv6 ct state new drop
    }}
}}"#,
            name = self.name
        )
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
    use super::first_gateway_from_subnet_block;

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
}
