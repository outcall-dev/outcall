//! Network Manager (S002) — creates and manages Docker bridge networks
//! that share a single host bridge interface, governed by nftables policy.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bollard::network::{
    CreateNetworkOptions, InspectNetworkOptions, ListNetworksOptions,
};
use bollard::models::{Ipam, IpamConfig};
use bollard::Docker;
use tracing::{info, warn};

use outcall_api::{
    NetworkContainer, NetworkCreateRequest, NetworkCreateResult, NetworkDestroyResult,
    NetworkStatus, DEFAULT_GATEWAY, DEFAULT_NETWORK_NAME, DEFAULT_SUBNET, NETWORK_PREFIX,
};

use crate::bridge::BridgeManager;

/// Manages outcall Docker networks via the Docker Engine API (FR-001, FR-022).
pub struct NetworkManager {
    docker: Docker,
    bridge_name: String,
    /// CIDR block to allocate /24 subnets from (default: `10.200.0.0/16`).
    subnet_block: SubnetBlock,
    bridge: Arc<tokio::sync::Mutex<BridgeManager>>,
}

#[derive(Clone, Debug)]
struct SubnetBlock {
    /// Network address (e.g. 10.200.0.0).
    base: Ipv4Addr,
    /// Block prefix length (e.g. 16).
    prefix: u8,
}

impl SubnetBlock {
    fn parse(cidr: &str) -> Result<Self> {
        let (ip_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| anyhow!("invalid CIDR \"{cidr}\": missing prefix"))?;
        let base: Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("invalid IP in CIDR \"{cidr}\""))?;
        let prefix: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix in CIDR \"{cidr}\""))?;
        if prefix > 24 {
            return Err(anyhow!(
                "subnet block must be /24 or larger (got /{prefix})"
            ));
        }
        Ok(SubnetBlock { base, prefix })
    }

    /// Iterate every /24 contained in this block.
    fn iter_24(&self) -> impl Iterator<Item = (Ipv4Addr, Ipv4Addr)> + '_ {
        let host_bits = 32 - self.prefix as u32;
        let count = if host_bits >= 8 {
            1u32 << (host_bits - 8)
        } else {
            1
        };
        let base_octets = self.base.octets();
        // For prefix in [8..24]: walk the third octet (and second when needed).
        (0..count).map(move |i| {
            let total: u32 = u32::from_be_bytes(base_octets) + (i << 8);
            let net = Ipv4Addr::from(total.to_be_bytes());
            // Gateway is .1 in the /24.
            let mut g = net.octets();
            g[3] = 1;
            (net, Ipv4Addr::from(g))
        })
    }
}

// ── FR-030: RFC 1918 validation ──
fn is_rfc1918(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

impl NetworkManager {
    /// Connect to the local Docker engine. Connection failure is logged but does
    /// not block startup (FR-023).
    pub fn new(
        bridge: Arc<tokio::sync::Mutex<BridgeManager>>,
        bridge_name: impl Into<String>,
        subnet_block_cidr: &str,
    ) -> Result<Arc<Self>> {
        let block = SubnetBlock::parse(subnet_block_cidr)?;
        if !is_rfc1918(block.base) {
            return Err(anyhow!(
                "subnet block {subnet_block_cidr} is not in RFC 1918 private space"
            ));
        }

        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Docker client init failed: {e} — network endpoints will return errors"
                );
                // Still create a client object so endpoint calls return a proper error.
                Docker::connect_with_local_defaults().map_err(|e| anyhow!("{e}"))?
            }
        };

        Ok(Arc::new(Self {
            docker,
            bridge_name: bridge_name.into(),
            subnet_block: block,
            bridge,
        }))
    }

    /// Compute the full network name from a user-supplied suffix.
    /// `None` → `outcall-default`. `Some("staging")` → `outcall-staging`.
    fn full_name(name: Option<&str>) -> Result<String> {
        match name {
            None | Some("") => Ok(DEFAULT_NETWORK_NAME.to_string()),
            Some(n) => {
                // FR-011: validate name characters.
                if n.is_empty() || n.len() > 64 {
                    return Err(anyhow!(
                        "network name must be 1-64 characters (got {})",
                        n.len()
                    ));
                }
                if !n
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(anyhow!(
                        "network name \"{n}\" contains invalid characters (allowed: alphanumeric, -, _)"
                    ));
                }
                if n.starts_with(NETWORK_PREFIX) {
                    Ok(n.to_string())
                } else {
                    Ok(format!("{NETWORK_PREFIX}{n}"))
                }
            }
        }
    }

    /// FR-001-005: create a network. Idempotent.
    pub async fn create_network(
        &self,
        req: NetworkCreateRequest,
    ) -> Result<NetworkCreateResult> {
        // FR-004: bridge must be up.
        if !self.bridge.lock().await.status().await.up {
            return Err(anyhow!("cannot create network: bridge is not up"));
        }

        let full_name = Self::full_name(req.name.as_deref())?;

        // FR-003: idempotent create.
        if let Some(existing) = self.try_inspect(&full_name).await {
            let subnet = first_subnet(&existing);
            info!(name = %full_name, "network already exists — idempotent");
            return Ok(NetworkCreateResult {
                network_id: existing.id.unwrap_or_default(),
                name: full_name,
                created: false,
                subnet,
            });
        }

        // Resolve subnet: explicit > default-network → DEFAULT_SUBNET > auto.
        let (subnet, gateway) = if let Some(s) = req.subnet.as_deref() {
            // FR-015: explicit subnet still checked for collisions.
            self.check_subnet_collision(s).await?;
            let g = req
                .gateway
                .clone()
                .unwrap_or_else(|| derive_gateway(s).unwrap_or_else(|| DEFAULT_GATEWAY.to_string()));
            (s.to_string(), g)
        } else if full_name == DEFAULT_NETWORK_NAME {
            // FR-006: default network uses default subnet (still verify free).
            if self.is_subnet_in_use(DEFAULT_SUBNET).await {
                return Err(anyhow!(
                    "default subnet {DEFAULT_SUBNET} is already in use by another Docker network"
                ));
            }
            (DEFAULT_SUBNET.to_string(), DEFAULT_GATEWAY.to_string())
        } else {
            let (net, gw) = self.allocate_subnet().await?;
            (format!("{net}/24"), gw.to_string())
        };

        // Build IPAM config.
        let ipam_config = IpamConfig {
            subnet: Some(subnet.clone()),
            gateway: Some(gateway.clone()),
            ..Default::default()
        };
        let ipam = Ipam {
            driver: Some("default".to_string()),
            config: Some(vec![ipam_config]),
            options: None,
        };

        // FR-002: Docker bridge driver, attached to our bridge interface.
        let mut options_map = std::collections::HashMap::new();
        options_map.insert(
            "com.docker.network.bridge.name".to_string(),
            self.bridge_name.clone(),
        );

        let opts = CreateNetworkOptions {
            name: full_name.as_str(),
            driver: "bridge",
            ipam,
            options: options_map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
            ..Default::default()
        };

        let resp = self
            .docker
            .create_network(opts)
            .await
            .with_context(|| format!("failed to create network \"{full_name}\""))?;

        info!(name = %full_name, subnet = %subnet, "network created");

        Ok(NetworkCreateResult {
            network_id: resp.id,
            name: full_name,
            created: true,
            subnet: Some(subnet),
        })
    }

    /// FR-016, FR-017: status query — never cached.
    pub async fn inspect_network(&self, name: Option<&str>) -> Result<NetworkStatus> {
        let full_name = Self::full_name(name)?;
        match self.try_inspect(&full_name).await {
            Some(n) => Ok(network_to_status(&full_name, n)),
            None => Ok(NetworkStatus {
                exists: false,
                network_id: None,
                name: full_name,
                subnet: None,
                gateway: None,
                containers: vec![],
            }),
        }
    }

    /// FR-018: list all outcall-managed networks.
    pub async fn list_networks(&self) -> Result<Vec<NetworkStatus>> {
        let nets = self
            .docker
            .list_networks(None::<ListNetworksOptions<&str>>)
            .await
            .context("failed to list Docker networks")?;

        let mut out: Vec<NetworkStatus> = Vec::new();
        for n in nets {
            let name = n.name.clone().unwrap_or_default();
            if !name.starts_with(NETWORK_PREFIX) {
                continue;
            }
            // Re-inspect for the connected-containers map.
            if let Some(detail) = self.try_inspect(&name).await {
                out.push(network_to_status(&name, detail));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// FR-019: refuse if containers connected. FR-020: idempotent on missing.
    pub async fn destroy_network(&self, name: Option<&str>) -> Result<NetworkDestroyResult> {
        let full_name = Self::full_name(name)?;
        let existing = match self.try_inspect(&full_name).await {
            Some(n) => n,
            None => {
                info!(name = %full_name, "destroy: network does not exist (idempotent)");
                return Ok(NetworkDestroyResult {
                    name: full_name,
                    destroyed: false,
                });
            }
        };

        let connected = connected_containers(&existing);
        if !connected.is_empty() {
            let names: Vec<String> = connected.iter().map(|c| c.name.clone()).collect();
            return Err(anyhow!(
                "cannot destroy network \"{full_name}\": {} container{} still connected: {}",
                connected.len(),
                if connected.len() == 1 { "" } else { "s" },
                names.join(", ")
            ));
        }

        self.docker
            .remove_network(&full_name)
            .await
            .with_context(|| format!("failed to remove network \"{full_name}\""))?;

        info!(name = %full_name, "network destroyed");
        Ok(NetworkDestroyResult {
            name: full_name,
            destroyed: true,
        })
    }

    /// Return the configured subnet block CIDR (FR-031).
    pub fn subnet_block_cidr(&self) -> String {
        format!("{}/{}", self.subnet_block.base, self.subnet_block.prefix)
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    async fn try_inspect(&self, name: &str) -> Option<bollard::models::Network> {
        self.docker
            .inspect_network(name, None::<InspectNetworkOptions<&str>>)
            .await
            .ok()
    }

    /// FR-012, FR-013: find the next free /24 in the subnet block.
    async fn allocate_subnet(&self) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let used = self.collect_used_subnets().await;

        for (net, gw) in self.subnet_block.iter_24() {
            let cidr = format!("{net}/24");
            if !used.contains(&cidr) {
                return Ok((net, gw));
            }
        }
        Err(anyhow!(
            "no available subnets in {}",
            self.subnet_block_cidr()
        ))
    }

    async fn check_subnet_collision(&self, subnet: &str) -> Result<()> {
        if self.is_subnet_in_use(subnet).await {
            return Err(anyhow!(
                "subnet {subnet} is already in use by another Docker network"
            ));
        }
        Ok(())
    }

    async fn is_subnet_in_use(&self, subnet: &str) -> bool {
        let used = self.collect_used_subnets().await;
        used.contains(subnet)
    }

    async fn collect_used_subnets(&self) -> HashSet<String> {
        let mut used = HashSet::new();
        let nets = match self
            .docker
            .list_networks(None::<ListNetworksOptions<&str>>)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!("failed to list Docker networks for collision check: {e}");
                return used;
            }
        };
        for n in nets {
            if let Some(ipam) = n.ipam {
                if let Some(configs) = ipam.config {
                    for c in configs {
                        if let Some(s) = c.subnet {
                            used.insert(s);
                        }
                    }
                }
            }
        }
        used
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────

fn derive_gateway(subnet_cidr: &str) -> Option<String> {
    let (ip_str, _) = subnet_cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let mut o = ip.octets();
    o[3] = 1;
    Some(Ipv4Addr::from(o).to_string())
}

fn first_subnet(n: &bollard::models::Network) -> Option<String> {
    n.ipam
        .as_ref()?
        .config
        .as_ref()?
        .first()?
        .subnet
        .clone()
}

fn first_gateway(n: &bollard::models::Network) -> Option<String> {
    n.ipam
        .as_ref()?
        .config
        .as_ref()?
        .first()?
        .gateway
        .clone()
}

fn connected_containers(n: &bollard::models::Network) -> Vec<NetworkContainer> {
    let containers = match &n.containers {
        Some(c) => c,
        None => return vec![],
    };
    let mut out: Vec<NetworkContainer> = containers
        .iter()
        .map(|(_id, ep)| NetworkContainer {
            name: ep.name.clone().unwrap_or_default(),
            ipv4_address: ep
                .ipv4_address
                .clone()
                .unwrap_or_default()
                .split('/')
                .next()
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn network_to_status(name: &str, n: bollard::models::Network) -> NetworkStatus {
    let containers = connected_containers(&n);
    let subnet = first_subnet(&n);
    let gateway = first_gateway(&n);
    NetworkStatus {
        exists: true,
        network_id: n.id,
        name: name.to_string(),
        subnet,
        gateway,
        containers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_name_default() {
        assert_eq!(NetworkManager::full_name(None).unwrap(), "outcall-default");
        assert_eq!(NetworkManager::full_name(Some("")).unwrap(), "outcall-default");
    }

    #[test]
    fn full_name_prepends_prefix() {
        assert_eq!(
            NetworkManager::full_name(Some("staging")).unwrap(),
            "outcall-staging"
        );
    }

    #[test]
    fn full_name_keeps_existing_prefix() {
        assert_eq!(
            NetworkManager::full_name(Some("outcall-prod")).unwrap(),
            "outcall-prod"
        );
    }

    #[test]
    fn full_name_rejects_invalid() {
        assert!(NetworkManager::full_name(Some("bad name")).is_err());
        assert!(NetworkManager::full_name(Some("bad/name")).is_err());
    }

    #[test]
    fn full_name_allows_underscore_hyphen() {
        assert!(NetworkManager::full_name(Some("a-b_c")).is_ok());
    }

    #[test]
    fn full_name_length_limit() {
        let s: String = std::iter::repeat('a').take(65).collect();
        assert!(NetworkManager::full_name(Some(&s)).is_err());
    }

    #[test]
    fn subnet_block_iter_24_count() {
        let b = SubnetBlock::parse("10.200.0.0/16").unwrap();
        let collected: Vec<_> = b.iter_24().take(3).collect();
        assert_eq!(collected[0].0.to_string(), "10.200.0.0");
        assert_eq!(collected[0].1.to_string(), "10.200.0.1");
        assert_eq!(collected[1].0.to_string(), "10.200.1.0");
        assert_eq!(collected[2].0.to_string(), "10.200.2.0");
        assert_eq!(b.iter_24().count(), 256);
    }

    #[test]
    fn subnet_block_iter_24_block() {
        let b = SubnetBlock::parse("10.42.0.0/22").unwrap();
        // /22 contains 4 /24 subnets
        assert_eq!(b.iter_24().count(), 4);
    }

    #[test]
    fn rfc1918_check() {
        assert!(is_rfc1918("10.200.0.0".parse().unwrap()));
        assert!(is_rfc1918("172.16.0.0".parse().unwrap()));
        assert!(is_rfc1918("172.31.255.255".parse().unwrap()));
        assert!(is_rfc1918("192.168.1.1".parse().unwrap()));
        assert!(!is_rfc1918("8.8.8.8".parse().unwrap()));
        assert!(!is_rfc1918("172.32.0.0".parse().unwrap()));
        assert!(!is_rfc1918("172.15.0.0".parse().unwrap()));
    }

    #[test]
    fn parse_invalid_cidr() {
        assert!(SubnetBlock::parse("not-a-cidr").is_err());
        assert!(SubnetBlock::parse("10.0.0.0/40").is_err());
        // /25 is too small to allocate /24s from
        assert!(SubnetBlock::parse("10.0.0.0/25").is_err());
    }

    #[test]
    fn derive_gateway_from_subnet() {
        assert_eq!(
            derive_gateway("10.200.5.0/24"),
            Some("10.200.5.1".to_string())
        );
    }
}
