//! Network Manager (S002) — creates and manages Docker bridge networks
//! that share a single host bridge interface, governed by nftables policy.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bollard::models::{Ipam, IpamConfig};
use bollard::network::{CreateNetworkOptions, InspectNetworkOptions, ListNetworksOptions};
use bollard::Docker;
use tracing::{info, warn};

use outcall_api::{
    NetworkCreateRequest, NetworkCreateResult, NetworkDestroyResult, NetworkStatus,
    DEFAULT_NETWORK_NAME, NETWORK_PREFIX,
};

use crate::{
    bridge::BridgeManager,
    docker::{operation, DockerManager},
    network_cidr::{parse_agent_subnet, resolve_gateway, AllocationBlock},
};

mod allocation;
mod metadata;
mod name;

/// Manages outcall Docker networks via the Docker Engine API (FR-001, FR-022).
pub struct NetworkManager {
    docker: Option<Docker>,
    bridge_name: String,
    /// CIDR block to allocate /24 subnets from (default: `10.200.0.0/16`).
    subnet_block: AllocationBlock,
    bridge: Arc<tokio::sync::Mutex<BridgeManager>>,
}

impl NetworkManager {
    /// Connect to the local Docker engine. Connection failure is logged but does
    /// not block startup (FR-023).
    pub fn new(
        bridge: Arc<tokio::sync::Mutex<BridgeManager>>,
        bridge_name: impl Into<String>,
        subnet_block_cidr: &str,
        docker_manager: &DockerManager,
    ) -> Result<Arc<Self>> {
        let block = AllocationBlock::parse(subnet_block_cidr)?;

        let docker = docker_manager.client();
        if docker.is_none() {
            warn!("Docker unavailable — network management endpoints are disabled");
        }

        Ok(Arc::new(Self {
            docker,
            bridge_name: bridge_name.into(),
            subnet_block: block,
            bridge,
        }))
    }

    /// FR-001-005: create a network. Idempotent.
    pub async fn create_network(&self, req: NetworkCreateRequest) -> Result<NetworkCreateResult> {
        validate_create_request(&req)?;
        let docker = self.docker()?;

        // FR-004: bridge must be up.
        if !self.bridge.lock().await.status().await?.up {
            return Err(anyhow!("cannot create network: bridge is not up"));
        }

        let full_name = name::full_name(req.name.as_deref())?;

        // FR-003: idempotent create.
        if let Some(existing) = self.try_inspect(docker, &full_name).await? {
            self.validate_existing_configuration(&existing, &full_name, &req)?;
            info!(name = %full_name, "network already exists — idempotent");
            return metadata::existing_result(existing, full_name, &self.bridge_name);
        }

        // Resolve subnet: explicit > first subnet for default network > auto.
        let (subnet, gateway) = if let Some(s) = req.subnet.as_deref() {
            // FR-015: explicit subnet still checked for collisions.
            let subnet = parse_agent_subnet(s)?;
            self.check_subnet_collision(docker, subnet).await?;
            let gateway = resolve_gateway(subnet, req.gateway.as_deref())?;
            (subnet.to_string(), gateway)
        } else if full_name == DEFAULT_NETWORK_NAME {
            // FR-006, FR-029: default network uses the active block's first /24.
            let (subnet, gateway) = self.subnet_block.first_subnet();
            let requested = parse_agent_subnet(&subnet)?;
            if self.is_subnet_in_use(docker, requested).await? {
                return Err(anyhow!(
                    "default subnet {subnet} is already in use by another Docker network"
                ));
            }
            (subnet, gateway)
        } else {
            let (net, gw) = self.allocate_subnet(docker).await?;
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
            options: options_map
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            ..Default::default()
        };

        let response = match operation::run(
            format!("create network {full_name}"),
            docker.create_network(opts),
        )
        .await
        {
            Ok(response) => response,
            Err(error) if error.status_code() == Some(409) => {
                let existing = self
                    .try_inspect(docker, &full_name)
                    .await?
                    .with_context(|| {
                        format!(
                            "Docker reported a create conflict for \"{full_name}\", but the network could not be inspected"
                        )
                    })?;
                info!(name = %full_name, "network was created concurrently — idempotent");
                metadata::validate_configuration(&existing, &subnet, &gateway)?;
                return metadata::existing_result(existing, full_name, &self.bridge_name);
            }
            Err(error) => return Err(error.into()),
        };

        if !response.warning.is_empty() {
            warn!(name = %full_name, warning = %response.warning, "Docker created network with warning");
        }
        if response.id.trim().is_empty() {
            return Err(anyhow!(
                "Docker created network \"{full_name}\" without returning an immutable ID; refusing unsafe name-based cleanup"
            ));
        }

        let created = match self.try_inspect(docker, &response.id).await {
            Ok(Some(network)) => network,
            Ok(None) => {
                return rollback_created_network(
                    docker,
                    &response.id,
                    anyhow!("network \"{full_name}\" missing after Docker create"),
                )
                .await;
            }
            Err(error) => {
                return rollback_created_network(docker, &response.id, error).await;
            }
        };
        let inspected_id = match metadata::validate_created(
            &created,
            &response.id,
            &full_name,
            &self.bridge_name,
            &subnet,
            &gateway,
        ) {
            Ok(id) => id,
            Err(error) => {
                return rollback_created_network(docker, &response.id, error).await;
            }
        };

        info!(name = %full_name, subnet = %subnet, "network created");

        Ok(NetworkCreateResult {
            network_id: inspected_id,
            name: full_name,
            created: true,
            subnet: Some(subnet),
        })
    }

    /// FR-016, FR-017: status query — never cached.
    pub async fn inspect_network(&self, name: Option<&str>) -> Result<NetworkStatus> {
        let docker = self.docker()?;
        let full_name = name::full_name(name)?;
        match self.try_inspect(docker, &full_name).await? {
            Some(network) => {
                metadata::validate_identity(&network, &full_name, &self.bridge_name)?;
                metadata::to_status(&full_name, network)
            }
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
        let docker = self.docker()?;
        let nets = operation::run(
            "list Docker networks",
            docker.list_networks(None::<ListNetworksOptions<&str>>),
        )
        .await?;

        let mut out: Vec<NetworkStatus> = Vec::new();
        for n in nets {
            let name = n.name.clone().unwrap_or_default();
            if !name.starts_with(NETWORK_PREFIX) {
                continue;
            }
            // Re-inspect for the connected-containers map.
            if let Some(detail) = self.try_inspect(docker, &name).await? {
                if let Err(error) = metadata::validate_identity(&detail, &name, &self.bridge_name) {
                    warn!(name = %name, %error, "ignoring prefixed Docker network that is not managed by Outcall");
                    continue;
                }
                out.push(metadata::to_status(&name, detail)?);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// FR-019: refuse if containers connected. FR-020: idempotent on missing.
    pub async fn destroy_network(&self, name: Option<&str>) -> Result<NetworkDestroyResult> {
        let docker = self.docker()?;
        let full_name = name::full_name(name)?;
        let existing = match self.try_inspect(docker, &full_name).await? {
            Some(n) => n,
            None => {
                info!(name = %full_name, "destroy: network does not exist (idempotent)");
                return Ok(NetworkDestroyResult {
                    name: full_name,
                    destroyed: false,
                });
            }
        };

        metadata::validate_identity(&existing, &full_name, &self.bridge_name)?;

        let connected = metadata::connected_containers(&existing)?;
        if !connected.is_empty() {
            let names: Vec<String> = connected.iter().map(|c| c.name.clone()).collect();
            return Err(anyhow!(
                "cannot destroy network \"{full_name}\": {} container{} still connected: {}",
                connected.len(),
                if connected.len() == 1 { "" } else { "s" },
                names.join(", ")
            ));
        }

        operation::run(
            format!("remove network {full_name}"),
            docker.remove_network(&full_name),
        )
        .await?;

        info!(name = %full_name, "network destroyed");
        Ok(NetworkDestroyResult {
            name: full_name,
            destroyed: true,
        })
    }

    /// Return the configured subnet block CIDR (FR-031).
    pub fn subnet_block_cidr(&self) -> String {
        self.subnet_block.cidr()
    }

    /// Returns `true` when Docker-backed network management is unavailable.
    pub fn is_unavailable(&self) -> bool {
        self.docker.is_none()
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn docker(&self) -> Result<&Docker> {
        self.docker.as_ref().context(
            "Docker manager unavailable: network management requires a reachable Docker Engine",
        )
    }

    async fn try_inspect(
        &self,
        docker: &Docker,
        name: &str,
    ) -> Result<Option<bollard::models::Network>> {
        match operation::run(
            format!("inspect network {name}"),
            docker.inspect_network(name, None::<InspectNetworkOptions<&str>>),
        )
        .await
        {
            Ok(network) => Ok(Some(network)),
            Err(error) if error.status_code() == Some(404) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn validate_existing_configuration(
        &self,
        network: &bollard::models::Network,
        full_name: &str,
        request: &NetworkCreateRequest,
    ) -> Result<()> {
        if let Some(subnet) = request.subnet.as_deref() {
            let subnet = parse_agent_subnet(subnet)?;
            let gateway = resolve_gateway(subnet, request.gateway.as_deref())?;
            return metadata::validate_configuration(network, &subnet.to_string(), &gateway);
        }

        if full_name == DEFAULT_NETWORK_NAME {
            let (subnet, gateway) = self.subnet_block.first_subnet();
            return metadata::validate_configuration(network, &subnet, &gateway);
        }

        let subnet_text = metadata::first_subnet(network)
            .context("existing Outcall network has no IPv4 subnet")?;
        let subnet = parse_agent_subnet(&subnet_text)?;
        if !self.subnet_block.contains_allocated_subnet(subnet) {
            anyhow::bail!(
                "existing Outcall network subnet {subnet} is not an allocated /24 in {}",
                self.subnet_block_cidr()
            );
        }
        let expected_gateway = resolve_gateway(subnet, None)?;
        metadata::validate_configuration(network, &subnet.to_string(), &expected_gateway)
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────

fn validate_create_request(request: &NetworkCreateRequest) -> Result<()> {
    if request.gateway.is_some() && request.subnet.is_none() {
        anyhow::bail!("an explicit network gateway requires an explicit subnet");
    }
    Ok(())
}

async fn rollback_created_network<T>(
    docker: &Docker,
    network_id: &str,
    error: anyhow::Error,
) -> Result<T> {
    match operation::run(
        format!("roll back network {network_id}"),
        docker.remove_network(network_id),
    )
    .await
    {
        Ok(()) => Err(error),
        Err(cleanup) if cleanup.status_code() == Some(404) => Err(error),
        Err(cleanup) => anyhow::bail!("{error}; network cleanup also failed: {cleanup}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bollard::models::{Ipam, IpamConfig, Network};

    use super::*;

    async fn manager() -> Arc<NetworkManager> {
        let gateway = "10.200.0.1".parse().unwrap();
        let bridge = BridgeManager::new(
            Some("outcall0"),
            gateway,
            16,
            crate::bridge::HostServiceAccess::default_for_gateway(gateway),
        )
        .await
        .unwrap();
        NetworkManager::new(
            Arc::new(tokio::sync::Mutex::new(bridge)),
            "outcall0",
            "10.200.0.0/16",
            &DockerManager::new_unavailable(),
        )
        .unwrap()
    }

    fn network(subnet: &str, gateway: &str) -> Network {
        Network {
            ipam: Some(Ipam {
                config: Some(vec![IpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: Some(gateway.to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            options: Some(HashMap::new()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unavailable_docker_does_not_block_manager_initialization() {
        let manager = manager().await;

        assert!(manager.is_unavailable());
        let error = manager.list_networks().await.unwrap_err();
        assert!(error.to_string().contains("Docker manager unavailable"));
    }

    #[test]
    fn gateway_without_subnet_is_rejected() {
        let request = NetworkCreateRequest {
            name: None,
            subnet: None,
            gateway: Some("10.200.0.1".to_string()),
        };
        assert!(validate_create_request(&request).is_err());
    }

    #[tokio::test]
    async fn existing_network_must_match_requested_or_allocated_configuration() {
        let manager = manager().await;
        let default_request = NetworkCreateRequest {
            name: None,
            subnet: None,
            gateway: None,
        };
        assert!(manager
            .validate_existing_configuration(
                &network("10.200.0.0/24", "10.200.0.1"),
                DEFAULT_NETWORK_NAME,
                &default_request,
            )
            .is_ok());
        assert!(manager
            .validate_existing_configuration(
                &network("10.200.1.0/24", "10.200.1.1"),
                DEFAULT_NETWORK_NAME,
                &default_request,
            )
            .is_err());

        let automatic_request = NetworkCreateRequest {
            name: Some("worker".to_string()),
            subnet: None,
            gateway: None,
        };
        assert!(manager
            .validate_existing_configuration(
                &network("10.200.12.0/24", "10.200.12.1"),
                "outcall-worker",
                &automatic_request,
            )
            .is_ok());
        assert!(manager
            .validate_existing_configuration(
                &network("10.201.12.0/24", "10.201.12.1"),
                "outcall-worker",
                &automatic_request,
            )
            .is_err());
    }
}
