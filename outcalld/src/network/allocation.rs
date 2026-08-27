use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};
use bollard::network::ListNetworksOptions;
use bollard::Docker;

use super::NetworkManager;
use crate::docker::operation;
use crate::network_cidr::{networks_overlap, parse_agent_subnet, parse_docker_subnet};

impl NetworkManager {
    pub(super) async fn allocate_subnet(&self, docker: &Docker) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let used = self.collect_used_subnets(docker).await?;

        for (network, gateway) in self.subnet_block.iter_24() {
            let candidate = parse_agent_subnet(&format!("{network}/24"))?;
            if !used.iter().any(|used| networks_overlap(candidate, *used)) {
                return Ok((network, gateway));
            }
        }
        Err(anyhow!(
            "no available subnets in {}",
            self.subnet_block_cidr()
        ))
    }

    pub(super) async fn check_subnet_collision(
        &self,
        docker: &Docker,
        subnet: ipnet::Ipv4Net,
    ) -> Result<()> {
        if self.is_subnet_in_use(docker, subnet).await? {
            anyhow::bail!("subnet {subnet} is already in use by another Docker network");
        }
        Ok(())
    }

    pub(super) async fn is_subnet_in_use(
        &self,
        docker: &Docker,
        subnet: ipnet::Ipv4Net,
    ) -> Result<bool> {
        let used = self.collect_used_subnets(docker).await?;
        Ok(used.iter().any(|used| networks_overlap(subnet, *used)))
    }

    async fn collect_used_subnets(&self, docker: &Docker) -> Result<Vec<ipnet::Ipv4Net>> {
        let networks = operation::run(
            "list Docker networks for collision check",
            docker.list_networks(None::<ListNetworksOptions<&str>>),
        )
        .await?;
        let mut used = Vec::new();
        for network in networks {
            for config in network
                .ipam
                .into_iter()
                .flat_map(|ipam| ipam.config.unwrap_or_default())
            {
                if let Some(subnet) = config.subnet {
                    if let Some(subnet) = parse_docker_subnet(&subnet)? {
                        used.push(subnet);
                    }
                }
            }
        }
        Ok(used)
    }
}
