use anyhow::{Context, Result};
use bollard::models::Network;
use outcall_api::{NetworkContainer, NetworkCreateResult, NetworkStatus};

pub(super) fn first_subnet(network: &Network) -> Option<String> {
    network
        .ipam
        .as_ref()?
        .config
        .as_ref()?
        .first()?
        .subnet
        .clone()
}

pub(super) fn first_gateway(network: &Network) -> Option<String> {
    network
        .ipam
        .as_ref()?
        .config
        .as_ref()?
        .first()?
        .gateway
        .clone()
}

pub(super) fn connected_containers(network: &Network) -> Result<Vec<NetworkContainer>> {
    let Some(containers) = &network.containers else {
        return Ok(vec![]);
    };
    let mut result = containers
        .values()
        .map(|endpoint| {
            let name = endpoint
                .name
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .context("connected Docker endpoint had no container name")?
                .to_string();
            let ipv4_address = endpoint
                .ipv4_address
                .as_deref()
                .context("connected Docker endpoint had no IPv4 address")?
                .parse::<ipnet::Ipv4Net>()
                .context("connected Docker endpoint had an invalid IPv4 address")?
                .addr()
                .to_string();
            Ok(NetworkContainer { name, ipv4_address })
        })
        .collect::<Result<Vec<_>>>()?;
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

pub(super) fn to_status(name: &str, network: Network) -> Result<NetworkStatus> {
    Ok(NetworkStatus {
        exists: true,
        network_id: Some(required_id(&network, name)?),
        name: name.to_string(),
        subnet: first_subnet(&network),
        gateway: first_gateway(&network),
        containers: connected_containers(&network)?,
    })
}

pub(super) fn existing_result(
    network: Network,
    name: String,
    bridge_name: &str,
) -> Result<NetworkCreateResult> {
    validate_identity(&network, &name, bridge_name)?;
    Ok(NetworkCreateResult {
        network_id: required_id(&network, &name)?,
        subnet: first_subnet(&network),
        name,
        created: false,
    })
}

pub(super) fn validate_created(
    network: &Network,
    created_id: &str,
    name: &str,
    bridge_name: &str,
    subnet: &str,
    gateway: &str,
) -> Result<String> {
    validate_identity(network, name, bridge_name)?;
    validate_configuration(network, subnet, gateway)?;
    let inspected_id = required_id(network, name)?;
    if created_id != inspected_id {
        anyhow::bail!("network \"{name}\" identity changed during creation");
    }
    Ok(inspected_id)
}

pub(super) fn required_id(network: &Network, name: &str) -> Result<String> {
    network
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .with_context(|| format!("Docker network \"{name}\" has no immutable ID"))
}

pub(super) fn validate_configuration(
    network: &Network,
    expected_subnet: &str,
    expected_gateway: &str,
) -> Result<()> {
    let actual_subnet = first_subnet(network).context("created Docker network has no subnet")?;
    let actual_gateway = first_gateway(network).context("created Docker network has no gateway")?;
    if actual_subnet != expected_subnet {
        anyhow::bail!(
            "created Docker network subnet is {actual_subnet}, expected {expected_subnet}"
        );
    }
    if actual_gateway != expected_gateway {
        anyhow::bail!(
            "created Docker network gateway is {actual_gateway}, expected {expected_gateway}"
        );
    }
    Ok(())
}

pub(super) fn validate_identity(
    network: &Network,
    expected_name: &str,
    bridge_name: &str,
) -> Result<()> {
    let actual_name = network
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .context("Docker network has no name")?;
    if actual_name != expected_name {
        anyhow::bail!(
            "Docker network identity mismatch: expected name \"{expected_name}\", got \"{actual_name}\""
        );
    }
    required_id(network, expected_name)?;
    let configured_bridge = network
        .options
        .as_ref()
        .and_then(|options| options.get("com.docker.network.bridge.name"))
        .map(String::as_str);
    crate::managed_network::validate_managed_network(
        expected_name,
        network.driver.as_deref(),
        configured_bridge,
        bridge_name,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bollard::models::{Ipam, IpamConfig};

    use super::*;

    fn managed_network(id: Option<&str>) -> Network {
        Network {
            id: id.map(str::to_string),
            name: Some("outcall-default".to_string()),
            driver: Some("bridge".to_string()),
            options: Some(HashMap::from([(
                "com.docker.network.bridge.name".to_string(),
                "outcall0".to_string(),
            )])),
            ipam: Some(Ipam {
                config: Some(vec![IpamConfig {
                    subnet: Some("10.200.0.0/24".to_string()),
                    gateway: Some("10.200.0.1".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn existing_network_requires_identity_and_id() {
        let result = existing_result(
            managed_network(Some("network-id")),
            "outcall-default".to_string(),
            "outcall0",
        )
        .unwrap();
        assert_eq!(result.network_id, "network-id");
        assert!(!result.created);
        assert!(existing_result(
            managed_network(None),
            "outcall-default".to_string(),
            "outcall0"
        )
        .is_err());
    }

    #[test]
    fn created_configuration_and_name_must_match() {
        let network = managed_network(Some("network-id"));
        assert!(validate_created(
            &network,
            "network-id",
            "outcall-default",
            "outcall0",
            "10.200.0.0/24",
            "10.200.0.1"
        )
        .is_ok());
        assert!(validate_configuration(&network, "10.200.1.0/24", "10.200.0.1").is_err());

        let mut wrong_name = network;
        wrong_name.name = Some("outcall-other".to_string());
        assert!(validate_identity(&wrong_name, "outcall-default", "outcall0").is_err());
    }

    #[test]
    fn connected_container_metadata_is_required() {
        let mut network = managed_network(Some("network-id"));
        network.containers = Some(HashMap::from([(
            "container-id".to_string(),
            bollard::models::NetworkContainer {
                name: Some("project-1".to_string()),
                ipv4_address: Some("10.200.0.2/24".to_string()),
                ..Default::default()
            },
        )]));
        let containers = connected_containers(&network).unwrap();
        assert_eq!(containers[0].name, "project-1");
        assert_eq!(containers[0].ipv4_address, "10.200.0.2");

        network
            .containers
            .as_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .name = None;
        assert!(connected_containers(&network).is_err());
    }
}
