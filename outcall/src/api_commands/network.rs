use anyhow::Result;
use outcall::request_target;
use outcall_api::{
    NetworkCreateRequest, NetworkCreateResult, NetworkDestroyRequest, NetworkDestroyResult,
    NetworkStatus,
};

use super::response_data;
use crate::daemon_client::{http_get, http_post_json};

pub(crate) fn cmd_network_create(
    socket: &str,
    name: Option<String>,
    subnet: Option<String>,
    gateway: Option<String>,
) -> Result<()> {
    let request = NetworkCreateRequest {
        name,
        subnet,
        gateway,
    };
    let result: NetworkCreateResult =
        response_data(&http_post_json(socket, "/api/v1/network/create", &request)?)?;
    if result.created {
        if let Some(subnet) = result.subnet {
            println!("Network \"{}\" created ({}).", result.name, subnet);
        } else {
            println!("Network \"{}\" created.", result.name);
        }
    } else {
        println!(
            "Network \"{}\" already exists (id: {}).",
            result.name,
            &result.network_id[..12.min(result.network_id.len())]
        );
    }
    Ok(())
}

pub(crate) fn cmd_network_status(socket: &str, name: Option<&str>) -> Result<()> {
    let path = match name {
        Some(name) => format!("/api/v1/network?name={}", request_target::query_value(name)),
        None => "/api/v1/network".to_string(),
    };
    let status: NetworkStatus = response_data(&http_get(socket, &path)?)?;
    if !status.exists {
        println!("Network \"{}\" does not exist.", status.name);
        return Ok(());
    }

    println!("Network:      {}", status.name);
    println!("Status:       active");
    if let Some(subnet) = status.subnet {
        println!("Subnet:       {subnet}");
    }
    if let Some(gateway) = status.gateway {
        println!("Gateway:      {gateway}");
    }
    println!("Containers:   {}", status.containers.len());
    for container in status.containers {
        println!("  {:<16} {}", container.name, container.ipv4_address);
    }
    Ok(())
}

pub(crate) fn cmd_network_list(socket: &str) -> Result<()> {
    let networks: Vec<NetworkStatus> = response_data(&http_get(socket, "/api/v1/networks")?)?;
    println!("{:<18} {:<16} CONTAINERS", "NAME", "SUBNET");
    for network in networks {
        println!(
            "{:<18} {:<16} {}",
            network.name,
            network.subnet.unwrap_or_else(|| "-".to_string()),
            network.containers.len()
        );
    }
    Ok(())
}

pub(crate) fn cmd_network_destroy(socket: &str, name: Option<String>) -> Result<()> {
    let request = NetworkDestroyRequest { name };
    let result: NetworkDestroyResult = response_data(&http_post_json(
        socket,
        "/api/v1/network/destroy",
        &request,
    )?)?;
    if result.destroyed {
        println!("Network \"{}\" destroyed.", result.name);
    } else {
        println!("Network \"{}\" did not exist.", result.name);
    }
    Ok(())
}
