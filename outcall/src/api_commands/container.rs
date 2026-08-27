use anyhow::Result;
use outcall::{parse_memory_arg, request_target};
use outcall_api::{
    ContainerCreateRequest, ContainerCreateResult, ContainerInfo, ContainerInspectResult,
    ContainerRemoveRequest, ContainerRemoveResult, ContainerStopRequest, ContainerStopResult,
    ImagePullRequest, ImagePullResult,
};

use super::response_data;
use crate::daemon_client::{http_get, http_post_json};
use crate::docker_support::invoking_container_user;

pub(crate) fn cmd_container_create(
    socket: &str,
    image: String,
    network: Option<String>,
    name: Option<String>,
    memory: Option<String>,
    cpu_shares: Option<i64>,
) -> Result<()> {
    let memory_limit = memory.as_deref().map(parse_memory_arg).transpose()?;
    if let Some(cpu_shares) = cpu_shares
        && !outcall_api::valid_cpu_shares(cpu_shares)
    {
        anyhow::bail!(
            "cpu shares must be at least {}",
            outcall_api::MIN_CPU_SHARES
        );
    }

    let request = ContainerCreateRequest {
        image,
        network,
        name,
        user: invoking_container_user(),
        memory_limit,
        cpu_shares,
        env: None,
        cmd: None,
        entrypoint: None,
        working_dir: None,
        volumes: None,
        include_outcall_helper_mounts: Some(false),
        interactive: None,
        tty: None,
    };
    let result: ContainerCreateResult = response_data(&http_post_json(
        socket,
        "/api/v1/container/create",
        &request,
    )?)?;
    println!("Container \"{}\" created and started.", result.name);
    Ok(())
}

pub(crate) fn cmd_container_list(socket: &str) -> Result<()> {
    let containers: Vec<ContainerInfo> = response_data(&http_get(socket, "/api/v1/containers")?)?;
    if containers.is_empty() {
        println!("No agent containers found.");
        return Ok(());
    }

    println!(
        "{:<30} {:<20} {:<10} {:<20} CREATED",
        "NAME", "IMAGE", "STATE", "NETWORK"
    );
    for container in containers {
        println!(
            "{:<30} {:<20} {:<10} {:<20} {}",
            container.name,
            container.image,
            container.state,
            container.network,
            container.created_at
        );
    }
    Ok(())
}

pub(crate) fn cmd_container_inspect(socket: &str, name: &str) -> Result<()> {
    let container = container_inspect_request(socket, name)?;

    println!("Container:    {}", container.name);
    println!("ID:           {}", container.container_id);
    println!("Image:        {}", container.image);
    println!("State:        {}", container.state);
    println!("Network:      {}", container.network);
    println!("IP Address:   {}", container.ip_address);
    if !container.mounts.is_empty() {
        println!("Mounts:");
        for mount in container.mounts {
            println!("  {mount}");
        }
    }
    if !container.env.is_empty() {
        println!("Environment (values redacted):");
        for variable in container.env {
            println!("  {variable}");
        }
    }
    println!("Created:      {}", container.created_at);
    Ok(())
}

pub(crate) fn container_inspect_request(
    socket: &str,
    name: &str,
) -> Result<ContainerInspectResult> {
    let path = format!(
        "/api/v1/container?name={}",
        request_target::query_value(name)
    );
    response_data(&http_get(socket, &path)?)
}

pub(crate) fn cmd_container_stop(socket: &str, name: &str, timeout: Option<i64>) -> Result<()> {
    if let Some(timeout) = timeout
        && !outcall_api::valid_stop_timeout(timeout)
    {
        anyhow::bail!(
            "container stop timeout must be between 0 and {} seconds",
            outcall_api::MAX_STOP_TIMEOUT_SECS
        );
    }
    let request = ContainerStopRequest {
        name: name.to_string(),
        timeout,
    };
    let result: ContainerStopResult =
        response_data(&http_post_json(socket, "/api/v1/container/stop", &request)?)?;
    println!("Container \"{}\" stopped.", result.name);
    Ok(())
}

pub(crate) fn cmd_container_remove(socket: &str, name: &str, force: bool) -> Result<()> {
    let result = container_remove_request(socket, name, force)?;
    println!("Container \"{}\" removed.", result.name);
    Ok(())
}

pub(crate) fn container_remove_request(
    socket: &str,
    name: &str,
    force: bool,
) -> Result<ContainerRemoveResult> {
    let request = ContainerRemoveRequest {
        name: name.to_string(),
        force: Some(force),
    };
    response_data(&http_post_json(
        socket,
        "/api/v1/container/remove",
        &request,
    )?)
}

pub(crate) fn cmd_container_pull(socket: &str, image: &str) -> Result<()> {
    let request = ImagePullRequest {
        image: image.to_string(),
    };
    let result: ImagePullResult =
        response_data(&http_post_json(socket, "/api/v1/container/pull", &request)?)?;
    println!("Image \"{}\" pulled.", result.image);
    Ok(())
}
