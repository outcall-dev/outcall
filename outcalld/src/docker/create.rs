use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use bollard::container::{
    Config, CreateContainerOptions, NetworkingConfig, RemoveContainerOptions, StartContainerOptions,
};
use bollard::models::EndpointSettings;
use bollard::Docker;
use outcall_api::{
    ContainerCreateRequest, ContainerCreateResult, AGENT_SOCKET_CONTAINER_PATH, CONTAINER_PREFIX,
    CREATED_AT_LABEL, DEFAULT_CONTAINER_USER, DEFAULT_CPU_SHARES, DEFAULT_MEMORY_LIMIT,
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, NETWORK_LABEL, SHIM_CONTAINER_PATH,
};
use tracing::info;

use super::metadata::required_text;
use super::operation;
use super::utility::{managed_host_config, random_hex_suffix};
use super::DockerManager;
use crate::container_env::container_environment;
use crate::timestamp::now_iso8601;

impl DockerManager {
    pub async fn create_container(
        &self,
        request: ContainerCreateRequest,
        proxy_addr: Option<&str>,
        dns_addr: &str,
    ) -> Result<ContainerCreateResult> {
        crate::container_request::validate(&request)?;
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let network_name = request
            .network
            .as_deref()
            .unwrap_or("outcall-default")
            .to_string();
        self.check_network(&network_name).await?;

        let container_name = match request.name.clone() {
            Some(name) => name,
            None => format!("{CONTAINER_PREFIX}{}", random_hex_suffix()?),
        };
        let memory = request.memory_limit.unwrap_or(DEFAULT_MEMORY_LIMIT);
        let cpu_shares = request.cpu_shares.unwrap_or(DEFAULT_CPU_SHARES);
        let user = managed_container_user(request.user.as_deref());

        let mut binds = Vec::new();
        if helper_mounts_requested(&request) {
            validate_helper_sources(
                Path::new(&self.agent_socket_host_path),
                Path::new(&self.shim_host_path),
            )?;
            binds.push(format!(
                "{}:{}:ro",
                self.agent_socket_host_path, AGENT_SOCKET_CONTAINER_PATH
            ));
            binds.push(format!(
                "{}:{}:ro",
                self.shim_host_path, SHIM_CONTAINER_PATH
            ));
        }
        if let Some(user_volumes) = request.volumes.as_ref() {
            crate::bind_mount::validate_bind_mounts(user_volumes, &self.denied_bind_paths)?;
            binds.extend(user_volumes.iter().cloned());
        }

        let environment = container_environment(proxy_addr, request.env.clone());
        let labels = HashMap::from([
            (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
            (NETWORK_LABEL.to_string(), network_name.clone()),
            (CREATED_AT_LABEL.to_string(), now_iso8601()?),
        ]);
        let endpoints = HashMap::from([(network_name.as_str(), EndpointSettings::default())]);
        let config = Config {
            image: Some(request.image.as_str()),
            user: Some(user),
            entrypoint: request
                .entrypoint
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            cmd: request
                .cmd
                .as_ref()
                .map(|values| values.iter().map(String::as_str).collect()),
            env: Some(environment.iter().map(String::as_str).collect()),
            working_dir: request.working_dir.as_deref(),
            attach_stdin: Some(request.interactive.unwrap_or(false)),
            open_stdin: Some(request.interactive.unwrap_or(false)),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(request.tty.unwrap_or(false)),
            labels: Some(
                labels
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect(),
            ),
            networking_config: Some(NetworkingConfig {
                endpoints_config: endpoints,
            }),
            host_config: Some(managed_host_config(
                binds,
                memory,
                cpu_shares,
                dns_addr,
                &network_name,
            )),
            ..Default::default()
        };

        let created = operation::run(
            format!("create container {container_name}"),
            docker.create_container(
                Some(CreateContainerOptions {
                    name: container_name.as_str(),
                    platform: None,
                }),
                config,
            ),
        )
        .await?;
        let container_id = required_text(Some(&created.id), "created container ID")?.to_string();

        if let Err(start_error) = operation::run(
            format!("start container {container_name}"),
            docker.start_container(&container_id, None::<StartContainerOptions<&str>>),
        )
        .await
        {
            return rollback_error(
                docker,
                &container_id,
                format!("failed to start container {container_name}: {start_error}"),
            )
            .await;
        }
        if let Err(identity_error) = self
            .identity_cache
            .record_container(docker, &container_id)
            .await
        {
            return rollback_error(
                docker,
                &container_id,
                format!("failed to register container {container_name}: {identity_error}"),
            )
            .await;
        }

        info!(name = %container_name, id = %container_id, "container started");
        Ok(ContainerCreateResult {
            container_id,
            name: container_name,
            created: true,
        })
    }

    async fn check_network(&self, network_name: &str) -> Result<()> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let network = operation::run(
            format!("inspect network {network_name}"),
            docker.inspect_network(
                network_name,
                None::<bollard::network::InspectNetworkOptions<&str>>,
            ),
        )
        .await
        .with_context(|| format!("network \"{network_name}\" does not exist"))?;
        let configured_bridge = network
            .options
            .as_ref()
            .and_then(|options| options.get("com.docker.network.bridge.name"))
            .map(String::as_str);
        crate::managed_network::validate_managed_network(
            network_name,
            network.driver.as_deref(),
            configured_bridge,
            &self.bridge_name,
        )
    }
}

fn managed_container_user(requested: Option<&str>) -> &str {
    requested.unwrap_or(DEFAULT_CONTAINER_USER)
}

fn helper_mounts_requested(request: &ContainerCreateRequest) -> bool {
    request.include_outcall_helper_mounts.unwrap_or(false)
}

fn validate_helper_sources(agent_socket: &Path, shim: &Path) -> Result<()> {
    let socket_metadata = std::fs::symlink_metadata(agent_socket)
        .with_context(|| format!("agent socket not found at {}", agent_socket.display()))?;
    if socket_metadata.file_type().is_symlink() || !socket_metadata.file_type().is_socket() {
        anyhow::bail!(
            "agent socket at {} must be a real unix socket",
            agent_socket.display()
        );
    }

    let shim_metadata = std::fs::symlink_metadata(shim)
        .with_context(|| format!("shim binary not found at {}", shim.display()))?;
    if shim_metadata.file_type().is_symlink() || !shim_metadata.is_file() {
        anyhow::bail!("shim binary at {} must be a real file", shim.display());
    }
    if shim_metadata.permissions().mode() & 0o111 == 0 {
        anyhow::bail!("shim binary at {} is not executable", shim.display());
    }
    Ok(())
}

async fn rollback_error<T>(docker: &Docker, container_id: &str, error: String) -> Result<T> {
    match operation::run(
        format!("roll back container {container_id}"),
        docker.remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                link: false,
            }),
        ),
    )
    .await
    {
        Ok(()) => anyhow::bail!(error),
        Err(cleanup_error) => anyhow::bail!("{error}; cleanup also failed: {cleanup_error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;

    use super::*;

    fn request_with_helper_mounts(value: Option<bool>) -> ContainerCreateRequest {
        ContainerCreateRequest {
            image: "probe:local".to_string(),
            network: None,
            name: None,
            user: None,
            memory_limit: None,
            cpu_shares: None,
            env: None,
            cmd: None,
            entrypoint: None,
            working_dir: None,
            volumes: None,
            include_outcall_helper_mounts: value,
            interactive: None,
            tty: None,
        }
    }

    #[test]
    fn helper_mounts_are_explicitly_opt_in() {
        assert!(!helper_mounts_requested(&request_with_helper_mounts(None)));
        assert!(!helper_mounts_requested(&request_with_helper_mounts(Some(
            false
        ))));
        assert!(helper_mounts_requested(&request_with_helper_mounts(Some(
            true
        ))));
    }

    #[test]
    fn omitted_user_uses_a_non_root_daemon_default() {
        assert_eq!(managed_container_user(None), DEFAULT_CONTAINER_USER);
        assert!(outcall_api::valid_container_user(DEFAULT_CONTAINER_USER));
        assert_ne!(DEFAULT_CONTAINER_USER, "0:0");
    }

    #[test]
    fn explicit_non_root_user_is_preserved() {
        assert_eq!(managed_container_user(Some("1000:1000")), "1000:1000");
    }

    #[test]
    fn validates_real_socket_and_executable_shim() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let shim = root.path().join("outcall");
        std::fs::write(&shim, "shim").unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_helper_sources(&socket, &shim).is_ok());
    }

    #[test]
    fn rejects_missing_wrong_type_or_symlinked_helpers() {
        let root = tempfile::tempdir().unwrap();
        let regular = root.path().join("regular");
        std::fs::write(&regular, "not a socket").unwrap();
        let executable = root.path().join("executable");
        std::fs::write(&executable, "shim").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_helper_sources(&regular, &executable).is_err());

        let socket = root.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let non_executable = root.path().join("non-executable");
        std::fs::write(&non_executable, "shim").unwrap();
        assert!(validate_helper_sources(&socket, &non_executable).is_err());

        let alias = root.path().join("shim-link");
        symlink(&executable, &alias).unwrap();
        assert!(validate_helper_sources(&socket, &alias).is_err());
    }
}
