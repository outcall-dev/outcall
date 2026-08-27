use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::container::{ListContainersOptions, RemoveContainerOptions, StopContainerOptions};
use bollard::models::{ContainerInspectResponse, ContainerSummary};
use bollard::Docker;
use outcall_api::{
    ContainerInfo, ContainerInspectResult, ContainerRemoveResult, ContainerStopResult,
    DEFAULT_STOP_TIMEOUT_SECS, MAX_STOP_TIMEOUT_SECS,
};
use tracing::info;

use super::metadata::{
    container_name as required_container_name, has_managed_label, managed_network_label,
    required_text,
};
use super::operation::{self, FINITE_OPERATION_TIMEOUT};
use super::DockerManager;
use crate::timestamp::format_unix_timestamp;

impl DockerManager {
    pub async fn stop_container(
        &self,
        name: &str,
        timeout: Option<i64>,
    ) -> Result<ContainerStopResult> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let details = inspect_managed_container(docker, name)
            .await?
            .with_context(|| format!("container \"{name}\" does not exist"))?;
        let canonical_name = required_container_name(details.name.as_deref())?;
        let running = details
            .state
            .as_ref()
            .and_then(|state| state.running)
            .unwrap_or(false);
        let id = details.id.context("managed container had no ID")?;
        if !running {
            self.identity_cache
                .remove_container(&id, &canonical_name)
                .await;
            return Ok(ContainerStopResult {
                name: canonical_name,
                stopped: false,
            });
        }
        let timeout = timeout.unwrap_or(DEFAULT_STOP_TIMEOUT_SECS);
        if !outcall_api::valid_stop_timeout(timeout) {
            anyhow::bail!(
                "container stop timeout must be between 0 and {MAX_STOP_TIMEOUT_SECS} seconds"
            );
        }
        let operation_timeout = Duration::from_secs(timeout as u64) + FINITE_OPERATION_TIMEOUT;
        operation::run_for(
            format!("stop container {canonical_name}"),
            operation_timeout,
            docker.stop_container(&id, Some(StopContainerOptions { t: timeout })),
        )
        .await?;
        self.identity_cache
            .remove_container(&id, &canonical_name)
            .await;

        info!(name = %canonical_name, id = %id, "container stopped");
        Ok(ContainerStopResult {
            name: canonical_name,
            stopped: true,
        })
    }

    pub async fn remove_container(&self, name: &str, force: bool) -> Result<ContainerRemoveResult> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let Some(details) = inspect_managed_container(docker, name).await? else {
            return Ok(ContainerRemoveResult {
                name: name.to_string(),
                removed: false,
            });
        };
        let canonical_name = required_container_name(details.name.as_deref())?;
        let id = details.id.context("managed container had no ID")?;
        operation::run(
            format!("remove container {canonical_name}"),
            docker.remove_container(
                &id,
                Some(RemoveContainerOptions {
                    force,
                    v: true,
                    link: false,
                }),
            ),
        )
        .await?;
        self.identity_cache
            .remove_container(&id, &canonical_name)
            .await;

        info!(name = %canonical_name, id = %id, "container removed");
        Ok(ContainerRemoveResult {
            name: canonical_name,
            removed: true,
        })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let mut filters = HashMap::new();
        filters.insert("label", vec!["managed-by=outcalld"]);
        let containers = operation::run(
            "list managed containers",
            docker.list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            })),
        )
        .await?;

        containers.into_iter().map(container_to_info).collect()
    }

    pub async fn inspect_container(&self, name: &str) -> Result<ContainerInspectResult> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let details = inspect_managed_container(docker, name)
            .await?
            .with_context(|| format!("container \"{name}\" does not exist"))?;
        let state = details
            .state
            .as_ref()
            .and_then(|state| state.status.as_ref())
            .map(|status| format!("{status:?}").to_lowercase())
            .context("managed container had no state")?;
        let mounts = details
            .host_config
            .as_ref()
            .and_then(|config| config.binds.as_ref())
            .cloned()
            .unwrap_or_default();
        let env = details
            .config
            .as_ref()
            .and_then(|config| config.env.as_ref())
            .map(|entries| redact_environment(entries))
            .unwrap_or_default();
        let network = managed_network_label(
            details
                .config
                .as_ref()
                .and_then(|config| config.labels.as_ref()),
        )?
        .to_string();
        let ip_address = details
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .and_then(|networks| networks.get(&network))
            .with_context(|| {
                format!("managed container is not attached to declared network {network}")
            })?
            .ip_address
            .clone()
            .unwrap_or_default();
        let canonical_name = required_container_name(details.name.as_deref())?;

        Ok(ContainerInspectResult {
            container_id: required_text(details.id.as_deref(), "managed container ID")?.to_string(),
            name: canonical_name,
            image: required_text(
                details
                    .config
                    .as_ref()
                    .and_then(|config| config.image.as_deref()),
                "managed container image",
            )?
            .to_string(),
            state,
            network,
            ip_address,
            mounts,
            env,
            created_at: required_text(
                details.created.as_deref(),
                "managed container creation time",
            )?
            .to_string(),
        })
    }
}

fn redact_environment(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            entry.split_once('=').map_or_else(
                || "<redacted>".to_string(),
                |(key, _)| format!("{key}=<redacted>"),
            )
        })
        .collect()
}

async fn inspect_managed_container(
    docker: &Docker,
    name: &str,
) -> Result<Option<ContainerInspectResponse>> {
    let details = match operation::run(
        format!("inspect container {name}"),
        docker.inspect_container(name, None),
    )
    .await
    {
        Ok(details) => details,
        Err(error) if error.status_code() == Some(404) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let labels = details
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref());
    if !has_managed_label(labels) {
        anyhow::bail!("container \"{name}\" is not managed by outcalld");
    }
    managed_network_label(labels)?;
    Ok(Some(details))
}

fn container_to_info(container: ContainerSummary) -> Result<ContainerInfo> {
    let network = managed_network_label(container.labels.as_ref())?.to_string();
    let networks = container
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .context("managed container had no network settings")?;
    if !networks.contains_key(&network) {
        anyhow::bail!("managed container is not attached to declared network {network}");
    }

    Ok(ContainerInfo {
        container_id: required_text(container.id.as_deref(), "managed container ID")?.to_string(),
        name: required_container_name(
            container
                .names
                .as_ref()
                .and_then(|names| names.first())
                .map(String::as_str),
        )?,
        image: required_text(container.image.as_deref(), "managed container image")?.to_string(),
        state: required_text(container.state.as_deref(), "managed container state")?.to_string(),
        network,
        created_at: format_unix_timestamp(
            container
                .created
                .context("managed container had no creation time")?,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_outcalld_label_is_managed() {
        let valid = HashMap::from([("managed-by".to_string(), "outcalld".to_string())]);
        let other = HashMap::from([("managed-by".to_string(), "someone-else".to_string())]);
        assert!(has_managed_label(Some(&valid)));
        assert!(!has_managed_label(Some(&other)));
        assert!(!has_managed_label(None));
    }

    #[test]
    fn inspect_environment_never_exposes_values() {
        assert_eq!(
            redact_environment(&[
                "API_TOKEN=secret".to_string(),
                "URL=https://user:pass@example.test?a=b".to_string(),
                "MALFORMED".to_string(),
            ]),
            ["API_TOKEN=<redacted>", "URL=<redacted>", "<redacted>",]
        );
    }
}
