//! Docker lifecycle management for hardened Outcall agent containers (S008).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::background_task::BackgroundTask;

mod containers;
mod create;
mod events;
mod identity;
mod image;
mod metadata;
pub(crate) mod operation;
mod utility;

pub use events::{ContainerEvent, ContainerEventKind};
pub use identity::ManagedContainerIdentity;

const DOCKER_PING_TIMEOUT: Duration = Duration::from_secs(3);

/// Shared Docker client, managed-container identity index, and lifecycle events.
pub struct DockerManager {
    docker: Option<Docker>,
    pub agent_socket_host_path: String,
    pub shim_host_path: String,
    bridge_name: String,
    denied_bind_paths: Vec<PathBuf>,
    event_tx: broadcast::Sender<ContainerEvent>,
    identity_cache: Arc<identity::IdentityCache>,
    event_task: BackgroundTask,
}

impl DockerManager {
    /// Create a manager and verify the Docker engine responds. A missing,
    /// unreachable, or hung engine yields a degraded manager rather than
    /// preventing the policy daemon from starting.
    pub async fn new(
        agent_socket_host_path: impl Into<String>,
        shim_host_path: impl Into<String>,
        bridge_name: impl Into<String>,
        host_socket_path: impl Into<PathBuf>,
    ) -> Arc<Self> {
        let docker = responsive_client().await;
        let (event_tx, _) = broadcast::channel(64);
        let mut denied_bind_paths = outcall_api::HOST_SOCKET_DENY_PATHS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let host_socket_path = host_socket_path.into();
        if !denied_bind_paths.contains(&host_socket_path) {
            denied_bind_paths.push(host_socket_path);
        }

        let identity_cache = identity::IdentityCache::new();
        let event_task = BackgroundTask::new();
        let cancellation = event_task.cancellation_token();
        let manager = Arc::new(Self {
            docker,
            agent_socket_host_path: agent_socket_host_path.into(),
            shim_host_path: shim_host_path.into(),
            bridge_name: bridge_name.into(),
            denied_bind_paths,
            event_tx,
            identity_cache: identity_cache.clone(),
            event_task,
        });
        if let Some(docker) = manager.docker.as_ref() {
            manager.event_task.spawn(events::watch(
                docker.clone(),
                manager.event_tx.clone(),
                identity_cache,
                cancellation,
            ));
        }
        manager
    }

    pub fn new_unavailable() -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            docker: None,
            agent_socket_host_path: String::new(),
            shim_host_path: String::new(),
            bridge_name: outcall_api::DEFAULT_BRIDGE_NAME.to_string(),
            denied_bind_paths: outcall_api::HOST_SOCKET_DENY_PATHS
                .iter()
                .map(PathBuf::from)
                .collect(),
            event_tx,
            identity_cache: identity::IdentityCache::new(),
            event_task: BackgroundTask::new(),
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ContainerEvent> {
        self.event_tx.subscribe()
    }

    pub fn is_unavailable(&self) -> bool {
        self.docker.is_none()
    }

    pub async fn shutdown(&self) {
        self.event_task
            .shutdown(Duration::from_secs(10), "Docker event watcher")
            .await;
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn client(&self) -> Option<Docker> {
        self.docker.clone()
    }

    pub async fn lookup_container_by_pid(
        &self,
        pid: u32,
    ) -> Result<Option<ManagedContainerIdentity>> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        identity::lookup_container_by_pid(docker, pid).await
    }

    pub async fn lookup_container_name_by_ip(&self, ip: &str) -> Result<Option<String>> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        self.identity_cache.lookup_name_by_ip(docker, ip).await
    }
}

async fn responsive_client() -> Option<Docker> {
    let docker = match Docker::connect_with_local_defaults() {
        Ok(docker) => docker,
        Err(error) => {
            warn!(%error, "Docker client initialization failed; using degraded mode");
            return None;
        }
    };
    match tokio::time::timeout(DOCKER_PING_TIMEOUT, docker.ping()).await {
        Ok(Ok(_)) => {
            info!("Docker manager connected and responsive");
            Some(docker)
        }
        Ok(Err(error)) => {
            warn!(%error, "Docker engine ping failed; using degraded mode");
            None
        }
        Err(_) => {
            warn!(
                timeout_secs = DOCKER_PING_TIMEOUT.as_secs(),
                "Docker engine ping timed out; using degraded mode"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_manager_reports_degraded_state() {
        assert!(DockerManager::new_unavailable().is_unavailable());
    }
}
