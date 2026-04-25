//! Docker Manager (S008) — creates, manages, and monitors agent containers.
//!
//! All public methods are `async` and safe to call from multiple tasks.
//! Container events (die/kill/oom) are broadcast on a Tokio channel so that
//! the Dynamic Rule Manager (S009) can subscribe and clean up nftables rules.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use bollard::container::{
    CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::container::NetworkingConfig;
use bollard::models::{EndpointSettings, HostConfig};
use bollard::system::EventsOptions;
use bollard::Docker;
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use outcall_api::{
    ContainerCreateRequest, ContainerCreateResult, ContainerInfo, ContainerInspectResult,
    ContainerRemoveResult, ContainerStopResult, ImagePullResult, AGENT_SOCKET_CONTAINER_PATH,
    DEFAULT_CPU_SHARES, DEFAULT_MEMORY_LIMIT, DEFAULT_PID_LIMIT,
    DEFAULT_STOP_TIMEOUT_SECS, SHIM_CONTAINER_PATH,
};

// ── Event types ───────────────────────────────────────────────────────────────

/// A container lifecycle event broadcast by `DockerManager`.
#[derive(Debug, Clone)]
pub struct ContainerEvent {
    pub kind: ContainerEventKind,
    /// Full container name (e.g. `outcall-agent-a3f7b201`).
    pub container_name: String,
    /// Docker container short ID.
    pub container_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerEventKind {
    Die,
    Oom,
    Kill,
    Destroy,
}

// ── DockerManager ─────────────────────────────────────────────────────────────

/// Manages agent containers via the Docker API (bollard).
///
/// Acts as a helper that wires up the outcall network, socket, and shim into
/// any container the caller wants to create. Users are free to choose container
/// names, networks, and additional mounts — the manager just ensures the
/// outcall infrastructure is present.
///
/// Wraps in an `Arc` so it can be shared across Axum handler tasks.
pub struct DockerManager {
    docker: Docker,
    /// Host path of the agent unix socket to bind-mount (read-only).
    pub agent_socket_host_path: String,
    /// Host path of the outcall-agent shim binary to bind-mount (read-only).
    pub shim_host_path: String,
    /// Broadcast channel for container lifecycle events (subscribed by S009).
    event_tx: broadcast::Sender<ContainerEvent>,
}

impl DockerManager {
    /// Connect to the local Docker Engine and start the event-monitoring task.
    pub fn new(
        agent_socket_host_path: impl Into<String>,
        shim_host_path: impl Into<String>,
    ) -> Result<Arc<Self>> {
        let docker = Docker::connect_with_local_defaults()
            .context("failed to connect to Docker — is the Docker daemon running?")?;

        let (event_tx, _) = broadcast::channel(64);

        let mgr = Arc::new(Self {
            docker,
            agent_socket_host_path: agent_socket_host_path.into(),
            shim_host_path: shim_host_path.into(),
            event_tx,
        });

        // Spawn the background event watcher task.
        tokio::spawn(event_watch_loop(mgr.docker.clone(), mgr.event_tx.clone()));

        Ok(mgr)
    }

    /// Subscribe to container lifecycle events (for S009 rule cleanup).
    pub fn subscribe_events(&self) -> broadcast::Receiver<ContainerEvent> {
        self.event_tx.subscribe()
    }

    // ── Container creation ─────────────────────────────────────────────────

    /// Create and start an agent container.
    ///
    /// Acts as a helper: wires up the outcall network, proxy/DNS settings, agent
    /// socket, and shim binary. The caller controls the container name, mounts,
    /// network, and any extra environment variables.
    pub async fn create_container(
        &self,
        req: ContainerCreateRequest,
        proxy_addr: &str,
        dns_addr: &str,
    ) -> Result<ContainerCreateResult> {
        let network_name = req
            .network
            .as_deref()
            .unwrap_or("outcall-default")
            .to_string();

        // Verify the target network exists.
        self.check_network(&network_name).await?;

        // Container name: caller-supplied or auto-generated.
        let container_name = req
            .name
            .clone()
            .unwrap_or_else(|| format!("outcall-{}", random_hex_suffix()));

        // Outcall helper mounts — always added (agent socket + shim binary).
        let agent_bind = format!(
            "{}:{}:ro",
            self.agent_socket_host_path, AGENT_SOCKET_CONTAINER_PATH
        );
        let shim_bind = format!("{}:{}:ro", self.shim_host_path, SHIM_CONTAINER_PATH);

        // User-supplied mounts are appended after the helper mounts.
        let mut binds = vec![agent_bind, shim_bind];
        if let Some(user_vols) = req.volumes {
            binds.extend(user_vols);
        }

        // Build environment (proxy + DNS always present; caller can add more).
        let mut env = vec![
            format!("HTTP_PROXY=http://{proxy_addr}"),
            format!("HTTPS_PROXY=http://{proxy_addr}"),
            "NO_PROXY=localhost,127.0.0.1".to_string(),
        ];
        if let Some(extra) = req.env {
            env.extend(extra);
        }

        // Build labels — managed-by=outcalld is how we track these containers.
        let mut labels = HashMap::new();
        labels.insert("managed-by".to_string(), "outcalld".to_string());
        labels.insert("outcall.network".to_string(), network_name.clone());
        labels.insert(
            "outcall.created-at".to_string(),
            chrono_now_iso8601(),
        );

        let memory = req.memory_limit.unwrap_or(DEFAULT_MEMORY_LIMIT);
        let cpu_shares = req.cpu_shares.unwrap_or(DEFAULT_CPU_SHARES);

        // Build networking config — endpoints_config keys must match Config<T> type param.
        let mut endpoints: HashMap<&str, EndpointSettings> = HashMap::new();
        endpoints.insert(network_name.as_str(), EndpointSettings::default());

        let config = bollard::container::Config {
            image: Some(req.image.as_str()),
            cmd: req
                .cmd
                .as_ref()
                .map(|v| v.iter().map(String::as_str).collect()),
            env: Some(env.iter().map(String::as_str).collect()),
            labels: Some(labels.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()),
            networking_config: Some(NetworkingConfig {
                endpoints_config: endpoints,
            }),
            host_config: Some(HostConfig {
                binds: Some(binds),
                memory: Some(memory),
                cpu_shares: Some(cpu_shares as i64),
                pids_limit: Some(DEFAULT_PID_LIMIT),
                readonly_rootfs: Some(true),  // bollard field name (no underscore split)
                privileged: Some(false),
                cap_drop: Some(vec!["ALL".to_string()]),
                dns: Some(vec![dns_addr.to_string()]),
                tmpfs: Some(HashMap::from([("/tmp".to_string(), "".to_string())])),
                ..Default::default()
            }),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: container_name.as_str(),
            platform: None,
        };

        let create_resp = self
            .docker
            .create_container(Some(options), config)
            .await
            .with_context(|| format!("failed to create container {container_name}"))?;

        let container_id = create_resp.id.clone();

        // FR-011: start the container.
        self.docker
            .start_container(&container_id, None::<StartContainerOptions<&str>>)
            .await
            .with_context(|| format!("failed to start container {container_name}"))?;

        info!(name = %container_name, id = %container_id, "container started");

        Ok(ContainerCreateResult {
            container_id,
            name: container_name,
            created: true,
        })
    }

    // ── Container lifecycle ────────────────────────────────────────────────

    /// Stop a running container (FR-012).
    pub async fn stop_container(
        &self,
        name: &str,
        timeout: Option<i64>,
    ) -> Result<ContainerStopResult> {
        let t = timeout.unwrap_or(DEFAULT_STOP_TIMEOUT_SECS);
        self.docker
            .stop_container(name, Some(StopContainerOptions { t }))
            .await
            .with_context(|| format!("failed to stop container {name}"))?;

        info!(name = %name, "container stopped");
        Ok(ContainerStopResult {
            name: name.to_string(),
            stopped: true,
        })
    }

    /// Remove a stopped container (FR-013).
    pub async fn remove_container(
        &self,
        name: &str,
        force: bool,
    ) -> Result<ContainerRemoveResult> {
        self.docker
            .remove_container(
                name,
                Some(RemoveContainerOptions {
                    force,
                    v: true, // remove anonymous volumes too
                    link: false,
                }),
            )
            .await
            .with_context(|| format!("failed to remove container {name}"))?;

        info!(name = %name, "container removed");
        Ok(ContainerRemoveResult {
            name: name.to_string(),
            removed: true,
        })
    }

    // ── Container listing and inspection ───────────────────────────────────

    /// List all outcall-managed containers (identified by `managed-by=outcalld` label).
    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        let mut filters = HashMap::new();
        filters.insert("label", vec!["managed-by=outcalld"]);

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
            .context("failed to list containers")?;

        let items = containers
            .into_iter()
            .map(|c| {
                let name = c
                    .names
                    .as_ref()
                    .and_then(|n| n.first())
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_default();

                let network = c
                    .network_settings
                    .as_ref()
                    .and_then(|ns| ns.networks.as_ref())
                    .and_then(|nets| nets.keys().next())
                    .cloned()
                    .unwrap_or_default();

                ContainerInfo {
                    container_id: c.id.unwrap_or_default(),
                    name,
                    image: c.image.unwrap_or_default(),
                    state: c.state.unwrap_or_default(),
                    network,
                    created_at: c
                        .created
                        .map(|t| format_unix_timestamp(t))
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(items)
    }

    /// Inspect a single container by name (FR-015).
    pub async fn inspect_container(&self, name: &str) -> Result<ContainerInspectResult> {
        let details = self
            .docker
            .inspect_container(name, None)
            .await
            .with_context(|| format!("container \"{name}\" does not exist"))?;

        let state = details
            .state
            .as_ref()
            .and_then(|s| s.status.as_ref())
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_default();

        let hc = details.host_config.as_ref();
        let mounts: Vec<String> = hc
            .and_then(|h| h.binds.as_ref())
            .map(|b| b.clone())
            .unwrap_or_default();

        let env: Vec<String> = details
            .config
            .as_ref()
            .and_then(|c| c.env.as_ref())
            .cloned()
            .unwrap_or_default();

        // Find primary network and IP.
        let ns = details.network_settings.as_ref();
        let (network, ip_address) = ns
            .and_then(|ns| ns.networks.as_ref())
            .and_then(|nets| nets.iter().next())
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.ip_address.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();

        let container_name = details
            .name
            .as_deref()
            .unwrap_or(name)
            .trim_start_matches('/')
            .to_string();

        let image = details
            .config
            .as_ref()
            .and_then(|c| c.image.as_ref())
            .cloned()
            .unwrap_or_default();

        let created_at = details.created.as_deref().unwrap_or("").to_string();

        Ok(ContainerInspectResult {
            container_id: details.id.unwrap_or_default(),
            name: container_name,
            image,
            state,
            network,
            ip_address,
            mounts,
            env,
            created_at,
        })
    }

    // ── Image management ──────────────────────────────────────────────────

    /// Pull an image from a registry (FR-017).
    /// Returns `pulled: false` if the image was already present locally.
    pub async fn pull_image(&self, image: &str) -> Result<ImagePullResult> {
        // Check if image exists locally first.
        let already_present = self.docker.inspect_image(image).await.is_ok();

        // Pull regardless (Docker handles up-to-date detection).
        let (from_image, tag) = match image.rsplit_once(':') {
            Some((img, tag)) => (img, tag),
            None => (image, "latest"),
        };

        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image,
                tag,
                ..Default::default()
            }),
            None,
            None,
        );

        while let Some(item) = stream.next().await {
            item.with_context(|| format!("failed to pull image \"{image}\""))?;
        }

        info!(image = %image, "image pull complete");
        Ok(ImagePullResult {
            image: image.to_string(),
            pulled: !already_present,
        })
    }

    /// Look up the container name that owns a given host-namespace PID (S004-FR-005).
    ///
    /// Reads `/proc/<pid>/cgroup` to extract the Docker container ID, then
    /// verifies via Docker that the container is managed by outcalld.
    /// Returns the container name on success, or `None` if the PID does not
    /// belong to a known managed container.
    pub async fn lookup_container_by_pid(&self, pid: u32) -> Option<String> {
        let cgroup_content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let container_id = extract_container_id_from_cgroup(&cgroup_content)?;

        let details = self
            .docker
            .inspect_container(
                &container_id,
                None::<bollard::container::InspectContainerOptions>,
            )
            .await
            .ok()?;

        let labels = details.config.as_ref()?.labels.as_ref()?;
        if labels.get("managed-by").map(|s| s.as_str()) != Some("outcalld") {
            return None;
        }

        details
            .name
            .map(|n| n.trim_start_matches('/').to_string())
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Check that the named network exists.
    async fn check_network(&self, network_name: &str) -> Result<()> {
        self.docker
            .inspect_network(network_name, None::<bollard::network::InspectNetworkOptions<&str>>)
            .await
            .with_context(|| format!("network \"{network_name}\" does not exist"))?;
        Ok(())
    }
}

/// Extract a Docker container short ID from `/proc/<pid>/cgroup` contents.
/// Supports cgroup v1 (`:/docker/<id>`) and v2 (`docker-<id>.scope`).
fn extract_container_id_from_cgroup(content: &str) -> Option<String> {
    for line in content.lines() {
        // cgroup v1:  "12:memory:/docker/<64-hex>"
        if let Some(rest) = line.split(":/docker/").nth(1) {
            let id = rest.trim().trim_end_matches('/');
            if id.len() >= 12 && id.chars().take(12).all(|c| c.is_ascii_hexdigit()) {
                return Some(id[..12].to_string());
            }
        }
        // cgroup v2:  "0::/system.slice/docker-<64-hex>.scope"
        if let Some(base) = line.strip_suffix(".scope") {
            if let Some((_, id_part)) = base.rsplit_once("docker-") {
                if id_part.len() >= 12 && id_part.chars().take(12).all(|c| c.is_ascii_hexdigit()) {
                    return Some(id_part[..12].to_string());
                }
            }
        }
    }
    None
}

// ── Background event watcher ──────────────────────────────────────────────────

/// Watches Docker events for managed container deaths and re-broadcasts them.
/// Reconnects automatically on stream errors (FR-031).
async fn event_watch_loop(docker: Docker, tx: broadcast::Sender<ContainerEvent>) {
    loop {
        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("label", vec!["managed-by=outcalld"]);

        let options = EventsOptions {
            filters,
            ..Default::default()
        };

        let mut stream = docker.events(Some(options));

        while let Some(ev) = stream.next().await {
            match ev {
                Ok(msg) => {
                    let action = msg.action.as_deref().unwrap_or("");
                    let kind = match action {
                        "die" => ContainerEventKind::Die,
                        "oom" => ContainerEventKind::Oom,
                        "kill" => ContainerEventKind::Kill,
                        "destroy" => ContainerEventKind::Destroy,
                        _ => continue,
                    };

                    let actor = msg.actor.as_ref();
                    let container_id = actor
                        .and_then(|a| a.id.as_deref())
                        .unwrap_or("")
                        .to_string();
                    let container_name = actor
                        .and_then(|a| a.attributes.as_ref())
                        .and_then(|attrs| attrs.get("name"))
                        .cloned()
                        .unwrap_or_default();

                    // Events are pre-filtered by label in the EventsOptions query;
                    // no secondary name-prefix check needed.
                    info!(
                        name = %container_name,
                        id = %container_id,
                        action = %action,
                        "container event"
                    );

                    // Ignore send errors — receivers may have dropped.
                    let _ = tx.send(ContainerEvent {
                        kind,
                        container_name,
                        container_id,
                    });
                }
                Err(e) => {
                    warn!("Docker event stream error: {e} — reconnecting in 5s");
                    break;
                }
            }
        }

        // Reconnect after a brief pause unless all receivers are gone.
        if tx.receiver_count() == 0 {
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Generate 8 random lowercase hex characters from `/dev/urandom`.
fn random_hex_suffix() -> String {
    let mut buf = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    } else {
        // Fallback: mix time + pid.
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let v = t ^ (std::process::id() << 8);
        buf.copy_from_slice(&v.to_le_bytes());
    }
    buf.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
        s
    })
}

/// Format a Unix timestamp (seconds since epoch) as ISO 8601.
fn format_unix_timestamp(secs: i64) -> String {
    // Minimal ISO 8601 formatter without chrono.
    // 2001-09-09T01:46:40Z is epoch 1_000_000_000 — good enough sanity check.
    let secs = secs as u64;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    // Convert days since epoch to Y-M-D (Gregorian calendar).
    let (y, mo, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}

/// Return the current time as an ISO 8601 string.
fn chrono_now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_unix_timestamp(secs as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_suffix_is_8_chars() {
        let s = random_hex_suffix();
        assert_eq!(s.len(), 8, "hex suffix must be 8 chars: {s}");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "must be hex: {s}");
    }

    #[test]
    fn format_unix_timestamp_epoch() {
        // Unix epoch should be 1970-01-01T00:00:00Z
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_unix_timestamp_known() {
        // 2026-04-24T00:00:00Z = 1745452800
        assert_eq!(format_unix_timestamp(1_745_452_800), "2026-04-24T00:00:00Z");
    }

    #[test]
    fn extract_container_id_cgroup_v1() {
        let content = "12:memory:/docker/abc123def4567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        assert_eq!(
            extract_container_id_from_cgroup(content),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn extract_container_id_cgroup_v2() {
        let content = "0::/system.slice/docker-abc123def4567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n";
        assert_eq!(
            extract_container_id_from_cgroup(content),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn extract_container_id_no_match() {
        assert_eq!(extract_container_id_from_cgroup("nothing here\n"), None);
    }

    #[test]
    fn container_name_defaults_to_outcall_prefix() {
        // When no name is provided, the generated name should start with "outcall-".
        let name = format!("outcall-{}", random_hex_suffix());
        assert!(name.starts_with("outcall-"), "auto name: {name}");
        assert_eq!(name.len(), "outcall-".len() + 8);
    }
}
