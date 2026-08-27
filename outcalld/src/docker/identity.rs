use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::Docker;
use tokio::sync::RwLock;

use super::metadata::{container_name, managed_network_label, required_text};
use super::operation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedContainerIdentity {
    pub id: String,
    pub name: String,
}

#[derive(Default)]
struct IdentityState {
    entries: HashMap<IpAddr, ManagedContainerIdentity>,
    generation: u64,
    healthy: bool,
}

/// In-memory peer identity index maintained from Docker lifecycle events.
pub(super) struct IdentityCache {
    state: RwLock<IdentityState>,
}

impl IdentityCache {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(IdentityState::default()),
        })
    }

    /// Replace the cache with an authoritative Docker snapshot and enable it.
    pub(super) async fn refresh(&self, docker: &Docker) -> Result<()> {
        let entries = load_managed_identities(docker).await?;
        let mut state = self.state.write().await;
        state.entries = entries;
        state.generation = state.generation.wrapping_add(1);
        state.healthy = true;
        Ok(())
    }

    /// Disable and clear the cache while the Docker event stream is unhealthy.
    pub(super) async fn invalidate(&self) {
        let mut state = self.state.write().await;
        state.entries.clear();
        state.generation = state.generation.wrapping_add(1);
        state.healthy = false;
    }

    pub(super) async fn record_container(&self, docker: &Docker, id: &str) -> Result<()> {
        let Some((identity, addresses)) = inspect_managed_identity(docker, id).await? else {
            anyhow::bail!("container {id} is not managed by outcalld");
        };
        let mut state = self.state.write().await;
        state
            .entries
            .retain(|_, cached| cached.id != identity.id && cached.name != identity.name);
        for address in addresses {
            state.entries.insert(address, identity.clone());
        }
        state.generation = state.generation.wrapping_add(1);
        Ok(())
    }

    pub(super) async fn remove_container(&self, id: &str, name: &str) {
        let mut state = self.state.write().await;
        state
            .entries
            .retain(|_, identity| identity.id != id && identity.name != name);
        state.generation = state.generation.wrapping_add(1);
    }

    /// Return a cached identity when event synchronization is healthy. A miss
    /// is verified against one authoritative Docker list call. The generation
    /// guard prevents a concurrent lifecycle event from being overwritten by
    /// a stale snapshot.
    pub(super) async fn lookup_name_by_ip(
        &self,
        docker: &Docker,
        ip: &str,
    ) -> Result<Option<String>> {
        let address: IpAddr = ip.parse().context("invalid peer IP address")?;
        let (generation, healthy) = {
            let state = self.state.read().await;
            if state.healthy {
                if let Some(identity) = state.entries.get(&address) {
                    return Ok(Some(identity.name.clone()));
                }
            }
            (state.generation, state.healthy)
        };

        let snapshot = load_managed_identities(docker).await?;
        let result = snapshot.get(&address).map(|identity| identity.name.clone());

        if healthy {
            let mut state = self.state.write().await;
            if state.healthy && state.generation == generation {
                state.entries = snapshot;
                state.generation = state.generation.wrapping_add(1);
            }
        }

        Ok(result)
    }
}

pub(super) async fn lookup_container_by_pid(
    docker: &Docker,
    pid: u32,
) -> Result<Option<ManagedContainerIdentity>> {
    let cgroup_content = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("read cgroup identity for peer PID {pid}"))?;
    let Some(container_id) = extract_container_id_from_cgroup(&cgroup_content) else {
        return Ok(None);
    };
    Ok(inspect_managed_identity(docker, &container_id)
        .await?
        .map(|(identity, _)| identity))
}

/// Extract a Docker short ID from cgroup v1, systemd cgroup v2, or Docker
/// Desktop-style cgroup paths. Docker container IDs are exactly 64 hex bytes.
fn extract_container_id_from_cgroup(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(candidate) = line.split(":/docker/").nth(1) {
            if let Some(id) = short_container_id(candidate.trim().trim_end_matches('/')) {
                return Some(id);
            }
        }
        if let Some(id) = line
            .strip_suffix(".scope")
            .and_then(|base| base.rsplit_once("docker-").map(|(_, candidate)| candidate))
            .and_then(short_container_id)
        {
            return Some(id);
        }
        if let Some(id) = line
            .split(':')
            .next_back()
            .and_then(|path| path.rsplit('/').next())
            .and_then(short_container_id)
        {
            return Some(id);
        }
    }
    None
}

fn short_container_id(candidate: &str) -> Option<String> {
    (candidate.len() == 64
        && candidate
            .chars()
            .all(|character| character.is_ascii_hexdigit()))
    .then(|| candidate[..12].to_ascii_lowercase())
}

async fn load_managed_identities(
    docker: &Docker,
) -> Result<HashMap<IpAddr, ManagedContainerIdentity>> {
    let mut filters = HashMap::new();
    filters.insert("label", vec!["managed-by=outcalld"]);
    let containers = operation::run(
        "list managed containers for peer identity",
        docker.list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        })),
    )
    .await?;

    let mut entries = HashMap::new();
    for container in containers {
        let labels = container.labels.as_ref();
        let network_name = managed_network_label(labels)?;
        let networks = container
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .context("managed container had no network settings")?;
        let addresses = addresses_from_declared_network(network_name, networks)?;
        if addresses.is_empty() {
            continue;
        }
        let id = required_text(container.id.as_deref(), "managed container ID")?.to_string();
        let name = container_name(
            container
                .names
                .as_ref()
                .and_then(|names| names.first())
                .map(String::as_str),
        )?;
        let identity = ManagedContainerIdentity { id, name };
        for address in addresses {
            insert_unique_identity(&mut entries, address, &identity)?;
        }
    }
    Ok(entries)
}

async fn inspect_managed_identity(
    docker: &Docker,
    id: &str,
) -> Result<Option<(ManagedContainerIdentity, Vec<IpAddr>)>> {
    let details = operation::run(
        format!("inspect managed container {id}"),
        docker.inspect_container(id, None::<InspectContainerOptions>),
    )
    .await?;
    let labels = details
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref());
    if labels.and_then(|labels| labels.get("managed-by").map(String::as_str)) != Some("outcalld") {
        return Ok(None);
    }

    let network_name = managed_network_label(labels)?;
    let identity = ManagedContainerIdentity {
        id: required_text(details.id.as_deref(), "managed container ID")?.to_string(),
        name: container_name(details.name.as_deref())?,
    };
    let networks = details
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .context("managed container had no network settings")?;
    let addresses = addresses_from_declared_network(network_name, networks)?;
    Ok(Some((identity, addresses)))
}

fn addresses_from_declared_network<T>(
    network_name: &str,
    networks: &HashMap<String, T>,
) -> Result<Vec<IpAddr>>
where
    T: NetworkAddress,
{
    let endpoint = networks.get(network_name).with_context(|| {
        format!("managed container is not attached to declared network {network_name}")
    })?;
    let mut addresses = Vec::new();
    for raw in [endpoint.ipv4_address(), endpoint.ipv6_address()]
        .into_iter()
        .flatten()
        .filter(|raw| !raw.is_empty())
    {
        addresses.push(
            raw.parse()
                .with_context(|| format!("Docker returned invalid container IP {raw}"))?,
        );
    }
    Ok(addresses)
}

fn insert_unique_identity(
    entries: &mut HashMap<IpAddr, ManagedContainerIdentity>,
    address: IpAddr,
    identity: &ManagedContainerIdentity,
) -> Result<()> {
    if let Some(existing) = entries.get(&address) {
        if existing != identity {
            anyhow::bail!(
                "Docker assigned {address} to both managed containers {} and {}",
                existing.name,
                identity.name
            );
        }
    }
    entries.insert(address, identity.clone());
    Ok(())
}

trait NetworkAddress {
    fn ipv4_address(&self) -> Option<&str>;
    fn ipv6_address(&self) -> Option<&str>;
}

impl NetworkAddress for bollard::models::EndpointSettings {
    fn ipv4_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    fn ipv6_address(&self) -> Option<&str> {
        self.global_ipv6_address.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEndpoint {
        ipv4: Option<String>,
        ipv6: Option<String>,
    }

    impl NetworkAddress for TestEndpoint {
        fn ipv4_address(&self) -> Option<&str> {
            self.ipv4.as_deref()
        }

        fn ipv6_address(&self) -> Option<&str> {
            self.ipv6.as_deref()
        }
    }

    #[tokio::test]
    async fn invalidation_clears_cached_identities() {
        let cache = IdentityCache::new();
        {
            let mut state = cache.state.write().await;
            state.healthy = true;
            state.entries.insert(
                "10.200.0.2".parse().unwrap(),
                ManagedContainerIdentity {
                    id: "abc".to_string(),
                    name: "codex-1".to_string(),
                },
            );
        }

        cache.invalidate().await;

        let state = cache.state.read().await;
        assert!(!state.healthy);
        assert!(state.entries.is_empty());
    }

    #[tokio::test]
    async fn container_removal_drops_every_address_for_that_identity() {
        let cache = IdentityCache::new();
        {
            let mut state = cache.state.write().await;
            state.healthy = true;
            for address in ["10.200.0.2", "fd00::2"] {
                state.entries.insert(
                    address.parse().unwrap(),
                    ManagedContainerIdentity {
                        id: "abc".to_string(),
                        name: "codex-1".to_string(),
                    },
                );
            }
        }

        cache.remove_container("abc", "codex-1").await;

        assert!(cache.state.read().await.entries.is_empty());
    }

    #[test]
    fn extracts_ids_from_supported_cgroup_formats() {
        let full_id = "abc123def4567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(full_id.len(), 64);
        for content in [
            format!("12:memory:/docker/{full_id}\n"),
            format!("0::/system.slice/docker-{full_id}.scope\n"),
            format!("0::/../{full_id}\n"),
        ] {
            assert_eq!(
                extract_container_id_from_cgroup(&content),
                Some("abc123def456".to_string())
            );
        }
    }

    #[test]
    fn rejects_partial_or_non_hex_cgroup_ids() {
        assert_eq!(extract_container_id_from_cgroup("0::/abc123def456\n"), None);
        assert_eq!(
            extract_container_id_from_cgroup(
                "0::/abc123def4567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz\n"
            ),
            None
        );
    }

    #[test]
    fn trusts_only_addresses_on_the_declared_network() {
        let networks = HashMap::from([
            (
                "outcall-default".to_string(),
                TestEndpoint {
                    ipv4: Some("10.200.0.2".to_string()),
                    ipv6: None,
                },
            ),
            (
                "bridge".to_string(),
                TestEndpoint {
                    ipv4: Some("172.17.0.2".to_string()),
                    ipv6: None,
                },
            ),
        ]);

        let addresses = addresses_from_declared_network("outcall-default", &networks).unwrap();

        assert_eq!(addresses, vec!["10.200.0.2".parse::<IpAddr>().unwrap()]);
        assert!(addresses_from_declared_network("outcall-missing", &networks).is_err());
    }

    #[test]
    fn duplicate_addresses_for_different_containers_fail_closed() {
        let address = "10.200.0.2".parse().unwrap();
        let first = ManagedContainerIdentity {
            id: "first-id".to_string(),
            name: "first-1".to_string(),
        };
        let second = ManagedContainerIdentity {
            id: "second-id".to_string(),
            name: "second-1".to_string(),
        };
        let mut entries = HashMap::new();

        insert_unique_identity(&mut entries, address, &first).unwrap();
        assert!(insert_unique_identity(&mut entries, address, &second).is_err());
        assert_eq!(entries.get(&address), Some(&first));
    }
}
