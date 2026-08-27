use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tracing::{info, warn};

use outcalld::agent_api::AgentApiError;

pub(super) struct ApiSockets {
    host_listener: Option<UnixListener>,
    agent_listener: Option<UnixListener>,
    host_path: PathBuf,
    agent_path: PathBuf,
}

impl ApiSockets {
    pub(super) fn bind(
        host_path: &Path,
        agent_path: &Path,
        operator_uid: u32,
        operator_gid: u32,
    ) -> Result<Self> {
        require_distinct_absolute_paths(host_path, agent_path)?;
        let host_listener = bind_host(host_path, operator_uid, operator_gid)?;
        let agent_listener = match bind_agent(agent_path) {
            Ok(listener) => listener,
            Err(error) => {
                drop(host_listener);
                if let Err(cleanup) = outcalld::unix_socket::remove_stale(host_path) {
                    return Err(
                        error.context(format!("host socket cleanup also failed: {cleanup}"))
                    );
                }
                return Err(error);
            }
        };

        Ok(Self {
            host_listener: Some(host_listener),
            agent_listener: Some(agent_listener),
            host_path: host_path.to_path_buf(),
            agent_path: agent_path.to_path_buf(),
        })
    }

    pub(super) fn take_host(&mut self) -> Result<UnixListener> {
        self.host_listener
            .take()
            .context("host API listener was already taken")
    }

    pub(super) fn take_agent(&mut self) -> Result<UnixListener> {
        self.agent_listener
            .take()
            .context("agent API listener was already taken")
    }

    pub(super) fn cleanup(&self) {
        cleanup_path(&self.host_path, "host API");
        cleanup_path(&self.agent_path, "agent API");
    }
}

impl Drop for ApiSockets {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn bind_host(path: &Path, operator_uid: u32, operator_gid: u32) -> Result<UnixListener> {
    prepare(path)?;
    let listener = bind_with_umask(path, 0o077)?;
    outcalld::unix_socket::set_mode(path, 0o600)?;
    set_owner_if_needed(path, operator_uid, operator_gid)?;
    info!(
        socket = %path.display(),
        owner_uid = operator_uid,
        owner_gid = operator_gid,
        "host API listening (mode 0600)"
    );
    Ok(listener)
}

#[cfg(unix)]
fn set_owner_if_needed(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect socket ownership at {}", path.display()))?;
    if metadata.uid() == uid && metadata.gid() == gid {
        return Ok(());
    }
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .with_context(|| {
        format!(
            "failed to assign host API socket {} to uid {uid}, gid {gid}",
            path.display()
        )
    })
}

fn bind_agent(path: &Path) -> Result<UnixListener> {
    prepare(path)?;
    let listener =
        bind_with_umask(path, 0o111).map_err(|source| AgentApiError::socket_bind(path, source))?;
    outcalld::unix_socket::set_mode(path, 0o666)?;
    info!(socket = %path.display(), "agent API listening (mode 0666; peer identity enforced)");
    Ok(listener)
}

fn prepare(path: &Path) -> Result<()> {
    outcalld::unix_socket::ensure_parent(path)?;
    outcalld::unix_socket::remove_stale(path)?;
    Ok(())
}

fn bind_with_umask(path: &Path, mask: u32) -> std::io::Result<UnixListener> {
    let old_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(mask));
    let result = UnixListener::bind(path);
    rustix::process::umask(old_umask);
    result
}

fn require_distinct_absolute_paths(host: &Path, agent: &Path) -> Result<()> {
    if !host.is_absolute() || !agent.is_absolute() {
        anyhow::bail!("host and agent socket paths must be absolute");
    }
    let host_identity = canonical_socket_identity(host)?;
    let agent_identity = canonical_socket_identity(agent)?;
    if host_identity == agent_identity {
        anyhow::bail!("host and agent API sockets must use different paths");
    }
    Ok(())
}

fn canonical_socket_identity(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("socket path must have a parent directory")?;
    outcalld::unix_socket::ensure_parent(path)?;
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("failed to resolve socket parent {}", parent.display()))?;
    let file_name = path
        .file_name()
        .context("socket path must have a file name")?;
    Ok(parent.join(file_name))
}

fn cleanup_path(path: &Path, label: &str) {
    if let Err(error) = outcalld::unix_socket::remove_stale(path) {
        warn!(%error, socket = %path.display(), "could not remove {label} socket");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_paths_must_be_absolute_and_distinct() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        assert!(require_distinct_absolute_paths(&socket, &socket).is_err());
        assert!(require_distinct_absolute_paths(Path::new("host.sock"), &socket).is_err());
        assert!(require_distinct_absolute_paths(&socket, &root.path().join("agent.sock")).is_ok());
    }

    #[test]
    fn retaining_current_socket_owner_needs_no_chown_capability() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("owner.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();

        set_owner_if_needed(&socket, metadata.uid(), metadata.gid()).unwrap();
    }
}
