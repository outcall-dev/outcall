//! Validation for host paths exposed to managed agent containers.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use outcall_api::{AGENT_SOCKET_CONTAINER_PATH, SHIM_CONTAINER_PATH};

const PROTECTED_CONTAINER_PATHS: &[&str] = &[
    AGENT_SOCKET_CONTAINER_PATH,
    SHIM_CONTAINER_PATH,
    "/etc/resolv.conf",
];

/// Reject bind mounts that expose a protected path directly or through one of
/// its parent directories. Named Docker volumes remain allowed.
pub fn validate_bind_mounts(mounts: &[String], denied_paths: &[PathBuf]) -> Result<()> {
    let denied = denied_paths
        .iter()
        .map(|path| path_identities(path))
        .collect::<Result<Vec<_>>>()?;

    for mount in mounts {
        let (source, destination) = parse_bind_mount(mount)?;
        validate_container_destination(destination)?;

        let source = Path::new(source);
        if !source.is_absolute() {
            let mut components = source.components();
            if !matches!(components.next(), Some(Component::Normal(_)))
                || components.next().is_some()
            {
                anyhow::bail!(
                    "relative bind mount source {source:?} is ambiguous; use an absolute host path or a named Docker volume"
                );
            }
            continue;
        }

        let source_identities = path_identities(source)?;
        for denied_identities in &denied {
            for denied_path in denied_identities {
                if source_identities.iter().any(|resolved_source| {
                    denied_path == resolved_source || denied_path.starts_with(resolved_source)
                }) {
                    anyhow::bail!(
                        "bind mount denied - {source:?} exposes protected host path {denied_path:?}"
                    );
                }
            }
        }
    }
    Ok(())
}

fn parse_bind_mount(mount: &str) -> Result<(&str, &str)> {
    let mut fields = mount.split(':');
    let source = fields.next().unwrap_or_default();
    let destination = fields.next().unwrap_or_default();
    let options = fields.next();
    if source.is_empty() || destination.is_empty() {
        anyhow::bail!("invalid bind mount {mount:?}; expected source:destination[:options]");
    }
    if fields.next().is_some() || options.is_some_and(str::is_empty) {
        anyhow::bail!("invalid bind mount {mount:?}; expected source:destination[:options]");
    }
    Ok((source, destination))
}

fn validate_container_destination(destination: &str) -> Result<()> {
    let destination = lexical_absolute(Path::new(destination)).with_context(|| {
        format!("container bind destination {destination:?} must be an absolute path")
    })?;
    for protected in PROTECTED_CONTAINER_PATHS {
        let protected = Path::new(protected);
        if destination == protected || protected.starts_with(&destination) {
            anyhow::bail!(
                "bind mount destination {destination:?} covers protected container path {protected:?}"
            );
        }
    }
    Ok(())
}

fn path_identities(path: &Path) -> Result<Vec<PathBuf>> {
    let lexical = lexical_absolute(path)?;
    let mut identities = vec![lexical];
    if let Ok(canonical) = std::fs::canonicalize(path) {
        if !identities.contains(&canonical) {
            identities.push(canonical);
        }
    }
    Ok(identities)
}

fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!("protected bind path {path:?} must be absolute");
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized == Path::new("/") || !normalized.pop() {
                    anyhow::bail!("bind path {path:?} escapes the filesystem root");
                }
            }
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_normal_bind_paths_and_named_volumes() {
        let denied = vec![PathBuf::from("/run/outcall/host.sock")];
        validate_bind_mounts(
            &[
                "/workspace/project:/workspace".to_string(),
                "agent-cache:/cache:rw".to_string(),
            ],
            &denied,
        )
        .unwrap();
    }

    #[test]
    fn rejects_protected_path_and_ancestor_mounts() {
        let denied = vec![PathBuf::from("/var/run/docker.sock")];
        for mount in [
            "/var/run/docker.sock:/docker.sock",
            "/var/run:/host-run:ro",
            "/:/host",
        ] {
            assert!(
                validate_bind_mounts(&[mount.to_string()], &denied).is_err(),
                "{mount}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_to_protected_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("host.sock");
        std::fs::write(&protected, "socket placeholder").unwrap();
        let alias = temp.path().join("alias");
        symlink(&protected, &alias).unwrap();
        let mount = format!("{}:/host.sock", alias.display());

        assert!(validate_bind_mounts(&[mount], &[protected]).is_err());
    }

    #[test]
    fn rejects_malformed_and_relative_bind_sources() {
        let denied = vec![PathBuf::from("/run/outcall/host.sock")];
        assert!(validate_bind_mounts(&["missing-destination".to_string()], &denied).is_err());
        assert!(validate_bind_mounts(&["./relative:/data".to_string()], &denied).is_err());
        assert!(validate_bind_mounts(&["source:relative".to_string()], &denied).is_err());
        assert!(validate_bind_mounts(&["source:/data:".to_string()], &denied).is_err());
        assert!(validate_bind_mounts(&["source:/data:ro:extra".to_string()], &denied).is_err());
    }

    #[test]
    fn rejects_mounts_covering_container_control_paths() {
        let denied = Vec::new();
        for mount in [
            "/tmp/agent:/run/outcall/agent.sock",
            "tools:/usr/local/bin",
            "/tmp/resolver:/etc/resolv.conf:ro",
            "/tmp/root:/:ro",
        ] {
            assert!(
                validate_bind_mounts(&[mount.to_string()], &denied).is_err(),
                "{mount}"
            );
        }
    }
}
