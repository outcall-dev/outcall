use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

pub fn ensure_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("socket path {} must have a parent", path.display()))?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!(
                "socket parent {} must be a real directory",
                parent.display()
            );
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create socket parent {}", parent.display()))?;
            let metadata = std::fs::symlink_metadata(parent)
                .with_context(|| format!("failed to stat socket parent {}", parent.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "socket parent {} must be a real directory",
                    parent.display()
                );
            }
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to stat socket parent {}", parent.display()))
        }
    }
}

pub fn remove_stale(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
            Ok(true)
        }
        Ok(_) => anyhow::bail!("refusing to replace non-socket entry at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat socket {}", path.display()))?;
    if !metadata.file_type().is_socket() {
        anyhow::bail!("{} is not a Unix socket", path.display());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod socket {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_socket_removal_refuses_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("daemon.sock");
        std::fs::write(&path, "keep").unwrap();

        let error = remove_stale(&path).unwrap_err().to_string();

        assert!(error.contains("non-socket"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "keep");
    }

    #[test]
    fn stale_socket_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);

        assert!(remove_stale(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn socket_mode_is_explicit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        set_mode(&path, 0o666).unwrap();

        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_parent_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = root.path().join("run");
        symlink(outside.path(), &parent).unwrap();

        let error = ensure_parent(&parent.join("daemon.sock"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("real directory"));
    }
}
