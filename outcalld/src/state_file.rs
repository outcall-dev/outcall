use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a real file, not a symlink", path.display());
    }
    if metadata.len() > limit as u64 {
        anyhow::bail!("{} exceeds {limit} bytes", path.display());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !opened_metadata.is_file() {
        anyhow::bail!("{} must be a real file, not a symlink", path.display());
    }
    let mut bytes = Vec::with_capacity((opened_metadata.len() as usize).min(limit));
    std::io::Read::by_ref(&mut file)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() > limit {
        anyhow::bail!("{} exceeds {limit} bytes", path.display());
    }
    Ok(Some(bytes))
}

pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let temporary = write_temporary(path, contents, mode)?;
    let result = (|| -> Result<()> {
        std::fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to replace {} with {}",
                path.display(),
                temporary.display()
            )
        })?;
        sync_parent(path)
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(with_temporary_cleanup(error, &temporary)),
    }
}

pub fn write_new_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("{} already exists", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }
    let temporary = write_temporary(path, contents, mode)?;
    let result = (|| -> Result<()> {
        std::fs::hard_link(&temporary, path).with_context(|| {
            format!(
                "failed to install new file {} from {}",
                path.display(),
                temporary.display()
            )
        })?;
        std::fs::remove_file(&temporary)
            .with_context(|| format!("failed to remove {}", temporary.display()))?;
        sync_parent(path)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(with_temporary_cleanup(error, &temporary)),
    }
}

pub fn remove_if_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            anyhow::bail!("{} is a directory", path.display());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }
    std::fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    sync_parent(path)?;
    Ok(true)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} must have a parent directory", path.display()))?;
    std::fs::File::open(parent)
        .with_context(|| format!("failed to open {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync {}", parent.display()))
}

fn write_temporary(path: &Path, contents: &[u8], mode: u32) -> Result<PathBuf> {
    let parent = path
        .parent()
        .with_context(|| format!("{} must have a parent directory", path.display()))?;
    ensure_real_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("state file name must be valid UTF-8")?;
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{file_name}.outcall-tmp-{}-{sequence}",
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        set_mode(&file, mode)?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(with_temporary_cleanup(error, &temporary));
    }
    Ok(temporary)
}

fn with_temporary_cleanup(error: anyhow::Error, temporary: &Path) -> anyhow::Error {
    match std::fs::remove_file(temporary) {
        Ok(()) => error,
        Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => error,
        Err(cleanup) => error.context(format!(
            "also failed to remove temporary file {}: {cleanup}",
            temporary.display()
        )),
    }
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("{} must be a real directory, not a symlink", path.display());
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            let metadata = std::fs::symlink_metadata(path)
                .with_context(|| format!("failed to stat {}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("{} must be a real directory, not a symlink", path.display());
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

#[cfg(unix)]
fn set_mode(file: &std::fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .context("failed to set state file permissions")
}

#[cfg(not(unix))]
fn set_mode(_file: &std::fs::File, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_rejects_large_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        std::fs::write(&path, "12345").unwrap();

        let error = read_optional(&path, 4).unwrap_err().to_string();

        assert!(error.contains("exceeds 4 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let path = root.path().join("state");
        std::fs::write(&target, "secret").unwrap();
        symlink(&target, &path).unwrap();

        let error = read_optional(&path, 1024).unwrap_err().to_string();

        assert!(error.contains("real file"));
    }

    #[test]
    fn create_new_does_not_replace_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("rule.yaml");
        std::fs::write(&path, "existing").unwrap();

        let error = write_new_atomic(&path, b"new", 0o600)
            .unwrap_err()
            .to_string();

        assert!(error.contains("already exists"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "existing");
    }

    #[cfg(unix)]
    #[test]
    fn durable_remove_unlinks_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let path = root.path().join("state");
        std::fs::write(&target, "keep").unwrap();
        symlink(&target, &path).unwrap();

        assert!(remove_if_exists(&path).unwrap());
        assert!(!path.exists());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "keep");
        assert!(!remove_if_exists(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_does_not_follow_destination_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, "untouched").unwrap();
        let path = root.path().join("state");
        symlink(&sentinel, &path).unwrap();

        write_atomic(&path, b"new", 0o600).unwrap();

        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "untouched");
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = root.path().join("state");
        symlink(outside.path(), &parent).unwrap();

        let error = write_atomic(&parent.join("queue.json"), b"{}", 0o600)
            .unwrap_err()
            .to_string();

        assert!(error.contains("real directory"));
        assert!(!outside.path().join("queue.json").exists());
    }
}
