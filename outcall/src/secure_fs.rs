use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_REGULAR_FILE_BYTES: usize = 16 * 1024 * 1024;

pub fn ensure_secure_subdir(root: &Path, relative: &Path) -> Result<PathBuf> {
    secure_subdir(root, relative, true)?.context("created secure subdirectory must exist")
}

pub fn existing_secure_subdir(root: &Path, relative: &Path) -> Result<Option<PathBuf>> {
    secure_subdir(root, relative, false)
}

fn secure_subdir(root: &Path, relative: &Path, create: bool) -> Result<Option<PathBuf>> {
    if relative.is_absolute() {
        anyhow::bail!(
            "secure subdirectory path must be relative: {}",
            relative.display()
        );
    }
    let mut current = std::fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            anyhow::bail!(
                "secure subdirectory path must contain only normal components: {}",
                relative.display()
            );
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => validate_real_directory(&current, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&current)
                    .with_context(|| format!("failed to create {}", current.display()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", current.display()));
            }
        }
        if create {
            secure_runtime_dir(&current)?;
        }
    }
    Ok(Some(current))
}

pub fn write_runtime_file(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} must have a parent directory", path.display()))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("failed to stat {}", parent.display()))?;
    validate_real_directory(parent, &parent_metadata)?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("runtime file name must be valid UTF-8")?;
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
        secure_runtime_file(&temporary)?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        drop(file);
        replace_file(&temporary, path)?;
        sync_parent_directory(path)
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(with_temporary_cleanup(error, &temporary)),
    }
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

pub fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    read_regular_file_bounded(path, MAX_REGULAR_FILE_BYTES)
}

pub fn read_regular_file_bounded(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let Some(metadata) = path_entry(path)? else {
        return Ok(None);
    };
    validate_regular_file(path, &metadata)?;
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
    validate_regular_file(
        path,
        &file
            .metadata()
            .with_context(|| format!("failed to inspect {}", path.display()))?,
    )?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(limit));
    std::io::Read::by_ref(&mut file)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() > limit {
        anyhow::bail!("{} exceeds {limit} bytes", path.display());
    }
    Ok(Some(bytes))
}

pub fn regular_file_exists(path: &Path) -> Result<bool> {
    let Some(metadata) = path_entry(path)? else {
        return Ok(false);
    };
    validate_regular_file(path, &metadata)?;
    Ok(true)
}

pub fn read_regular_string(path: &Path) -> Result<Option<String>> {
    read_regular_string_bounded(path, MAX_REGULAR_FILE_BYTES)
}

pub fn read_regular_string_bounded(path: &Path, limit: usize) -> Result<Option<String>> {
    let Some(bytes) = read_regular_file_bounded(path, limit)? else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Some)
        .with_context(|| format!("{} must contain valid UTF-8", path.display()))
}

pub fn remove_file_entry(path: &Path) -> Result<bool> {
    let Some(metadata) = path_entry(path)? else {
        return Ok(false);
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        anyhow::bail!("{} is a directory", path.display());
    }
    std::fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    sync_parent_directory(path)?;
    Ok(true)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} must have a parent directory", path.display()))?;
    std::fs::File::open(parent)
        .with_context(|| format!("failed to open {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn path_entry(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

#[cfg(unix)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    std::fs::rename(temporary, destination).with_context(|| {
        format!(
            "failed to replace {} with {}",
            destination.display(),
            temporary.display()
        )
    })
}

#[cfg(not(unix))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(destination) {
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            anyhow::bail!("{} is a directory", destination.display());
        }
        std::fs::remove_file(destination)
            .with_context(|| format!("failed to remove {}", destination.display()))?;
    }
    std::fs::rename(temporary, destination).with_context(|| {
        format!(
            "failed to replace {} with {}",
            destination.display(),
            temporary.display()
        )
    })
}

fn validate_real_directory(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{} must be a real directory, not a symlink", path.display());
    }
    Ok(())
}

fn validate_regular_file(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a real file, not a symlink", path.display());
    }
    Ok(())
}

#[cfg(unix)]
pub fn secure_runtime_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{} must be a real directory, not a symlink", path.display());
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn secure_runtime_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn secure_runtime_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a real file, not a symlink", path.display());
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn secure_runtime_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secure_subdir_rejects_symlink_components() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(".outcall")).unwrap();

        let error = ensure_secure_subdir(root.path(), Path::new(".outcall/home/claude"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("must be a real directory"));
        assert!(!outside.path().join("home").exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_runtime_write_replaces_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let runtime = ensure_secure_subdir(root.path(), Path::new(".outcall/auth/claude")).unwrap();
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, "untouched").unwrap();
        let mode = runtime.join("mode");
        symlink(&sentinel, &mode).unwrap();

        write_runtime_file(&mode, b"copy").unwrap();

        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "untouched");
        assert_eq!(std::fs::read_to_string(&mode).unwrap(), "copy");
        assert!(
            !std::fs::symlink_metadata(&mode)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_read_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, "secret").unwrap();
        let link = root.path().join("config");
        symlink(&sentinel, &link).unwrap();

        let error = read_regular_string(&link).unwrap_err().to_string();

        assert!(error.contains("must be a real file"));
    }

    #[test]
    fn regular_file_read_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config");
        std::fs::write(&path, "12345").unwrap();

        let error = read_regular_file_bounded(&path, 4).unwrap_err().to_string();

        assert!(error.contains("exceeds 4 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn remove_file_entry_unlinks_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, "secret").unwrap();
        let link = root.path().join("generated");
        symlink(&sentinel, &link).unwrap();

        assert!(remove_file_entry(&link).unwrap());
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "secret");
        assert!(!link.exists());
    }
}
