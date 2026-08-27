use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::secure_fs::{ensure_secure_subdir, secure_runtime_file};

use super::Recipe;

pub(super) const MAX_AUTH_COPY_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AUTH_COPY_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_AUTH_COPY_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStaging {
    pub home_dir: PathBuf,
    pub copied: Vec<(PathBuf, PathBuf)>,
    pub missing: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMountPlan {
    pub mounts: Vec<String>,
}

pub fn stage_auth_copy(
    project_dir: &Path,
    recipe: &Recipe,
    force: bool,
    include_global_config: bool,
) -> Result<AuthStaging> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    stage_auth_copy_with_home_options(
        project_dir,
        recipe,
        home.as_deref(),
        force,
        include_global_config,
    )
}

pub fn stage_global_config_copy(
    project_dir: &Path,
    recipe: &Recipe,
    force: bool,
) -> Result<AuthStaging> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    stage_global_config_copy_with_home(project_dir, recipe, home.as_deref(), force)
}

#[cfg(test)]
pub(super) fn stage_auth_copy_with_home(
    project_dir: &Path,
    recipe: &Recipe,
    home: Option<&Path>,
    force: bool,
) -> Result<AuthStaging> {
    stage_auth_copy_with_home_options(project_dir, recipe, home, force, false)
}

pub(super) fn stage_auth_copy_with_home_options(
    project_dir: &Path,
    recipe: &Recipe,
    home: Option<&Path>,
    force: bool,
    include_global_config: bool,
) -> Result<AuthStaging> {
    let candidates = copy_candidates(recipe, include_global_config);
    stage_copy_candidates(project_dir, recipe, home, force, &candidates)
}

pub(super) fn stage_global_config_copy_with_home(
    project_dir: &Path,
    recipe: &Recipe,
    home: Option<&Path>,
    force: bool,
) -> Result<AuthStaging> {
    stage_copy_candidates(project_dir, recipe, home, force, recipe.global_config_paths)
}

fn stage_copy_candidates(
    project_dir: &Path,
    recipe: &Recipe,
    home: Option<&Path>,
    force: bool,
    candidates: &[&'static str],
) -> Result<AuthStaging> {
    let home_parent = ensure_secure_subdir(project_dir, Path::new(".outcall/home"))?;
    let home_dir = home_parent.join(recipe.id);
    let auth_parent = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("auth").join(recipe.id),
    )?;
    migrate_legacy_auth_home(&auth_parent.join("home"), &home_dir)?;
    let home_dir = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("home").join(recipe.id),
    )?;

    let mut budget = CopyBudget::default();
    for candidate in candidates {
        let src = expanded_path_with_home(candidate, home);
        if src.exists() {
            validate_copy_path(&src, &mut budget).with_context(|| {
                format!(
                    "cannot safely stage {candidate}; use `--auth mount` to opt into direct host mounting"
                )
            })?;
        }
    }

    let mut copied = Vec::new();
    let mut missing = Vec::new();
    for candidate in candidates {
        let src = expanded_path_with_home(candidate, home);
        if !src.exists() {
            missing.push(*candidate);
            continue;
        }
        let relative = candidate.strip_prefix("~/").unwrap_or(candidate);
        let relative = Path::new(relative);
        let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
        let dest_parent = ensure_secure_subdir(&home_dir, parent_relative)?;
        let dest = dest_parent.join(
            relative
                .file_name()
                .context("auth/config copy path must have a file name")?,
        );
        copy_path(&src, &dest, force)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
        if dest.exists() {
            copied.push((src, dest));
        }
    }
    for candidate in recipe.credential_paths {
        let relative = candidate.strip_prefix("~/").unwrap_or(candidate);
        let credential = home_dir.join(relative);
        if std::fs::symlink_metadata(&credential)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            secure_runtime_file(&credential)?;
        }
    }

    Ok(AuthStaging {
        home_dir,
        copied,
        missing,
    })
}

fn copy_candidates(recipe: &Recipe, include_global_config: bool) -> Vec<&'static str> {
    let mut candidates = recipe.user_paths.to_vec();
    if include_global_config {
        candidates.extend_from_slice(recipe.global_config_paths);
    }
    candidates
}

fn migrate_legacy_auth_home(legacy: &Path, home_dir: &Path) -> Result<()> {
    let Ok(metadata) = std::fs::symlink_metadata(legacy) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "legacy recipe home {} must be a real directory, not a symlink or special file",
            legacy.display()
        );
    }
    if home_dir.exists() {
        return Ok(());
    }
    std::fs::rename(legacy, home_dir).with_context(|| {
        format!(
            "failed to migrate legacy recipe home {} to {}",
            legacy.display(),
            home_dir.display()
        )
    })?;
    Ok(())
}

#[derive(Default)]
struct CopyBudget {
    entries: usize,
    total_bytes: u64,
}

fn validate_copy_path(path: &Path, budget: &mut CopyBudget) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    budget.entries += 1;
    if budget.entries > MAX_AUTH_COPY_ENTRIES {
        anyhow::bail!(
            "auth/config copy contains more than {MAX_AUTH_COPY_ENTRIES} filesystem entries"
        );
    }

    if metadata.is_file() {
        let size = metadata.len();
        if size > MAX_AUTH_COPY_FILE_BYTES {
            anyhow::bail!(
                "{} is larger than the {} MiB per-file auth/config copy limit",
                path.display(),
                MAX_AUTH_COPY_FILE_BYTES / (1024 * 1024)
            );
        }
        budget.total_bytes = budget
            .total_bytes
            .checked_add(size)
            .context("auth/config copy size overflow")?;
        if budget.total_bytes > MAX_AUTH_COPY_TOTAL_BYTES {
            anyhow::bail!(
                "auth/config copy is larger than the {} MiB total limit",
                MAX_AUTH_COPY_TOTAL_BYTES / (1024 * 1024)
            );
        }
        return Ok(());
    }

    if metadata.is_dir() {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            validate_copy_path(&entry?.path(), budget)?;
        }
        return Ok(());
    }

    anyhow::bail!("{} is not a regular file or directory", path.display())
}

pub fn auth_mount_plan(recipe: &Recipe, container_home: &Path) -> AuthMountPlan {
    let host_home = std::env::var_os("HOME").map(PathBuf::from);
    auth_mount_plan_with_home(recipe, host_home.as_deref(), container_home)
}

pub fn has_host_credential_file(recipe: &Recipe) -> bool {
    let host_home = std::env::var_os("HOME").map(PathBuf::from);
    has_credential_file_with_home(recipe, host_home.as_deref())
}

pub fn has_credential_file_in_home(recipe: &Recipe, home: &Path) -> bool {
    has_credential_file_with_home(recipe, Some(home))
}

fn has_credential_file_with_home(recipe: &Recipe, home: Option<&Path>) -> bool {
    recipe
        .credential_paths
        .iter()
        .map(|candidate| expanded_path_with_home(candidate, home))
        .any(|path| {
            std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        })
}

pub(super) fn auth_mount_plan_with_home(
    recipe: &Recipe,
    host_home: Option<&Path>,
    container_home: &Path,
) -> AuthMountPlan {
    let mut mounts = Vec::new();
    for candidate in recipe.mount_paths {
        let src = expanded_path_with_home(candidate, host_home);
        if !src.exists() {
            continue;
        }
        let relative = candidate.strip_prefix("~/").unwrap_or(candidate);
        let dest = container_home.join(relative);
        mounts.push(format!("{}:{}", src.display(), dest.display()));
    }

    AuthMountPlan { mounts }
}

fn copy_path(src: &Path, dest: &Path, force: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(src)
        .with_context(|| format!("failed to stat {}", src.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if let Ok(dest_metadata) = std::fs::symlink_metadata(dest) {
        if force {
            if dest_metadata.is_dir() && !dest_metadata.file_type().is_symlink() {
                std::fs::remove_dir_all(dest)
                    .with_context(|| format!("failed to remove {}", dest.display()))?;
            } else {
                std::fs::remove_file(dest)
                    .with_context(|| format!("failed to remove {}", dest.display()))?;
            }
        } else {
            return Ok(());
        }
    }

    if src.is_dir() {
        std::fs::create_dir_all(dest)
            .with_context(|| format!("failed to create {}", dest.display()))?;
        for entry in
            std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
        {
            let entry = entry?;
            copy_path(&entry.path(), &dest.join(entry.file_name()), force)?;
        }
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::copy(src, dest)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
    }

    Ok(())
}

pub fn expanded_path(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expanded_path_with_home(path, home.as_deref())
}

fn expanded_path_with_home(path: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}
