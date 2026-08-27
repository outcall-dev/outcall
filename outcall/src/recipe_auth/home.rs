use std::path::{Component, Path, PathBuf};

use anyhow::Result;
use outcall::secure_fs::{ensure_secure_subdir, existing_secure_subdir};

const DEFAULT_CONTAINER_HOME: &str = "/home/node";

pub(super) fn existing_recipe_home(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<Option<PathBuf>> {
    existing_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("home").join(recipe.id),
    )
}

pub(super) fn ensure_recipe_home_mount(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
    config: &mut outcall::agent_config::AgentConfig,
    container_home: &Path,
) -> Result<PathBuf> {
    let home_dir = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("home").join(recipe.id),
    )?;
    add_home_mount(config, &home_dir, container_home);
    Ok(home_dir)
}

pub(super) fn add_home_mount(
    config: &mut outcall::agent_config::AgentConfig,
    home_dir: &Path,
    container_home: &Path,
) {
    let mount = format!("{}:{}", home_dir.display(), container_home.display());
    if !config.volumes.iter().any(|existing| existing == &mount) {
        config.volumes.push(mount);
    }
    configure_container_home(config, container_home);
}

fn configure_container_home(
    config: &mut outcall::agent_config::AgentConfig,
    container_home: &Path,
) {
    config
        .env
        .insert("HOME".to_string(), container_home.display().to_string());
    if let Some(user) = container_home.file_name().and_then(|name| name.to_str()) {
        config.env.insert("USER".to_string(), user.to_string());
        config.env.insert("LOGNAME".to_string(), user.to_string());
    }
}

pub(super) fn container_home_path(config: &outcall::agent_config::AgentConfig) -> Result<PathBuf> {
    let home = config
        .env
        .get("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTAINER_HOME));
    if !valid_container_home(&home) {
        anyhow::bail!(
            "recipe container HOME {} must be /root or a clean path below /home",
            home.display()
        );
    }
    let workspace = Path::new(&config.workspace);
    if home.starts_with(workspace) || workspace.starts_with(&home) {
        anyhow::bail!(
            "recipe container HOME {} must not overlap workspace {}",
            home.display(),
            workspace.display()
        );
    }
    Ok(home)
}

pub(super) fn valid_container_home(home: &Path) -> bool {
    let encoded = home.to_string_lossy();
    let under_home = home.starts_with("/home") && home != Path::new("/home");
    (home == Path::new("/root") || under_home)
        && !encoded.chars().any(|ch| matches!(ch, ':' | '\n' | '\r'))
        && !home
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}
