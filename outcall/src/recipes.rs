//! Built-in recipe registry for common agent runtimes.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::secure_fs::{ensure_secure_subdir, read_regular_string, write_runtime_file};

mod auth;
mod catalog;

pub use auth::{
    AuthMountPlan, AuthStaging, auth_mount_plan, expanded_path, has_credential_file_in_home,
    has_host_credential_file, stage_auth_copy, stage_global_config_copy,
};
#[cfg(test)]
use auth::{
    MAX_AUTH_COPY_FILE_BYTES, auth_mount_plan_with_home, stage_auth_copy_with_home,
    stage_auth_copy_with_home_options, stage_global_config_copy_with_home,
};
use catalog::HOST_RESOURCES_TEMPLATE;
pub use catalog::RECIPES;

#[derive(Debug, Clone)]
pub struct Recipe {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub manifest: &'static str,
    pub dockerfile: &'static str,
    pub rules: &'static str,
    pub readme: &'static str,
    pub context: &'static str,
    pub agent_config: &'static str,
    pub legacy_agent_configs: &'static [&'static str],
    pub policy_templates: &'static [PolicyTemplate],
    pub auth_env: &'static [&'static str],
    pub credential_paths: &'static [&'static str],
    pub user_paths: &'static [&'static str],
    pub global_config_paths: &'static [&'static str],
    pub mount_paths: &'static [&'static str],
    pub project_paths: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyTemplate {
    pub name: &'static str,
    pub id: &'static str,
    pub description: &'static str,
    pub condition: &'static str,
}

pub fn get_recipe(id: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|recipe| recipe.id == id)
}

pub fn recipe_ids() -> impl Iterator<Item = &'static str> {
    RECIPES.iter().map(|recipe| recipe.id)
}

pub fn init_recipe(project_dir: &Path, recipe: &Recipe, force: bool) -> Result<Vec<PathBuf>> {
    let outcall_dir = ensure_secure_subdir(project_dir, Path::new(".outcall"))?;
    let recipe_dir = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("recipes").join(recipe.id),
    )?;
    let rules_dir = ensure_secure_subdir(project_dir, Path::new(".outcall/rules"))?;

    let mut written = Vec::new();
    write_new(
        &recipe_dir.join("recipe.yaml"),
        recipe.manifest,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("Dockerfile"),
        recipe.dockerfile,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("README.md"),
        recipe.readme,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("context.md"),
        recipe.context,
        force,
        &mut written,
    )?;
    write_new(
        &rules_dir.join(format!("{}.yaml", recipe.id)),
        recipe.rules,
        force,
        &mut written,
    )?;
    write_agent_config(
        &outcall_dir.join("agent.yaml"),
        recipe.agent_config,
        force,
        &mut written,
    )?;
    write_shared_template(
        &outcall_dir.join("host-resources.yaml"),
        HOST_RESOURCES_TEMPLATE,
        &mut written,
    )?;
    if let Some(path) = ensure_outcall_gitignore(project_dir)? {
        written.push(path);
    }

    Ok(written)
}

/// Restore missing generated files while preserving every existing real file.
pub fn ensure_recipe(project_dir: &Path, recipe: &Recipe) -> Result<Vec<PathBuf>> {
    let outcall_dir = ensure_secure_subdir(project_dir, Path::new(".outcall"))?;
    let recipe_dir = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("recipes").join(recipe.id),
    )?;
    let rules_dir = ensure_secure_subdir(project_dir, Path::new(".outcall/rules"))?;

    let generated = [
        (recipe_dir.join("recipe.yaml"), recipe.manifest),
        (recipe_dir.join("Dockerfile"), recipe.dockerfile),
        (recipe_dir.join("README.md"), recipe.readme),
        (recipe_dir.join("context.md"), recipe.context),
        (rules_dir.join(format!("{}.yaml", recipe.id)), recipe.rules),
        (outcall_dir.join("agent.yaml"), recipe.agent_config),
        (
            outcall_dir.join("host-resources.yaml"),
            HOST_RESOURCES_TEMPLATE,
        ),
    ];
    let mut written = Vec::new();
    for (path, contents) in generated {
        write_missing(&path, contents, &mut written)?;
    }
    if let Some(path) = ensure_outcall_gitignore(project_dir)? {
        written.push(path);
    }
    Ok(written)
}

pub fn recipe_image_name(recipe: &Recipe) -> String {
    format!(
        "ghcr.io/outcall-dev/outcall-recipe-{}:v{}",
        recipe.id,
        env!("CARGO_PKG_VERSION")
    )
}

pub fn recipe_local_image_name(recipe: &Recipe) -> String {
    format!("outcall-recipe-{}:local", recipe.id)
}

pub fn recipe_dockerfile(project_dir: &Path, recipe: &Recipe) -> PathBuf {
    project_dir
        .join(".outcall")
        .join("recipes")
        .join(recipe.id)
        .join("Dockerfile")
}

pub fn recipe_dockerfile_is_custom(project_dir: &Path, recipe: &Recipe) -> Result<bool> {
    let path = recipe_dockerfile(project_dir, recipe);
    Ok(read_regular_string(&path)?.is_some_and(|contents| contents != recipe.dockerfile))
}

/// Return true when the shared agent config is an unmodified built-in recipe
/// template rather than a user-authored override.
pub fn has_generated_agent_config(project_dir: &Path) -> Result<bool> {
    let path = project_dir.join(".outcall").join("agent.yaml");
    Ok(read_existing_file(&path)?.is_some_and(|existing| {
        RECIPES.iter().any(|recipe| {
            existing == recipe.agent_config
                || recipe.legacy_agent_configs.contains(&existing.as_str())
        })
    }))
}

fn write_new(path: &Path, contents: &str, force: bool, written: &mut Vec<PathBuf>) -> Result<()> {
    if path_entry(path)?.is_some() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite generated recipe files",
            path.display()
        );
    }
    write_runtime_file(path, contents.as_bytes())?;
    written.push(path.to_path_buf());
    Ok(())
}

fn write_missing(path: &Path, contents: &str, written: &mut Vec<PathBuf>) -> Result<()> {
    if path_entry(path)?.is_some() {
        read_existing_file(path)?;
        return Ok(());
    }
    write_runtime_file(path, contents.as_bytes())?;
    written.push(path.to_path_buf());
    Ok(())
}

fn write_agent_config(
    path: &Path,
    contents: &str,
    force: bool,
    written: &mut Vec<PathBuf>,
) -> Result<()> {
    if !force && let Some(existing) = read_existing_file(path)? {
        if existing == contents {
            return Ok(());
        }
        if !RECIPES.iter().any(|recipe| {
            existing == recipe.agent_config
                || recipe.legacy_agent_configs.contains(&existing.as_str())
        }) {
            return Ok(());
        }
    }

    write_runtime_file(path, contents.as_bytes())?;
    written.push(path.to_path_buf());
    Ok(())
}

fn write_shared_template(path: &Path, contents: &str, written: &mut Vec<PathBuf>) -> Result<()> {
    if path_entry(path)?.is_some() {
        read_existing_file(path)?;
        return Ok(());
    }

    write_runtime_file(path, contents.as_bytes())?;
    written.push(path.to_path_buf());
    Ok(())
}

fn path_entry(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

fn read_existing_file(path: &Path) -> Result<Option<String>> {
    let Some(metadata) = path_entry(path)? else {
        return Ok(None);
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a real file, not a symlink", path.display());
    }
    std::fs::read_to_string(path)
        .map(Some)
        .with_context(|| format!("failed to read {}", path.display()))
}

pub fn ensure_outcall_gitignore(project_dir: &Path) -> Result<Option<PathBuf>> {
    let outcall_dir = ensure_secure_subdir(project_dir, Path::new(".outcall"))?;
    let path = outcall_dir.join(".gitignore");
    let existing = read_existing_file(&path)?.unwrap_or_default();
    let has_auth = existing.lines().any(|line| line.trim() == "auth/");
    let has_home = existing.lines().any(|line| line.trim() == "home/");
    let has_run = existing.lines().any(|line| line.trim() == "run/");
    let has_broker_rule = existing
        .lines()
        .any(|line| line.trim() == "rules/.outcall-host-broker.yaml");
    if has_auth && has_home && has_run && has_broker_rule {
        return Ok(None);
    }

    let mut next = existing;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    if !has_auth {
        next.push_str("auth/\n");
    }
    if !has_home {
        next.push_str("home/\n");
    }
    if !has_run {
        next.push_str("run/\n");
    }
    if !has_broker_rule {
        next.push_str("rules/.outcall-host-broker.yaml\n");
    }
    write_runtime_file(&path, next.as_bytes())?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests;
