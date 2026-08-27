use std::path::{Path, PathBuf};

use anyhow::Result;
use outcall::secure_fs::{
    ensure_secure_subdir, existing_secure_subdir, read_regular_string_bounded, write_runtime_file,
};

use crate::cli::RecipeAuthMode;

const MAX_AUTH_MODE_BYTES: usize = 32;

pub(crate) fn save_auth_preference(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
    mode: RecipeAuthMode,
) -> Result<()> {
    let value = match mode {
        RecipeAuthMode::Auto => "auto",
        RecipeAuthMode::Copy => "copy",
        RecipeAuthMode::Mount => "mount",
        RecipeAuthMode::EnvOnly => "env-only",
    };
    let parent = ensure_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("auth").join(recipe.id),
    )?;
    write_runtime_file(&parent.join("mode"), value.as_bytes())
}

pub(super) fn load_auth_preference(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
) -> Result<Option<RecipeAuthMode>> {
    let Some(parent) = existing_secure_subdir(
        project_dir,
        &PathBuf::from(".outcall").join("auth").join(recipe.id),
    )?
    else {
        return Ok(None);
    };
    let path = parent.join("mode");
    let Some(value) = read_regular_string_bounded(&path, MAX_AUTH_MODE_BYTES)? else {
        return Ok(None);
    };
    let mode = match value.trim() {
        "copy" => RecipeAuthMode::Copy,
        "mount" => RecipeAuthMode::Mount,
        "env-only" => RecipeAuthMode::EnvOnly,
        "auto" => RecipeAuthMode::Auto,
        _ => anyhow::bail!("invalid saved auth mode in {}", path.display()),
    };
    Ok(Some(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_preference_is_rejected() {
        let project = tempfile::tempdir().unwrap();
        let recipe = outcall::recipes::get_recipe("codex").unwrap();
        let parent = project.path().join(".outcall/auth/codex");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("mode"), "x".repeat(MAX_AUTH_MODE_BYTES + 1)).unwrap();

        let error = load_auth_preference(project.path(), recipe)
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeds"));
    }
}
