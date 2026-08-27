use anyhow::{Context, Result};
use outcall::secure_fs::{
    ensure_secure_subdir, existing_secure_subdir, read_regular_string, write_runtime_file,
};

use crate::recipe_auth::recipe_has_user_auth_paths;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecipeAuthHint {
    None,
    EnvOnly,
    Copy,
}

pub(super) fn auth_hint(env_auth: bool, file_auth: bool) -> RecipeAuthHint {
    match (env_auth, file_auth) {
        (true, false) => RecipeAuthHint::EnvOnly,
        (_, true) => RecipeAuthHint::Copy,
        (false, false) => RecipeAuthHint::None,
    }
}

pub(super) fn recommended_recipe_command(recipe: &outcall::recipes::Recipe) -> String {
    recommended_recipe_command_with_hint(recipe, default_auth_hint_for_recipe(recipe))
}

pub(super) fn recommended_recipe_command_with_hint(
    recipe: &outcall::recipes::Recipe,
    hint: RecipeAuthHint,
) -> String {
    match hint {
        RecipeAuthHint::EnvOnly => format!("outcall run {} --auth env-only", recipe.id),
        RecipeAuthHint::Copy | RecipeAuthHint::None => format!("outcall run {}", recipe.id),
    }
}

fn default_auth_hint_for_recipe(recipe: &outcall::recipes::Recipe) -> RecipeAuthHint {
    if recipe_has_env_auth(recipe) {
        RecipeAuthHint::EnvOnly
    } else {
        RecipeAuthHint::Copy
    }
}

pub(super) fn recipe_has_auth_candidate(recipe: &outcall::recipes::Recipe) -> bool {
    recipe_has_env_auth(recipe) || recipe_has_user_auth_paths(recipe)
}

fn recipe_has_project_context(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
) -> bool {
    recipe
        .project_paths
        .iter()
        .map(|path| project_dir.join(path))
        .any(|path| path.exists())
}

fn recipe_has_env_auth(recipe: &outcall::recipes::Recipe) -> bool {
    recipe
        .auth_env
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
}

fn detect_recipe_candidates() -> Vec<&'static outcall::recipes::Recipe> {
    outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_auth_candidate(recipe))
        .collect::<Vec<_>>()
}

pub(super) struct RecipeSelection {
    pub(super) recipe: &'static outcall::recipes::Recipe,
    pub(super) source: RecipeSource,
}

pub(super) enum RecipeSource {
    Explicit,
    SavedDefault,
    ProjectContext,
    HostAuth,
}

impl RecipeSource {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::SavedDefault => "saved project default",
            Self::ProjectContext => "project context",
            Self::HostAuth => "host auth",
        }
    }
}

pub(super) fn default_recipe_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    project_dir.join(".outcall").join("default-recipe")
}

pub(super) fn save_default_recipe(
    project_dir: &std::path::Path,
    recipe: &str,
) -> Result<std::path::PathBuf> {
    let outcall_dir = ensure_secure_subdir(project_dir, std::path::Path::new(".outcall"))?;
    let secure_path = outcall_dir.join("default-recipe");
    write_runtime_file(&secure_path, format!("{recipe}\n").as_bytes())?;
    Ok(default_recipe_path(project_dir))
}

pub(super) fn load_default_recipe(
    project_dir: &std::path::Path,
) -> Result<Option<&'static outcall::recipes::Recipe>> {
    let Some(outcall_dir) = existing_secure_subdir(project_dir, std::path::Path::new(".outcall"))?
    else {
        return Ok(None);
    };
    let path = outcall_dir.join("default-recipe");
    let Some(recipe_id) = read_regular_string(&path)? else {
        return Ok(None);
    };
    let recipe_id = recipe_id.trim();
    if recipe_id.is_empty() {
        return Ok(None);
    }
    let recipe = outcall::recipes::get_recipe(recipe_id)
        .with_context(|| format!("invalid recipe id {:?} in {}", recipe_id, path.display()))?;
    Ok(Some(recipe))
}

pub(super) fn detect_default_recipe() -> Result<RecipeSelection> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    if let Some(recipe) = load_default_recipe(&project_dir)? {
        return Ok(RecipeSelection {
            recipe,
            source: RecipeSource::SavedDefault,
        });
    }

    let context_candidates = outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_project_context(&project_dir, recipe))
        .collect::<Vec<_>>();
    match context_candidates.as_slice() {
        [recipe] => {
            return Ok(RecipeSelection {
                recipe,
                source: RecipeSource::ProjectContext,
            });
        }
        [] => {}
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "found project context for multiple agents ({ids}); choose one explicitly:\n  outcall run claude\n  outcall run codex"
            )
        }
    }

    let candidates = detect_recipe_candidates();

    match candidates.as_slice() {
        [recipe] => Ok(RecipeSelection {
            recipe,
            source: RecipeSource::HostAuth,
        }),
        [] => anyhow::bail!(
            "could not infer which agent to start; no Claude or Codex auth candidates were found.\n\
             Run `outcall doctor`, then choose one explicitly:\n  outcall run claude\n  outcall run codex"
        ),
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "found auth candidates for multiple agents ({ids}); choose one explicitly:\n  outcall run claude\n  outcall run codex"
            )
        }
    }
}

pub(super) fn print_first_run_recommendation() {
    let project_dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) => {
            println!("Recommended first command:");
            println!("  outcall run codex");
            return;
        }
    };

    if let Ok(Some(recipe)) = load_default_recipe(&project_dir) {
        println!("Recommended first command:");
        println!("  outcall run {}", recipe.id);
        println!("  # project default recipe: {}", recipe.id);
        return;
    }

    let context_candidates = outcall::recipes::RECIPES
        .iter()
        .filter(|recipe| recipe_has_project_context(&project_dir, recipe))
        .collect::<Vec<_>>();
    match context_candidates.as_slice() {
        [recipe] => {
            println!("Recommended first command:");
            println!("  outcall run {}", recipe.id);
            println!("  # detected {} project context in this repo", recipe.name);
            return;
        }
        [] => {}
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            println!("Recommended first command:");
            println!("  outcall run claude");
            println!("  outcall run codex");
            println!("  # multiple project context candidates detected: {ids}");
            return;
        }
    }

    match detect_recipe_candidates().as_slice() {
        [recipe] => {
            println!("Recommended first command:");
            println!("  outcall run {}", recipe.id);
            println!("  # detected {} auth/config on this host", recipe.name);
        }
        [] => {
            println!("Recommended first command:");
            println!("  outcall run claude     # choose Claude explicitly");
            println!("  outcall run codex      # choose Codex explicitly");
        }
        many => {
            let ids = many
                .iter()
                .map(|recipe| recipe.id)
                .collect::<Vec<_>>()
                .join(", ");
            println!("Recommended first command:");
            println!("  outcall run claude");
            println!("  outcall run codex");
            println!("  # multiple auth candidates detected: {ids}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn default_recipe_load_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outcall_dir = project.path().join(".outcall");
        std::fs::create_dir(&outcall_dir).unwrap();
        let sentinel = project.path().join("sentinel");
        std::fs::write(&sentinel, "codex\n").unwrap();
        symlink(&sentinel, outcall_dir.join("default-recipe")).unwrap();

        let error = load_default_recipe(project.path()).unwrap_err().to_string();

        assert!(error.contains("must be a real file"));
    }

    #[cfg(unix)]
    #[test]
    fn default_recipe_save_replaces_symlink_without_overwriting_target() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outcall_dir = project.path().join(".outcall");
        std::fs::create_dir(&outcall_dir).unwrap();
        let sentinel = project.path().join("sentinel");
        std::fs::write(&sentinel, "untouched").unwrap();
        symlink(&sentinel, outcall_dir.join("default-recipe")).unwrap();

        save_default_recipe(project.path(), "codex").unwrap();

        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "untouched");
        assert_eq!(
            std::fs::read_to_string(outcall_dir.join("default-recipe")).unwrap(),
            "codex\n"
        );
    }
}
