use std::path::Path;

use anyhow::{Context, Result};
use outcall::secure_fs::ensure_secure_subdir;

use super::selection::{
    RecipeSource, detect_default_recipe, load_default_recipe, print_first_run_recommendation,
    save_default_recipe,
};
use crate::recipe_runtime::recipe_or_bail;

pub(crate) fn cmd_onboarding() -> Result<()> {
    println!("Outcall");
    println!();
    print_first_run_recommendation();
    println!();
    println!("Common commands:");
    println!("  outcall run claude    # initialize and launch Claude Code");
    println!("  outcall run codex     # initialize and launch Codex CLI");
    println!("  outcall setup         # initialize, verify, and smoke-test without launching");
    println!("  outcall doctor        # inspect Docker, scaffold, and auth detection");
    println!("  outcall recipe list   # show built-in recipes");
    Ok(())
}

pub(crate) fn cmd_init(recipe: Option<&str>, force: bool) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let rules_dir = ensure_secure_subdir(&project_dir, Path::new(".outcall/rules"))?;

    println!("Initialized Outcall in {}.", project_dir.display());

    if let Some(id) = recipe {
        let recipe = recipe_or_bail(id)?;
        print_written(outcall::recipes::init_recipe(&project_dir, recipe, force)?);
        let selected = save_default_recipe(&project_dir, recipe.id)?;
        println!("  wrote {}", selected.display());
        println!("  ensured {}", rules_dir.display());
        print_init_next(recipe.id);
        return Ok(());
    }

    let config_path =
        outcall::agent_config::AgentConfig::save_template_with_force(&project_dir, force)?;
    println!("  wrote {}", config_path.display());
    if let Some(path) = outcall::recipes::ensure_outcall_gitignore(&project_dir)? {
        println!("  wrote {}", path.display());
    }
    println!("  ensured {}", rules_dir.display());

    if load_default_recipe(&project_dir)?.is_none()
        && let Ok(selection) = detect_default_recipe()
        && !matches!(selection.source, RecipeSource::SavedDefault)
    {
        let selected = save_default_recipe(&project_dir, selection.recipe.id)?;
        println!("  wrote {}", selected.display());
        println!(
            "  selected default recipe: {} ({})",
            selection.recipe.id,
            selection.source.label()
        );
    }

    println!();
    println!("Suggested next steps:");
    println!("  outcall doctor");
    println!("  outcall setup");
    println!("  outcall run claude");
    println!("  outcall run codex");
    Ok(())
}

pub(crate) fn ensure_recipe_setup_state(
    project_dir: &Path,
    recipe: &outcall::recipes::Recipe,
    force: bool,
) -> Result<()> {
    ensure_secure_subdir(project_dir, Path::new(".outcall"))?;
    let rules_dir = ensure_secure_subdir(project_dir, Path::new(".outcall/rules"))?;

    println!("Initialized Outcall in {}.", project_dir.display());
    let written = if force {
        outcall::recipes::init_recipe(project_dir, recipe, true)?
    } else {
        outcall::recipes::ensure_recipe(project_dir, recipe)?
    };
    if written.is_empty() {
        println!("  kept existing generated recipe files");
    } else {
        print_written(written);
    }

    let selected = save_default_recipe(project_dir, recipe.id)?;
    println!("  wrote {}", selected.display());
    println!("  ensured {}", rules_dir.display());
    print_init_next(recipe.id);
    Ok(())
}

fn print_written(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        println!("  wrote {}", path.display());
    }
}

fn print_init_next(recipe_id: &str) {
    println!();
    println!("Next:");
    println!("  outcall run {recipe_id}");
    println!("  outcall setup         # repeat first-run checks without launching");
    println!("  outcall run {recipe_id} --detach");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_repairs_a_partial_recipe_without_force() {
        let project = tempfile::tempdir().unwrap();
        let recipe = outcall::recipes::get_recipe("codex").unwrap();
        ensure_recipe_setup_state(project.path(), recipe, false).unwrap();

        let dockerfile = outcall::recipes::recipe_dockerfile(project.path(), recipe);
        std::fs::remove_file(&dockerfile).unwrap();
        ensure_recipe_setup_state(project.path(), recipe, false).unwrap();

        assert!(dockerfile.is_file());
    }
}
