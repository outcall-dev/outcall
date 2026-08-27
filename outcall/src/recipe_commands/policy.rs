use anyhow::{Context, Result};

use super::selection::{detect_default_recipe, recommended_recipe_command, save_default_recipe};
use crate::cli::RecipeAuthMode;
use crate::docker_support::ensure_docker_access;
use crate::recipe_auth::{
    missing_unattended_auth_message, recipe_agent_config, save_auth_preference, stage_recipe_auth,
};
use crate::recipe_runtime::{
    ensure_recipe_initialized, ensure_recipe_runtime_ready, recipe_or_bail,
};

pub(crate) fn cmd_auth(
    recipe_id: &str,
    auth_mode: RecipeAuthMode,
    force: bool,
    include_global_config: bool,
) -> Result<()> {
    let recipe = recipe_or_bail(recipe_id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let selected = save_default_recipe(&project_dir, recipe.id)?;
    let image = outcall::recipes::recipe_image_name(recipe);
    let mut config = recipe_agent_config(&project_dir, recipe, &image, true)?;
    let staged = stage_recipe_auth(
        &project_dir,
        recipe,
        auth_mode,
        force,
        include_global_config,
        &mut config,
    )?;
    if !staged.credential_ready {
        anyhow::bail!(missing_unattended_auth_message(recipe));
    }
    save_auth_preference(&project_dir, recipe, staged.effective_mode)?;

    println!("Authentication ready for {}.", recipe.name);
    println!("  Project recipe: {}", selected.display());
    println!("  Mode: {:?}", staged.effective_mode);
    println!("  Next: {}", recommended_recipe_command(recipe));
    Ok(())
}

pub(crate) fn cmd_allow(socket: &str, recipe_id: &str, target: &str) -> Result<()> {
    let recipe = recipe_or_bail(recipe_id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let change = outcall::policy::allow(&project_dir, recipe, target)?;
    if change.changed {
        println!("Allowed {} for {}.", target, recipe.name);
    } else {
        println!("{} is already allowed for {}.", target, recipe.name);
    }
    println!("  Rules: {}", change.path.display());
    println!("  Default deny remains active for every other destination.");

    if ensure_docker_access().is_ok() && ensure_recipe_runtime_ready(socket, &project_dir).is_ok() {
        println!("  Active: reloaded into the managed daemon.");
    } else {
        println!("  Pending: the grant will load when you next run this recipe.");
    }
    Ok(())
}

pub(crate) fn cmd_policy_explain(requested_recipe: Option<&str>) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let recipe = match requested_recipe {
        Some(id) => recipe_or_bail(id)?,
        None => detect_default_recipe()?.recipe,
    };
    let rules = outcall::policy::explain(&project_dir, recipe)?;
    println!(
        "Policy: {} ({})",
        recipe.id,
        outcall::policy::rule_path(&project_dir, recipe).display()
    );
    println!("Default: block every destination not listed below.");
    if rules.is_empty() {
        println!("  No allow rules are configured.");
    } else {
        for rule in rules {
            match rule.description {
                Some(description) => println!("  {} - {}", rule.id, description),
                None => println!("  {}", rule.id),
            }
        }
    }
    let templates = outcall::policy::template_names(recipe).collect::<Vec<_>>();
    if !templates.is_empty() {
        println!("Named grants: {}", templates.join(", "));
    }
    Ok(())
}
