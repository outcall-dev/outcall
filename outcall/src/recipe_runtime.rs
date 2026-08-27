use anyhow::{Context, Result};

use crate::api_commands::container_remove_request;
use crate::cli::RecipeAuthMode;
use crate::docker_support::{
    ensure_docker_access, ensure_runtime_bridge_netfilter_enforceable, prepare_recipe_image,
};
use crate::host_broker::maybe_prepare_host_broker;
use crate::recipe_auth::{missing_unattended_auth_message, recipe_agent_config, stage_recipe_auth};

mod arguments;
mod container;
mod daemon;
mod project;

#[cfg(test)]
pub(crate) use arguments::rewrite_container_output_path;
pub(crate) use arguments::rewrite_recipe_entrypoint_args;
use container::{RecipeContainerOutcome, launch_managed_recipe_container, recipe_smoke_test};
#[cfg(test)]
pub(crate) use container::{
    automatic_name_retry_candidate, is_container_name_conflict, protected_outcall_mount,
};
pub(crate) use daemon::ensure_recipe_runtime_ready;
pub(crate) use project::{ensure_recipe_initialized, recipe_or_bail, recipe_setup_is_complete};

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_recipe_run(
    socket: &str,
    id: &str,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    include_global_config: bool,
    detach: bool,
    keep: bool,
    name: Option<String>,
    args: Vec<String>,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let image = outcall::recipes::recipe_image_name(recipe);
    let mut config = recipe_agent_config(&project_dir, recipe, &image, detach)?;
    if let Some(name) = name {
        config.name = Some(name);
    }

    let command_needs_credential =
        recipe_command_requires_credential(recipe, config.detach, config.command.as_deref(), &args);
    let auth_result = stage_recipe_auth(
        &project_dir,
        recipe,
        auth_mode,
        force_auth_copy,
        include_global_config,
        &mut config,
    )?;
    if command_needs_credential && !auth_result.credential_ready {
        anyhow::bail!(missing_unattended_auth_message(recipe));
    }
    if !command_needs_credential && args.is_empty() && !auth_result.credential_ready {
        println!(
            "No portable credential is present. Complete the provider login inside this managed container; its Linux credential file will persist for later runs."
        );
    }

    ensure_docker_access()?;
    prepare_recipe_image(&project_dir, recipe, &config, no_build)?;
    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;
    maybe_prepare_host_broker(socket, &project_dir, &mut config)?;

    println!(
        "Starting recipe \"{}\" with auth mode {:?}.",
        recipe.id, auth_result.effective_mode
    );
    let entrypoint_args = rewrite_recipe_entrypoint_args(&project_dir, &config.workspace, args)?;
    let outcome = launch_managed_recipe_container(socket, &project_dir, config, entrypoint_args)?;
    finalize_recipe_outcome(socket, outcome, keep)
}

fn finalize_recipe_outcome(
    socket: &str,
    outcome: RecipeContainerOutcome,
    keep: bool,
) -> Result<()> {
    finalize_recipe_outcome_with(outcome, keep, |name| {
        container_remove_request(socket, name, true).map(|_| ())
    })
}

fn finalize_recipe_outcome_with<F>(
    outcome: RecipeContainerOutcome,
    keep: bool,
    mut remove: F,
) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    let RecipeContainerOutcome {
        name,
        completed,
        completion_error,
    } = outcome;
    if completed_container_should_be_removed(completed, keep) {
        match remove(&name) {
            Ok(_) => println!("Removed completed agent '{}'.", name),
            Err(error) => {
                eprintln!(
                    "warning: failed to remove completed agent {}: {error}",
                    name
                );
            }
        }
    }
    if let Some(error) = completion_error {
        return Err(error);
    }
    Ok(())
}

fn completed_container_should_be_removed(completed: bool, keep: bool) -> bool {
    completed && !keep
}

pub(crate) fn cmd_recipe_test(
    socket: &str,
    id: &str,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    include_global_config: bool,
) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    ensure_recipe_initialized(&project_dir, recipe)?;
    let image = outcall::recipes::recipe_image_name(recipe);
    let mut config = recipe_agent_config(&project_dir, recipe, &image, true)?;

    let auth_result = stage_recipe_auth(
        &project_dir,
        recipe,
        auth_mode,
        force_auth_copy,
        include_global_config,
        &mut config,
    )?;
    if auth_result.credential_ready {
        println!("  PASS portable provider credential detected");
    } else {
        println!(
            "  WARN no portable provider credential detected; this smoke test checks the image and managed runtime only"
        );
    }

    ensure_docker_access()?;
    prepare_recipe_image(&project_dir, recipe, &config, no_build)?;
    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;

    recipe_smoke_test(socket, &project_dir, &config)?;
    println!("Recipe test passed: {}", recipe.id);
    Ok(())
}

pub(crate) fn recipe_command_requires_credential(
    recipe: &outcall::recipes::Recipe,
    detach: bool,
    configured_command: Option<&[String]>,
    args: &[String],
) -> bool {
    if configured_command.is_some() {
        return true;
    }
    if args.is_empty() {
        return detach;
    }
    if matches!(args, [arg] if matches!(arg.as_str(), "--version" | "-V" | "--help" | "-h")) {
        return false;
    }
    !matches!(
        (recipe.id, args.first().map(String::as_str)),
        ("claude", Some("auth")) | ("codex", Some("login"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_attached_runs_are_removed_unless_kept() {
        assert!(completed_container_should_be_removed(true, false));
        assert!(!completed_container_should_be_removed(true, true));
        assert!(!completed_container_should_be_removed(false, false));
    }

    #[test]
    fn failed_completed_runs_are_removed_before_error_is_returned() {
        let mut removed = false;
        let outcome = RecipeContainerOutcome {
            name: "project-1".to_string(),
            completed: true,
            completion_error: Some(anyhow::anyhow!("agent exited with code 1")),
        };

        let error = finalize_recipe_outcome_with(outcome, false, |name| {
            assert_eq!(name, "project-1");
            removed = true;
            Ok(())
        })
        .unwrap_err();

        assert!(removed);
        assert_eq!(error.to_string(), "agent exited with code 1");
    }

    #[test]
    fn keep_preserves_failed_completed_runs() {
        let outcome = RecipeContainerOutcome {
            name: "project-1".to_string(),
            completed: true,
            completion_error: Some(anyhow::anyhow!("agent exited with code 1")),
        };

        let error = finalize_recipe_outcome_with(outcome, true, |_| {
            panic!("kept container must not be removed")
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "agent exited with code 1");
    }

    #[test]
    fn only_interactive_login_and_metadata_commands_can_start_without_credentials() {
        let claude = outcall::recipes::get_recipe("claude").unwrap();
        let codex = outcall::recipes::get_recipe("codex").unwrap();

        assert!(!recipe_command_requires_credential(
            claude,
            false,
            None,
            &[],
        ));
        assert!(recipe_command_requires_credential(claude, true, None, &[]));
        assert!(!recipe_command_requires_credential(
            claude,
            false,
            None,
            &["--version".to_string()],
        ));
        assert!(!recipe_command_requires_credential(
            claude,
            false,
            None,
            &["auth".to_string(), "login".to_string()],
        ));
        assert!(!recipe_command_requires_credential(
            codex,
            false,
            None,
            &["login".to_string()],
        ));
        assert!(recipe_command_requires_credential(
            claude,
            false,
            None,
            &["-p".to_string(), "hi".to_string()],
        ));
        assert!(recipe_command_requires_credential(
            claude,
            false,
            Some(&["-p".to_string(), "hi".to_string()]),
            &[],
        ));
    }
}
