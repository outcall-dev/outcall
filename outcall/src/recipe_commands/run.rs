use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

use super::doctor::cmd_recipe_doctor;
use super::onboarding::ensure_recipe_setup_state;
use super::selection::{
    RecipeSelection, RecipeSource, detect_default_recipe, recommended_recipe_command,
    save_default_recipe,
};
use crate::api_commands::container_inspect_request;
use crate::cli::RecipeAuthMode;
use crate::docker_support::{
    CommandTimeoutError, attach_container, command_status_with_timeout, containerized_runtime_note,
};
use crate::recipe_auth::{missing_unattended_auth_message, unattended_auth_ready};
use crate::recipe_runtime::{
    cmd_recipe_run, cmd_recipe_test, recipe_command_requires_credential, recipe_or_bail,
    recipe_setup_is_complete,
};

const LOG_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct SetupOptions {
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    include_global_config: bool,
    print_next: bool,
}

pub(crate) fn cmd_agent_logs(socket: &str, name: &str, follow: bool) -> Result<()> {
    let container = container_inspect_request(socket, name)?;
    let mut command = Command::new("docker");
    command.arg("logs");
    if follow {
        command.arg("--follow");
    }
    command.arg(&container.container_id);
    let status = if follow {
        command.status().context("failed to invoke docker logs")?
    } else {
        command_status_with_timeout(&mut command, LOG_COMMAND_TIMEOUT).map_err(
            |error| match error {
                CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
                    "docker logs timed out after {} seconds for {name}",
                    timeout.as_secs()
                ),
                CommandTimeoutError::Io(error) => error.context("failed to invoke docker logs"),
            },
        )?
    };
    if !status.success() {
        anyhow::bail!("docker logs failed for {name}");
    }
    Ok(())
}

pub(crate) fn cmd_agent_attach(socket: &str, name: &str) -> Result<()> {
    let container = container_inspect_request(socket, name)?;
    let status = attach_container(&container.container_id, &container.name)?;
    let current = container_inspect_request(socket, &container.name)?;
    if current.state == "running" {
        println!(
            "Detached from '{}'; the agent is still running.",
            current.name
        );
        return Ok(());
    }
    if !status.success() {
        anyhow::bail!(
            "managed agent '{}' exited or attach failed (code {:?})",
            current.name,
            status.code()
        );
    }
    println!("Managed agent '{}' stopped.", current.name);
    Ok(())
}

pub(crate) fn cmd_setup(
    socket: &str,
    id: Option<&str>,
    force: bool,
    no_build: bool,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    include_global_config: bool,
) -> Result<()> {
    let selection = match id {
        Some(id) => RecipeSelection {
            recipe: recipe_or_bail(id)?,
            source: RecipeSource::Explicit,
        },
        None => detect_default_recipe()?,
    };
    println!(
        "Setting up recipe: {} ({})",
        selection.recipe.id,
        selection.source.label()
    );
    println!();
    cmd_setup_inner(
        socket,
        selection.recipe.id,
        SetupOptions {
            force,
            no_build,
            auth_mode,
            force_auth_copy,
            include_global_config,
            print_next: true,
        },
    )
}

fn cmd_setup_inner(socket: &str, id: &str, options: SetupOptions) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Outcall setup: {} ({})", recipe.id, recipe.name);
    println!("Project:       {}", project_dir.display());
    println!();

    ensure_recipe_setup_state(&project_dir, recipe, options.force)?;
    println!();
    cmd_recipe_doctor(recipe.id)?;

    if let Some(message) = containerized_runtime_note() {
        println!();
        println!("{message}");
    }

    println!();
    cmd_recipe_test(
        socket,
        recipe.id,
        options.no_build,
        options.auth_mode,
        options.force_auth_copy,
        options.include_global_config,
    )?;
    if options.print_next {
        println!();
        println!("Setup complete.");
        println!("Next:");
        println!("  {}", recommended_recipe_command(recipe));
        println!("  {} --detach", recommended_recipe_command(recipe));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_run(
    socket: &str,
    id: &str,
    force: bool,
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
    if recipe_command_requires_credential(recipe, detach, None, &args)
        && !unattended_auth_ready(&project_dir, recipe, auth_mode)?
    {
        anyhow::bail!(missing_unattended_auth_message(recipe));
    }
    let needs_setup = force || !recipe_setup_is_complete(&project_dir, recipe)?;
    if needs_setup {
        cmd_setup_inner(
            socket,
            id,
            SetupOptions {
                force,
                no_build,
                auth_mode,
                force_auth_copy,
                include_global_config,
                print_next: false,
            },
        )?;
    } else {
        println!("Project recipe is ready; starting {}.", recipe.name);
    }
    save_default_recipe(&project_dir, recipe.id)?;
    println!();
    cmd_recipe_run(
        socket,
        id,
        no_build || needs_setup,
        auth_mode,
        force_auth_copy,
        include_global_config,
        detach,
        keep,
        name,
        args,
    )
}
