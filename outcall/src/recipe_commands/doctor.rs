use std::path::Path;

use anyhow::{Context, Result};

use super::selection::{
    auth_hint, default_recipe_path, detect_default_recipe, load_default_recipe,
    print_first_run_recommendation, recipe_has_auth_candidate, recommended_recipe_command,
    recommended_recipe_command_with_hint, save_default_recipe,
};
use crate::cli::RecipeAuthMode;
use crate::docker_support::{
    doctor_bool, doctor_br_netfilter, doctor_command, doctor_docker_engine, doctor_path,
    doctor_platform, doctor_socket_dir, ensure_daemon_image_available,
    ensure_docker_access_with_fix, ensure_runtime_bridge_netfilter_enforceable,
};
use crate::host_broker::host_broker_diagnostic;
use crate::recipe_auth::unattended_auth_ready;
use crate::recipe_runtime::{
    ensure_recipe_initialized, ensure_recipe_runtime_ready, recipe_or_bail,
};

pub(crate) fn cmd_doctor(socket: &str, recipe: Option<&str>, fix: bool) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Outcall doctor");
    println!("Project: {}", project_dir.display());
    println!();
    print_runtime_prerequisites();

    println!();
    println!("Project scaffold:");
    doctor_path("outcall dir", &project_dir.join(".outcall"));
    doctor_path("agent config", &project_dir.join(".outcall/agent.yaml"));
    doctor_path("rules dir", &project_dir.join(".outcall/rules"));
    doctor_path("gitignore", &project_dir.join(".outcall/.gitignore"));
    if let Some(default_recipe) = load_default_recipe(&project_dir)? {
        doctor_path("default recipe", &default_recipe_path(&project_dir));
        println!("  selected recipe: {}", default_recipe.id);
    } else {
        println!("  default recipe: not set");
    }

    println!();
    println!("Recipes:");
    for recipe in outcall::recipes::RECIPES {
        let manifest = project_dir
            .join(".outcall/recipes")
            .join(recipe.id)
            .join("recipe.yaml");
        let status = if manifest.exists() {
            "initialized"
        } else {
            "not initialized"
        };
        let auth_status = if recipe_has_auth_candidate(recipe) {
            "auth candidate found"
        } else {
            "no auth candidate"
        };
        println!("  {:<12} {:<16} {}", recipe.id, status, auth_status);
    }

    println!();
    println!("Managed runtime:");
    println!("  `outcall run <recipe>` starts or reuses the daemon and network automatically.");
    println!("  Manual daemon/network commands are available for troubleshooting.");
    println!("  host broker: {}", host_broker_diagnostic(&project_dir)?);

    if let Some(id) = recipe {
        println!();
        cmd_recipe_doctor(id)?;
    } else {
        println!();
        print_first_run_recommendation();
    }

    if fix {
        println!();
        cmd_doctor_fix(socket, recipe)?;
    }

    Ok(())
}

fn cmd_doctor_fix(socket: &str, requested_recipe: Option<&str>) -> Result<()> {
    println!("Applying explicit first-run repairs...");
    ensure_docker_access_with_fix()?;

    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let recipe = match requested_recipe {
        Some(id) => recipe_or_bail(id)?,
        None => detect_default_recipe()?.recipe,
    };
    ensure_recipe_initialized(&project_dir, recipe)?;
    let selected = save_default_recipe(&project_dir, recipe.id)?;
    println!(
        "  PASS project recipe: {} ({})",
        recipe.id,
        selected.display()
    );

    ensure_daemon_image_available()?;
    ensure_recipe_runtime_ready(socket, &project_dir)?;
    ensure_runtime_bridge_netfilter_enforceable()?;
    println!("  PASS managed runtime: daemon and network are ready");
    println!("Repair complete. Start the agent with:");
    println!("  {}", recommended_recipe_command(recipe));
    Ok(())
}

pub(crate) fn cmd_recipe_doctor(id: &str) -> Result<()> {
    let recipe = recipe_or_bail(id)?;
    let project_dir = std::env::current_dir().context("failed to get current directory")?;

    println!("Recipe doctor: {} ({})", recipe.id, recipe.name);
    println!("Project:       {}", project_dir.display());
    println!();
    print_runtime_prerequisites();

    let generated = [
        project_dir.join(format!(".outcall/recipes/{}/recipe.yaml", recipe.id)),
        project_dir.join(format!(".outcall/recipes/{}/Dockerfile", recipe.id)),
        project_dir.join(format!(".outcall/rules/{}.yaml", recipe.id)),
        project_dir.join(".outcall/agent.yaml"),
        project_dir.join(".outcall/host-resources.yaml"),
    ];
    for path in generated {
        doctor_path("generated file", &path);
    }

    println!();
    println!("Portable credential candidates:");
    let mut env_auth = false;
    for key in recipe.auth_env {
        let present = std::env::var_os(key).is_some_and(|value| !value.is_empty());
        env_auth |= present;
        doctor_bool("env", key, present);
    }
    for path in recipe.credential_paths {
        let expanded = outcall::recipes::expanded_path(path);
        doctor_bool("credential file", path, expanded.exists());
    }
    let portable_auth = unattended_auth_ready(&project_dir, recipe, RecipeAuthMode::Auto)?;
    doctor_bool("selected mode", "portable credential", portable_auth);
    if !portable_auth && recipe.id == "claude" {
        println!(
            "  WARN run `outcall run claude` once for a persistent container /login, or run `claude setup-token` on the host and export CLAUDE_CODE_OAUTH_TOKEN for unattended use"
        );
    } else if !portable_auth {
        println!("  WARN no portable credential found; sign in or set a listed env variable");
    }

    println!();
    println!("Optional user config/state:");
    for path in recipe.global_config_paths {
        let expanded = outcall::recipes::expanded_path(path);
        doctor_bool("user path", path, expanded.exists());
    }
    println!("  INFO copy selected paths with `--include-global-config`");
    println!(
        "  INFO `--auth mount` opts into direct mounting of: {}",
        recipe.mount_paths.join(", ")
    );

    println!();
    println!("Project context:");
    let mut any_context = false;
    for path in recipe.project_paths {
        let present = project_dir.join(path).exists();
        any_context |= present;
        doctor_bool("project path", path, present);
    }
    if !any_context {
        println!(
            "  WARN no project context files found; the agent will only see raw workspace files"
        );
    }

    print_recipe_guidance(recipe, &project_dir, env_auth, portable_auth);
    Ok(())
}

fn print_runtime_prerequisites() {
    doctor_platform();
    doctor_command("docker", &["--version"]);
    doctor_command("git", &["--version"]);
    let docker_engine_available = doctor_docker_engine();
    doctor_socket_dir(Path::new("/tmp/outcall"));
    if docker_engine_available {
        doctor_br_netfilter();
    } else {
        println!(
            "  INFO secure unattended mode: bridge inspection skipped until Docker's engine responds"
        );
    }
}

fn print_recipe_guidance(
    recipe: &outcall::recipes::Recipe,
    project_dir: &Path,
    env_auth: bool,
    portable_auth: bool,
) {
    println!();
    println!("Network reminder:");
    println!(
        "  `{}` handles init, daemon, network, smoke test, and launch.",
        recommended_recipe_command(recipe)
    );
    println!(
        "  Run `outcall recipe test {}` for a full smoke check.",
        recipe.id
    );
    println!(
        "  Copy or mount only selected auth/config paths; do not mount the whole home directory."
    );
    let host_resources = project_dir.join(".outcall/host-resources.yaml");
    if host_resources.exists() {
        println!("  Host resource registry: {}", host_resources.display());
    }
    println!();
    println!("Recommended first command:");
    println!(
        "  {}",
        recommended_recipe_command_with_hint(
            recipe,
            auth_hint(env_auth, portable_auth && !env_auth)
        )
    );
}
