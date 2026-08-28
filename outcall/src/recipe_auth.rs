use anyhow::Result;

use crate::cli::RecipeAuthMode;

mod home;
mod preference;

use home::{add_home_mount, container_home_path, ensure_recipe_home_mount, existing_recipe_home};
use preference::load_auth_preference;
pub(crate) use preference::save_auth_preference;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthStageResult {
    pub(crate) credential_ready: bool,
    pub(crate) effective_mode: RecipeAuthMode,
}

pub(crate) fn recipe_has_user_auth_paths(recipe: &outcall::recipes::Recipe) -> bool {
    recipe
        .user_paths
        .iter()
        .chain(recipe.global_config_paths.iter())
        .map(|path| outcall::recipes::expanded_path(path))
        .any(|path| path.exists())
}

pub(crate) fn recipe_agent_config(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    image: &str,
    detach: bool,
) -> Result<outcall::agent_config::AgentConfig> {
    let mut config = outcall::agent_config::AgentConfig::load(project_dir)?;
    let mut defaults: outcall::agent_config::AgentConfig =
        serde_yaml::from_str(recipe.agent_config)?;
    defaults.image = Some(image.to_string());
    if outcall::recipes::has_generated_agent_config(project_dir)? {
        config = defaults;
    } else {
        if config.image.is_none() {
            config.image = defaults.image.or_else(|| Some(image.to_string()));
        }
        if config.entrypoint.is_none() {
            config.entrypoint = defaults
                .entrypoint
                .or_else(|| Some(vec![recipe.id.to_string()]));
        }
    }
    config.detach |= detach;

    // Recipe containers use a read-only root filesystem. stage_recipe_auth
    // supplies a writable project-local home mount for each auth mode.
    config
        .env
        .entry("HOME".to_string())
        .or_insert_with(|| "/home/node".to_string());
    config.validate_managed_runtime()?;
    Ok(config)
}

pub(crate) fn stage_recipe_auth(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    auth_mode: RecipeAuthMode,
    force_auth_copy: bool,
    include_global_config: bool,
    config: &mut outcall::agent_config::AgentConfig,
) -> Result<AuthStageResult> {
    let container_home = container_home_path(config)?;
    let mut credential_ready = false;
    let mut env_auth = false;
    for key in recipe.auth_env {
        if let Some(value) = auth_env_value(key) {
            credential_ready = true;
            env_auth = true;
            config.env.insert((*key).to_string(), value);
        }
    }

    let saved_mode = if auth_mode == RecipeAuthMode::Auto {
        load_auth_preference(project_dir, recipe)?
    } else {
        None
    };
    let effective_mode = resolve_recipe_auth_mode(
        auth_mode,
        saved_mode,
        env_auth,
        recipe_has_user_auth_paths(recipe),
    );

    if auth_mode == RecipeAuthMode::Auto {
        println!(
            "Auto auth mode selected: {}{}.",
            match effective_mode {
                RecipeAuthMode::Copy => "copy",
                RecipeAuthMode::Mount => "mount",
                RecipeAuthMode::EnvOnly => "env-only",
                RecipeAuthMode::Auto => "auto",
            },
            if saved_mode.is_some() {
                " (saved project choice)"
            } else {
                ""
            }
        );
    }

    match effective_mode {
        RecipeAuthMode::Auto => {
            anyhow::bail!("automatic auth mode did not resolve to a concrete transfer mode")
        }
        RecipeAuthMode::Copy => {
            if !include_global_config
                && recipe
                    .global_config_paths
                    .iter()
                    .any(|path| outcall::recipes::expanded_path(path).exists())
            {
                println!(
                    "Skipping optional global provider config. Pass --include-global-config to copy it after reviewing host-only MCP and hook commands."
                );
            }
            let staged = outcall::recipes::stage_auth_copy(
                project_dir,
                recipe,
                force_auth_copy,
                include_global_config,
            )?;
            if staged.copied.is_empty() {
                println!(
                    "No host auth/config paths found; using an empty project-local home for recipe \"{}\".",
                    recipe.id
                );
            } else {
                println!("Project-local auth/config paths:");
                for (src, dest) in &staged.copied {
                    println!("  {} -> {}", src.display(), dest.display());
                }
            }
            add_home_mount(config, &staged.home_dir, &container_home);
            credential_ready |=
                outcall::recipes::has_credential_file_in_home(recipe, &staged.home_dir);
        }
        RecipeAuthMode::Mount => {
            // Auth paths are mounted from the host, while CLIs still need an
            // ordinary writable home for state and helpers.
            ensure_recipe_home_mount(project_dir, recipe, config, &container_home)?;
            let mount_plan = outcall::recipes::auth_mount_plan(recipe, &container_home);
            if mount_plan.mounts.is_empty() {
                println!(
                    "No existing user auth paths found to mount for recipe \"{}\".",
                    recipe.id
                );
            } else {
                println!("Direct host auth/config mounts (read-write):");
                for mount in &mount_plan.mounts {
                    println!("  {mount}");
                }
                println!("  Changes under these paths persist on the host.");
            }
            config.volumes.extend(mount_plan.mounts);
            credential_ready |= outcall::recipes::has_host_credential_file(recipe);
            if include_global_config {
                println!(
                    "Global provider config is already included by the complete --auth mount."
                );
            }
        }
        RecipeAuthMode::EnvOnly => {
            let home_dir = if include_global_config {
                let staged = outcall::recipes::stage_global_config_copy(
                    project_dir,
                    recipe,
                    force_auth_copy,
                )?;
                if staged.copied.is_empty() {
                    println!(
                        "No optional global provider config paths found for recipe \"{}\".",
                        recipe.id
                    );
                } else {
                    println!("Project-local global config paths:");
                    for (src, dest) in &staged.copied {
                        println!("  {} -> {}", src.display(), dest.display());
                    }
                }
                add_home_mount(config, &staged.home_dir, &container_home);
                staged.home_dir
            } else {
                ensure_recipe_home_mount(project_dir, recipe, config, &container_home)?
            };
            credential_ready |= outcall::recipes::has_credential_file_in_home(recipe, &home_dir);
        }
    }

    Ok(AuthStageResult {
        credential_ready,
        effective_mode,
    })
}

pub(crate) fn resolve_recipe_auth_mode(
    requested_mode: RecipeAuthMode,
    saved_mode: Option<RecipeAuthMode>,
    env_auth: bool,
    user_auth_paths: bool,
) -> RecipeAuthMode {
    if requested_mode != RecipeAuthMode::Auto {
        return requested_mode;
    }
    if let Some(saved_mode) = saved_mode.filter(|mode| *mode != RecipeAuthMode::Auto) {
        return saved_mode;
    }
    if env_auth {
        RecipeAuthMode::EnvOnly
    } else if user_auth_paths {
        RecipeAuthMode::Copy
    } else {
        RecipeAuthMode::EnvOnly
    }
}

pub(crate) fn unattended_auth_ready(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    requested_mode: RecipeAuthMode,
) -> Result<bool> {
    let env_auth = recipe
        .auth_env
        .iter()
        .any(|key| auth_env_value(key).is_some());
    let saved_mode = if requested_mode == RecipeAuthMode::Auto {
        load_auth_preference(project_dir, recipe)?
    } else {
        None
    };
    let effective_mode = resolve_recipe_auth_mode(
        requested_mode,
        saved_mode,
        env_auth,
        recipe_has_user_auth_paths(recipe),
    );
    credential_ready_for_mode(
        project_dir,
        recipe,
        effective_mode,
        env_auth,
        outcall::recipes::has_host_credential_file(recipe),
    )
}

pub(crate) fn missing_unattended_auth_message(recipe: &outcall::recipes::Recipe) -> String {
    if recipe.id == "claude" {
        let platform_note = if cfg!(target_os = "macos") {
            "\nThe host Claude /login session is stored in macOS Keychain and does not transfer into a Linux container."
        } else {
            ""
        };
        return format!(
            "no portable credential found for unattended Claude Code.{platform_note}\nChoose one:\n  1. Run `outcall run claude` without agent arguments and complete /login once inside the managed container.\n  2. Run `claude setup-token` on the host, export CLAUDE_CODE_OAUTH_TOKEN, and retry.\n  3. Export ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN."
        );
    }

    format!(
        "no portable credential found for unattended {}. Set one of: {}, or sign in with the provider CLI so its credential file can be copied, then retry",
        recipe.name,
        recipe.auth_env.join(", ")
    )
}

fn credential_ready_for_mode(
    project_dir: &std::path::Path,
    recipe: &outcall::recipes::Recipe,
    mode: RecipeAuthMode,
    env_auth: bool,
    host_credential: bool,
) -> Result<bool> {
    if env_auth {
        return Ok(true);
    }
    let project_credential = existing_recipe_home(project_dir, recipe)?
        .is_some_and(|home| outcall::recipes::has_credential_file_in_home(recipe, &home));
    Ok(match mode {
        RecipeAuthMode::Auto => false,
        RecipeAuthMode::Copy => project_credential || host_credential,
        RecipeAuthMode::Mount => host_credential,
        RecipeAuthMode::EnvOnly => project_credential,
    })
}

fn auth_env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use home::{container_home_path, valid_container_home};
    use preference::load_auth_preference;

    #[test]
    fn recipe_config_loads_project_overrides_and_cli_detach() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".outcall")).unwrap();
        std::fs::write(
            temp.path().join(".outcall/agent.yaml"),
            r#"image: custom/agent:1
name: custom-agent
workspace: /work
network: outcall-private
detach: false
auto_pull: false
volumes:
  - /tmp/data:/data:ro
env:
  CUSTOM: value
resources:
  memory: 1g
  cpus: "512"
"#,
        )
        .unwrap();
        let recipe = outcall::recipes::get_recipe("codex").unwrap();

        let config = recipe_agent_config(
            temp.path(),
            recipe,
            &outcall::recipes::recipe_image_name(recipe),
            true,
        )
        .unwrap();

        assert_eq!(config.image.as_deref(), Some("custom/agent:1"));
        assert_eq!(config.name.as_deref(), Some("custom-agent"));
        assert_eq!(config.workspace, "/work");
        assert_eq!(config.network, "outcall-private");
        assert!(config.detach);
        assert!(!config.auto_pull);
        assert_eq!(config.env.get("CUSTOM").map(String::as_str), Some("value"));
        assert_eq!(
            config.env.get("HOME").map(String::as_str),
            Some("/home/node")
        );
        assert_eq!(config.entrypoint, Some(vec!["outcall-codex".to_string()]));
    }

    #[test]
    fn recipe_config_preserves_custom_entrypoint_override() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".outcall")).unwrap();
        std::fs::write(
            temp.path().join(".outcall/agent.yaml"),
            "entrypoint:\n  - custom-launcher\n",
        )
        .unwrap();
        let recipe = outcall::recipes::get_recipe("codex").unwrap();

        let config = recipe_agent_config(
            temp.path(),
            recipe,
            &outcall::recipes::recipe_image_name(recipe),
            false,
        )
        .unwrap();

        assert_eq!(config.entrypoint, Some(vec!["custom-launcher".to_string()]));
    }

    #[test]
    fn requested_recipe_replaces_other_generated_recipe_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let codex = outcall::recipes::get_recipe("codex").unwrap();
        let claude = outcall::recipes::get_recipe("claude").unwrap();

        for (initialized, requested, expected_entrypoint) in
            [(claude, codex, "outcall-codex"), (codex, claude, "claude")]
        {
            outcall::recipes::init_recipe(temp.path(), initialized, true).unwrap();
            let expected_image = outcall::recipes::recipe_image_name(requested);
            let config =
                recipe_agent_config(temp.path(), requested, &expected_image, false).unwrap();
            assert_eq!(config.image.as_deref(), Some(expected_image.as_str()));
            assert!(config.auto_pull);
            assert_eq!(
                config.entrypoint.as_deref(),
                Some([expected_entrypoint.to_string()].as_slice())
            );
        }
    }

    #[test]
    fn project_local_container_login_counts_as_a_portable_credential() {
        let temp = tempfile::tempdir().unwrap();
        let recipe = outcall::recipes::get_recipe("claude").unwrap();
        let credential = temp
            .path()
            .join(".outcall/home")
            .join(recipe.id)
            .join(".claude")
            .join(".credentials.json");
        std::fs::create_dir_all(credential.parent().unwrap()).unwrap();
        std::fs::write(&credential, "{}").unwrap();

        assert!(
            credential_ready_for_mode(temp.path(), recipe, RecipeAuthMode::Copy, false, false,)
                .unwrap()
        );
        assert!(
            !credential_ready_for_mode(temp.path(), recipe, RecipeAuthMode::Mount, false, false,)
                .unwrap()
        );
    }

    #[test]
    fn claude_auth_error_gives_interactive_and_unattended_recovery_paths() {
        let recipe = outcall::recipes::get_recipe("claude").unwrap();
        let message = missing_unattended_auth_message(recipe);

        assert!(message.contains("outcall run claude"));
        assert!(message.contains("claude setup-token"));
        assert!(message.contains("CLAUDE_CODE_OAUTH_TOKEN"));
    }

    #[test]
    fn container_home_requires_a_clean_unix_path() {
        assert!(valid_container_home(std::path::Path::new("/home/node")));
        assert!(valid_container_home(std::path::Path::new("/root")));
        for invalid in [
            "/",
            "/home",
            "/Users/mark",
            "relative/home",
            "/home/../root",
            "/home/bad:path",
        ] {
            assert!(!valid_container_home(std::path::Path::new(invalid)));
        }
    }

    #[test]
    fn container_home_cannot_overlap_workspace() {
        let mut config = outcall::agent_config::AgentConfig {
            workspace: "/home/node/project".to_string(),
            ..Default::default()
        };
        config
            .env
            .insert("HOME".to_string(), "/home/node".to_string());

        let error = container_home_path(&config).unwrap_err().to_string();

        assert!(error.contains("must not overlap"));
    }

    #[cfg(unix)]
    #[test]
    fn auth_preference_never_reads_or_overwrites_a_symlink_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let recipe = outcall::recipes::get_recipe("claude").unwrap();
        let parent = temp.path().join(".outcall/auth/claude");
        std::fs::create_dir_all(&parent).unwrap();
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, "mount").unwrap();
        symlink(&sentinel, parent.join("mode")).unwrap();

        assert!(load_auth_preference(temp.path(), recipe).is_err());
        save_auth_preference(temp.path(), recipe, RecipeAuthMode::Copy).unwrap();

        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "mount");
        assert_eq!(
            std::fs::read_to_string(parent.join("mode")).unwrap(),
            "copy"
        );
    }
}
