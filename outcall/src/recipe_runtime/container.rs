use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};
use outcall::parse_memory_arg;
use outcall::secure_fs::existing_secure_subdir;
use outcall_api::ContainerCreateResult;

use crate::api_commands::{container_inspect_request, container_remove_request};
use crate::daemon_client::{Response, http_post_json};
use crate::docker_support::{CommandTimeoutError, command_output_with_timeout};
use crate::docker_support::{attach_container, invoking_container_user};

pub(super) struct RecipeContainerOutcome {
    pub(super) name: String,
    pub(super) completed: bool,
    pub(super) completion_error: Option<anyhow::Error>,
}

pub(super) fn launch_managed_recipe_container(
    socket: &str,
    project_dir: &Path,
    config: outcall::agent_config::AgentConfig,
    entrypoint_args: Vec<String>,
) -> Result<RecipeContainerOutcome> {
    let image = config.effective_image();
    let name = config.effective_name(project_dir);
    let workspace = config.workspace.clone();
    let project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let memory_limit = config
        .resources
        .as_ref()
        .and_then(|resources| resources.memory.as_deref())
        .map(parse_memory_arg)
        .transpose()?;
    let cpu_shares = config
        .resources
        .as_ref()
        .and_then(|resources| resources.cpus.as_deref())
        .map(parse_cpu_shares)
        .transpose()?;

    let mut volumes = vec![format!("{}:{}", project_dir.display(), workspace)];
    volumes.extend(config.volumes.clone());
    volumes.push(protected_outcall_mount(&project_dir, &workspace)?);

    let env = (!config.env.is_empty()).then(|| {
        config
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    });
    let batch_command = !entrypoint_args.is_empty() || config.command.is_some();
    let (interactive, tty) = recipe_container_io(
        config.detach,
        batch_command,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    );
    let command = if entrypoint_args.is_empty() {
        config.command.clone()
    } else {
        Some(entrypoint_args)
    };
    let automatic_name = config.name.is_none();
    let mut request = outcall_api::ContainerCreateRequest {
        image,
        network: Some(config.network.clone()),
        name: Some(name.clone()),
        user: invoking_container_user(),
        memory_limit,
        cpu_shares,
        env,
        cmd: command,
        entrypoint: config.entrypoint.clone(),
        working_dir: Some(config.workspace.clone()),
        volumes: Some(volumes),
        include_outcall_helper_mounts: Some(false),
        interactive: Some(interactive),
        tty: Some(tty),
    };

    println!(
        "Booting managed agent '{}' for project '{}'...",
        name,
        project_dir.display()
    );
    println!("  Image: {}", request.image);
    println!("  Workspace: {} -> {}", project_dir.display(), workspace);
    println!("  Network: {}", config.network);
    println!("  Starting container via outcalld...");

    let result = create_with_name_retry(socket, automatic_name, &mut request)?;

    if config.detach {
        println!(
            "Agent '{}' started ({}) in detached mode.",
            result.name,
            &result.container_id[..12.min(result.container_id.len())]
        );
        println!("  Attach: outcall attach {}", result.name);
        println!("  Logs:   outcall logs {} --follow", result.name);
        println!("  Stop:   outcall stop {}", result.name);
        return Ok(RecipeContainerOutcome {
            name: result.name,
            completed: false,
            completion_error: None,
        });
    }

    if batch_command {
        let completion_error = wait_for_recipe_container(&result.name).err();
        println!("\nAgent '{}' stopped.", result.name);
        return Ok(RecipeContainerOutcome {
            name: result.name,
            completed: true,
            completion_error,
        });
    }

    let status = attach_container(&result.container_id, &result.name)?;
    let current = container_inspect_request(socket, &result.name)?;
    if current.state == "running" {
        println!(
            "Detached from '{}'; the agent is still running.",
            result.name
        );
        return Ok(RecipeContainerOutcome {
            name: result.name,
            completed: false,
            completion_error: None,
        });
    }
    let completion_error =
        (!status.success()).then(|| anyhow::anyhow!("agent exited with code {:?}", status.code()));

    println!("\nAgent '{}' stopped.", result.name);
    Ok(RecipeContainerOutcome {
        name: result.name,
        completed: true,
        completion_error,
    })
}

fn create_with_name_retry(
    socket: &str,
    automatic_name: bool,
    request: &mut outcall_api::ContainerCreateRequest,
) -> Result<ContainerCreateResult> {
    let mut retry_count = 0;
    loop {
        let response = post_managed_container_create(socket, request)?;
        if response.success {
            return serde_json::from_value(response.data.context("no data")?)
                .context("failed to parse managed container response");
        }

        let error = response.error.unwrap_or_else(|| "unknown error".into());
        let current_name = request.name.as_deref().unwrap_or_default();
        if is_container_name_conflict(&error)
            && let Some(next_name) =
                automatic_name_retry_candidate(automatic_name, retry_count, current_name)
        {
            retry_count += 1;
            println!(
                "  Container name '{current_name}' already exists; retrying as '{next_name}'..."
            );
            request.name = Some(next_name);
            continue;
        }
        anyhow::bail!("{error}");
    }
}

fn recipe_container_io(
    detach: bool,
    batch_command: bool,
    stdin_terminal: bool,
    stdout_terminal: bool,
) -> (bool, bool) {
    if batch_command {
        return (false, false);
    }
    if detach {
        return (true, true);
    }
    (true, stdin_terminal && stdout_terminal)
}

fn post_managed_container_create(
    socket: &str,
    request: &outcall_api::ContainerCreateRequest,
) -> Result<Response> {
    let body = http_post_json(socket, "/api/v1/container/create", request)?;
    serde_json::from_str(&body).context("failed to parse managed container response")
}

pub(crate) fn automatic_name_retry_candidate(
    automatic_name: bool,
    retry_count: usize,
    current_name: &str,
) -> Option<String> {
    const MAX_NAME_RETRIES: usize = 1_000;
    if !automatic_name || retry_count >= MAX_NAME_RETRIES {
        return None;
    }

    let (base, suffix) = current_name.rsplit_once('-')?;
    let next_suffix = suffix.parse::<u32>().ok()?.checked_add(1)?;
    Some(format!("{base}-{next_suffix}"))
}

pub(crate) fn is_container_name_conflict(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("status code 409")
        && error.contains("container name")
        && error.contains("already in use")
}

pub(crate) fn protected_outcall_mount(project_dir: &Path, workspace: &str) -> Result<String> {
    let source = existing_secure_subdir(project_dir, Path::new(".outcall"))?
        .context("project .outcall directory does not exist")?;
    let destination = format!("{}/.outcall", workspace.trim_end_matches('/'));
    Ok(format!("{}:{destination}:ro", source.display()))
}

fn wait_for_recipe_container(name: &str) -> Result<()> {
    let logs = std::process::Command::new("docker")
        .args(["logs", "--follow", name])
        .status()
        .context("failed to invoke docker logs")?;
    if !logs.success() {
        anyhow::bail!("failed to follow agent container logs for {name}");
    }

    let inspect = command_output_with_timeout(
        "docker",
        &["inspect", "--format", "{{.State.ExitCode}}", name],
        std::time::Duration::from_secs(30),
    )
    .map_err(|error| match error {
        CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
            "docker inspect timed out after {} seconds for agent container {name}",
            timeout.as_secs()
        ),
        CommandTimeoutError::Io(error) => error.context("failed to invoke docker inspect"),
    })?;
    if !inspect.status.success() {
        anyhow::bail!(
            "failed to inspect agent container {name}: {}",
            String::from_utf8_lossy(&inspect.stderr).trim()
        );
    }
    let exit_code = parse_container_exit_code(&inspect.stdout)?;
    if exit_code != 0 {
        anyhow::bail!("agent exited with code {exit_code}");
    }
    Ok(())
}

fn parse_container_exit_code(output: &[u8]) -> Result<i32> {
    std::str::from_utf8(output)
        .context("docker inspect returned a non-UTF-8 exit code")?
        .trim()
        .parse::<i32>()
        .context("docker inspect returned an invalid exit code")
}

fn parse_cpu_shares(value: &str) -> Result<i64> {
    let value = value
        .parse::<i64>()
        .with_context(|| format!("invalid cpu shares value: {value}"))?;
    if !outcall_api::valid_cpu_shares(value) {
        anyhow::bail!(
            "cpu shares must be between {} and {}",
            outcall_api::MIN_CPU_SHARES,
            outcall_api::MAX_CPU_SHARES
        );
    }
    Ok(value)
}

pub(super) fn recipe_smoke_test(
    socket: &str,
    project_dir: &Path,
    config: &outcall::agent_config::AgentConfig,
) -> Result<()> {
    let mut smoke_config = config.clone();
    smoke_config.detach = false;
    smoke_config.name = Some(outcall::agent_config::container_name_with_suffix(
        &config.effective_name(project_dir),
        &format!("smoke-{}", std::process::id()),
    )?);

    println!("Running managed recipe smoke test...");
    let outcome = launch_managed_recipe_container(
        socket,
        project_dir,
        smoke_config,
        vec!["--version".to_string()],
    )?;
    let RecipeContainerOutcome {
        name,
        completed,
        completion_error,
    } = outcome;
    if !completed {
        anyhow::bail!("recipe smoke container unexpectedly remained running");
    }

    if let Err(error) = container_remove_request(socket, &name, true) {
        eprintln!("warning: failed to remove smoke container {name}: {error}");
    }
    if let Some(error) = completion_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_share_parser_enforces_docker_minimum() {
        assert_eq!(parse_cpu_shares("2").unwrap(), 2);
        assert_eq!(
            parse_cpu_shares(&outcall_api::MAX_CPU_SHARES.to_string()).unwrap(),
            outcall_api::MAX_CPU_SHARES
        );
        assert!(parse_cpu_shares("1").is_err());
        assert!(parse_cpu_shares(&(outcall_api::MAX_CPU_SHARES + 1).to_string()).is_err());
        assert!(parse_cpu_shares("invalid").is_err());
    }

    #[test]
    fn container_exit_code_parser_is_strict() {
        assert_eq!(parse_container_exit_code(b"0\n").unwrap(), 0);
        assert_eq!(parse_container_exit_code(b"127").unwrap(), 127);
        assert!(parse_container_exit_code(b"success").is_err());
        assert!(parse_container_exit_code(&[0xff]).is_err());
    }

    #[test]
    fn explicit_names_are_not_rewritten_after_conflict() {
        assert_eq!(automatic_name_retry_candidate(false, 0, "fixed"), None);
    }

    #[test]
    fn detached_interactive_agents_receive_a_container_tty() {
        assert_eq!(recipe_container_io(true, false, false, false), (true, true));
    }

    #[test]
    fn batch_commands_do_not_receive_interactive_io() {
        assert_eq!(recipe_container_io(false, true, true, true), (false, false));
        assert_eq!(recipe_container_io(true, true, true, true), (false, false));
    }

    #[test]
    fn attached_interactive_agents_only_request_a_tty_from_a_terminal() {
        assert_eq!(recipe_container_io(false, false, true, true), (true, true));
        assert_eq!(
            recipe_container_io(false, false, true, false),
            (true, false)
        );
        assert_eq!(
            recipe_container_io(false, false, false, true),
            (true, false)
        );
    }
}
