use anyhow::{Context, Result};
use outcall::secure_fs::existing_secure_subdir;

use crate::api_commands::{cmd_network_create, cmd_rules_reload};
use crate::daemon_client::{
    DEFAULT_DAEMON_NAME, daemon_exec_socket_ready, daemon_requests_via_exec,
};
use crate::daemon_commands::{
    DEFAULT_DAEMON_IMAGE, cmd_daemon_start, cmd_daemon_stop, daemon_container_info,
    daemon_container_logs, daemon_container_state,
};
use crate::docker_support::{CommandTimeoutError, command_output_with_timeout};
use crate::host_broker::remove_invalid_host_broker_transport_rule;

const DAEMON_INSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const DAEMON_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn ensure_recipe_runtime_ready(
    socket: &str,
    project_dir: &std::path::Path,
) -> Result<()> {
    if remove_invalid_host_broker_transport_rule(project_dir)? {
        println!("Removed invalid generated host broker transport rule.");
    }
    let rules_dir = existing_secure_subdir(project_dir, std::path::Path::new(".outcall/rules"))?
        .context("project rules directory does not exist")?;
    ensure_daemon_ready(socket, Some(&rules_dir))?;
    cmd_rules_reload(socket)?;
    ensure_default_network(socket)
}

fn ensure_daemon_ready(socket: &str, rules_dir: Option<&std::path::Path>) -> Result<()> {
    let desired_rules_dir = rules_dir
        .map(std::fs::canonicalize)
        .transpose()
        .with_context(|| {
            rules_dir
                .map(|path| format!("failed to canonicalize rules dir {}", path.display()))
                .unwrap_or_else(|| "failed to canonicalize rules dir".to_string())
        })?;
    let configured_image = std::env::var("OUTCALL_DAEMON_IMAGE")
        .ok()
        .map(|image| image.trim().to_string())
        .filter(|image| !image.is_empty());
    let existing = daemon_container_info(DEFAULT_DAEMON_NAME)?;
    let desired_image = preferred_daemon_image(
        configured_image,
        existing.as_ref().map(|daemon| daemon.image.clone()),
    );

    match existing {
        Some(existing) if existing.running => {
            let rules_mismatch = match desired_rules_dir.as_ref() {
                Some(desired) => daemon_rules_mount_mismatch(DEFAULT_DAEMON_NAME, desired)?,
                None => false,
            };
            let image_mismatch = existing.image != desired_image;
            if rules_mismatch || image_mismatch {
                let desired = desired_rules_dir
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new("/etc/outcall/rules.d"));
                println!(
                    "Restarting outcall-daemon with project rules from {}...",
                    desired.display()
                );
                cmd_daemon_stop(None)?;
                start_daemon_with_rules(socket, desired, Some(desired_image))?;
            }
            wait_for_daemon_socket(socket)
        }
        _ => {
            println!("Starting outcall-daemon...");
            if let Some(ref desired) = desired_rules_dir {
                start_daemon_with_rules(socket, desired, Some(desired_image))?;
            } else {
                start_daemon_with_rules(
                    socket,
                    std::path::Path::new("/etc/outcall/rules.d"),
                    Some(desired_image),
                )?;
            }
            wait_for_daemon_socket(socket)
        }
    }
}

fn preferred_daemon_image(
    configured_image: Option<String>,
    existing_image: Option<String>,
) -> String {
    if let Some(configured_image) = configured_image {
        return configured_image;
    }
    match existing_image {
        Some(existing_image) if !is_official_daemon_image(&existing_image) => existing_image,
        _ => DEFAULT_DAEMON_IMAGE.to_string(),
    }
}

fn is_official_daemon_image(image: &str) -> bool {
    image.starts_with("ghcr.io/outcall-dev/outcalld:")
        || image.starts_with("ghcr.io/outcall-dev/outcalld@")
}

fn start_daemon_with_rules(
    socket: &str,
    rules_dir: &std::path::Path,
    image: Option<String>,
) -> Result<()> {
    let agent_socket = std::path::Path::new(socket)
        .parent()
        .map(|parent| parent.join("agent.sock"))
        .and_then(|path| path.into_os_string().into_string().ok());
    cmd_daemon_start(
        image,
        None,
        Some(rules_dir.display().to_string()),
        None,
        Some(socket.to_string()),
        agent_socket,
        false,
        None,
    )
}

fn daemon_rules_mount_mismatch(name: &str, desired_rules_dir: &std::path::Path) -> Result<bool> {
    let output = docker_inspect_output(
        &[
            "inspect",
            "--format",
            "{{range .Mounts}}{{if eq .Destination \"/etc/outcall/rules.d\"}}{{.Source}}{{end}}{{end}}",
            name,
        ],
        "inspect daemon rules mount",
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to inspect daemon rules mount: {}",
            command_detail(&output)
        );
    }

    let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if actual.is_empty() {
        return Ok(true);
    }

    let actual = std::path::PathBuf::from(actual);
    let actual = std::fs::canonicalize(&actual).unwrap_or(actual);
    Ok(actual != desired_rules_dir)
}

fn wait_for_daemon_socket(socket: &str) -> Result<()> {
    use std::time::Duration;

    let deadline = std::time::Instant::now() + DAEMON_START_TIMEOUT;
    if daemon_requests_via_exec() {
        let mut last_error = None;
        while std::time::Instant::now() < deadline {
            match daemon_exec_socket_ready(socket) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    ensure_daemon_still_running(socket)?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let last_error = last_error.unwrap_or_else(|| "unknown error".to_string());
        let logs = daemon_container_logs(DEFAULT_DAEMON_NAME).unwrap_or_default();
        anyhow::bail!(
            "cannot reach outcalld inside daemon container after startup wait: {last_error}\n{logs}"
        );
    }

    use std::os::unix::net::UnixStream;
    let mut last_error = None;
    while std::time::Instant::now() < deadline {
        match UnixStream::connect(socket) {
            Ok(_) => return Ok(()),
            Err(err) => {
                ensure_daemon_still_running(socket)?;
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let last_error = last_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let logs = daemon_container_logs(DEFAULT_DAEMON_NAME).unwrap_or_default();
    anyhow::bail!(
        "cannot connect to outcalld at {socket} after startup wait: {last_error}\n{logs}"
    );
}

fn docker_inspect_output(args: &[&str], action: &str) -> Result<std::process::Output> {
    command_output_with_timeout("docker", args, DAEMON_INSPECT_TIMEOUT).map_err(|error| match error
    {
        CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
            "docker timed out after {} seconds while attempting to {action}",
            timeout.as_secs()
        ),
        CommandTimeoutError::Io(error) => error.context(format!("failed to {action}")),
    })
}

fn command_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("docker exited with {:?}", output.status.code())
    }
}

fn ensure_daemon_still_running(socket: &str) -> Result<()> {
    if let Some(state) = daemon_container_state(DEFAULT_DAEMON_NAME)?
        && state != "running"
    {
        let logs = daemon_container_logs(DEFAULT_DAEMON_NAME)?;
        anyhow::bail!(
            "outcalld container is not running (state: {state}) while waiting for {socket}\n{logs}"
        );
    }
    Ok(())
}

fn ensure_default_network(socket: &str) -> Result<()> {
    println!("Ensuring default Outcall network exists...");
    cmd_network_create(socket, None, None, None)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_DAEMON_IMAGE, preferred_daemon_image};

    #[test]
    fn configured_daemon_image_overrides_existing_image() {
        assert_eq!(
            preferred_daemon_image(
                Some("outcall-daemon-review:local".to_string()),
                Some("ghcr.io/outcall-dev/outcalld:v0.1.35".to_string()),
            ),
            "outcall-daemon-review:local".to_string()
        );
    }

    #[test]
    fn existing_daemon_image_is_preserved_for_rules_restart() {
        assert_eq!(
            preferred_daemon_image(None, Some("outcall-daemon-review:local".to_string())),
            "outcall-daemon-review:local".to_string()
        );
    }

    #[test]
    fn stale_official_daemon_image_is_replaced_with_cli_version() {
        assert_eq!(
            preferred_daemon_image(
                None,
                Some("ghcr.io/outcall-dev/outcalld:v0.1.34".to_string()),
            ),
            DEFAULT_DAEMON_IMAGE
        );
    }
}
