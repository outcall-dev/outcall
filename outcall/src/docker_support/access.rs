use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::command::{CommandTimeoutError, command_output_with_timeout};
use crate::daemon_client::daemon_exec_output;

pub(crate) fn ensure_docker_access() -> Result<()> {
    let failure = match retry_with_delay(
        docker_probe_attempts(),
        docker_probe_retry_delay(),
        docker_info_probe,
    ) {
        Ok(()) => return Ok(()),
        Err(failure) => failure,
    };

    match failure {
        DockerProbeFailure::Io(error) => Err(error).context(
            "failed to invoke `docker info`; install Docker and ensure the CLI is available",
        ),
        DockerProbeFailure::TimedOut { timeout } => {
            let context_name = docker_context_name().unwrap_or_else(|_| "unknown".to_string());
            anyhow::bail!(
                "Docker is not ready for Outcall.\n\
                 Detail: `docker info` did not respond within {} seconds after {} attempts.\n\
                 Active Docker context: {context_name}\n\
                 Start or restart Docker Desktop, wait for the daemon to finish booting, then rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first.",
                timeout.as_secs(),
                docker_probe_attempts()
            );
        }
        DockerProbeFailure::Unavailable { detail } if detail.contains("permission denied") => {
            anyhow::bail!(
                "Docker is installed but the current user cannot access the Docker socket.\n\
                 Detail: {detail}\n\
                 Start Docker Desktop or fix Docker socket permissions, then rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first."
            );
        }
        DockerProbeFailure::Unavailable { detail } => {
            let context_name = docker_context_name().unwrap_or_else(|_| "unknown".to_string());
            anyhow::bail!(
                "Docker is not ready for Outcall after {} attempts.\n\
                 Detail: {detail}\n\
                 Active Docker context: {context_name}\n\
                 Start Docker and rerun `outcall`.\n\
                 Run `outcall doctor` if you want the full prerequisite report first.",
                docker_probe_attempts()
            );
        }
    }
}

#[derive(Debug)]
enum DockerProbeFailure {
    TimedOut { timeout: Duration },
    Io(anyhow::Error),
    Unavailable { detail: String },
}

fn docker_info_probe() -> std::result::Result<(), DockerProbeFailure> {
    let output = command_output_with_timeout("docker", &["info"], docker_probe_timeout()).map_err(
        |error| match error {
            CommandTimeoutError::TimedOut { timeout } => DockerProbeFailure::TimedOut { timeout },
            CommandTimeoutError::Io(error) => DockerProbeFailure::Io(error),
        },
    )?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "docker info failed".to_string()
    };
    Err(DockerProbeFailure::Unavailable { detail })
}

pub(crate) fn retry_with_delay<T, E>(
    attempts: usize,
    delay: Duration,
    mut operation: impl FnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let attempts = attempts.max(1);
    let mut attempt = 1;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if attempt >= attempts => return Err(error),
            Err(_) => {
                std::thread::sleep(delay);
                attempt += 1;
            }
        }
    }
}

pub(crate) fn ensure_docker_access_with_fix() -> Result<()> {
    match ensure_docker_access() {
        Ok(()) => Ok(()),
        Err(initial_error) if std::env::consts::OS != "macos" => Err(initial_error),
        Err(initial_error) => {
            println!("  Starting Docker Desktop and waiting for it to become ready...");
            let launched = std::process::Command::new("open")
                .args(["-gja", "Docker"])
                .status()
                .context("failed to ask macOS to open Docker Desktop")?;
            if !launched.success() {
                return Err(initial_error).context("Docker Desktop did not start");
            }
            let timeout = Duration::from_secs(90);
            let deadline = Instant::now() + timeout;
            loop {
                if docker_info_probe().is_ok() {
                    println!("  PASS docker: Docker Desktop is ready");
                    return Ok(());
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                std::thread::sleep(
                    Duration::from_secs(1).min(deadline.saturating_duration_since(now)),
                );
            }
            Err(initial_error).context("Docker Desktop did not become ready within 90 seconds")
        }
    }
}

pub(crate) fn ensure_bridge_netfilter_enforceable() -> Result<()> {
    if std::env::consts::OS != "linux" {
        return Ok(());
    }

    let (iptables, ip6tables) = bridge_netfilter_values()?;
    validate_bridge_netfilter_values(&iptables, &ip6tables, "host")
}

pub(crate) fn ensure_runtime_bridge_netfilter_enforceable() -> Result<()> {
    if std::env::consts::OS == "linux" {
        return ensure_bridge_netfilter_enforceable();
    }

    let iptables = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-iptables"])?;
    let ip6tables = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-ip6tables"])?;
    validate_bridge_netfilter_values(iptables.trim(), ip6tables.trim(), "Docker Linux runtime")
}

fn validate_bridge_netfilter_values(ipv4: &str, ipv6: &str, location: &str) -> Result<()> {
    if ipv4 == "1" && ipv6 == "1" {
        return Ok(());
    }

    anyhow::bail!(
        "Secure unattended mode requires bridge netfilter enforcement in the {location}.\n\
         Current values are:\n\
         - /proc/sys/net/bridge/bridge-nf-call-iptables = {ipv4}\n\
         - /proc/sys/net/bridge/bridge-nf-call-ip6tables = {ipv6}\n\
         Enable `br_netfilter` and set both sysctls to `1`."
    )
}

pub(super) fn bridge_netfilter_values() -> Result<(String, String)> {
    fn read_bridge_sysctl(path: &str) -> Result<String> {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {path}"))
            .map(|value| value.trim().to_string())
    }

    Ok((
        read_bridge_sysctl("/proc/sys/net/bridge/bridge-nf-call-iptables")?,
        read_bridge_sysctl("/proc/sys/net/bridge/bridge-nf-call-ip6tables")?,
    ))
}

pub(super) fn bridge_netfilter_enforceable() -> bool {
    if std::env::consts::OS != "linux" {
        return false;
    }

    matches!(bridge_netfilter_values(), Ok((ipv4, ipv6)) if ipv4 == "1" && ipv6 == "1")
}

fn docker_context_name() -> Result<String> {
    let output =
        command_output_with_timeout("docker", &["context", "show"], doctor_command_timeout())
            .map_err(|error| match error {
                CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
                    "`docker context show` timed out after {} seconds",
                    timeout.as_secs()
                ),
                CommandTimeoutError::Io(error) => error,
            })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!("docker context show failed: {detail}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(super) fn doctor_command_timeout() -> Duration {
    Duration::from_secs(3)
}

fn docker_probe_timeout() -> Duration {
    Duration::from_secs(5)
}

fn docker_probe_attempts() -> usize {
    3
}

fn docker_probe_retry_delay() -> Duration {
    Duration::from_millis(250)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_recovers_and_zero_attempts_still_runs_once() {
        let mut attempts = 0;
        let value = retry_with_delay(3, Duration::ZERO, || {
            attempts += 1;
            (attempts == 3).then_some("ready").ok_or("not ready")
        });
        assert_eq!(value, Ok("ready"));
        assert_eq!(attempts, 3);

        let mut attempts = 0;
        let value = retry_with_delay(0, Duration::ZERO, || {
            attempts += 1;
            Err::<(), _>("not ready")
        });
        assert_eq!(value, Err("not ready"));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn bridge_netfilter_validation_is_fail_closed() {
        assert!(validate_bridge_netfilter_values("1", "1", "test").is_ok());
        let error = validate_bridge_netfilter_values("0", "1", "test")
            .unwrap_err()
            .to_string();
        assert!(error.contains("test"));
        assert!(error.contains("iptables = 0"));
    }
}
