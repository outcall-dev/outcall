use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::daemon_client::DEFAULT_DAEMON_NAME;

use super::command::{COMMAND_TIMEOUT, bounded_output, bounded_status, output_detail};
use super::inspect::daemon_container_info;

const DAEMON_STOP_TIMEOUT_SECS: &str = "30";
const DAEMON_STOP_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_LOG_TAIL_LINES: usize = 100_000;

pub(super) fn remove_daemon_container(name: &str) -> Result<bool> {
    let Some(info) = daemon_container_info(name)? else {
        return Ok(false);
    };

    if state_requires_stop(&info.state) {
        let output = bounded_output(
            "docker",
            &["stop", "--time", DAEMON_STOP_TIMEOUT_SECS, name],
            DAEMON_STOP_COMMAND_TIMEOUT,
            "stop daemon container",
        )?;
        if !output.status.success() {
            anyhow::bail!(
                "docker stop failed for daemon '{name}': {}",
                output_detail(&output)
            );
        }
    }

    let output = bounded_output(
        "docker",
        &["rm", name],
        COMMAND_TIMEOUT,
        "remove daemon container",
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "docker rm failed for daemon '{name}': {}",
            output_detail(&output)
        );
    }

    Ok(true)
}

fn state_requires_stop(state: &str) -> bool {
    !matches!(state, "created" | "dead" | "exited")
}

pub(crate) fn daemon_container_logs(name: &str) -> Result<String> {
    if daemon_container_info(name)?.is_none() {
        return Ok(String::new());
    }
    let output = bounded_output(
        "docker",
        &["logs", "--tail", "200", name],
        COMMAND_TIMEOUT,
        "fetch daemon container logs",
    )?;
    if !output.status.success() {
        anyhow::bail!("failed to fetch daemon logs: {}", output_detail(&output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok(match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    })
}

pub(crate) fn cmd_daemon_stop(name: Option<String>) -> Result<()> {
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    if !remove_daemon_container(&name)? {
        println!("Daemon \"{name}\" was not running.");
        return Ok(());
    }
    println!("Daemon \"{name}\" stopped.");
    Ok(())
}

pub(crate) fn cmd_daemon_logs(name: Option<String>, follow: bool, tail: usize) -> Result<()> {
    if tail > MAX_LOG_TAIL_LINES {
        anyhow::bail!("daemon log tail must not exceed {MAX_LOG_TAIL_LINES} lines");
    }
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    if daemon_container_info(&name)?.is_none() {
        anyhow::bail!("daemon container {name:?} does not exist");
    }
    let mut args: Vec<String> = vec!["logs".into(), "--tail".into(), tail.to_string()];
    if follow {
        args.push("-f".into());
    }
    args.push(name.clone());
    let mut command = Command::new("docker");
    command.args(&args);
    let status = if follow {
        command.status().context("failed to invoke docker logs")?
    } else {
        bounded_status(&mut command, COMMAND_TIMEOUT, "read daemon logs")?
    };
    if !status.success() {
        anyhow::bail!(
            "docker logs failed (exit {:?}); is the container \"{name}\" running?",
            status.code()
        );
    }
    Ok(())
}

pub(crate) fn cmd_daemon_status(name: Option<String>) -> Result<()> {
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let Some(info) = daemon_container_info(&name)? else {
        println!("Daemon \"{name}\" is not running (no such container).");
        return Ok(());
    };
    println!(
        "Daemon \"{name}\": {} (image={})",
        if info.running { "running" } else { "stopped" },
        info.image
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_daemon_is_stopped_gracefully_before_removal() {
        for state in ["running", "paused", "restarting"] {
            assert!(state_requires_stop(state), "state={state}");
        }
        for state in ["created", "dead", "exited"] {
            assert!(!state_requires_stop(state), "state={state}");
        }
    }

    #[test]
    fn daemon_log_tail_is_bounded() {
        assert!(cmd_daemon_logs(None, false, MAX_LOG_TAIL_LINES + 1).is_err());
    }
}
