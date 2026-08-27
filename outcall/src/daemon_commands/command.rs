use std::process::{Command, Output};
use std::time::Duration;

use anyhow::Result;

use crate::docker_support::{
    CommandTimeoutError, command_output_with_timeout, command_status_with_timeout,
};

pub(super) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn bounded_output(
    command: &str,
    args: &[&str],
    timeout: Duration,
    action: &str,
) -> Result<Output> {
    command_output_with_timeout(command, args, timeout)
        .map_err(|error| command_error(error, action))
}

pub(super) fn bounded_status(
    command: &mut Command,
    timeout: Duration,
    action: &str,
) -> Result<std::process::ExitStatus> {
    command_status_with_timeout(command, timeout).map_err(|error| command_error(error, action))
}

fn command_error(error: CommandTimeoutError, action: &str) -> anyhow::Error {
    match error {
        CommandTimeoutError::TimedOut { timeout } => anyhow::anyhow!(
            "timed out after {} seconds while attempting to {action}",
            timeout.as_secs()
        ),
        CommandTimeoutError::Io(error) => error.context(format!("failed to {action}")),
    }
}

pub(super) fn missing_container(output: &Output) -> bool {
    let detail = output_detail(output).to_ascii_lowercase();
    detail.contains("no such object") || detail.contains("no such container")
}

pub(super) fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("command exited with {:?}", output.status.code())
    }
}
