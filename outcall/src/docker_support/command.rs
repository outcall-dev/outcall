use std::process::{Command, ExitStatus, Output};
use std::time::Duration;

use crate::process_control::{ProcessRunError, output_with_limits, status_with_timeout};

const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum CommandTimeoutError {
    TimedOut { timeout: Duration },
    Io(anyhow::Error),
}

pub(crate) fn command_output_with_timeout(
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Output, CommandTimeoutError> {
    let mut command = Command::new(command);
    command.args(args);
    map_process_result(output_with_limits(
        &mut command,
        timeout,
        MAX_COMMAND_OUTPUT_BYTES,
    ))
}

pub(crate) fn command_status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, CommandTimeoutError> {
    map_process_result(status_with_timeout(command, timeout))
}

fn map_process_result<T>(result: Result<T, ProcessRunError>) -> Result<T, CommandTimeoutError> {
    match result {
        Ok(value) => Ok(value),
        Err(ProcessRunError::TimedOut { timeout }) => {
            Err(CommandTimeoutError::TimedOut { timeout })
        }
        Err(ProcessRunError::OutputLimit { stream, limit }) => Err(CommandTimeoutError::Io(
            anyhow::anyhow!("command {stream} exceeded {limit} bytes"),
        )),
        Err(ProcessRunError::Io(error)) => Err(CommandTimeoutError::Io(error)),
    }
}
