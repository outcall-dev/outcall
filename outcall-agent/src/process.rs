use std::process::{ExitCode, ExitStatus};
use std::time::Duration;

use anyhow::Context;
use tokio::sync::oneshot;

use crate::heartbeat::{HeartbeatExit, receive_exit};

#[derive(Debug)]
pub(crate) enum CommandError {
    Action(anyhow::Error),
    Unreachable(anyhow::Error),
}

/// Executes an allowed command while retaining fail-closed heartbeat coverage.
/// The boolean result records whether the heartbeat completion was consumed.
pub(crate) async fn execute_command(
    args: Vec<String>,
    heartbeat: &mut oneshot::Receiver<HeartbeatExit>,
) -> Result<(ExitCode, bool), CommandError> {
    if args.is_empty() {
        return Ok((ExitCode::SUCCESS, false));
    }

    let mut command = tokio::process::Command::new(&args[0]);
    command.args(&args[1..]).kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to execute '{}'", args[0]))
        .map_err(CommandError::Action)?;

    tokio::select! {
        status = child.wait() => {
            let status = status
                .with_context(|| format!("failed to wait for '{}'", args[0]))
                .map_err(CommandError::Action)?;
            Ok((exit_code(status), false))
        }
        heartbeat = heartbeat => {
            match receive_exit(heartbeat).map_err(CommandError::Unreachable)? {
                HeartbeatExit::Stopped => {
                    let status = child
                        .wait()
                        .await
                        .with_context(|| format!("failed to wait for '{}'", args[0]))
                        .map_err(CommandError::Action)?;
                    Ok((exit_code(status), true))
                }
                HeartbeatExit::Unreachable(error) => {
                    tokio::time::timeout(Duration::from_secs(5), child.kill())
                        .await
                        .with_context(|| format!("timed out terminating '{}'", args[0]))
                        .and_then(|result| {
                            result.with_context(|| format!("failed to terminate '{}'", args[0]))
                        })
                        .map_err(|cleanup_error| {
                            CommandError::Unreachable(anyhow::anyhow!(
                                "{error:#}; child cleanup also failed: {cleanup_error:#}"
                            ))
                        })?;
                    Err(CommandError::Unreachable(error))
                }
            }
        }
    }
}

fn exit_code(status: ExitStatus) -> ExitCode {
    match status.code().and_then(|code| u8::try_from(code).ok()) {
        Some(code) => ExitCode::from(code),
        None => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn heartbeat_failure_cancels_active_child() {
        let (heartbeat_tx, mut heartbeat_rx) = oneshot::channel();
        heartbeat_tx
            .send(HeartbeatExit::Unreachable(anyhow::anyhow!("test outage")))
            .unwrap();
        let started = Instant::now();

        let error = execute_command(
            vec!["sh".to_string(), "-c".to_string(), "sleep 5".to_string()],
            &mut heartbeat_rx,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            CommandError::Unreachable(error) if error.to_string().contains("test outage")
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn preserves_child_exit_code() {
        let (_heartbeat_tx, mut heartbeat_rx) = oneshot::channel();
        let (exit, consumed) = execute_command(
            vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
            &mut heartbeat_rx,
        )
        .await
        .expect("execute child");

        assert_eq!(exit, ExitCode::from(42));
        assert!(!consumed);
    }

    #[tokio::test]
    async fn stop_signal_waits_for_child_and_preserves_its_exit_code() {
        let (heartbeat_tx, mut heartbeat_rx) = oneshot::channel();
        heartbeat_tx
            .send(HeartbeatExit::Stopped)
            .expect("send stop event");
        let (exit, consumed) = execute_command(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 0.05; exit 7".to_string(),
            ],
            &mut heartbeat_rx,
        )
        .await
        .expect("execute child");

        assert_eq!(exit, ExitCode::from(7));
        assert!(consumed);
    }
}
