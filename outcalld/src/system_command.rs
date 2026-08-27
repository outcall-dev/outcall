use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::{Child, Command};

pub(crate) const SYSTEM_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn output_with_timeout(
    command: &mut Command,
    timeout: Duration,
    description: &str,
) -> Result<Output> {
    command.kill_on_drop(true);
    tokio::time::timeout(timeout, command.output())
        .await
        .with_context(|| format!("{description} timed out after {}s", timeout.as_secs()))?
        .with_context(|| format!("failed to {description}"))
}

pub(crate) async fn wait_with_output(
    child: Child,
    timeout: Duration,
    description: &str,
) -> Result<Output> {
    tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .with_context(|| format!("{description} timed out after {}s", timeout.as_secs()))?
        .with_context(|| format!("failed to {description}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn command_timeout_is_bounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]);

        let error = output_with_timeout(
            &mut command,
            Duration::from_millis(20),
            "run timeout fixture",
        )
        .await
        .expect_err("command should time out");

        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn child_wait_timeout_is_bounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]).kill_on_drop(true);
        let child = command.spawn().expect("spawn timeout fixture");

        let error = wait_with_output(child, Duration::from_millis(20), "wait for timeout fixture")
            .await
            .expect_err("child wait should time out");

        assert!(error.to_string().contains("timed out"));
    }
}
