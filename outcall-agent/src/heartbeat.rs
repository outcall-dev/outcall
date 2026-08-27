use std::time::Duration;

use anyhow::{Context, Result};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info};

use outcall_api::DEFAULT_HEARTBEAT_INTERVAL_SECS;

use crate::api_client::verify_socket_reachable;

#[derive(Debug)]
pub(crate) enum HeartbeatExit {
    Stopped,
    Unreachable(anyhow::Error),
}

pub(crate) struct Heartbeat {
    stop_tx: watch::Sender<bool>,
    completion_rx: oneshot::Receiver<HeartbeatExit>,
    task: Option<JoinHandle<()>>,
    signal_task: Option<JoinHandle<()>>,
}

impl Heartbeat {
    pub(crate) fn start(socket_path: String, request_timeout: Duration) -> Self {
        let (stop_tx, stop_rx) = watch::channel(false);
        let (completion_tx, completion_rx) = oneshot::channel();
        let task = tokio::spawn(run_loop(
            socket_path,
            request_timeout,
            stop_rx,
            completion_tx,
        ));
        Self {
            stop_tx,
            completion_rx,
            task: Some(task),
            signal_task: None,
        }
    }

    pub(crate) fn completion(&mut self) -> &mut oneshot::Receiver<HeartbeatExit> {
        &mut self.completion_rx
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        let _receiver_was_open = self.stop_tx.send(true).is_ok();
        let exit = receive_exit((&mut self.completion_rx).await);
        self.join_tasks().await?;
        match exit? {
            HeartbeatExit::Stopped => Ok(()),
            HeartbeatExit::Unreachable(error) => Err(error),
        }
    }

    pub(crate) fn install_sigterm_handler(&mut self) -> Result<()> {
        if self.signal_task.is_some() {
            anyhow::bail!("SIGTERM handler is already installed");
        }
        let stop_tx = self.stop_tx.clone();
        let mut sigterm = signal(SignalKind::terminate())?;
        self.signal_task = Some(tokio::spawn(async move {
            if sigterm.recv().await.is_none() {
                error!(component = "shim", "SIGTERM receiver hung up unexpectedly");
                return;
            }
            info!(
                component = "shim",
                "SIGTERM received — completing in-flight work"
            );
            let _receiver_was_open = stop_tx.send(true).is_ok();
        }));
        Ok(())
    }

    async fn join_tasks(&mut self) -> Result<()> {
        if let Some(task) = self.task.take() {
            task.await.context("heartbeat task failed")?;
        }
        if let Some(task) = self.signal_task.take() {
            task.abort();
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                return Err(anyhow::Error::new(error).context("SIGTERM handler task failed"));
            }
        }
        Ok(())
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(task) = self.signal_task.take() {
            task.abort();
        }
    }
}

pub(crate) fn receive_exit(
    result: std::result::Result<HeartbeatExit, oneshot::error::RecvError>,
) -> Result<HeartbeatExit> {
    result.context("heartbeat task ended without reporting its status")
}

async fn run_loop(
    socket_path: String,
    request_timeout: Duration,
    mut stop_rx: watch::Receiver<bool>,
    completion: oneshot::Sender<HeartbeatExit>,
) {
    let interval = Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let reachable = tokio::time::timeout(
                    request_timeout,
                    verify_socket_reachable(&socket_path),
                )
                .await
                .is_ok_and(|result| result.is_ok());

                if !reachable {
                    error!(component = "shim", "outcalld unreachable — stopping active action (fail closed)");
                    drop(completion.send(HeartbeatExit::Unreachable(anyhow::anyhow!(
                        "outcalld unreachable during heartbeat"
                    ))));
                    return;
                }
            }
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    drop(completion.send(HeartbeatExit::Stopped));
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_joins_owned_heartbeat_and_signal_tasks() {
        let mut heartbeat = Heartbeat::start(
            "/tmp/outcall-heartbeat-test.sock".to_string(),
            Duration::from_secs(1),
        );
        heartbeat
            .install_sigterm_handler()
            .expect("install SIGTERM handler");

        heartbeat.stop().await.expect("stop heartbeat");

        assert!(heartbeat.task.is_none());
        assert!(heartbeat.signal_task.is_none());
    }
}
