use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Owns one daemon-lifetime task and guarantees cancellation on drop.
pub(crate) struct BackgroundTask {
    cancellation: CancellationToken,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl BackgroundTask {
    pub(crate) fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            handle: Mutex::new(None),
        }
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let task = tokio::spawn(future);
        let mut slot = match self.handle.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(previous) = slot.replace(task) {
            previous.abort();
            warn!("replaced an existing owned background task");
        }
    }

    pub(crate) async fn shutdown(&self, timeout: Duration, label: &'static str) {
        self.cancellation.cancel();
        let task = {
            let mut slot = match self.handle.lock() {
                Ok(slot) => slot,
                Err(poisoned) => poisoned.into_inner(),
            };
            slot.take()
        };
        let Some(mut task) = task else {
            return;
        };

        match tokio::time::timeout(timeout, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(task = label, %error, "background task failed"),
            Err(_) => {
                warn!(
                    task = label,
                    "background task exceeded shutdown deadline; aborting"
                );
                task.abort();
                if let Err(error) = task.await {
                    if !error.is_cancelled() {
                        warn!(task = label, %error, "background task failed after abort");
                    }
                }
            }
        }
    }
}

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.cancellation.cancel();
        let slot = match self.handle.get_mut() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(task) = slot.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_and_joins_owned_task() {
        let task = BackgroundTask::new();
        let cancellation = task.cancellation_token();
        task.spawn(async move { cancellation.cancelled().await });

        task.shutdown(Duration::from_secs(1), "test task").await;
    }
}
