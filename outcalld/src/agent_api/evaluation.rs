use std::sync::Arc;
use std::time::Duration;

use outcall_api::{EvalContext, EvaluateResult};
use tokio::sync::Semaphore;
use tokio::task::JoinError;
use tokio::time::{timeout_at, Instant};

use crate::rules::RuleEngine;

pub(super) const EVALUATION_CONCURRENCY: usize = 16;

#[derive(Clone)]
pub(super) struct EvaluationExecutor {
    permits: Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum EvaluationError {
    #[error("evaluation timeout")]
    Timeout,
    #[error("evaluation worker failed: {0}")]
    Worker(#[from] JoinError),
}

impl EvaluationExecutor {
    pub(super) fn new(timeout: Duration) -> Self {
        Self::with_concurrency(timeout, EVALUATION_CONCURRENCY)
    }

    fn with_concurrency(timeout: Duration, concurrency: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            timeout,
        }
    }

    pub(super) async fn evaluate(
        &self,
        rules: &RuleEngine,
        context: EvalContext,
    ) -> Result<EvaluateResult, EvaluationError> {
        let rule_set = rules.snapshot().await;
        self.run(move || RuleEngine::evaluate_snapshot(&rule_set, &context))
            .await
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, EvaluationError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let deadline = Instant::now() + self.timeout;
        let permit = timeout_at(deadline, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| EvaluationError::Timeout)?
            .map_err(|_| EvaluationError::Timeout)?;

        let worker = tokio::task::spawn_blocking(move || {
            // A timed-out blocking task cannot be aborted. Retain its permit
            // until it actually exits so abandoned work remains bounded.
            let _permit = permit;
            operation()
        });
        timeout_at(deadline, worker)
            .await
            .map_err(|_| EvaluationError::Timeout)?
            .map_err(EvaluationError::Worker)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn timed_out_work_retains_its_capacity_until_it_exits() {
        let executor = EvaluationExecutor::with_concurrency(Duration::from_millis(25), 1);
        let first = executor
            .run(|| std::thread::sleep(Duration::from_millis(100)))
            .await;
        assert!(matches!(first, Err(EvaluationError::Timeout)));

        let second_started = Arc::new(AtomicBool::new(false));
        let started = second_started.clone();
        let second = executor
            .run(move || started.store(true, Ordering::SeqCst))
            .await;
        assert!(matches!(second, Err(EvaluationError::Timeout)));
        assert!(!second_started.load(Ordering::SeqCst));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(executor.run(|| 42).await.is_ok());
    }
}
