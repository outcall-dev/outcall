use std::future::Future;
use std::time::Duration;

use bollard::errors::Error as DockerError;
use thiserror::Error;

pub(crate) const FINITE_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const IMAGE_PULL_STALL_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const IMAGE_PULL_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Error)]
pub(crate) enum DockerOperationError {
    #[error("Docker {operation} timed out after {timeout:?}")]
    Timeout {
        operation: String,
        timeout: Duration,
    },
    #[error("Docker {operation} failed: {source}")]
    Engine {
        operation: String,
        #[source]
        source: DockerError,
    },
}

impl DockerOperationError {
    pub(crate) fn status_code(&self) -> Option<u16> {
        match self {
            Self::Engine {
                source: DockerError::DockerResponseServerError { status_code, .. },
                ..
            } => Some(*status_code),
            _ => None,
        }
    }
}

pub(crate) async fn run<T>(
    operation: impl Into<String>,
    future: impl Future<Output = Result<T, DockerError>>,
) -> Result<T, DockerOperationError> {
    run_for(operation, FINITE_OPERATION_TIMEOUT, future).await
}

pub(crate) async fn run_for<T>(
    operation: impl Into<String>,
    timeout: Duration,
    future: impl Future<Output = Result<T, DockerError>>,
) -> Result<T, DockerOperationError> {
    let operation = operation.into();
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(source)) => Err(DockerOperationError::Engine { operation, source }),
        Err(_) => Err(DockerOperationError::Timeout { operation, timeout }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finite_operation_timeout_is_enforced() {
        let result = run_for("test operation", Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, DockerError>(())
        })
        .await;

        assert!(matches!(result, Err(DockerOperationError::Timeout { .. })));
    }

    #[tokio::test]
    async fn engine_status_code_is_preserved() {
        let result = run("inspect", async {
            Err::<(), _>(DockerError::DockerResponseServerError {
                status_code: 404,
                message: "missing".to_string(),
            })
        })
        .await;

        assert_eq!(result.unwrap_err().status_code(), Some(404));
    }
}
