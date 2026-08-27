use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tracing::debug;

use outcall_api::{ApiResponse, DEFAULT_REQUEST_TIMEOUT_SECS};

const MAX_API_BODY_BYTES: usize = 65_536;
const MAX_REQUEST_TIMEOUT_SECS: u64 = 300;

struct ConnectionDriver {
    task: Option<JoinHandle<()>>,
}

impl ConnectionDriver {
    fn new(task: JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    async fn stop(mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        if let Err(error) = task.await
            && !error.is_cancelled()
        {
            debug!(%error, "outcalld HTTP connection driver task failed");
        }
    }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(crate) fn request_timeout_from_env() -> Result<Duration> {
    let value = match std::env::var("OUTCALL_TIMEOUT_SECS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("OUTCALL_TIMEOUT_SECS must be valid UTF-8")
        }
    };
    parse_request_timeout(value.as_deref())
}

fn parse_request_timeout(value: Option<&str>) -> Result<Duration> {
    let seconds = match value {
        Some(value) => value
            .parse::<u64>()
            .context("OUTCALL_TIMEOUT_SECS must be an integer")?,
        None => DEFAULT_REQUEST_TIMEOUT_SECS,
    };
    if !(1..=MAX_REQUEST_TIMEOUT_SECS).contains(&seconds) {
        anyhow::bail!("OUTCALL_TIMEOUT_SECS must be between 1 and {MAX_REQUEST_TIMEOUT_SECS}");
    }
    Ok(Duration::from_secs(seconds))
}

pub(crate) async fn verify_socket_reachable(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        anyhow::bail!("agent socket not found at {path}");
    }
    UnixStream::connect(path)
        .await
        .with_context(|| format!("cannot connect to agent socket at {path}"))?;
    Ok(())
}

pub(crate) async fn post_json<T, R>(
    socket_path: &str,
    path: &str,
    body: &T,
    auth: Option<&str>,
) -> Result<R>
where
    T: serde::Serialize,
    R: for<'de> serde::Deserialize<'de>,
{
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to {socket_path}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP handshake failed")?;
    let driver = ConnectionDriver::new(tokio::spawn(async move {
        if let Err(error) = connection.await {
            debug!(%error, "outcalld HTTP connection driver stopped with an error");
        }
    }));

    let result = async {
        let body_bytes = serialize_bounded_json(body)?;
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("content-length", body_bytes.len().to_string());
        if let Some(token) = auth {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder
            .body(Full::new(Bytes::from(body_bytes)))
            .context("failed to build HTTP request")?;
        let response = sender
            .send_request(request)
            .await
            .context("HTTP request to outcalld failed")?;

        let status = response.status();
        let raw = collect_bounded_body(response.into_body())
            .await
            .context("failed to read response body")?;
        let api_response: ApiResponse<R> = serde_json::from_slice(&raw)
            .with_context(|| format!("malformed response from outcalld (HTTP {status})"))?;

        if !status.is_success() || !api_response.success {
            anyhow::bail!(
                "{}",
                api_response
                    .error
                    .unwrap_or_else(|| format!("HTTP {status}"))
            );
        }
        api_response
            .data
            .ok_or_else(|| anyhow::anyhow!("outcalld returned success with no data"))
    }
    .await;
    drop(sender);
    driver.stop().await;
    result
}

fn serialize_bounded_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).context("failed to serialize request body")?;
    if bytes.len() > MAX_API_BODY_BYTES {
        anyhow::bail!("request body exceeds {MAX_API_BODY_BYTES} bytes");
    }
    Ok(bytes)
}

async fn collect_bounded_body<B>(body: B) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let collected = Limited::new(body, MAX_API_BODY_BYTES)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("failed to read bounded response body: {error}"))?;
    Ok(collected.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_timeout_is_strict_and_bounded() {
        assert_eq!(
            parse_request_timeout(None).unwrap(),
            Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS)
        );
        assert_eq!(
            parse_request_timeout(Some("5")).unwrap(),
            Duration::from_secs(5)
        );
        for value in ["", "0", "301", "2s", " 2"] {
            assert!(
                parse_request_timeout(Some(value)).is_err(),
                "value={value:?}"
            );
        }
    }

    #[test]
    fn serialized_request_body_is_bounded() {
        assert!(serialize_bounded_json(&"small").is_ok());
        assert!(serialize_bounded_json(&"x".repeat(MAX_API_BODY_BYTES)).is_err());
    }

    #[tokio::test]
    async fn response_body_is_bounded() {
        let accepted = collect_bounded_body(Full::new(Bytes::from(vec![b'x'; MAX_API_BODY_BYTES])))
            .await
            .unwrap();
        assert_eq!(accepted.len(), MAX_API_BODY_BYTES);

        let oversized = Full::new(Bytes::from(vec![b'x'; MAX_API_BODY_BYTES + 1]));
        assert!(collect_bounded_body(oversized).await.is_err());
    }

    #[tokio::test]
    async fn connection_driver_aborts_its_task_on_drop() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _receiver_was_open = sender.send(()).is_ok();
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _receiver_was_open = started_tx.send(()).is_ok();
            std::future::pending::<()>().await;
        });
        let driver = ConnectionDriver::new(task);
        started_rx.await.expect("connection task started");

        drop(driver);

        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("connection task cancellation timed out")
            .expect("connection task drop signal");
    }
}
