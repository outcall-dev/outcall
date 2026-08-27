use std::io::Write;

use anyhow::{Context, Result};

use crate::daemon_client::Response;

use super::http::{MAX_PATH_BYTES, write_json as write_http_json};

const MAX_BROKER_ARGS: usize = 256;
pub(super) const MAX_BROKER_ARG_BYTES: usize = 32_768;
const MAX_BROKER_ARG_TOTAL_BYTES: usize = 65_536;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerToolExecRequest {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) cwd: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct BrokerToolExecResult {
    pub(super) status: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerFileReadRequest {
    pub(super) id: String,
    #[serde(default)]
    pub(super) relative_path: Option<String>,
}

#[derive(serde::Serialize)]
pub(super) struct BrokerFileReadResult {
    pub(super) path: String,
    pub(super) contents: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BrokerError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    TooLarge(String),
    #[error("{0}")]
    Unprocessable(String),
    #[error("{0}")]
    Timeout(String),
    #[error("internal host broker error")]
    Internal(#[source] anyhow::Error),
}

pub(super) type BrokerResult<T> = std::result::Result<T, BrokerError>;

impl BrokerError {
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::TooLarge(_) => 413,
            Self::Unprocessable(_) => 422,
            Self::Timeout(_) => 504,
            Self::Internal(_) => 500,
        }
    }

    pub(super) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

pub(super) fn validate_tool_request(request: &BrokerToolExecRequest) -> Result<()> {
    outcall::host_resources::validate_resource_id(&request.id).context("invalid host tool ID")?;
    if request.args.len() > MAX_BROKER_ARGS
        || request
            .args
            .iter()
            .any(|arg| arg.len() > MAX_BROKER_ARG_BYTES || arg.as_bytes().contains(&b'\0'))
        || request.args.iter().map(String::len).sum::<usize>() > MAX_BROKER_ARG_TOTAL_BYTES
    {
        anyhow::bail!("host tool arguments exceed configured limits");
    }
    if request.cwd.as_ref().is_some_and(|cwd| {
        cwd.len() > MAX_PATH_BYTES
            || cwd.as_bytes().contains(&b'\0')
            || cwd.chars().any(char::is_control)
    }) {
        anyhow::bail!("host tool cwd is invalid or exceeds {MAX_PATH_BYTES} bytes");
    }
    Ok(())
}

pub(super) fn validate_file_request(request: &BrokerFileReadRequest) -> Result<()> {
    outcall::host_resources::validate_resource_id(&request.id).context("invalid host file ID")?;
    if request.relative_path.as_ref().is_some_and(|path| {
        path.is_empty()
            || std::path::Path::new(path).is_absolute()
            || path.len() > MAX_PATH_BYTES
            || path.as_bytes().contains(&b'\0')
            || path.chars().any(char::is_control)
    }) {
        anyhow::bail!(
            "relative_path must be a safe relative path of at most {MAX_PATH_BYTES} bytes"
        );
    }
    Ok(())
}

pub(super) fn write_broker_error(
    stream: &mut impl Write,
    status: u16,
    message: String,
) -> Result<()> {
    write_http_json(
        stream,
        status,
        &Response {
            success: false,
            data: None,
            error: Some(message),
        },
    )
}

pub(super) fn write_broker_result<S: Write, T: serde::Serialize>(
    stream: &mut S,
    result: BrokerResult<T>,
) -> Result<()> {
    match result {
        Ok(data) => {
            let response = Response::ok(data).context("failed to encode host broker response")?;
            write_http_json(stream, 200, &response)
        }
        Err(error) => {
            let status = broker_error_status(&error);
            if let BrokerError::Internal(source) = &error {
                eprintln!("host broker operation failed: {source:#}");
            }
            write_http_json(
                stream,
                status,
                &Response {
                    success: false,
                    data: None,
                    error: Some(error.to_string()),
                },
            )
        }
    }
}

pub(crate) fn broker_error_status(error: &BrokerError) -> u16 {
    error.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_request_requires_relative_paths() {
        for path in ["/etc/passwd", ""] {
            let request = BrokerFileReadRequest {
                id: "notes".to_string(),
                relative_path: Some(path.to_string()),
            };
            assert!(validate_file_request(&request).is_err());
        }
    }
}
