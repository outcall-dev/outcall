use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::process_control::{ProcessRunError, output_with_input_limits, output_with_limits};

pub(crate) const DEFAULT_DAEMON_NAME: &str = "outcall-daemon";
const DAEMON_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const DAEMON_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_DAEMON_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_DAEMON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DAEMON_ERROR_DETAIL_BYTES: usize = 4096;

/// Response envelope shared by the daemon API and host broker.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Response {
    pub(crate) success: bool,
    pub(crate) data: Option<serde_json::Value>,
    pub(crate) error: Option<String>,
}

impl Response {
    pub(crate) fn ok<T: Serialize>(data: T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            success: true,
            data: Some(serde_json::to_value(data)?),
            error: None,
        })
    }
}

pub(crate) fn http_get(socket: &str, path: &str) -> Result<String> {
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("GET", socket, path, None);
    }
    let mut stream = connect(socket)?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    read_body(&mut stream)
}

pub(crate) fn http_post(socket: &str, path: &str) -> Result<String> {
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("POST", socket, path, Some(String::new()));
    }
    let mut stream = connect(socket)?;
    write!(
        stream,
        "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
    )?;
    read_body(&mut stream)
}

pub(crate) fn http_post_json<T: Serialize>(socket: &str, path: &str, body: &T) -> Result<String> {
    let json = serialize_request_body(body)?;
    if daemon_requests_via_exec() {
        return daemon_http_request_via_exec("POST", socket, path, Some(json));
    }
    let mut stream = connect(socket)?;
    write!(
        stream,
        "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    )?;
    read_body(&mut stream)
}

fn connect(socket: &str) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket)
        .with_context(|| format!("cannot connect to outcalld at {socket} — is it running?"))?;
    stream
        .set_read_timeout(Some(DAEMON_REQUEST_TIMEOUT))
        .context("failed to set daemon socket read timeout")?;
    stream
        .set_write_timeout(Some(DAEMON_REQUEST_TIMEOUT))
        .context("failed to set daemon socket write timeout")?;
    Ok(stream)
}

pub(crate) fn daemon_requests_via_exec() -> bool {
    daemon_requests_via_exec_for(
        std::env::consts::OS,
        std::env::var("OUTCALL_DAEMON_TRANSPORT").ok().as_deref(),
    )
}

fn daemon_requests_via_exec_for(os: &str, transport: Option<&str>) -> bool {
    match transport {
        Some("unix") => false,
        Some("docker") => true,
        _ => os == "macos",
    }
}

pub(crate) fn daemon_exec_output<const N: usize>(args: [&str; N]) -> Result<String> {
    let mut command = std::process::Command::new("docker");
    command.arg("exec").arg(DEFAULT_DAEMON_NAME).args(args);
    let output = bounded_command_output(&mut command, DAEMON_REQUEST_TIMEOUT)
        .context("failed to invoke docker exec against outcall-daemon")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!(
            "docker exec {} failed: {}",
            DEFAULT_DAEMON_NAME,
            if detail.is_empty() {
                "unknown error"
            } else {
                detail.as_str()
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn daemon_exec_socket_ready(socket: &str) -> Result<bool> {
    daemon_exec_socket_ready_for(DEFAULT_DAEMON_NAME, socket)
}

pub(crate) fn daemon_exec_socket_ready_for(name: &str, socket: &str) -> Result<bool> {
    let mut command = std::process::Command::new("docker");
    command.args(["exec", name, "test", "-S", socket]);
    let output = bounded_command_output(&mut command, DAEMON_PROBE_TIMEOUT)
        .context("failed to probe daemon socket via docker exec")?;
    Ok(output.status.success())
}

fn daemon_http_request_via_exec(
    method: &str,
    socket: &str,
    path: &str,
    body: Option<String>,
) -> Result<String> {
    let headers = body
        .as_ref()
        .filter(|body| !body.is_empty())
        .map_or_else(Vec::new, |_| {
            vec![("Content-Type".to_string(), "application/json".to_string())]
        });
    let response = daemon_raw_http_request_via_exec(
        socket,
        method,
        path,
        &headers,
        body.map(String::into_bytes),
    )?;
    let response = String::from_utf8(response)
        .context("daemon HTTP response via docker exec is not valid UTF-8")?;
    parse_http_response(response)
}

pub(crate) fn daemon_raw_http_request_via_exec(
    socket: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    validate_exec_http_request(method, path, headers)?;
    let mut command = docker_curl_command(socket, method, path, headers, body.is_some());
    let output = bounded_command_output_with_input(&mut command, body, DAEMON_REQUEST_TIMEOUT)
        .context("failed to invoke docker exec curl against outcall-daemon")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = match (stdout.is_empty(), stderr.is_empty()) {
            (true, true) => String::new(),
            (false, true) => stdout,
            (true, false) => stderr,
            (false, false) => format!("{stdout}\n{stderr}"),
        };
        anyhow::bail!(
            "daemon API request via docker exec failed: {}",
            if detail.is_empty() {
                "unknown error"
            } else {
                detail.as_str()
            }
        );
    }
    validate_raw_http_response(&output.stdout)?;
    Ok(output.stdout)
}

fn docker_curl_command(
    socket: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    has_body: bool,
) -> std::process::Command {
    let mut command = std::process::Command::new("docker");
    command.args([
        "exec",
        "-i",
        DEFAULT_DAEMON_NAME,
        "curl",
        "--silent",
        "--show-error",
        "--include",
        "--raw",
        "--http1.1",
        "--path-as-is",
        "--max-time",
        "25",
        "--unix-socket",
        socket,
        "--header",
        "Host: localhost",
        "--header",
        "Expect:",
        "--request",
        method,
    ]);
    if has_body {
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            command.args(["--header", "Content-Type:"]);
        }
        command.args(["--data-binary", "@-"]);
    }
    for (name, value) in headers {
        command.arg("--header").arg(format!("{name}: {value}"));
    }
    command.arg(format!("http://localhost{path}"));
    command
}

fn validate_exec_http_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
) -> Result<()> {
    if method.is_empty() || !method.bytes().all(is_http_token_byte) {
        anyhow::bail!("invalid HTTP method for daemon request");
    }
    if !path.starts_with('/') || path.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        anyhow::bail!("invalid HTTP path for daemon request");
    }
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            anyhow::bail!("invalid HTTP header name for daemon request");
        }
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            anyhow::bail!("invalid HTTP header value for daemon request");
        }
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_raw_http_response(response: &[u8]) -> Result<()> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("daemon HTTP response has no complete headers")?;
    let status_line_end = response[..header_end]
        .windows(2)
        .position(|window| window == b"\r\n")
        .context("daemon HTTP response has no status line")?;
    let status_line = std::str::from_utf8(&response[..status_line_end])
        .context("daemon HTTP response status line is not valid UTF-8")?;
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().and_then(|value| value.parse::<u16>().ok());
    if !version.starts_with("HTTP/1.")
        || !status.is_some_and(|status| (100..=599).contains(&status))
    {
        anyhow::bail!("daemon HTTP response has an invalid status line");
    }
    Ok(())
}

fn serialize_request_body<T: Serialize>(body: &T) -> Result<String> {
    let json = serde_json::to_string(body)?;
    if json.len() > MAX_DAEMON_REQUEST_BODY_BYTES {
        anyhow::bail!("daemon API request body exceeds {MAX_DAEMON_REQUEST_BODY_BYTES} bytes");
    }
    Ok(json)
}

pub(crate) fn read_body(stream: &mut impl Read) -> Result<String> {
    read_body_with_limit(stream, MAX_DAEMON_RESPONSE_BYTES)
}

fn read_body_with_limit(stream: &mut impl Read, limit: usize) -> Result<String> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    stream
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        anyhow::bail!("daemon HTTP response exceeds {limit} bytes");
    }
    let response = String::from_utf8(bytes).context("daemon HTTP response is not valid UTF-8")?;
    parse_http_response(response)
}

fn parse_http_response(response: String) -> Result<String> {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("malformed HTTP response from outcalld")?;
    let status_line = head
        .lines()
        .next()
        .context("daemon HTTP response has no status line")?;
    let mut status_parts = status_line.split_ascii_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .context("daemon HTTP response has no status code")?
        .parse::<u16>()
        .context("daemon HTTP response has an invalid status code")?;
    if !version.starts_with("HTTP/1.") || !(100..=599).contains(&status) {
        anyhow::bail!("daemon HTTP response has an invalid status line");
    }
    if !(200..300).contains(&status) {
        let detail = bounded_error_detail(body);
        anyhow::bail!(
            "daemon API request failed with HTTP {status}: {}",
            if detail.is_empty() {
                "empty response"
            } else {
                &detail
            }
        );
    }
    Ok(body.to_string())
}

fn bounded_error_detail(body: &str) -> String {
    if body.len() <= MAX_DAEMON_ERROR_DETAIL_BYTES {
        return body.trim().to_string();
    }
    let end = body
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_DAEMON_ERROR_DETAIL_BYTES)
        .last()
        .unwrap_or(0);
    format!("{}...", body[..end].trim())
}

fn bounded_command_output(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::Output> {
    match output_with_limits(command, timeout, MAX_DAEMON_RESPONSE_BYTES) {
        Ok(output) => Ok(output),
        Err(ProcessRunError::TimedOut { timeout }) => {
            anyhow::bail!("command timed out after {} seconds", timeout.as_secs())
        }
        Err(ProcessRunError::OutputLimit { stream, limit }) => {
            anyhow::bail!("command {stream} exceeds {limit} bytes")
        }
        Err(ProcessRunError::Io(error)) => Err(error),
    }
}

fn bounded_command_output_with_input(
    command: &mut std::process::Command,
    input: Option<Vec<u8>>,
    timeout: std::time::Duration,
) -> Result<std::process::Output> {
    match output_with_input_limits(command, input, timeout, MAX_DAEMON_RESPONSE_BYTES) {
        Ok(output) => Ok(output),
        Err(ProcessRunError::TimedOut { timeout }) => {
            anyhow::bail!("command timed out after {} seconds", timeout.as_secs())
        }
        Err(ProcessRunError::OutputLimit { stream, limit }) => {
            anyhow::bail!("command {stream} exceeds {limit} bytes")
        }
        Err(ProcessRunError::Io(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_transport_defaults_by_platform_and_honors_explicit_override() {
        assert!(daemon_requests_via_exec_for("macos", None));
        assert!(!daemon_requests_via_exec_for("linux", None));
        assert!(!daemon_requests_via_exec_for("macos", Some("unix")));
        assert!(daemon_requests_via_exec_for("linux", Some("docker")));
        assert!(!daemon_requests_via_exec_for("linux", Some("invalid")));
    }

    #[test]
    fn docker_dashboard_command_preserves_validated_request_fields() {
        let headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let command = docker_curl_command(
            "/tmp/outcall/host.sock",
            "POST",
            "/api/v1/requests/rules/demo/reject?audit=true",
            &headers,
            true,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), "docker");
        assert!(
            args.windows(3)
                .any(|args| args == ["exec", "-i", "outcall-daemon"])
        );
        assert!(args.windows(2).any(|args| args == ["--request", "POST"]));
        assert!(args.windows(2).any(|args| args == ["--data-binary", "@-"]));
        assert!(
            args.windows(2)
                .any(|args| args == ["--header", "Accept: application/json"])
        );
        assert!(
            args.iter().any(|arg| {
                arg == "http://localhost/api/v1/requests/rules/demo/reject?audit=true"
            })
        );
    }

    #[test]
    fn docker_dashboard_request_validation_rejects_protocol_injection() {
        let invalid_path = validate_exec_http_request("GET", "/ui/\r\nInjected: yes", &[])
            .unwrap_err()
            .to_string();
        let invalid_header = validate_exec_http_request(
            "GET",
            "/ui/",
            &[("Accept".to_string(), "text/html\nInjected: yes".to_string())],
        )
        .unwrap_err()
        .to_string();

        assert!(invalid_path.contains("invalid HTTP path"));
        assert!(invalid_header.contains("invalid HTTP header value"));
    }

    #[test]
    fn docker_dashboard_response_requires_valid_http_headers() {
        validate_raw_http_response(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(validate_raw_http_response(b"not HTTP").is_err());
        assert!(validate_raw_http_response(b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n").is_err());
        assert!(validate_raw_http_response(b"HTTP/1.1 nope\r\nContent-Length: 0\r\n\r\n").is_err());
    }

    #[test]
    fn response_reader_extracts_body() {
        let mut response = std::io::Cursor::new(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");

        assert_eq!(read_body_with_limit(&mut response, 1024).unwrap(), "ok");
    }

    #[test]
    fn response_reader_enforces_limit() {
        let mut response = std::io::Cursor::new(b"HTTP/1.0 200 OK\r\n\r\n12345");

        let error = read_body_with_limit(&mut response, 4)
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeds 4 bytes"));
    }

    #[test]
    fn response_reader_rejects_non_success_status() {
        let mut response =
            std::io::Cursor::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\ndenied!");

        let error = read_body_with_limit(&mut response, 1024)
            .unwrap_err()
            .to_string();

        assert!(error.contains("HTTP 403"));
        assert!(error.contains("denied!"));
    }

    #[test]
    fn response_reader_rejects_invalid_status_line() {
        let mut response = std::io::Cursor::new(b"NOT-HTTP\r\n\r\nbody");

        assert!(read_body_with_limit(&mut response, 1024).is_err());
    }

    #[test]
    fn error_detail_is_utf8_boundary_safe_and_bounded() {
        let detail = "x".repeat(MAX_DAEMON_ERROR_DETAIL_BYTES - 1) + "é";

        let bounded = bounded_error_detail(&detail);

        assert!(bounded.len() <= MAX_DAEMON_ERROR_DETAIL_BYTES + 3);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn request_serializer_enforces_exact_body_limit() {
        let accepted = "x".repeat(MAX_DAEMON_REQUEST_BODY_BYTES - 2);
        assert_eq!(
            serialize_request_body(&accepted).unwrap().len(),
            MAX_DAEMON_REQUEST_BODY_BYTES
        );

        let rejected = "x".repeat(MAX_DAEMON_REQUEST_BODY_BYTES - 1);
        assert!(serialize_request_body(&rejected).is_err());
    }
}
