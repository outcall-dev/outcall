//! `outcall-agent` — the agent shim for Outcall.
//!
//! This binary is bind-mounted read-only into agent containers at
//! `/usr/local/bin/outcall`. It gates every tool invocation and network
//! request through `outcalld` via the agent Unix socket.
//!
//! Usage:
//!   outcall bash <cmd> [args...]   — shell command (shell_exec)
//!   outcall exec <tool> [args...]  — named tool (tool_exec)
//!   outcall fetch <url>            — outbound HTTP/network (network_call)
//!   outcall file <path>            — file access (file_access)
//!
//! Exit codes:
//!   0  — action succeeded
//!   1  — action failed or was blocked by policy
//!   5  — outcalld unreachable (fail-closed)

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tracing::{debug, error, info};

use outcall_api::{
    ActionType, ApiResponse, CheckinData, PermissionRequest, Verdict,
    DEFAULT_AGENT_SOCKET, DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_REQUEST_TIMEOUT_SECS,
    UNREACHABLE_EXIT_CODE,
};

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    // FR-016: all diagnostic output goes to stderr
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(exit) => exit,
        Err(e) => {
            // FR-004/012: connectivity failure → exit 5 (fail-closed)
            eprintln!("outcall-agent: {e:#}");
            ExitCode::from(UNREACHABLE_EXIT_CODE as u8)
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = DEFAULT_AGENT_SOCKET;

    // FR-014: timeout configurable via OUTCALL_TIMEOUT_SECS
    let timeout_secs = std::env::var("OUTCALL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);
    let req_timeout = Duration::from_secs(timeout_secs);

    // FR-002: verify socket is reachable (connection attempt, not just path check)
    tokio::time::timeout(req_timeout, verify_socket_reachable(socket_path))
        .await
        .context("socket reachability check timed out")?
        .context(format!("agent socket not reachable at {socket_path}"))?;

    // FR-003: check in with outcalld (empty body — identity derived from SO_PEERCRED)
    let checkin: CheckinData =
        tokio::time::timeout(req_timeout, post_json(socket_path, "/v1/checkin", &Empty {}, None))
            .await
            .context("check-in timed out — outcalld unreachable")?
            .context("check-in rejected")?;

    let session_token = checkin.session_token.clone();
    info!(component = "shim", container_id = %checkin.container_id, "registered with outcalld");

    // Parse CLI args
    if args.len() < 2 {
        eprintln!("Usage: outcall <tool> [args...]");
        return Ok(ExitCode::from(1));
    }
    let (action_type, target, metadata, exec_args) = parse_invocation(&args[1..]);

    // FR-019: start background heartbeat loop
    let (stop_tx, stop_rx) = watch::channel(false);
    let hb_socket = socket_path.to_string();
    let hb_handle = tokio::spawn(heartbeat_loop(hb_socket, req_timeout, stop_rx));

    // FR-007/010: send permission check with session token
    let perm_req = PermissionRequest {
        action_type,
        target: target.clone(),
        metadata: if metadata.is_empty() { None } else { Some(metadata) },
    };

    let verdict_result = tokio::time::timeout(
        req_timeout,
        post_json::<_, Verdict>(
            socket_path,
            "/v1/permissions/check",
            &perm_req,
            Some(&session_token),
        ),
    )
    .await;

    // Stop heartbeat regardless of outcome
    let _ = stop_tx.send(true);
    let _ = hb_handle.await;

    let verdict: Verdict = match verdict_result {
        Err(_elapsed) => {
            // FR-013: timeout → unreachable → exit 5
            return Err(anyhow::anyhow!(
                "permission check timed out — outcalld unreachable"
            ));
        }
        Ok(Err(e)) => {
            // FR-011/012: error response or connectivity failure → fail-closed
            return Err(e.context("permission check failed — outcalld unreachable"));
        }
        Ok(Ok(v)) => v,
    };

    // FR-022: log full verdict (matched_rule + reason)
    debug!(
        component = "shim",
        allowed = verdict.allowed,
        matched_rule = ?verdict.matched_rule,
        reason = ?verdict.reason,
        "verdict received"
    );

    // FR-009: denied → return error to agent, do NOT execute
    if !verdict.allowed {
        let reason = verdict.reason.as_deref().unwrap_or("blocked by policy");
        eprintln!("outcall-agent: action blocked — {reason}");
        if let Some(rule) = &verdict.matched_rule {
            debug!(component = "shim", matched_rule = %rule, "block rule matched");
        }
        // FR-015.b: exit 1 for policy-denied action
        return Ok(ExitCode::from(1));
    }

    info!(
        component = "shim",
        target = %target,
        matched_rule = ?verdict.matched_rule,
        "action allowed — executing"
    );

    // FR-008: execute the action
    if let Some(cmd) = exec_args {
        execute_command(cmd).await
    } else {
        // Non-executable actions (tool_exec, network_call, file_access):
        // permission granted — caller is responsible for the actual operation
        Ok(ExitCode::SUCCESS)
    }
}

// ── Heartbeat ──────────────────────────────────────────────────────────────

/// Background task that periodically verifies outcalld is reachable.
/// If a ping fails, exits the process with code 5 (fail-closed).
async fn heartbeat_loop(
    socket_path: String,
    req_timeout: Duration,
    mut stop_rx: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let reachable = tokio::time::timeout(
                    req_timeout,
                    verify_socket_reachable(&socket_path),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

                if !reachable {
                    error!(component = "shim", "outcalld unreachable — exiting (fail closed)");
                    std::process::exit(UNREACHABLE_EXIT_CODE);
                }
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

// ── Socket helpers ─────────────────────────────────────────────────────────

/// FR-002: Verify the socket exists AND is accepting connections.
async fn verify_socket_reachable(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        anyhow::bail!("agent socket not found at {path}");
    }
    // Attempt an actual connection to confirm the socket is serving
    UnixStream::connect(path)
        .await
        .with_context(|| format!("cannot connect to agent socket at {path}"))?;
    Ok(())
}

// ── HTTP client over Unix domain socket ───────────────────────────────────

/// Marker for serializing an empty JSON object `{}`.
#[derive(serde::Serialize)]
struct Empty {}

/// POST JSON to the agent API over the Unix domain socket.
/// Returns the deserialized `data` field on success, or an error.
async fn post_json<T, R>(
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
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

    // Drive the connection in the background
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body_bytes = serde_json::to_vec(body).context("failed to serialize request body")?;

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len().to_string());

    if let Some(token) = auth {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    let req = builder
        .body(Full::new(Bytes::from(body_bytes)))
        .context("failed to build HTTP request")?;

    let response = sender
        .send_request(req)
        .await
        .context("HTTP request to outcalld failed")?;

    let status = response.status();
    let raw = response
        .collect()
        .await
        .context("failed to read response body")?
        .to_bytes();

    // FR-011: non-well-formed response treated as block
    let api_resp: ApiResponse<R> = serde_json::from_slice(&raw)
        .with_context(|| format!("malformed response from outcalld (HTTP {status})"))?;

    if !api_resp.success {
        anyhow::bail!(
            "{}",
            api_resp.error.unwrap_or_else(|| format!("HTTP {status}"))
        );
    }

    api_resp
        .data
        .ok_or_else(|| anyhow::anyhow!("outcalld returned success with no data"))
}

// ── CLI argument parsing ───────────────────────────────────────────────────

/// Parse CLI arguments into (action_type, target, metadata, optional_exec_args).
///
/// Accepted forms:
///   outcall bash <cmd> [args...]   → shell_exec
///   outcall sh   <cmd> [args...]   → shell_exec
///   outcall exec <tool> [args...]  → tool_exec
///   outcall fetch <url>            → network_call
///   outcall http  <url>            → network_call
///   outcall file  <path>           → file_access
///   outcall read  <path>           → file_access
///   outcall <other> [args...]      → tool_exec
fn parse_invocation(
    args: &[String],
) -> (ActionType, String, HashMap<String, String>, Option<Vec<String>>) {
    debug_assert!(!args.is_empty(), "parse_invocation called with empty args");

    let verb = args[0].as_str();
    let rest: Vec<String> = args[1..].to_vec();

    match verb {
        "bash" | "sh" | "shell" => {
            // shell_exec: target = command to run, args in metadata
            let target = rest.first().cloned().unwrap_or_default();
            let mut meta = HashMap::new();
            if rest.len() > 1 {
                meta.insert("args".to_string(), rest[1..].join(" "));
            }
            let exec = if target.is_empty() {
                None
            } else {
                let mut cmd = vec![target.clone()];
                cmd.extend_from_slice(&rest[1..]);
                Some(cmd)
            };
            (ActionType::ShellExec, target, meta, exec)
        }
        "fetch" | "http" | "https" | "curl" | "wget" => {
            let target = rest.first().cloned().unwrap_or_default();
            let mut meta = HashMap::new();
            // Default to GET; callers may pass method as second arg
            let method = rest.get(1).cloned().unwrap_or_else(|| "GET".to_string());
            meta.insert("method".to_string(), method);
            (ActionType::NetworkCall, target, meta, None)
        }
        "file" | "read" | "write" => {
            let target = rest.first().cloned().unwrap_or_default();
            let mut meta = HashMap::new();
            if verb == "write" {
                meta.insert("mode".to_string(), "write".to_string());
            } else {
                meta.insert("mode".to_string(), "read".to_string());
            }
            (ActionType::FileAccess, target, meta, None)
        }
        // Generic tool — everything else maps to tool_exec
        tool => {
            let mut meta = HashMap::new();
            if !rest.is_empty() {
                meta.insert("args".to_string(), rest.join(" "));
            }
            (ActionType::ToolExec, tool.to_string(), meta, None)
        }
    }
}

// ── Command execution ──────────────────────────────────────────────────────

/// Execute a shell command after receiving an ALLOW verdict.
async fn execute_command(args: Vec<String>) -> Result<ExitCode> {
    if args.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    let status = tokio::process::Command::new(&args[0])
        .args(&args[1..])
        .status()
        .await
        .with_context(|| format!("failed to execute '{}'", args[0]))?;

    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        // FR-015.b: exit 1 for action failure (not a policy issue)
        Ok(ExitCode::from(1))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_invocation() {
        let args = ["bash", "ls", "/tmp"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let (action, target, meta, exec) = parse_invocation(&args);
        assert_eq!(action, ActionType::ShellExec);
        assert_eq!(target, "ls");
        assert_eq!(meta.get("args").map(String::as_str), Some("/tmp"));
        assert_eq!(exec, Some(vec!["ls".to_string(), "/tmp".to_string()]));
    }

    #[test]
    fn test_parse_fetch_invocation() {
        let args = ["fetch", "https://api.example.com"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let (action, target, meta, exec) = parse_invocation(&args);
        assert_eq!(action, ActionType::NetworkCall);
        assert_eq!(target, "https://api.example.com");
        assert_eq!(meta.get("method").map(String::as_str), Some("GET"));
        assert!(exec.is_none());
    }

    #[test]
    fn test_parse_file_read() {
        let args = ["file", "/workspace/config.yaml"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let (action, target, meta, exec) = parse_invocation(&args);
        assert_eq!(action, ActionType::FileAccess);
        assert_eq!(target, "/workspace/config.yaml");
        assert_eq!(meta.get("mode").map(String::as_str), Some("read"));
        assert!(exec.is_none());
    }

    #[test]
    fn test_parse_generic_tool() {
        let args = ["read_file", "--path", "/tmp/x"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let (action, target, _meta, exec) = parse_invocation(&args);
        assert_eq!(action, ActionType::ToolExec);
        assert_eq!(target, "read_file");
        assert!(exec.is_none());
    }
}
