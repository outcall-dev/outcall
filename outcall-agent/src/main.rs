//! `outcall-agent` is the opt-in policy shim mounted in managed containers.
//!
//! `bash`, `exec`, and direct command forms execute only after an allow verdict.
//! `fetch` and `file` forms are permission probes; network isolation itself is
//! enforced by the managed bridge, DNS service, proxy, and firewall policy.

#![forbid(unsafe_code)]

mod api_client;
mod heartbeat;
mod invocation;
mod process;

use std::process::ExitCode;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{debug, info};

use outcall_api::{
    CheckinData, DEFAULT_AGENT_SOCKET, PermissionRequest, UNREACHABLE_EXIT_CODE, Verdict,
};

use api_client::{post_json, request_timeout_from_env, verify_socket_reachable};
use heartbeat::{Heartbeat, HeartbeatExit, receive_exit};
use invocation::parse_invocation;
use process::{CommandError, execute_command};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("outcall-agent: {error:#}");
            ExitCode::from(UNREACHABLE_EXIT_CODE as u8)
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args = std::env::args().collect::<Vec<_>>();
    if print_static_output(&args) {
        return Ok(ExitCode::SUCCESS);
    }
    if args.len() < 2 {
        eprintln!("Usage: outcall <tool> [args...]");
        return Ok(ExitCode::from(1));
    }

    let request_timeout = request_timeout_from_env()?;
    tokio::time::timeout(
        request_timeout,
        verify_socket_reachable(DEFAULT_AGENT_SOCKET),
    )
    .await
    .context("socket reachability check timed out")?
    .context(format!(
        "agent socket not reachable at {DEFAULT_AGENT_SOCKET}"
    ))?;

    let checkin: CheckinData = tokio::time::timeout(
        request_timeout,
        post_json(DEFAULT_AGENT_SOCKET, "/v1/checkin", &Empty {}, None),
    )
    .await
    .context("check-in timed out — outcalld unreachable")?
    .context("check-in rejected")?;
    info!(component = "shim", container_id = %checkin.container_id, "registered with outcalld");

    let invocation = parse_invocation(&args[1..])?;
    let mut heartbeat = Heartbeat::start(DEFAULT_AGENT_SOCKET.to_string(), request_timeout);
    heartbeat.install_sigterm_handler()?;

    let permission = PermissionRequest {
        action_type: invocation.action_type,
        target: invocation.target.clone(),
        metadata: (!invocation.metadata.is_empty()).then_some(invocation.metadata),
    };
    let verdict_future = tokio::time::timeout(
        request_timeout,
        post_json::<_, Verdict>(
            DEFAULT_AGENT_SOCKET,
            "/v1/permissions/check",
            &permission,
            Some(&checkin.session_token),
        ),
    );
    tokio::pin!(verdict_future);
    let verdict_result = tokio::select! {
        result = &mut verdict_future => result,
        completion = heartbeat.completion() => {
            match receive_exit(completion)? {
                HeartbeatExit::Stopped => {
                    return Ok(ExitCode::SUCCESS);
                }
                HeartbeatExit::Unreachable(error) => return Err(error),
            }
        }
    };
    let verdict = parse_verdict_result(verdict_result)?;

    debug!(
        component = "shim",
        allowed = verdict.allowed,
        matched_rule = ?verdict.matched_rule,
        reason = ?verdict.reason,
        "verdict received"
    );
    if !verdict.allowed {
        let reason = verdict.reason.as_deref().unwrap_or("blocked by policy");
        eprintln!("outcall-agent: action blocked — {reason}");
        heartbeat.stop().await?;
        return Ok(ExitCode::from(1));
    }

    info!(
        component = "shim",
        target = %invocation.target,
        matched_rule = ?verdict.matched_rule,
        "action allowed"
    );
    let Some(command) = invocation.command else {
        heartbeat.stop().await?;
        return Ok(ExitCode::SUCCESS);
    };

    let (exit_code, heartbeat_consumed) =
        match execute_command(command, heartbeat.completion()).await {
            Ok(result) => result,
            Err(CommandError::Unreachable(error)) => return Err(error),
            Err(CommandError::Action(error)) => {
                eprintln!("outcall-agent: {error:#}");
                heartbeat.stop().await?;
                return Ok(ExitCode::from(1));
            }
        };
    if !heartbeat_consumed {
        heartbeat.stop().await?;
    }
    Ok(exit_code)
}

fn parse_verdict_result(
    result: std::result::Result<Result<Verdict>, tokio::time::error::Elapsed>,
) -> Result<Verdict> {
    match result {
        Err(_) => anyhow::bail!("permission check timed out — outcalld unreachable"),
        Ok(Err(error)) => Err(error.context("permission check failed — outcalld unreachable")),
        Ok(Ok(verdict)) => Ok(verdict),
    }
}

fn print_static_output(args: &[String]) -> bool {
    if args
        .iter()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
    {
        println!("outcall-agent {}", env!("CARGO_PKG_VERSION"));
        return true;
    }
    if args
        .iter()
        .skip(1)
        .any(|arg| arg == "--help" || arg == "-h")
    {
        println!(
            "outcall-agent {}\n\nUsage:\n  outcall bash <program> [args...]\n  outcall exec <program> [args...]\n  outcall <program> [args...]\n  outcall fetch <url> [method]\n  outcall file <path>",
            env!("CARGO_PKG_VERSION")
        );
        return true;
    }
    false
}

#[derive(Serialize)]
struct Empty {}
