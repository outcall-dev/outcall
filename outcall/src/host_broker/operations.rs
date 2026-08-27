use std::path::{Path, PathBuf};

use anyhow::Context;
use outcall_api::{EvalContext, EvaluateRequest};

use super::protocol::{
    BrokerError, BrokerFileReadRequest, BrokerFileReadResult, BrokerResult, BrokerToolExecRequest,
    BrokerToolExecResult,
};
use crate::daemon_client::{Response, http_post_json};
use crate::process_control::{ProcessRunError, output_with_limits};

const HOST_TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_HOST_TOOL_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_HOST_FILE_BYTES: usize = 1024 * 1024;

pub(crate) fn broker_exec_tool(
    daemon_socket: &str,
    config: &outcall::host_resources::HostResourcesConfig,
    req: BrokerToolExecRequest,
) -> BrokerResult<BrokerToolExecResult> {
    let tool = outcall::host_resources::find_tool(config, &req.id)
        .ok_or_else(|| BrokerError::Forbidden(format!("host tool not declared: {}", req.id)))?;
    let project_dir = std::env::current_dir()
        .context("failed to get current project directory")
        .map_err(BrokerError::internal)?;
    let cwd = resolve_tool_cwd(&project_dir, req.cwd.as_deref())?;
    evaluate_broker_rule(
        daemon_socket,
        EvalContext {
            run: Some(outcall_api::RunContext {
                tool: format!("host.tool.{}", req.id),
                args: req.args.clone(),
                cwd: cwd.display().to_string(),
                ..Default::default()
            }),
            ..Default::default()
        },
    )?;

    let path = outcall::host_resources::resolve_tool_path(&project_dir, tool)
        .map_err(BrokerError::internal)?;
    let mut command = std::process::Command::new(&path);
    command.args(&tool.default_args).args(&req.args);
    command.current_dir(cwd).env_clear();
    for key in ["PATH", "LANG", "LC_ALL", "TMPDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in &tool.forward_env {
        let value = std::env::var_os(key)
            .with_context(|| format!("forwarded host environment variable {key} is not set"))
            .map_err(BrokerError::internal)?;
        command.env(key, value);
    }
    for (key, value) in &tool.env {
        command.env(key, value);
    }
    let output =
        match output_with_limits(&mut command, HOST_TOOL_TIMEOUT, MAX_HOST_TOOL_OUTPUT_BYTES) {
            Ok(output) => output,
            Err(ProcessRunError::TimedOut { timeout }) => {
                return Err(BrokerError::Timeout(format!(
                    "host tool timed out after {} seconds",
                    timeout.as_secs()
                )));
            }
            Err(ProcessRunError::OutputLimit { stream, limit }) => {
                return Err(BrokerError::TooLarge(format!(
                    "host tool {stream} exceeds {limit} bytes"
                )));
            }
            Err(ProcessRunError::Io(error)) => {
                return Err(error)
                    .with_context(|| format!("failed to execute host tool {}", path.display()))
                    .map_err(BrokerError::internal);
            }
        };
    Ok(BrokerToolExecResult {
        status: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub(super) fn resolve_tool_cwd(
    project_dir: &Path,
    requested: Option<&str>,
) -> BrokerResult<PathBuf> {
    let project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))
        .map_err(BrokerError::internal)?;
    let candidate = match requested.filter(|cwd| !cwd.is_empty()) {
        None => project_dir.clone(),
        Some(cwd) => {
            let cwd = Path::new(cwd);
            if cwd.is_absolute() {
                let relative = cwd.strip_prefix("/workspace").map_err(|_| {
                    BrokerError::BadRequest(
                        "host tool cwd must be /workspace, a path below /workspace, or a relative project path"
                            .to_string(),
                    )
                })?;
                project_dir.join(relative)
            } else {
                project_dir.join(cwd)
            }
        }
    };
    let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BrokerError::BadRequest("host tool cwd does not exist".to_string())
        } else {
            BrokerError::internal(anyhow::Error::new(error).context(format!(
                "failed to canonicalize host tool cwd {}",
                candidate.display()
            )))
        }
    })?;
    if !resolved.starts_with(&project_dir) || !resolved.is_dir() {
        return Err(BrokerError::BadRequest(
            "host tool cwd must resolve to a directory inside the project".to_string(),
        ));
    }
    Ok(resolved)
}

pub(super) fn broker_read_file(
    daemon_socket: &str,
    config: &outcall::host_resources::HostResourcesConfig,
    req: BrokerFileReadRequest,
) -> BrokerResult<BrokerFileReadResult> {
    let file = outcall::host_resources::find_file(config, &req.id).ok_or_else(|| {
        BrokerError::Forbidden(format!("host file root not declared: {}", req.id))
    })?;
    let root = outcall::host_resources::expand_home(&file.path);
    let project_dir = std::env::current_dir()
        .context("failed to get current project directory")
        .map_err(BrokerError::internal)?;
    let canonical_root = external_host_file_root(&project_dir, &root)?;
    let relative_path = req.relative_path.as_deref();
    let logical_path = relative_path
        .map(|relative| format!("{}/{relative}", req.id))
        .unwrap_or_else(|| req.id.clone());
    let resolved = resolve_host_file_path(&canonical_root, relative_path)?;
    evaluate_broker_rule(
        daemon_socket,
        EvalContext {
            run: Some(outcall_api::RunContext {
                tool: format!("host.file.{}", req.id),
                args: vec![logical_path.clone()],
                context: std::collections::HashMap::from([
                    ("resource_id".to_string(), serde_json::json!(req.id)),
                    (
                        "relative_path".to_string(),
                        serde_json::json!(relative_path.unwrap_or_default()),
                    ),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        },
    )?;

    let bytes = read_file_bounded(&resolved, MAX_HOST_FILE_BYTES)?;
    let contents = String::from_utf8(bytes)
        .map_err(|_| BrokerError::Unprocessable("host file is not valid UTF-8".to_string()))?;
    Ok(BrokerFileReadResult {
        path: logical_path,
        contents,
    })
}

pub(super) fn external_host_file_root(project_dir: &Path, root: &Path) -> BrokerResult<PathBuf> {
    let project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))
        .map_err(BrokerError::internal)?;
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize {}", root.display()))
        .map_err(BrokerError::internal)?;
    if root.starts_with(&project_dir) {
        return Err(BrokerError::Forbidden(
            "host file root resolves inside the writable project; access it directly through /workspace"
                .to_string(),
        ));
    }
    Ok(root)
}

pub(super) fn read_file_bounded(path: &Path, limit: usize) -> BrokerResult<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BrokerError::NotFound("host file does not exist".to_string())
        } else {
            BrokerError::internal(anyhow::Error::new(error).context("failed to inspect host file"))
        }
    })?;
    if metadata.len() > limit as u64 {
        return Err(BrokerError::TooLarge(format!(
            "host file exceeds {limit} bytes"
        )));
    }
    outcall::secure_fs::read_regular_file_bounded(path, limit)
        .map_err(BrokerError::internal)?
        .ok_or_else(|| BrokerError::NotFound("host file does not exist".to_string()))
}

pub(crate) fn resolve_host_file_path(root: &Path, relative: Option<&str>) -> BrokerResult<PathBuf> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize {}", root.display()))
        .map_err(BrokerError::internal)?;
    let candidate = if root.is_dir() {
        let relative = relative.ok_or_else(|| {
            BrokerError::BadRequest("relative_path is required for directory resources".to_string())
        })?;
        root.join(relative)
    } else if relative.is_some() {
        return Err(BrokerError::BadRequest(
            "relative_path is not allowed for file resources".to_string(),
        ));
    } else {
        root.clone()
    };
    let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BrokerError::NotFound("host file does not exist".to_string())
        } else {
            BrokerError::internal(
                anyhow::Error::new(error)
                    .context(format!("failed to canonicalize {}", candidate.display())),
            )
        }
    })?;
    if root.is_dir() && !resolved.starts_with(&root) {
        return Err(BrokerError::Forbidden(
            "resolved path escapes declared host file root".to_string(),
        ));
    }
    Ok(resolved)
}

fn evaluate_broker_rule(daemon_socket: &str, context: EvalContext) -> BrokerResult<()> {
    let req = EvaluateRequest { context };
    let body = http_post_json(daemon_socket, "/api/v1/rule/evaluate", &req)
        .map_err(BrokerError::internal)?;
    let resp: Response = serde_json::from_str(&body)
        .context("failed to parse response")
        .map_err(BrokerError::internal)?;
    if !resp.success {
        return Err(BrokerError::internal(anyhow::anyhow!(
            "daemon rule evaluation failed: {}",
            resp.error.unwrap_or_else(|| "unknown error".into())
        )));
    }
    let data = resp
        .data
        .context("daemon rule evaluation returned no data")
        .map_err(BrokerError::internal)?;
    let result: outcall_api::EvaluateResult =
        serde_json::from_value(data).map_err(|error| BrokerError::internal(error.into()))?;
    if result.decision == outcall_api::Decision::Block {
        return Err(BrokerError::Forbidden(format!(
            "blocked by rules{}",
            result
                .matched_rule
                .as_deref()
                .map(|id| format!(" ({id})"))
                .unwrap_or_default()
        )));
    }
    Ok(())
}
