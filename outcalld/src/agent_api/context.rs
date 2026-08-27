use std::collections::HashMap;

use anyhow::Context;
use outcall_api::{
    ActionType, AgentContext, EvalContext, HttpContext, NetworkContext, PermissionRequest,
    RunContext,
};

/// Derives the agent name from a container name by stripping the trailing `-N`
/// replica suffix. Falls back to the full name if no numeric suffix is found.
pub(crate) fn derive_agent_name(container_name: &str) -> String {
    match container_name.rsplit_once('-') {
        Some((base, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            base.to_string()
        }
        _ => container_name.to_string(),
    }
}

pub(super) fn build_eval_context(
    req: &PermissionRequest,
    container_name: &str,
) -> anyhow::Result<EvalContext> {
    if req.target.trim().is_empty() {
        anyhow::bail!("target must not be empty");
    }
    let agent_name = derive_agent_name(container_name);
    let metadata = req.metadata.clone().unwrap_or_default();
    let metadata_context = || {
        let metadata_object = metadata
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect::<serde_json::Map<_, _>>();
        let mut context = metadata_object
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<HashMap<_, _>>();
        context.insert(
            "action_type".to_string(),
            serde_json::Value::String(action_type_name(&req.action_type).to_string()),
        );
        context.insert(
            "target".to_string(),
            serde_json::Value::String(req.target.clone()),
        );
        context.insert(
            "metadata".to_string(),
            serde_json::Value::Object(metadata_object),
        );
        context
    };

    let mut context = match req.action_type {
        ActionType::NetworkCall => {
            let target = parse_network_target(&req.target, &metadata)?;
            EvalContext {
                network: Some(NetworkContext {
                    hostname: Some(target.hostname),
                    ip: String::new(),
                    port: target.port,
                    protocol: target.protocol,
                }),
                http: target.http,
                run: Some(RunContext {
                    tool: "network_call".to_string(),
                    args: vec![req.target.clone()],
                    context: metadata_context(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        }
        ActionType::ToolExec => {
            let args = parse_command_args(&metadata)?;
            EvalContext {
                run: Some(RunContext {
                    tool: req.target.clone(),
                    flags: command_flags(&args),
                    args,
                    cwd: metadata.get("cwd").cloned().unwrap_or_default(),
                    context: metadata_context(),
                }),
                ..Default::default()
            }
        }
        ActionType::FileAccess => EvalContext {
            run: Some(RunContext {
                tool: "file".to_string(),
                args: vec![req.target.clone()],
                cwd: metadata.get("cwd").cloned().unwrap_or_default(),
                context: metadata_context(),
                ..Default::default()
            }),
            ..Default::default()
        },
        ActionType::ShellExec => {
            let args = parse_command_args(&metadata)?;
            EvalContext {
                run: Some(RunContext {
                    tool: req.target.clone(),
                    flags: command_flags(&args),
                    args,
                    cwd: metadata.get("cwd").cloned().unwrap_or_default(),
                    context: metadata_context(),
                }),
                ..Default::default()
            }
        }
    };

    context.agent = Some(AgentContext { name: agent_name });
    Ok(context)
}

fn action_type_name(action_type: &ActionType) -> &'static str {
    match action_type {
        ActionType::ToolExec => "tool_exec",
        ActionType::NetworkCall => "network_call",
        ActionType::FileAccess => "file_access",
        ActionType::ShellExec => "shell_exec",
    }
}

fn parse_command_args(metadata: &HashMap<String, String>) -> anyhow::Result<Vec<String>> {
    const MAX_ARGS: usize = 1_024;
    const MAX_ARG_BYTES: usize = 32_768;
    const MAX_TOTAL_BYTES: usize = 65_536;

    let args = match metadata.get("args_json") {
        Some(value) => serde_json::from_str::<Vec<String>>(value)
            .context("metadata.args_json must be a JSON string array")?,
        None => metadata.get("args").cloned().into_iter().collect(),
    };
    if args.len() > MAX_ARGS {
        anyhow::bail!("command has more than {MAX_ARGS} arguments");
    }
    let mut total = 0usize;
    for arg in &args {
        if arg.len() > MAX_ARG_BYTES || arg.contains('\0') {
            anyhow::bail!("command argument is invalid or exceeds {MAX_ARG_BYTES} bytes");
        }
        total = total.saturating_add(arg.len());
    }
    if total > MAX_TOTAL_BYTES {
        anyhow::bail!("command arguments exceed {MAX_TOTAL_BYTES} bytes");
    }
    Ok(args)
}

fn command_flags(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| arg.starts_with('-') && arg.as_str() != "-")
        .cloned()
        .collect()
}

struct ParsedNetworkTarget {
    hostname: String,
    port: u16,
    protocol: String,
    http: Option<HttpContext>,
}

fn parse_network_target(
    target: &str,
    metadata: &HashMap<String, String>,
) -> anyhow::Result<ParsedNetworkTarget> {
    let protocol = metadata
        .get("protocol")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    if !matches!(protocol.as_str(), "tcp" | "udp") {
        anyhow::bail!("protocol must be tcp or udp");
    }

    if target.contains("://") {
        let url = url::Url::parse(target).context("invalid network URL")?;
        if !matches!(url.scheme(), "http" | "https") {
            anyhow::bail!("network URL scheme must be http or https");
        }
        if protocol != "tcp" {
            anyhow::bail!("HTTP URLs require the tcp protocol");
        }
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("network URL must not contain credentials");
        }
        let hostname = url
            .host_str()
            .context("network URL must include a hostname")?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .context("network URL has no known default port")?;
        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let method = metadata
            .get("method")
            .map(|value| value.to_ascii_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        if method.is_empty()
            || method.len() > 32
            || !method.bytes().all(|byte| byte.is_ascii_alphabetic())
        {
            anyhow::bail!("HTTP method must contain 1 to 32 ASCII letters");
        }
        return Ok(ParsedNetworkTarget {
            hostname: hostname.clone(),
            port,
            protocol,
            http: Some(HttpContext {
                method,
                path,
                host: hostname,
                ..Default::default()
            }),
        });
    }

    if target.bytes().any(|byte| byte.is_ascii_whitespace()) {
        anyhow::bail!("network target must be an HTTP(S) URL or hostname with optional port");
    }
    let (hostname, port) = if let Ok(address) = target.parse::<std::net::SocketAddr>() {
        (address.ip().to_string(), address.port())
    } else if target.parse::<std::net::IpAddr>().is_ok() {
        (target.to_string(), 443)
    } else if let Some((host, port)) = target.rsplit_once(':') {
        if host.contains(':') {
            anyhow::bail!("IPv6 targets with a port must use bracket notation");
        }
        let port = port.parse::<u16>().context("invalid network target port")?;
        (host.to_string(), port)
    } else {
        (target.to_string(), 443)
    };
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 || hostname.contains('/') {
        anyhow::bail!("invalid network target hostname");
    }
    url::Host::parse(&hostname).context("invalid network target hostname")?;
    if port == 0 {
        anyhow::bail!("network target port must be nonzero");
    }
    Ok(ParsedNetworkTarget {
        hostname,
        port,
        protocol,
        http: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_target_with_port() {
        let target = parse_network_target("example.com:8080", &HashMap::new()).unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 8080);
        assert!(target.http.is_none());
    }

    #[test]
    fn parse_network_url_populates_http_context() {
        let metadata = HashMap::from([("method".to_string(), "post".to_string())]);
        let target =
            parse_network_target("https://Example.com:8443/v1/items?q=1", &metadata).unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 8443);
        let http = target.http.unwrap();
        assert_eq!(http.method, "POST");
        assert_eq!(http.path, "/v1/items?q=1");
        assert_eq!(http.host, "example.com");
    }

    #[test]
    fn malformed_network_targets_are_rejected() {
        for target in [
            "ftp://example.com/file",
            "https://user:secret@example.com/",
            "not a host",
            "example.com:0",
        ] {
            assert!(
                parse_network_target(target, &HashMap::new()).is_err(),
                "target {target:?} should fail"
            );
        }
    }

    #[test]
    fn builds_network_context() {
        let request = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "evil.com:443".to_string(),
            metadata: None,
        };
        let context = build_eval_context(&request, "test-agent-1").unwrap();
        let network = context.network.unwrap();
        assert_eq!(network.hostname, Some("evil.com".to_string()));
        assert_eq!(network.port, 443);
    }

    #[test]
    fn builds_shell_context() {
        let request = PermissionRequest {
            action_type: ActionType::ShellExec,
            target: "git".to_string(),
            metadata: Some(HashMap::from([(
                "args_json".to_string(),
                "[\"push\",\"--force\"]".to_string(),
            )])),
        };
        let context = build_eval_context(&request, "test-agent-1").unwrap();
        let run = context.run.unwrap();
        assert_eq!(run.tool, "git");
        assert_eq!(run.args, vec!["push", "--force"]);
        assert_eq!(run.flags, vec!["--force"]);
        assert_eq!(run.context["action_type"], "shell_exec");
        assert_eq!(run.context["target"], "git");
        assert_eq!(
            run.context["metadata"]["args_json"],
            "[\"push\",\"--force\"]"
        );
    }

    #[test]
    fn derives_agent_name() {
        let request = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "example.com:443".to_string(),
            metadata: None,
        };
        let context = build_eval_context(&request, "my-agent-12").unwrap();
        assert_eq!(context.agent.unwrap().name, "my-agent");

        assert_eq!(derive_agent_name("project-1"), "project");
        assert_eq!(derive_agent_name("project-001"), "project");
        assert_eq!(derive_agent_name("project-final"), "project-final");
        assert_eq!(derive_agent_name("project-"), "project-");
    }

    #[test]
    fn preserves_permission_metadata() {
        let request = PermissionRequest {
            action_type: ActionType::ToolExec,
            target: "browser".to_string(),
            metadata: Some(HashMap::from([
                ("profile".to_string(), "isolated".to_string()),
                ("cwd".to_string(), "/workspace".to_string()),
            ])),
        };

        let context = build_eval_context(&request, "web-1").unwrap();
        let run = context.run.unwrap();
        assert_eq!(run.cwd, "/workspace");
        assert_eq!(run.context["profile"], serde_json::json!("isolated"));
        assert_eq!(run.context["metadata"]["profile"], "isolated");
    }

    #[test]
    fn malformed_exact_arguments_are_rejected() {
        let request = PermissionRequest {
            action_type: ActionType::ToolExec,
            target: "browser".to_string(),
            metadata: Some(HashMap::from([(
                "args_json".to_string(),
                "not-json".to_string(),
            )])),
        };

        assert!(build_eval_context(&request, "web-1").is_err());
    }
}
