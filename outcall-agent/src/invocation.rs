use std::collections::HashMap;

use anyhow::{Context, Result};
use outcall_api::ActionType;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) action_type: ActionType,
    pub(crate) target: String,
    pub(crate) metadata: HashMap<String, String>,
    pub(crate) command: Option<Vec<String>>,
}

pub(crate) fn parse_invocation(args: &[String]) -> Result<Invocation> {
    let Some((verb, rest)) = args.split_first() else {
        anyhow::bail!("an action is required");
    };

    match verb.as_str() {
        "bash" | "sh" | "shell" => command_invocation(ActionType::ShellExec, rest),
        "exec" => command_invocation(ActionType::ToolExec, rest),
        "fetch" | "http" | "https" | "curl" | "wget" => {
            let target = rest.first().cloned().unwrap_or_default();
            let method = rest.get(1).cloned().unwrap_or_else(|| "GET".to_string());
            Ok(Invocation {
                action_type: ActionType::NetworkCall,
                target,
                metadata: HashMap::from([("method".to_string(), method)]),
                command: None,
            })
        }
        "file" | "read" | "write" => {
            let target = rest.first().cloned().unwrap_or_default();
            let mode = if verb == "write" { "write" } else { "read" };
            Ok(Invocation {
                action_type: ActionType::FileAccess,
                target,
                metadata: HashMap::from([("mode".to_string(), mode.to_string())]),
                command: None,
            })
        }
        tool => {
            let mut command = vec![tool.to_string()];
            command.extend_from_slice(rest);
            Ok(Invocation {
                action_type: ActionType::ToolExec,
                target: tool.to_string(),
                metadata: argument_metadata(rest)?,
                command: Some(command),
            })
        }
    }
}

fn command_invocation(action_type: ActionType, command: &[String]) -> Result<Invocation> {
    let target = command.first().cloned().unwrap_or_default();
    let args = command.get(1..).unwrap_or_default();
    Ok(Invocation {
        action_type,
        target,
        metadata: argument_metadata(args)?,
        command: (!command.is_empty()).then(|| command.to_vec()),
    })
}

fn argument_metadata(args: &[String]) -> Result<HashMap<String, String>> {
    if args.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(HashMap::from([
        ("args".to_string(), args.join(" ")),
        (
            "args_json".to_string(),
            serde_json::to_string(args).context("failed to encode command arguments")?,
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_shell_invocation_with_exact_arguments() {
        let invocation = parse_invocation(&args(&["bash", "ls", "/tmp"])).unwrap();
        assert_eq!(invocation.action_type, ActionType::ShellExec);
        assert_eq!(invocation.target, "ls");
        assert_eq!(
            invocation.metadata.get("args_json").map(String::as_str),
            Some("[\"/tmp\"]")
        );
        assert_eq!(invocation.command, Some(args(&["ls", "/tmp"])));
    }

    #[test]
    fn parses_explicit_and_implicit_tool_execution() {
        let explicit = parse_invocation(&args(&["exec", "git", "status"])).unwrap();
        let implicit = parse_invocation(&args(&["git", "status"])).unwrap();

        assert_eq!(explicit.action_type, ActionType::ToolExec);
        assert_eq!(explicit.target, "git");
        assert_eq!(explicit.command, Some(args(&["git", "status"])));
        assert_eq!(implicit, explicit);
    }

    #[test]
    fn parses_network_permission_probe() {
        let invocation = parse_invocation(&args(&["fetch", "https://api.example.com"])).unwrap();
        assert_eq!(invocation.action_type, ActionType::NetworkCall);
        assert_eq!(invocation.target, "https://api.example.com");
        assert_eq!(
            invocation.metadata.get("method").map(String::as_str),
            Some("GET")
        );
        assert!(invocation.command.is_none());
    }

    #[test]
    fn parses_file_permission_probe() {
        let invocation = parse_invocation(&args(&["file", "/workspace/config.yaml"])).unwrap();
        assert_eq!(invocation.action_type, ActionType::FileAccess);
        assert_eq!(invocation.target, "/workspace/config.yaml");
        assert_eq!(
            invocation.metadata.get("mode").map(String::as_str),
            Some("read")
        );
        assert!(invocation.command.is_none());
    }

    #[test]
    fn rejects_empty_invocation() {
        assert!(parse_invocation(&[]).is_err());
    }
}
