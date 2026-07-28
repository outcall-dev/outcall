//! Project-local host resource registry.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostResourcesConfig {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub tools: Vec<HostToolResource>,
    #[serde(default)]
    pub files: Vec<HostFileResource>,
    #[serde(default)]
    pub auth: HostAuthResource,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostAuthResource {
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostToolResource {
    pub id: String,
    pub path: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub default_args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostFileResource {
    pub id: String,
    pub path: String,
    #[serde(default = "default_file_mode")]
    pub mode: String,
}

fn default_file_mode() -> String {
    "read-only".to_string()
}

pub fn default_config_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".outcall").join("host-resources.yaml")
}

pub fn load_from_path(path: &Path) -> Result<HostResourcesConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn load_for_project(project_dir: &Path) -> Result<HostResourcesConfig> {
    load_from_path(&default_config_path(project_dir))
}

pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

pub fn resolve_tool_path(project_dir: &Path, tool: &HostToolResource) -> Result<PathBuf> {
    let project_dir = std::fs::canonicalize(project_dir)
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let expanded = expand_home(&tool.path);
    let resolved = std::fs::canonicalize(&expanded)
        .with_context(|| format!("failed to canonicalize host tool {}", expanded.display()))?;
    if resolved.starts_with(&project_dir) {
        anyhow::bail!(
            "host tool {} resolves inside the writable project; move it outside {}",
            resolved.display(),
            project_dir.display()
        );
    }
    if !resolved.is_file() {
        anyhow::bail!("host tool {} is not a file", resolved.display());
    }
    Ok(resolved)
}

pub fn find_tool<'a>(config: &'a HostResourcesConfig, id: &str) -> Option<&'a HostToolResource> {
    config.tools.iter().find(|tool| tool.id == id)
}

pub fn find_file<'a>(config: &'a HostResourcesConfig, id: &str) -> Option<&'a HostFileResource> {
    config.files.iter().find(|file| file.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_resources_file() {
        let raw = r#"
version: "1"
tools:
  - id: demo
    path: ~/bin/demo
    default_args: ["--json"]
files:
  - id: notes
    path: ~/notes
    mode: read-only
auth:
  notes:
    - Prefer tokens.
"#;
        let parsed: HostResourcesConfig = serde_yaml::from_str(raw).unwrap();
        assert_eq!(parsed.version, "1");
        assert_eq!(parsed.tools[0].id, "demo");
        assert_eq!(parsed.tools[0].default_args, vec!["--json"]);
        assert_eq!(parsed.files[0].id, "notes");
        assert_eq!(parsed.auth.notes.len(), 1);
    }

    #[test]
    fn rejects_host_tools_inside_the_writable_project() {
        let project = tempfile::tempdir().unwrap();
        let tool_path = project.path().join("agent-controlled-tool");
        std::fs::write(&tool_path, "#!/bin/sh\n").unwrap();
        let tool = HostToolResource {
            id: "unsafe".to_string(),
            path: tool_path.display().to_string(),
            notes: None,
            default_args: Vec::new(),
            env: HashMap::new(),
        };

        let error = resolve_tool_path(project.path(), &tool).unwrap_err();
        assert!(error.to_string().contains("inside the writable project"));
    }
}
