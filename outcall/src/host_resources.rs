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
}
