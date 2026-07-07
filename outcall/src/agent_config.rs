//! Agent configuration parser for `.outcall/agent.yaml` (S014-FR-004).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Agent configuration from `.outcall/agent.yaml`
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Docker image to use (default: outcall/agent:latest)
    #[serde(default)]
    pub image: Option<String>,

    /// Agent name override (default: <folder>-1, <folder>-2, ...)
    #[serde(default)]
    pub name: Option<String>,

    /// Additional volume mounts
    #[serde(default)]
    pub volumes: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Port forwarding
    #[serde(default)]
    pub ports: Vec<String>,

    /// Additional Docker capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Resource limits
    #[serde(default)]
    pub resources: Option<ResourceLimits>,

    /// Custom entrypoint
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,

    /// Custom command
    #[serde(default)]
    pub command: Option<Vec<String>>,

    /// Working directory inside container
    #[serde(default = "default_workspace")]
    pub workspace: String,

    /// Network to connect to (default: outcall-default)
    #[serde(default = "default_network")]
    pub network: String,

    /// Whether to run in detached mode
    #[serde(default)]
    pub detach: bool,

    /// Whether to auto-pull the image
    #[serde(default = "default_true")]
    pub auto_pull: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceLimits {
    pub memory: Option<String>,
    pub cpus: Option<String>,
}

fn default_workspace() -> String {
    "/workspace".to_string()
}

fn default_network() -> String {
    outcall_api::DEFAULT_NETWORK_NAME.to_string()
}

fn default_true() -> bool {
    true
}

impl AgentConfig {
    /// Load config from `.outcall/agent.yaml` in the given directory
    pub fn load(dir: &Path) -> Result<Self> {
        let config_path = dir.join(".outcall").join("agent.yaml");

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;

        let config: AgentConfig = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse {}", config_path.display()))?;

        Ok(config)
    }

    /// Save default config template to `.outcall/agent.yaml`
    pub fn save_template(dir: &Path) -> Result<PathBuf> {
        Self::save_template_with_force(dir, true)
    }

    /// Save default config template to `.outcall/agent.yaml`, optionally
    /// refusing to overwrite an existing file.
    pub fn save_template_with_force(dir: &Path, force: bool) -> Result<PathBuf> {
        let outcall_dir = dir.join(".outcall");
        std::fs::create_dir_all(&outcall_dir)
            .with_context(|| format!("failed to create {}", outcall_dir.display()))?;

        let config_path = outcall_dir.join("agent.yaml");
        if config_path.exists() && !force {
            anyhow::bail!(
                "{} already exists; pass --force to overwrite generated config",
                config_path.display()
            );
        }
        let template = r#"# Outcall Agent Configuration
# This file customizes how `outcall agent` boots containers for this project.

# Docker image to use (default: outcall/agent:latest)
# image: my-custom-agent:latest

# Agent name (default: <folder-name>-1, <folder-name>-2, ...)
# name: my-project-1

# Additional volume mounts
# volumes:
#   - /host/path:/container/path

# Environment variables
# env:
#   API_KEY: secret
#   DEBUG: "true"

# Port forwarding
# ports:
#   - 3000:3000
#   - 8080:8080

# Additional Docker capabilities
# capabilities:
#   - NET_ADMIN

# Resource limits
# resources:
#   memory: 4g
#   cpus: "2"

# Custom entrypoint (default: claude)
# entrypoint: ["/bin/bash", "-c"]

# Working directory inside container
# workspace: /workspace

# Network to connect to
# network: outcall-default

# Run in detached mode
# detach: false

# Auto-pull image if not present
# auto_pull: true
"#;

        std::fs::write(&config_path, template)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        Ok(config_path)
    }

    /// Merge CLI flags into config (CLI takes precedence)
    pub fn merge(&mut self, cli: &AgentCliFlags) {
        if let Some(ref image) = cli.image {
            self.image = Some(image.clone());
        }
        if let Some(ref name) = cli.name {
            self.name = Some(name.clone());
        }
        if let Some(ref network) = cli.network {
            self.network = network.clone();
        }
        if let Some(ref workspace) = cli.workspace {
            self.workspace = workspace.clone();
        }
        if cli.detach {
            self.detach = true;
        }
    }

    /// Get the effective image name
    pub fn effective_image(&self) -> String {
        self.image
            .clone()
            .unwrap_or_else(|| "outcall/agent:latest".to_string())
    }

    /// Get the effective name for a given project directory
    pub fn effective_name(&self, project_dir: &Path) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| next_project_container_name(project_dir))
    }
}

fn next_project_container_name(project_dir: &Path) -> String {
    let base = sanitized_project_name(project_dir);

    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return next_project_container_name_from_existing(&base, stdout.lines());
        }
    }

    format!("{base}-1")
}

fn next_project_container_name_from_existing<'a>(
    base: &str,
    existing: impl IntoIterator<Item = &'a str>,
) -> String {
    let prefix = format!("{base}-");
    let mut used = std::collections::BTreeSet::new();
    for line in existing {
        if let Some(rest) = line.strip_prefix(&prefix) {
            if let Ok(index) = rest.parse::<u32>() {
                used.insert(index);
            }
        }
    }

    let mut index = 1u32;
    while used.contains(&index) {
        index += 1;
    }
    format!("{base}-{index}")
}

fn sanitized_project_name(project_dir: &Path) -> String {
    let raw = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project");

    let mut name = String::with_capacity(raw.len());
    let mut last_was_sep = false;
    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            last_was_sep = false;
            ch.to_ascii_lowercase()
        } else if matches!(ch, '-' | '_' | '.') {
            last_was_sep = false;
            ch
        } else if !last_was_sep {
            last_was_sep = true;
            '-'
        } else {
            continue;
        };
        name.push(mapped);
    }

    let trimmed = name.trim_matches(|c| matches!(c, '-' | '_' | '.'));
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.to_string()
    }
}

/// CLI flags that can override config file values
#[derive(Debug, Clone, Default)]
pub struct AgentCliFlags {
    pub image: Option<String>,
    pub name: Option<String>,
    pub network: Option<String>,
    pub workspace: Option<String>,
    pub detach: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_name_prefers_explicit_override() {
        let config = AgentConfig {
            name: Some("custom-name".to_string()),
            ..Default::default()
        };
        assert_eq!(
            config.effective_name(Path::new("/tmp/Example Project")),
            "custom-name"
        );
    }

    #[test]
    fn next_project_container_name_fills_first_gap() {
        let next = next_project_container_name_from_existing(
            "foobar",
            ["foobar-1", "foobar-3", "other-1"].into_iter(),
        );
        assert_eq!(next, "foobar-2");
    }

    #[test]
    fn sanitized_project_name_normalizes_folder_name() {
        assert_eq!(
            sanitized_project_name(Path::new("/tmp/Foo bar.app")),
            "foo-bar.app"
        );
        assert_eq!(sanitized_project_name(Path::new("/tmp/---")), "project");
    }
}
