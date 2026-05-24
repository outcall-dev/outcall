//! Agent configuration parser for `.outcall/agent.yaml` (S014-FR-004).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Agent configuration from `.outcall/agent.yaml`
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Docker image to use (default: outcall/agent:latest)
    #[serde(default)]
    pub image: Option<String>,

    /// Agent name override (default: <folder>-agent)
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
        let outcall_dir = dir.join(".outcall");
        std::fs::create_dir_all(&outcall_dir)
            .with_context(|| format!("failed to create {}", outcall_dir.display()))?;

        let config_path = outcall_dir.join("agent.yaml");
        let template = r#"# Outcall Agent Configuration
# This file customizes how `outcall agent` boots containers for this project.

# Docker image to use (default: outcall/agent:latest)
# image: my-custom-agent:latest

# Agent name (default: <folder-name>-agent)
# name: my-project-agent

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
        self.name.clone().unwrap_or_else(|| {
            let folder_name = project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            format!("{}-agent", folder_name)
        })
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
