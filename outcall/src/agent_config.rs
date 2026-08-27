//! Agent configuration parser for `.outcall/agent.yaml` (S014-FR-004).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::secure_fs::{
    ensure_secure_subdir, existing_secure_subdir, read_regular_string, write_runtime_file,
};

/// Agent configuration from `.outcall/agent.yaml`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

    /// Port forwarding requests. Managed recipe runtimes reject these because
    /// publishing host ports widens the isolation boundary.
    #[serde(default)]
    pub ports: Vec<String>,

    /// Additional Docker capabilities. Managed recipe runtimes reject these.
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
#[serde(deny_unknown_fields)]
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

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            image: None,
            name: None,
            volumes: Vec::new(),
            env: HashMap::new(),
            ports: Vec::new(),
            capabilities: Vec::new(),
            resources: None,
            entrypoint: None,
            command: None,
            workspace: default_workspace(),
            network: default_network(),
            detach: false,
            auto_pull: default_true(),
        }
    }
}

impl AgentConfig {
    /// Load config from `.outcall/agent.yaml` in the given directory
    pub fn load(dir: &Path) -> Result<Self> {
        let Some(outcall_dir) = existing_secure_subdir(dir, Path::new(".outcall"))? else {
            return Ok(Self::default());
        };
        let config_path = outcall_dir.join("agent.yaml");
        let Some(contents) = read_regular_string(&config_path)? else {
            return Ok(Self::default());
        };

        let config: AgentConfig = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse {}", config_path.display()))?;

        Ok(config)
    }

    /// Validate settings supported by the hardened managed recipe runtime.
    pub fn validate_managed_runtime(&self) -> Result<()> {
        if self
            .image
            .as_deref()
            .is_some_and(|image| image.trim().is_empty())
        {
            anyhow::bail!("agent image must not be empty");
        }
        if self.network.trim().is_empty() {
            anyhow::bail!("agent network must not be empty");
        }
        if let Some(name) = self.name.as_deref()
            && !outcall_api::valid_container_name(name)
        {
            anyhow::bail!(
                "agent name must contain 1-{} ASCII letters, numbers, dots, underscores, or hyphens and start with a letter or number",
                outcall_api::MAX_CONTAINER_NAME_BYTES
            );
        }
        if !self.network.starts_with(outcall_api::NETWORK_PREFIX) {
            anyhow::bail!(
                "agent network {:?} is not managed by Outcall; use an outcall-* network",
                self.network
            );
        }
        let workspace = Path::new(&self.workspace);
        if !workspace.is_absolute()
            || workspace == Path::new("/")
            || workspace.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            anyhow::bail!(
                "agent workspace {:?} must be a clean absolute container path other than /",
                self.workspace
            );
        }
        if !self.ports.is_empty() {
            anyhow::bail!(
                "agent port publishing is not supported in secure managed mode; use an Outcall-mediated host tool instead"
            );
        }
        if !self.capabilities.is_empty() {
            anyhow::bail!(
                "additional Linux capabilities are not supported in secure managed mode; requested: {}",
                self.capabilities.join(", ")
            );
        }
        Ok(())
    }

    /// Save default config template to `.outcall/agent.yaml`
    pub fn save_template(dir: &Path) -> Result<PathBuf> {
        Self::save_template_with_force(dir, true)
    }

    /// Save default config template to `.outcall/agent.yaml`, optionally
    /// refusing to overwrite an existing file.
    pub fn save_template_with_force(dir: &Path, force: bool) -> Result<PathBuf> {
        let outcall_dir = ensure_secure_subdir(dir, Path::new(".outcall"))?;

        let config_path = outcall_dir.join("agent.yaml");
        match std::fs::symlink_metadata(&config_path) {
            Ok(_) if !force => {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite generated config",
                    config_path.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to stat {}", config_path.display()));
            }
        }
        let template = r#"# Outcall Agent Configuration
# This file customizes how `outcall run <recipe>` boots containers for this project.

# Docker image to use (default: the selected recipe's local image)
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

# Published host ports and added Linux capabilities are intentionally unsupported
# in secure managed mode.

# Resource limits
# resources:
#   memory: 4g
#   cpus: "1024" # Docker CPU shares; 1024 is the default weight

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

        write_runtime_file(&config_path, template.as_bytes())?;

        Ok(config_path)
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
            .unwrap_or_else(|| format!("{}-1", sanitized_project_name(project_dir)))
    }
}

fn sanitized_project_name(project_dir: &Path) -> String {
    // Reserve enough space for the largest automatic retry suffix, `-1001`.
    const MAX_BASE_BYTES: usize = outcall_api::MAX_CONTAINER_NAME_BYTES - 5;
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

    name.truncate(name.len().min(MAX_BASE_BYTES));
    let trimmed = name.trim_matches(|c| matches!(c, '-' | '_' | '.'));
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Append a generated suffix without exceeding Docker's container-name limit.
pub fn container_name_with_suffix(base: &str, suffix: &str) -> Result<String> {
    if !outcall_api::valid_container_name(base) {
        anyhow::bail!("cannot extend invalid container name {base:?}");
    }
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        anyhow::bail!("container name suffix is invalid");
    }
    let reserved = suffix
        .len()
        .checked_add(1)
        .context("container name suffix is too long")?;
    let max_base = outcall_api::MAX_CONTAINER_NAME_BYTES
        .checked_sub(reserved)
        .context("container name suffix is too long")?;
    if max_base == 0 {
        anyhow::bail!("container name suffix leaves no room for a base name");
    }

    // Valid Docker names are ASCII, so this byte boundary is also a UTF-8 boundary.
    let base = &base[..base.len().min(max_base)];
    let candidate = format!("{base}-{suffix}");
    if !outcall_api::valid_container_name(&candidate) {
        anyhow::bail!("generated container name is invalid");
    }
    Ok(candidate)
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
    fn rust_and_yaml_defaults_match_runtime_defaults() {
        let rust_default = AgentConfig::default();
        let yaml_default: AgentConfig = serde_yaml::from_str("{}").unwrap();

        assert_eq!(rust_default.workspace, "/workspace");
        assert_eq!(rust_default.network, "outcall-default");
        assert!(rust_default.auto_pull);
        assert_eq!(yaml_default.workspace, rust_default.workspace);
        assert_eq!(yaml_default.network, rust_default.network);
        assert_eq!(yaml_default.auto_pull, rust_default.auto_pull);
    }

    #[test]
    fn managed_runtime_rejects_isolation_weakening_options() {
        let ports = AgentConfig {
            ports: vec!["3000:3000".to_string()],
            ..Default::default()
        };
        assert!(ports.validate_managed_runtime().is_err());

        let capabilities = AgentConfig {
            capabilities: vec!["NET_ADMIN".to_string()],
            ..Default::default()
        };
        assert!(capabilities.validate_managed_runtime().is_err());

        let host_network = AgentConfig {
            network: "host".to_string(),
            ..Default::default()
        };
        assert!(host_network.validate_managed_runtime().is_err());

        let invalid_name = AgentConfig {
            name: Some("/invalid".to_string()),
            ..Default::default()
        };
        assert!(invalid_name.validate_managed_runtime().is_err());
    }

    #[test]
    fn managed_runtime_requires_clean_absolute_workspace() {
        for workspace in ["workspace", "/", "/workspace/../host"] {
            let config = AgentConfig {
                workspace: workspace.to_string(),
                ..Default::default()
            };
            assert!(config.validate_managed_runtime().is_err(), "{workspace}");
        }
        assert!(AgentConfig::default().validate_managed_runtime().is_ok());
    }

    #[test]
    fn load_rejects_unknown_fields() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".outcall")).unwrap();
        std::fs::write(
            temp.path().join(".outcall/agent.yaml"),
            "workspace: /workspace\nauto-pul: true\n",
        )
        .unwrap();

        let error = AgentConfig::load(temp.path()).unwrap_err().to_string();
        assert!(error.contains("failed to parse"));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_agent_config() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".outcall")).unwrap();
        let sentinel = temp.path().join("sentinel.yaml");
        std::fs::write(&sentinel, "workspace: /workspace\n").unwrap();
        symlink(&sentinel, temp.path().join(".outcall/agent.yaml")).unwrap();

        let error = AgentConfig::load(temp.path()).unwrap_err().to_string();

        assert!(error.contains("must be a real file"));
    }

    #[test]
    fn automatic_name_starts_at_one_without_querying_docker() {
        let config = AgentConfig::default();
        assert_eq!(config.effective_name(Path::new("/tmp/Foobar")), "foobar-1");
    }

    #[test]
    fn sanitized_project_name_normalizes_folder_name() {
        assert_eq!(
            sanitized_project_name(Path::new("/tmp/Foo bar.app")),
            "foo-bar.app"
        );
        assert_eq!(sanitized_project_name(Path::new("/tmp/---")), "project");
    }

    #[test]
    fn generated_name_reserves_space_for_all_retry_suffixes() {
        let folder = "a".repeat(200);
        let path = Path::new("/tmp").join(folder);
        let name = AgentConfig::default().effective_name(&path);
        let retry = format!("{}-1001", name.strip_suffix("-1").unwrap());

        assert!(name.len() <= outcall_api::MAX_CONTAINER_NAME_BYTES);
        assert!(retry.len() <= outcall_api::MAX_CONTAINER_NAME_BYTES);
        assert!(outcall_api::valid_container_name(&name));
        assert!(outcall_api::valid_container_name(&retry));
    }

    #[test]
    fn generated_suffix_truncates_long_base_at_ascii_boundary() {
        let base = "a".repeat(outcall_api::MAX_CONTAINER_NAME_BYTES);
        let name = container_name_with_suffix(&base, "smoke-12345").unwrap();

        assert_eq!(name.len(), outcall_api::MAX_CONTAINER_NAME_BYTES);
        assert!(name.ends_with("-smoke-12345"));
        assert!(outcall_api::valid_container_name(&name));
    }
}
