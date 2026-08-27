//! Project-local host resource registry.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::secure_fs::{existing_secure_subdir, read_regular_string_bounded};

const MAX_HOST_RESOURCE_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_RESOURCES_PER_KIND: usize = 256;
const MAX_RESOURCE_ID_BYTES: usize = 128;
const MAX_RESOURCE_PATH_BYTES: usize = 4_096;
const MAX_TOOL_ARGS: usize = 256;
const MAX_TOOL_ARG_BYTES: usize = 32_768;
const MAX_TOOL_ARG_TOTAL_BYTES: usize = 65_536;
const MAX_TOOL_ENV_KEYS: usize = 128;
const MAX_TOOL_ENV_VALUE_BYTES: usize = 65_536;
const MAX_AUTH_NOTES: usize = 256;
const MAX_NOTE_BYTES: usize = 4_096;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct HostAuthResource {
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostToolResource {
    pub id: String,
    pub path: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub default_args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub forward_env: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let raw = read_regular_string_bounded(path, MAX_HOST_RESOURCE_CONFIG_BYTES)?
        .with_context(|| format!("host resource registry {} does not exist", path.display()))?;
    parse_config(path, &raw)
}

fn parse_config(path: &Path, raw: &str) -> Result<HostResourcesConfig> {
    let config: HostResourcesConfig =
        serde_yaml::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))?;
    validate(&config)
        .with_context(|| format!("invalid host resource registry {}", path.display()))?;
    Ok(config)
}

pub fn load_for_project(project_dir: &Path) -> Result<HostResourcesConfig> {
    load_optional_for_project(project_dir)?
        .with_context(|| {
            format!(
                "host resource registry {} does not exist",
                default_config_path(project_dir).display()
            )
        })
        .map(|(_, config)| config)
}

pub fn load_optional_for_project(
    project_dir: &Path,
) -> Result<Option<(PathBuf, HostResourcesConfig)>> {
    let Some(outcall_dir) = existing_secure_subdir(project_dir, Path::new(".outcall"))? else {
        return Ok(None);
    };
    let path = outcall_dir.join("host-resources.yaml");
    let Some(raw) = read_regular_string_bounded(&path, MAX_HOST_RESOURCE_CONFIG_BYTES)? else {
        return Ok(None);
    };
    Ok(Some((path.clone(), parse_config(&path, &raw)?)))
}

pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

pub fn validate_resource_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_RESOURCE_ID_BYTES
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        anyhow::bail!(
            "host resource IDs must contain only ASCII letters, numbers, dots, underscores, or hyphens"
        );
    }
    Ok(())
}

fn validate(config: &HostResourcesConfig) -> Result<()> {
    if config.version != "1" {
        anyhow::bail!(
            "unsupported host resource registry version {:?}; expected \"1\"",
            config.version
        );
    }
    if config.tools.len() > MAX_RESOURCES_PER_KIND || config.files.len() > MAX_RESOURCES_PER_KIND {
        anyhow::bail!(
            "host resource registry supports at most {MAX_RESOURCES_PER_KIND} tools and files"
        );
    }
    if config.auth.notes.len() > MAX_AUTH_NOTES
        || config
            .auth
            .notes
            .iter()
            .any(|note| note.len() > MAX_NOTE_BYTES)
    {
        anyhow::bail!("host resource authentication notes exceed configured limits");
    }

    let mut tool_ids = HashSet::new();
    for tool in &config.tools {
        validate_resource_id(&tool.id)?;
        validate_resource_path(&tool.path)?;
        if !tool_ids.insert(tool.id.as_str()) {
            anyhow::bail!("duplicate host tool ID {:?}", tool.id);
        }
        if tool
            .notes
            .as_ref()
            .is_some_and(|note| note.len() > MAX_NOTE_BYTES)
        {
            anyhow::bail!(
                "notes for host tool {:?} exceed {MAX_NOTE_BYTES} bytes",
                tool.id
            );
        }
        if tool.default_args.len() > MAX_TOOL_ARGS
            || tool
                .default_args
                .iter()
                .any(|arg| arg.len() > MAX_TOOL_ARG_BYTES || arg.as_bytes().contains(&b'\0'))
            || tool.default_args.iter().map(String::len).sum::<usize>() > MAX_TOOL_ARG_TOTAL_BYTES
        {
            anyhow::bail!(
                "default arguments for host tool {:?} exceed configured limits",
                tool.id
            );
        }
        if tool.env.len() > MAX_TOOL_ENV_KEYS || tool.forward_env.len() > MAX_TOOL_ENV_KEYS {
            anyhow::bail!(
                "environment for host tool {:?} exceeds configured limits",
                tool.id
            );
        }
        for key in tool.env.keys().chain(&tool.forward_env) {
            validate_env_name(key)
                .with_context(|| format!("invalid environment key for host tool {:?}", tool.id))?;
        }
        if tool.env.values().any(|value| {
            value.len() > MAX_TOOL_ENV_VALUE_BYTES || value.as_bytes().contains(&b'\0')
        }) {
            anyhow::bail!(
                "environment value for host tool {:?} exceeds configured limits",
                tool.id
            );
        }
        let mut forwarded = HashSet::new();
        for key in &tool.forward_env {
            if !forwarded.insert(key) {
                anyhow::bail!("duplicate forwarded environment key {key:?}");
            }
        }
    }

    let mut file_ids = HashSet::new();
    for file in &config.files {
        validate_resource_id(&file.id)?;
        validate_resource_path(&file.path)?;
        if !file_ids.insert(file.id.as_str()) {
            anyhow::bail!("duplicate host file ID {:?}", file.id);
        }
        if file.mode != "read-only" {
            anyhow::bail!(
                "host file {:?} uses unsupported mode {:?}; only read-only is implemented",
                file.id,
                file.mode
            );
        }
    }

    Ok(())
}

fn validate_resource_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_RESOURCE_PATH_BYTES
        || path.as_bytes().contains(&b'\0')
        || path.chars().any(|character| character.is_control())
    {
        anyhow::bail!("host resource paths must contain 1 to {MAX_RESOURCE_PATH_BYTES} safe bytes");
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        anyhow::bail!(
            "environment names must start with an ASCII letter or underscore and contain only ASCII letters, numbers, or underscores"
        );
    }
    Ok(())
}

pub fn resolve_tool_path(project_dir: &Path, tool: &HostToolResource) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

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
    if std::fs::metadata(&resolved)?.permissions().mode() & 0o111 == 0 {
        anyhow::bail!("host tool {} is not executable", resolved.display());
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
            forward_env: Vec::new(),
        };

        let error = resolve_tool_path(project.path(), &tool).unwrap_err();
        assert!(error.to_string().contains("inside the writable project"));
    }

    #[test]
    fn rejects_host_tools_without_executable_permission() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let tool_path = tools.path().join("demo-tool");
        std::fs::write(&tool_path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tool = HostToolResource {
            id: "demo".to_string(),
            path: tool_path.display().to_string(),
            notes: None,
            default_args: Vec::new(),
            env: HashMap::new(),
            forward_env: Vec::new(),
        };

        let error = resolve_tool_path(project.path(), &tool)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not executable"));
    }

    #[test]
    fn rejects_unsupported_registry_versions() {
        let parsed: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "2"
tools: []
files: []
"#,
        )
        .unwrap();
        assert!(
            validate(&parsed)
                .unwrap_err()
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn rejects_duplicate_and_invalid_resource_ids() {
        let duplicates: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "1"
tools:
  - { id: demo, path: /bin/echo }
  - { id: demo, path: /bin/printf }
files: []
"#,
        )
        .unwrap();
        assert!(
            validate(&duplicates)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let invalid: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "1"
tools: []
files:
  - { id: "../notes", path: /tmp/notes }
"#,
        )
        .unwrap();
        assert!(validate(&invalid).unwrap_err().to_string().contains("IDs"));
    }

    #[test]
    fn rejects_unimplemented_writable_file_mode() {
        let parsed: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "1"
tools: []
files:
  - { id: notes, path: /tmp/notes, mode: read-write }
"#,
        )
        .unwrap();
        assert!(
            validate(&parsed)
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
    }

    #[test]
    fn rejects_unknown_registry_fields() {
        let error = serde_yaml::from_str::<HostResourcesConfig>(
            r#"version: "1"
tools: []
files: []
typo: true
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn validates_explicit_environment_forwarding() {
        let valid: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "1"
tools:
  - id: demo
    path: /bin/echo
    forward_env: [HOME, API_TOKEN]
files: []
"#,
        )
        .unwrap();
        validate(&valid).unwrap();

        let invalid: HostResourcesConfig = serde_yaml::from_str(
            r#"version: "1"
tools:
  - id: demo
    path: /bin/echo
    forward_env: ["BAD=NAME"]
files: []
"#,
        )
        .unwrap();
        assert!(validate(&invalid).unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn rejects_oversized_registry_values() {
        let config = HostResourcesConfig {
            version: "1".to_string(),
            tools: vec![HostToolResource {
                id: "demo".to_string(),
                path: "/bin/echo".to_string(),
                notes: None,
                default_args: vec!["x".repeat(MAX_TOOL_ARG_BYTES + 1)],
                env: HashMap::new(),
                forward_env: Vec::new(),
            }],
            ..Default::default()
        };

        assert!(validate(&config).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn project_registry_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".outcall")).unwrap();
        let sentinel = project.path().join("registry.yaml");
        std::fs::write(&sentinel, "version: \"1\"\ntools: []\nfiles: []\n").unwrap();
        symlink(
            &sentinel,
            project.path().join(".outcall/host-resources.yaml"),
        )
        .unwrap();

        let error = load_for_project(project.path()).unwrap_err().to_string();

        assert!(error.contains("must be a real file"));
    }
}
