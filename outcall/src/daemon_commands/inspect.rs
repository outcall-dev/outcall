use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::command::{COMMAND_TIMEOUT, bounded_output, missing_container, output_detail};

pub(super) const MANAGED_BY_LABEL: &str = "managed-by";
pub(super) const MANAGED_BY_VALUE: &str = "outcall-cli";
pub(super) const ROLE_LABEL: &str = "outcall.role";
pub(super) const ROLE_VALUE: &str = "daemon";

#[derive(Debug, Clone)]
pub(crate) struct DaemonContainerInfo {
    pub(crate) state: String,
    pub(crate) running: bool,
    pub(crate) image: String,
    managed: bool,
    legacy: bool,
}

#[derive(Deserialize)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "State")]
    state: Option<DockerState>,
    #[serde(rename = "Config")]
    config: Option<DockerConfig>,
}

#[derive(Deserialize)]
struct DockerState {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Running")]
    running: Option<bool>,
}

#[derive(Deserialize)]
struct DockerConfig {
    #[serde(rename = "Image")]
    image: Option<String>,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Labels", default)]
    labels: Option<HashMap<String, String>>,
}

pub(crate) fn daemon_container_info(name: &str) -> Result<Option<DaemonContainerInfo>> {
    let output = bounded_output(
        "docker",
        &["inspect", name],
        COMMAND_TIMEOUT,
        "inspect daemon container",
    )?;
    if !output.status.success() {
        if missing_container(&output) {
            return Ok(None);
        }
        anyhow::bail!(
            "failed to inspect daemon container: {}",
            output_detail(&output)
        );
    }
    let entries: Vec<DockerInspect> = serde_json::from_slice(&output.stdout)
        .context("Docker returned malformed daemon inspection JSON")?;
    let [entry] = entries.as_slice() else {
        anyhow::bail!(
            "Docker returned {} daemon inspection records",
            entries.len()
        );
    };
    let info = parse_daemon_info(entry)?;
    require_managed(name, &info)?;
    Ok(Some(info))
}

pub(crate) fn daemon_container_state(name: &str) -> Result<Option<String>> {
    Ok(daemon_container_info(name)?.map(|info| info.state))
}

fn parse_daemon_info(entry: &DockerInspect) -> Result<DaemonContainerInfo> {
    let state = entry
        .state
        .as_ref()
        .context("daemon inspection has no state")?;
    let config = entry
        .config
        .as_ref()
        .context("daemon inspection has no config")?;
    let id = required(entry.id.as_deref(), "container ID")?;
    if id.len() < 12 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("daemon inspection returned an invalid container ID");
    }
    let status = required(state.status.as_deref(), "container state")?;
    let running = state
        .running
        .context("daemon inspection has no running state")?;
    let image = required(config.image.as_deref(), "container image")?;
    let labels = config.labels.as_ref();
    let managed = labels.and_then(|labels| labels.get(MANAGED_BY_LABEL).map(String::as_str))
        == Some(MANAGED_BY_VALUE)
        && labels.and_then(|labels| labels.get(ROLE_LABEL).map(String::as_str)) == Some(ROLE_VALUE);
    let legacy = !managed
        && official_image(image)
        && config
            .entrypoint
            .as_deref()
            .and_then(|entrypoint| entrypoint.first())
            .is_some_and(|entrypoint| {
                std::path::Path::new(entrypoint)
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some("outcalld")
            });

    Ok(DaemonContainerInfo {
        state: status.to_string(),
        running,
        image: image.to_string(),
        managed,
        legacy,
    })
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("daemon inspection has no {field}"))
}

fn official_image(image: &str) -> bool {
    image.starts_with("ghcr.io/outcall-dev/outcalld:")
        || image.starts_with("ghcr.io/outcall-dev/outcalld@")
}

fn require_managed(name: &str, info: &DaemonContainerInfo) -> Result<()> {
    if info.managed || info.legacy {
        return Ok(());
    }
    anyhow::bail!("refusing to manage container {name:?}: it is not labeled as an Outcall daemon")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        image: &str,
        entrypoint: &[&str],
        labels: Option<HashMap<String, String>>,
    ) -> DockerInspect {
        DockerInspect {
            id: Some("a".repeat(64)),
            state: Some(DockerState {
                status: Some("running".to_string()),
                running: Some(true),
            }),
            config: Some(DockerConfig {
                image: Some(image.to_string()),
                entrypoint: Some(
                    entrypoint
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect(),
                ),
                labels,
            }),
        }
    }

    #[test]
    fn accepts_current_managed_metadata() {
        let entry = fixture(
            "custom:local",
            &["outcalld"],
            Some(HashMap::from([
                (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
                (ROLE_LABEL.to_string(), ROLE_VALUE.to_string()),
            ])),
        );
        let info = parse_daemon_info(&entry).unwrap();
        assert!(!info.legacy);
        assert!(require_managed("outcall-daemon", &info).is_ok());
    }

    #[test]
    fn recognizes_only_narrow_legacy_daemons() {
        let legacy = parse_daemon_info(&fixture(
            "ghcr.io/outcall-dev/outcalld:v0.1.35",
            &["outcalld"],
            None,
        ))
        .unwrap();
        assert!(legacy.legacy);

        let unrelated =
            parse_daemon_info(&fixture("redis:latest", &["redis-server"], None)).unwrap();
        assert!(!unrelated.legacy);
        assert!(require_managed("outcall-daemon", &unrelated).is_err());
    }
}
