use anyhow::{Context, Result};
use serde::Deserialize;

use outcall::secure_fs::{
    ensure_secure_subdir, existing_secure_subdir, read_regular_string, remove_file_entry,
    write_runtime_file,
};

#[derive(Deserialize)]
struct GeneratedHostBrokerRuleFile {
    version: String,
    rules: Vec<GeneratedHostBrokerRule>,
}

#[derive(Deserialize)]
struct GeneratedHostBrokerRule {
    id: String,
    description: String,
    condition: String,
    action: String,
    priority: i32,
    egress: GeneratedHostBrokerEgress,
}

#[derive(Deserialize)]
struct GeneratedHostBrokerEgress {
    mode: String,
    ports: Vec<u16>,
    allow_private_ips: bool,
}

#[cfg(test)]
pub(crate) fn host_broker_transport_rule_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    project_dir
        .join(".outcall")
        .join("rules")
        .join(".outcall-host-broker.yaml")
}

pub(crate) fn write_host_broker_transport_rule(
    project_dir: &std::path::Path,
    port: u16,
) -> Result<()> {
    let path = secure_host_broker_transport_rule_path(project_dir, true)?
        .context("created host broker rule directory must exist")?;
    let contents = format!(
        r#"version: "1"
rules:
  - id: outcall-host-broker-transport
    description: Internal Docker Desktop transport to the tokenized host broker.
    condition: 'http.host == "host.docker.internal" && network.port == {port}'
    action: allow
    priority: 0
    egress:
      mode: proxy
      ports: [{port}]
      allow_private_ips: true
"#
    );
    write_runtime_file(&path, contents.as_bytes())
}

pub(super) fn remove_host_broker_transport_rule(project_dir: &std::path::Path) -> Result<bool> {
    let Some(path) = secure_host_broker_transport_rule_path(project_dir, false)? else {
        return Ok(false);
    };
    remove_file_entry(&path)
}

pub(crate) fn remove_invalid_host_broker_transport_rule(
    project_dir: &std::path::Path,
) -> Result<bool> {
    let Some(path) = secure_host_broker_transport_rule_path(project_dir, false)? else {
        return Ok(false);
    };
    let Some(raw) = read_regular_string(&path)? else {
        return Ok(false);
    };
    if valid_host_broker_transport_rule(&raw) {
        return Ok(false);
    }
    remove_file_entry(&path)
}

fn secure_host_broker_transport_rule_path(
    project_dir: &std::path::Path,
    create: bool,
) -> Result<Option<std::path::PathBuf>> {
    let relative = std::path::Path::new(".outcall/rules");
    let rules_dir = if create {
        Some(ensure_secure_subdir(project_dir, relative)?)
    } else {
        existing_secure_subdir(project_dir, relative)?
    };
    Ok(rules_dir.map(|dir| dir.join(".outcall-host-broker.yaml")))
}

pub(crate) fn valid_host_broker_transport_rule(raw: &str) -> bool {
    let Ok(file) = serde_yaml::from_str::<GeneratedHostBrokerRuleFile>(raw) else {
        return false;
    };
    let [rule] = file.rules.as_slice() else {
        return false;
    };
    let [port] = rule.egress.ports.as_slice() else {
        return false;
    };
    file.version == "1"
        && rule.id == "outcall-host-broker-transport"
        && rule.description == "Internal Docker Desktop transport to the tokenized host broker."
        && rule.condition
            == format!("http.host == \"host.docker.internal\" && network.port == {port}")
        && rule.action == "allow"
        && rule.priority == 0
        && rule.egress.mode == "proxy"
        && rule.egress.allow_private_ips
}
