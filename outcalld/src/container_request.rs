use std::collections::HashSet;
use std::path::{Component, Path};

use anyhow::Result;
use outcall_api::{ContainerCreateRequest, DEFAULT_CONTAINER_USER, MAX_CONTAINER_NAME_BYTES};

const MAX_IMAGE_REFERENCE_BYTES: usize = 512;
const MAX_NETWORK_NAME_BYTES: usize = 128;
const MAX_ENV_ENTRIES: usize = 256;
const MAX_ENV_ENTRY_BYTES: usize = 65_536;
const MAX_PROCESS_ARGS: usize = 1_024;
const MAX_PROCESS_ARG_BYTES: usize = 32_768;
const MAX_PROCESS_ARG_TOTAL_BYTES: usize = 256 * 1024;
const MAX_MOUNTS: usize = 256;
const MAX_MOUNT_BYTES: usize = 8_192;
const MAX_WORKING_DIR_BYTES: usize = 4_096;

pub(crate) fn validate(request: &ContainerCreateRequest) -> Result<()> {
    validate_image(&request.image)?;
    if let Some(name) = request.name.as_deref() {
        validate_container_name(name)?;
    }
    if let Some(network) = request.network.as_deref() {
        validate_network_name(network)?;
    }
    validate_user(request.user.as_deref().unwrap_or(DEFAULT_CONTAINER_USER))?;
    validate_resources(
        request
            .memory_limit
            .unwrap_or(outcall_api::DEFAULT_MEMORY_LIMIT),
        request
            .cpu_shares
            .unwrap_or(outcall_api::DEFAULT_CPU_SHARES),
    )?;
    validate_environment(request.env.as_deref().unwrap_or_default())?;
    validate_process_args(
        "container command",
        request.cmd.as_deref().unwrap_or_default(),
    )?;
    validate_process_args(
        "container entrypoint",
        request.entrypoint.as_deref().unwrap_or_default(),
    )?;
    validate_working_dir(request.working_dir.as_deref())?;
    validate_mounts(request.volumes.as_deref().unwrap_or_default())
}

fn validate_user(user: &str) -> Result<()> {
    if !outcall_api::valid_container_user(user) {
        anyhow::bail!("container user must be a numeric non-root UID:GID");
    }
    Ok(())
}

fn validate_image(image: &str) -> Result<()> {
    if image.is_empty()
        || image.len() > MAX_IMAGE_REFERENCE_BYTES
        || !image.is_ascii()
        || image
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
    {
        anyhow::bail!(
            "container image must be a non-empty ASCII reference of at most {MAX_IMAGE_REFERENCE_BYTES} bytes"
        );
    }
    Ok(())
}

fn validate_container_name(name: &str) -> Result<()> {
    if !outcall_api::valid_container_name(name) {
        anyhow::bail!(
            "container name must contain 1-{MAX_CONTAINER_NAME_BYTES} ASCII letters, numbers, dots, underscores, or hyphens and start with a letter or number"
        );
    }
    Ok(())
}

fn validate_network_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NETWORK_NAME_BYTES
        || !name.is_ascii()
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        anyhow::bail!(
            "container network name is invalid or exceeds {MAX_NETWORK_NAME_BYTES} bytes"
        );
    }
    Ok(())
}

fn validate_resources(memory: i64, cpu_shares: i64) -> Result<()> {
    if !outcall_api::valid_memory_limit(memory) {
        anyhow::bail!(
            "container memory limit must be at least {} bytes (6m)",
            outcall_api::MIN_MEMORY_LIMIT
        );
    }
    if !outcall_api::valid_cpu_shares(cpu_shares) {
        anyhow::bail!(
            "container CPU shares must be between {} and {}",
            outcall_api::MIN_CPU_SHARES,
            outcall_api::MAX_CPU_SHARES
        );
    }
    Ok(())
}

fn validate_environment(entries: &[String]) -> Result<()> {
    if entries.len() > MAX_ENV_ENTRIES {
        anyhow::bail!("container environment exceeds {MAX_ENV_ENTRIES} entries");
    }
    let mut keys = HashSet::new();
    for entry in entries {
        if entry.len() > MAX_ENV_ENTRY_BYTES || entry.as_bytes().contains(&0) {
            anyhow::bail!(
                "container environment entry is invalid or exceeds {MAX_ENV_ENTRY_BYTES} bytes"
            );
        }
        let (key, _) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("container environment entries must use KEY=VALUE"))?;
        if !valid_environment_key(key) {
            anyhow::bail!("container environment key {key:?} is invalid");
        }
        if !keys.insert(key) {
            anyhow::bail!("duplicate container environment key {key:?}");
        }
    }
    Ok(())
}

fn valid_environment_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn validate_process_args(label: &str, args: &[String]) -> Result<()> {
    if args.len() > MAX_PROCESS_ARGS
        || args
            .iter()
            .any(|arg| arg.len() > MAX_PROCESS_ARG_BYTES || arg.as_bytes().contains(&0))
        || args.iter().map(String::len).sum::<usize>() > MAX_PROCESS_ARG_TOTAL_BYTES
    {
        anyhow::bail!("{label} exceeds configured argument limits");
    }
    Ok(())
}

fn validate_working_dir(working_dir: Option<&str>) -> Result<()> {
    let Some(working_dir) = working_dir else {
        return Ok(());
    };
    let path = Path::new(working_dir);
    if working_dir.len() > MAX_WORKING_DIR_BYTES
        || working_dir.as_bytes().contains(&0)
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        anyhow::bail!(
            "container working directory must be a clean absolute path of at most {MAX_WORKING_DIR_BYTES} bytes"
        );
    }
    Ok(())
}

fn validate_mounts(mounts: &[String]) -> Result<()> {
    if mounts.len() > MAX_MOUNTS
        || mounts
            .iter()
            .any(|mount| mount.len() > MAX_MOUNT_BYTES || mount.as_bytes().contains(&0))
    {
        anyhow::bail!("container mounts exceed configured limits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ContainerCreateRequest {
        ContainerCreateRequest {
            image: "example/agent:latest".to_string(),
            network: Some("outcall-default".to_string()),
            name: Some("project-1".to_string()),
            user: Some("1000:1000".to_string()),
            memory_limit: None,
            cpu_shares: None,
            env: Some(vec!["HOME=/home/node".to_string()]),
            cmd: Some(vec!["run".to_string()]),
            entrypoint: None,
            working_dir: Some("/workspace".to_string()),
            volumes: Some(vec!["/tmp/project:/workspace".to_string()]),
            include_outcall_helper_mounts: None,
            interactive: None,
            tty: None,
        }
    }

    #[test]
    fn accepts_bounded_managed_request() {
        assert!(validate(&request()).is_ok());

        let mut omitted_user = request();
        omitted_user.user = None;
        assert!(validate(&omitted_user).is_ok());
    }

    #[test]
    fn rejects_malformed_names_environment_and_paths() {
        let mut invalid = request();
        invalid.name = Some("/bad".to_string());
        assert!(validate(&invalid).is_err());

        let mut invalid = request();
        invalid.env = Some(vec!["TOKEN=one".to_string(), "TOKEN=two".to_string()]);
        assert!(validate(&invalid).is_err());

        let mut invalid = request();
        invalid.working_dir = Some("/workspace/../host".to_string());
        assert!(validate(&invalid).is_err());

        for user in ["0:0", "0:1000", "1000:0", "root", "1000", "1000:1000:1"] {
            let mut invalid = request();
            invalid.user = Some(user.to_string());
            assert!(validate(&invalid).is_err(), "accepted invalid user {user}");
        }
    }

    #[test]
    fn rejects_excessive_resource_and_collection_values() {
        let mut invalid = request();
        invalid.cpu_shares = Some(outcall_api::MAX_CPU_SHARES + 1);
        assert!(validate(&invalid).is_err());

        let mut invalid = request();
        invalid.volumes = Some(vec!["volume:/data".to_string(); MAX_MOUNTS + 1]);
        assert!(validate(&invalid).is_err());
    }
}
