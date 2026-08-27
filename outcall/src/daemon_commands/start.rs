use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use outcall::secure_fs::secure_runtime_dir;

use crate::daemon_client::{
    DEFAULT_DAEMON_NAME, daemon_exec_socket_ready_for, daemon_requests_via_exec,
};

use super::DEFAULT_DAEMON_IMAGE;
use super::command::{COMMAND_TIMEOUT, bounded_output, bounded_status, output_detail};
use super::inspect::{
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, ROLE_LABEL, ROLE_VALUE, daemon_container_info,
};
use super::lifecycle::{daemon_container_logs, remove_daemon_container};

const MANAGED_DAEMON_CAPABILITIES: &[&str] = &["NET_ADMIN", "NET_BIND_SERVICE"];
const UNIX_TRANSPORT_CAPABILITIES: &[&str] = &["CHOWN", "DAC_OVERRIDE"];
const DAEMON_RESTART_POLICY: &str = "unless-stopped";
const DAEMON_PID_MODE: &str = "host";
const DAEMON_RULES_MOUNT_MODE: &str = "rw";
const DAEMON_PIDS_LIMIT: &str = "512";
const DAEMON_STATE_DIR: &str = "/var/lib/outcall";
const DAEMON_TMPFS: &str = "/tmp:rw,nosuid,nodev,mode=1777,size=64m";
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const IMAGE_PULL_RUN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn daemon_build_inputs(
    dockerfile: impl AsRef<std::path::Path>,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let dockerfile = std::fs::canonicalize(dockerfile.as_ref()).with_context(|| {
        format!(
            "failed to resolve daemon Dockerfile {}",
            dockerfile.as_ref().display()
        )
    })?;
    let context = dockerfile
        .parent()
        .context("daemon Dockerfile has no parent directory")?
        .to_path_buf();
    Ok((dockerfile, context))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_daemon_start(
    image: Option<String>,
    bridge: Option<String>,
    rules_dir: Option<String>,
    name: Option<String>,
    socket: Option<String>,
    agent_socket_host_path: Option<String>,
    no_proxy: bool,
    build_from: Option<String>,
) -> Result<()> {
    let name = name.unwrap_or_else(|| DEFAULT_DAEMON_NAME.to_string());
    let image = image.unwrap_or_else(|| DEFAULT_DAEMON_IMAGE.to_string());
    let bridge = bridge.unwrap_or_else(|| outcall_api::DEFAULT_BRIDGE_NAME.to_string());
    let rules_dir =
        validate_rules_directory(&rules_dir.unwrap_or_else(|| "/etc/outcall/rules.d".to_string()))?;
    let socket = socket.unwrap_or_else(|| outcall_api::DEFAULT_HOST_SOCKET.to_string());
    let agent_socket_host_path =
        agent_socket_host_path.unwrap_or_else(|| outcall_api::DEFAULT_AGENT_SOCKET.to_string());
    let use_container_local_sockets = daemon_requests_via_exec();
    validate_daemon_name_for_transport(&name, use_container_local_sockets)?;
    let (operator_uid, operator_gid) = if use_container_local_sockets {
        (0, 0)
    } else {
        host_operator_identity()?
    };

    if let Some(dockerfile) = build_from {
        let (dockerfile, context) = daemon_build_inputs(dockerfile)?;
        println!("Building image {image} from {}...", dockerfile.display());
        let status = bounded_status(
            Command::new("docker")
                .arg("build")
                .arg("-f")
                .arg(&dockerfile)
                .arg("-t")
                .arg(&image)
                .arg(&context),
            IMAGE_BUILD_TIMEOUT,
            "build daemon image",
        )?;
        if !status.success() {
            anyhow::bail!("docker build failed (exit {:?})", status.code());
        }
    } else {
        ensure_daemon_image(&image)?;
    }

    // Idempotent replacement still uses SIGTERM so the existing daemon can
    // reset dynamic grants to the strict base policy before it is removed.
    remove_daemon_container(&name)?;

    let socket_dir = std::path::Path::new(&socket)
        .parent()
        .context("daemon socket path must have a parent directory")?;
    if !use_container_local_sockets {
        std::fs::create_dir_all(socket_dir).with_context(|| {
            format!(
                "failed to create daemon socket directory {}",
                socket_dir.display()
            )
        })?;
        secure_runtime_dir(socket_dir)?;
    }

    let mut args = daemon_run_args(&name, use_container_local_sockets);
    args.extend(daemon_mount_args(&name, &rules_dir));
    if !use_container_local_sockets {
        args.push("-v".into());
        args.push(format!("{}:{}", socket_dir.display(), socket_dir.display()));
    }
    let mut daemon_args = vec![
        "--entrypoint".into(),
        "outcalld".into(),
        image.clone(),
        "--socket".into(),
        socket.clone(),
        "--operator-uid".into(),
        operator_uid.to_string(),
        "--operator-gid".into(),
        operator_gid.to_string(),
        "--agent-socket-host-path".into(),
        agent_socket_host_path,
        "--bridge".into(),
        bridge.clone(),
    ];
    if no_proxy {
        daemon_args.push("--no-proxy".into());
    }
    args.extend(daemon_args);

    let output = bounded_output(
        "docker",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        IMAGE_PULL_RUN_TIMEOUT,
        "start daemon container",
    )?;
    if !output.status.success() {
        anyhow::bail!("docker run failed: {}", output_detail(&output));
    }

    let cid =
        String::from_utf8(output.stdout).context("docker run returned a non-UTF-8 container ID")?;
    let cid = cid.trim();
    if cid.len() < 12 || !cid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("docker run returned an invalid container ID");
    }
    wait_for_daemon_start(&name, &socket, use_container_local_sockets)?;
    println!(
        "Daemon \"{name}\" started ({}, image={image}, bridge={bridge}).",
        &cid[..12]
    );
    Ok(())
}

fn validate_daemon_name_for_transport(name: &str, container_local_sockets: bool) -> Result<()> {
    if !outcall_api::valid_container_name(name) {
        anyhow::bail!("invalid daemon container name {name:?}");
    }
    if container_local_sockets && name != DEFAULT_DAEMON_NAME {
        anyhow::bail!(
            "custom daemon names are not supported with Docker-based daemon transport; use {DEFAULT_DAEMON_NAME:?}"
        );
    }
    Ok(())
}

fn wait_for_daemon_start(name: &str, socket: &str, container_local_sockets: bool) -> Result<()> {
    let deadline = std::time::Instant::now() + DAEMON_START_TIMEOUT;
    let mut last_error = None;
    while std::time::Instant::now() < deadline {
        let ready = if container_local_sockets {
            daemon_exec_socket_ready_for(name, socket)
        } else {
            std::os::unix::net::UnixStream::connect(socket)
                .map(|_| true)
                .map_err(anyhow::Error::from)
        };
        match ready {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => last_error = Some(error.to_string()),
        }

        match daemon_container_info(name)? {
            Some(info) if info.running => {}
            Some(info) => {
                let logs = daemon_startup_logs(name);
                anyhow::bail!(
                    "daemon container {name:?} stopped during startup (state: {}){logs}",
                    info.state
                );
            }
            None => anyhow::bail!("daemon container {name:?} disappeared during startup"),
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let detail = last_error.unwrap_or_else(|| "daemon socket did not remain ready".to_string());
    let logs = daemon_startup_logs(name);
    anyhow::bail!(
        "daemon container {name:?} did not become ready within {} seconds: {detail}{logs}",
        DAEMON_START_TIMEOUT.as_secs()
    )
}

fn daemon_startup_logs(name: &str) -> String {
    match daemon_container_logs(name) {
        Ok(logs) if !logs.trim().is_empty() => format!("\nRecent daemon logs:\n{logs}"),
        Ok(_) => String::new(),
        Err(error) => format!("\nDaemon logs unavailable: {error}"),
    }
}

fn ensure_daemon_image(image: &str) -> Result<()> {
    let inspect = bounded_output(
        "docker",
        &["image", "inspect", image],
        COMMAND_TIMEOUT,
        "inspect daemon image",
    )?;
    if inspect.status.success() {
        return Ok(());
    }
    println!("Pulling daemon image {image}...");
    let status = bounded_status(
        Command::new("docker").arg("pull").arg(image),
        IMAGE_PULL_RUN_TIMEOUT,
        "pull daemon image",
    )?;
    if !status.success() {
        anyhow::bail!(
            "docker pull failed for {image} (exit {:?}); authenticate to the registry or preload/build the image",
            status.code()
        );
    }
    Ok(())
}

fn daemon_run_args(name: &str, container_local_sockets: bool) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.to_string(),
        "--label".into(),
        format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"),
        "--label".into(),
        format!("{ROLE_LABEL}={ROLE_VALUE}"),
        "--restart".into(),
        DAEMON_RESTART_POLICY.into(),
        "--init".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        DAEMON_TMPFS.into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        DAEMON_PIDS_LIMIT.into(),
        "--network".into(),
        "host".into(),
        "--pid".into(),
        DAEMON_PID_MODE.into(),
    ];
    for capability in MANAGED_DAEMON_CAPABILITIES {
        args.push("--cap-add".into());
        args.push((*capability).into());
    }
    if !container_local_sockets {
        for capability in UNIX_TRANSPORT_CAPABILITIES {
            args.push("--cap-add".into());
            args.push((*capability).into());
        }
    }
    args
}

fn daemon_state_volume(name: &str) -> String {
    if name == DEFAULT_DAEMON_NAME {
        "outcall-state".to_string()
    } else {
        format!("outcall-state-{name}")
    }
}

fn daemon_mount_args(name: &str, rules_dir: &str) -> Vec<String> {
    vec![
        "-v".into(),
        "/var/run/docker.sock:/var/run/docker.sock".into(),
        "-v".into(),
        format!("{rules_dir}:/etc/outcall/rules.d:{DAEMON_RULES_MOUNT_MODE}"),
        "-v".into(),
        format!("{}:{DAEMON_STATE_DIR}", daemon_state_volume(name)),
    ]
}

fn host_operator_identity() -> Result<(u32, u32)> {
    if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        return Ok((
            uid.parse::<u32>()
                .context("failed to parse SUDO_UID as a numeric uid")?,
            gid.parse::<u32>()
                .context("failed to parse SUDO_GID as a numeric gid")?,
        ));
    }

    fn read_id_flag(flag: &str) -> Result<u32> {
        let output = bounded_output(
            "id",
            &[flag],
            COMMAND_TIMEOUT,
            &format!("determine host operator identity with `id {flag}`"),
        )?;
        if !output.status.success() {
            anyhow::bail!("`id {flag}` failed: {}", output_detail(&output));
        }
        String::from_utf8(output.stdout)
            .context("`id` returned non-UTF-8 output")?
            .trim()
            .parse::<u32>()
            .with_context(|| format!("failed to parse `id {flag}` output as uid/gid"))
    }

    Ok((read_id_flag("-u")?, read_id_flag("-g")?))
}

fn validate_rules_directory(path: &str) -> Result<String> {
    let path = std::path::Path::new(path);
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("rules directory {} does not exist", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "rules directory {} must be a real directory",
            path.display()
        );
    }
    Ok(std::fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize rules directory {}", path.display()))?
        .display()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_daemon_uses_least_privilege_and_identity_labels() {
        assert_eq!(
            MANAGED_DAEMON_CAPABILITIES,
            &["NET_ADMIN", "NET_BIND_SERVICE"]
        );
        assert_eq!(UNIX_TRANSPORT_CAPABILITIES, &["CHOWN", "DAC_OVERRIDE"]);
        let args = daemon_run_args("outcall-daemon", true);
        assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--security-opt", "no-new-privileges"])
        );
        assert!(args.iter().any(|arg| arg == "--init"));
        assert!(args.iter().any(|arg| arg == "--read-only"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--cap-add", "NET_ADMIN"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--cap-add", "NET_BIND_SERVICE"])
        );
        assert!(!args.iter().any(|arg| arg == "CHOWN"));
        assert!(!args.iter().any(|arg| arg == "DAC_OVERRIDE"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--tmpfs", DAEMON_TMPFS])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--pids-limit", DAEMON_PIDS_LIMIT])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--label", &format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}")])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--label", &format!("{ROLE_LABEL}={ROLE_VALUE}")])
        );
    }

    #[test]
    fn unix_socket_transport_adds_only_its_required_capabilities() {
        let args = daemon_run_args(DEFAULT_DAEMON_NAME, false);

        for capability in ["NET_ADMIN", "NET_BIND_SERVICE", "CHOWN", "DAC_OVERRIDE"] {
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["--cap-add", capability])
            );
        }
    }

    #[test]
    fn managed_daemon_runtime_contract_is_explicit() {
        assert_eq!(DAEMON_RESTART_POLICY, "unless-stopped");
        assert_eq!(DAEMON_PID_MODE, "host");
        assert_eq!(DAEMON_RULES_MOUNT_MODE, "rw");
        assert_eq!(daemon_state_volume(DEFAULT_DAEMON_NAME), "outcall-state");
        assert_eq!(
            daemon_state_volume("outcall-test"),
            "outcall-state-outcall-test"
        );
        let mounts = daemon_mount_args(DEFAULT_DAEMON_NAME, "/rules");
        assert!(
            mounts
                .windows(2)
                .any(|pair| pair == ["-v", "outcall-state:/var/lib/outcall"])
        );
    }

    #[test]
    fn docker_transport_requires_the_canonical_daemon_name() {
        assert!(validate_daemon_name_for_transport(DEFAULT_DAEMON_NAME, true).is_ok());
        assert!(validate_daemon_name_for_transport("custom-daemon", false).is_ok());
        assert!(validate_daemon_name_for_transport("custom-daemon", true).is_err());
        assert!(validate_daemon_name_for_transport("/invalid", false).is_err());
    }

    #[test]
    fn daemon_rules_directory_must_exist_and_be_real() {
        let temp = tempfile::tempdir().unwrap();
        assert!(validate_rules_directory(temp.path().to_str().unwrap()).is_ok());
        assert!(validate_rules_directory(temp.path().join("missing").to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn daemon_rules_directory_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();
        assert!(validate_rules_directory(link.to_str().unwrap()).is_err());
    }
}
