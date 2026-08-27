use anyhow::{Context, Result};

use crate::api_commands::cmd_rules_reload;
use outcall::secure_fs::{
    ensure_secure_subdir, read_regular_string_bounded, remove_file_entry, secure_runtime_file,
    write_runtime_file,
};

use super::auth::random_broker_token;

mod health;
mod rule;

pub(crate) use health::host_broker_diagnostic;
use health::{
    tcp_host_broker_healthy, unix_host_broker_healthy, wait_for_tcp_host_broker,
    wait_for_unix_host_broker,
};
use rule::remove_host_broker_transport_rule;
#[cfg(test)]
pub(crate) use rule::{host_broker_transport_rule_path, valid_host_broker_transport_rule};
pub(crate) use rule::{
    remove_invalid_host_broker_transport_rule, write_host_broker_transport_rule,
};

const BROKER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const MAX_BROKER_TOKEN_BYTES: usize = 256;
const MAX_BROKER_PORT_BYTES: usize = 16;
const MAX_BROKER_PID_BYTES: usize = 32;

struct BrokerChildGuard {
    child: Option<std::process::Child>,
}

impl BrokerChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, std::process::Child::id)
    }

    fn disarm(mut self) {
        self.child.take();
    }
}

impl Drop for BrokerChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                eprintln!("failed to inspect partially started host broker: {error}");
            }
        }
        if let Err(error) = child.kill() {
            eprintln!("failed to terminate partially started host broker: {error}");
        }
        if let Err(error) = child.wait() {
            eprintln!("failed to reap partially started host broker: {error}");
        }
    }
}

#[derive(Debug, Clone)]
struct HostBrokerRuntime {
    transport: HostBrokerTransport,
    auth_token: String,
}

#[derive(Debug, Clone)]
enum HostBrokerTransport {
    Unix {
        host_socket: std::path::PathBuf,
        container_socket: String,
    },
    Http {
        listen_addr: std::net::SocketAddr,
        container_url: String,
    },
}

pub(crate) fn maybe_prepare_host_broker(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    config: &mut outcall::agent_config::AgentConfig,
) -> Result<()> {
    let Some((registry_path, registry)) =
        outcall::host_resources::load_optional_for_project(project_dir)?
    else {
        if remove_host_broker_transport_rule(project_dir)? {
            cmd_rules_reload(daemon_socket)?;
        }
        return Ok(());
    };
    if registry.tools.is_empty() && registry.files.is_empty() {
        if remove_host_broker_transport_rule(project_dir)? {
            cmd_rules_reload(daemon_socket)?;
        }
        return Ok(());
    }

    let runtime = ensure_host_broker_running(daemon_socket, project_dir, &registry_path)?;
    match runtime.transport {
        HostBrokerTransport::Unix {
            host_socket,
            container_socket,
        } => {
            println!(
                "Host broker ready: {} -> {}",
                host_socket.display(),
                container_socket
            );
            config
                .env
                .insert("OUTCALL_HOST_BROKER_SOCKET".to_string(), container_socket);
        }
        HostBrokerTransport::Http {
            listen_addr,
            container_url,
        } => {
            println!("Host broker ready: http://{listen_addr} -> {container_url}");
            config
                .env
                .insert("OUTCALL_HOST_BROKER_URL".to_string(), container_url);
        }
    }
    config.env.insert(
        "OUTCALL_HOST_BROKER_TOKEN".to_string(),
        runtime.auth_token.clone(),
    );
    config
        .env
        .insert("OUTCALL_HOST_BROKER_ENABLED".to_string(), "1".to_string());
    Ok(())
}

fn ensure_host_broker_running(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    registry_path: &std::path::Path,
) -> Result<HostBrokerRuntime> {
    let run_dir = ensure_secure_subdir(project_dir, std::path::Path::new(".outcall/run"))?;

    let token_path = run_dir.join("host-broker.token");
    let existing_token = read_regular_string_bounded(&token_path, MAX_BROKER_TOKEN_BYTES)?
        .map(|value| value.trim().to_string())
        .filter(|value| value.len() == 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()));
    let auth_token = if let Some(token) = existing_token {
        token
    } else {
        let token = random_broker_token()?;
        write_runtime_file(&token_path, token.as_bytes())?;
        token
    };
    secure_runtime_file(&token_path)?;

    if std::env::consts::OS == "macos" {
        return ensure_tcp_host_broker_running(
            daemon_socket,
            project_dir,
            registry_path,
            &run_dir,
            auth_token,
        );
    }

    if remove_host_broker_transport_rule(project_dir)? {
        cmd_rules_reload(daemon_socket)?;
    }
    ensure_unix_host_broker_running(daemon_socket, registry_path, &run_dir, auth_token)
}

fn ensure_unix_host_broker_running(
    daemon_socket: &str,
    registry_path: &std::path::Path,
    run_dir: &std::path::Path,
    auth_token: String,
) -> Result<HostBrokerRuntime> {
    use std::os::unix::process::CommandExt;

    let host_socket = run_dir.join("host-broker.sock");
    let runtime = HostBrokerRuntime {
        transport: HostBrokerTransport::Unix {
            host_socket: host_socket.clone(),
            container_socket: "/workspace/.outcall/run/host-broker.sock".to_string(),
        },
        auth_token,
    };

    if unix_host_broker_healthy(&host_socket, &runtime.auth_token) {
        return Ok(runtime);
    }

    let current_exe =
        std::env::current_exe().context("failed to resolve current outcall binary")?;
    let mut command = std::process::Command::new(current_exe);
    command
        .arg("--socket")
        .arg(daemon_socket)
        .arg("host-broker")
        .arg("serve")
        .arg("--broker-socket")
        .arg(&host_socket)
        .arg("--config")
        .arg(registry_path)
        .env("OUTCALL_HOST_BROKER_TOKEN", &runtime.auth_token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.process_group(0);

    let child = command.spawn().with_context(|| {
        format!(
            "failed to start host broker for {}",
            registry_path.display()
        )
    })?;

    let child = BrokerChildGuard::new(child);
    wait_for_unix_host_broker(&host_socket, &runtime.auth_token)?;
    write_host_broker_pid(run_dir, child.id())?;
    child.disarm();
    Ok(runtime)
}

fn ensure_tcp_host_broker_running(
    daemon_socket: &str,
    project_dir: &std::path::Path,
    registry_path: &std::path::Path,
    run_dir: &std::path::Path,
    auth_token: String,
) -> Result<HostBrokerRuntime> {
    use std::os::unix::process::CommandExt;

    let port_path = run_dir.join("host-broker.port");
    if let Some(value) = read_regular_string_bounded(&port_path, MAX_BROKER_PORT_BYTES)?
        && let Ok(port) = value.trim().parse::<u16>()
    {
        secure_runtime_file(&port_path)?;
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if tcp_host_broker_healthy(addr, &auth_token) {
            write_host_broker_transport_rule(project_dir, port)?;
            cmd_rules_reload(daemon_socket)?;
            return Ok(tcp_host_broker_runtime(addr, auth_token));
        }
    }

    let current_exe =
        std::env::current_exe().context("failed to resolve current outcall binary")?;
    for _ in 0..3 {
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0))
            .context("failed to reserve a loopback broker port")?;
        let addr = reservation
            .local_addr()
            .context("failed to inspect reserved broker port")?;
        drop(reservation);

        let mut command = std::process::Command::new(&current_exe);
        command
            .arg("--socket")
            .arg(daemon_socket)
            .arg("host-broker")
            .arg("serve-tcp")
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--config")
            .arg(registry_path)
            .env("OUTCALL_HOST_BROKER_TOKEN", &auth_token)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command.process_group(0);
        let child = command.spawn().with_context(|| {
            format!(
                "failed to start loopback host broker for {}",
                registry_path.display()
            )
        })?;

        let child = BrokerChildGuard::new(child);
        if wait_for_tcp_host_broker(addr, &auth_token) {
            let setup = (|| -> Result<()> {
                write_runtime_file(&port_path, format!("{}\n", addr.port()).as_bytes())?;
                write_host_broker_pid(run_dir, child.id())?;
                write_host_broker_transport_rule(project_dir, addr.port())?;
                cmd_rules_reload(daemon_socket)
            })();
            if let Err(error) = setup {
                cleanup_failed_tcp_broker_setup(project_dir, run_dir, &port_path);
                if let Err(reload_error) = cmd_rules_reload(daemon_socket) {
                    eprintln!(
                        "failed to reload rules after broker setup rollback: {reload_error:#}"
                    );
                }
                return Err(error).context("failed to activate host broker transport rule");
            }
            child.disarm();
            return Ok(tcp_host_broker_runtime(addr, auth_token));
        }
    }

    anyhow::bail!("host broker did not become ready on a loopback TCP port")
}

fn write_host_broker_pid(run_dir: &std::path::Path, pid: u32) -> Result<()> {
    let path = run_dir.join("host-broker.pid");
    write_runtime_file(&path, format!("{pid}\n").as_bytes())
}

fn cleanup_failed_tcp_broker_setup(
    project_dir: &std::path::Path,
    run_dir: &std::path::Path,
    port_path: &std::path::Path,
) {
    for path in [port_path.to_path_buf(), run_dir.join("host-broker.pid")] {
        if let Err(error) = remove_file_entry(&path) {
            eprintln!(
                "failed to remove incomplete broker state {}: {error}",
                path.display()
            );
        }
    }
    if let Err(error) = remove_host_broker_transport_rule(project_dir) {
        eprintln!("failed to remove inactive host broker transport rule: {error}");
    }
}

fn tcp_host_broker_runtime(
    listen_addr: std::net::SocketAddr,
    auth_token: String,
) -> HostBrokerRuntime {
    HostBrokerRuntime {
        transport: HostBrokerTransport::Http {
            listen_addr,
            container_url: format!("http://host.docker.internal:{}", listen_addr.port()),
        },
        auth_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_child_guard_terminates_and_reaps_child() {
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn broker fixture");
        let pid = child.id();

        drop(BrokerChildGuard::new(child));

        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).expect("PID fits i32"));
        assert!(nix::sys::signal::kill(pid, None).is_err());
    }
}
