use std::path::Path;

use super::access::{bridge_netfilter_enforceable, doctor_command_timeout};
use super::command::{CommandTimeoutError, command_output_with_timeout};
use crate::daemon_client::{DEFAULT_DAEMON_NAME, daemon_exec_output};
use crate::daemon_commands::daemon_container_state;

pub(crate) fn containerized_runtime_note() -> Option<String> {
    if std::env::consts::OS == "linux" {
        return None;
    }

    Some(format!(
        "Detected {}. Outcall will use Docker's Linux runtime for the daemon and agent containers.",
        std::env::consts::OS
    ))
}

pub(crate) fn doctor_command(command: &str, args: &[&str]) -> bool {
    match command_output_with_timeout(command, args, doctor_command_timeout()) {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let first = version.lines().next().unwrap_or("available");
            println!("  PASS {command}: {first}");
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.lines().next().unwrap_or("command failed");
            println!("  WARN {command}: {message}");
            false
        }
        Err(CommandTimeoutError::TimedOut { timeout }) => {
            println!(
                "  WARN {command}: timed out after {} seconds",
                timeout.as_secs()
            );
            false
        }
        Err(CommandTimeoutError::Io(error)) => {
            println!("  WARN {command}: {error}");
            false
        }
    }
}

pub(crate) fn doctor_docker_engine() -> bool {
    doctor_command(
        "docker",
        &[
            "version",
            "--format",
            "Docker Engine {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})",
        ],
    )
}

pub(crate) fn doctor_platform() {
    println!("{}", doctor_platform_line_for(std::env::consts::OS));
}

pub(crate) fn doctor_platform_line_for(os: &str) -> String {
    match os {
        "linux" => "  PASS platform: Linux host (native daemon runtime available)".to_string(),
        "macos" => "  INFO platform: macOS host detected; CLI runs locally and Outcall uses Docker Desktop's Linux runtime for the daemon and agent containers".to_string(),
        _ => format!(
            "  WARN platform: {os} host detected; the isolated daemon runtime still requires Linux"
        ),
    }
}

pub(crate) fn doctor_socket_dir(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            println!("  PASS socket dir: {}", path.display());
        }
        Ok(_) => println!(
            "  WARN socket dir: {} must be a real directory, not a file or symlink",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir_all(path) {
                Ok(()) => println!("  PASS socket dir: {} (created)", path.display()),
                Err(error) => println!("  WARN socket dir: {} ({error})", path.display()),
            }
        }
        Err(error) => println!("  WARN socket dir: {} ({error})", path.display()),
    }
}

pub(crate) fn doctor_br_netfilter() {
    if std::env::consts::OS != "linux" {
        doctor_containerized_br_netfilter();
        return;
    }

    if bridge_netfilter_enforceable() {
        println!("  PASS secure unattended mode: bridge netfilter enforcement enabled");
    } else {
        println!("  WARN secure unattended mode: bridge netfilter enforcement not fully enabled");
    }

    doctor_proc_value(
        "br_netfilter ipv4",
        Path::new("/proc/sys/net/bridge/bridge-nf-call-iptables"),
        "1",
        "load br_netfilter and set net.bridge.bridge-nf-call-iptables=1",
    );
    doctor_proc_value(
        "br_netfilter ipv6",
        Path::new("/proc/sys/net/bridge/bridge-nf-call-ip6tables"),
        "1",
        "set net.bridge.bridge-nf-call-ip6tables=1",
    );
}

fn doctor_containerized_br_netfilter() {
    match daemon_container_state(DEFAULT_DAEMON_NAME) {
        Ok(Some(state)) if state == "running" => {
            let ipv4 = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-iptables"]);
            let ipv6 = daemon_exec_output(["cat", "/proc/sys/net/bridge/bridge-nf-call-ip6tables"]);
            match (ipv4, ipv6) {
                (Ok(ipv4), Ok(ipv6)) => {
                    println!(
                        "{}",
                        runtime_bridge_netfilter_line(ipv4.trim(), ipv6.trim())
                    );
                }
                (Err(error), _) | (_, Err(error)) => println!(
                    "  WARN secure unattended mode: could not inspect Docker's Linux runtime ({error})"
                ),
            }
        }
        Ok(_) => println!(
            "  INFO secure unattended mode: bridge netfilter will be checked inside Docker's Linux runtime when `outcall run` starts"
        ),
        Err(error) => println!(
            "  WARN secure unattended mode: could not inspect Docker's Linux runtime ({error})"
        ),
    }
}

pub(crate) fn runtime_bridge_netfilter_line(ipv4: &str, ipv6: &str) -> String {
    if ipv4 == "1" && ipv6 == "1" {
        "  PASS secure unattended mode: Docker Linux runtime bridge netfilter enforcement enabled"
            .to_string()
    } else {
        format!(
            "  WARN secure unattended mode: Docker Linux runtime bridge netfilter is not enforceable (ipv4={ipv4}, ipv6={ipv6}; expected both to be 1)"
        )
    }
}

fn doctor_proc_value(label: &str, path: &Path, expected: &str, hint: &str) {
    match std::fs::read_to_string(path) {
        Ok(value) if value.trim() == expected => println!("  PASS {label}: {expected}"),
        Ok(value) => println!(
            "  WARN {label}: {} (expected {expected}; {hint})",
            value.trim()
        ),
        Err(error) => println!("  WARN {label}: {} ({error}; {hint})", path.display()),
    }
}

pub(crate) fn doctor_path(label: &str, path: &Path) {
    if path.exists() {
        println!("  PASS {label}: {}", path.display());
    } else {
        println!("  WARN {label}: {} missing", path.display());
    }
}

pub(crate) fn doctor_bool(label: &str, name: &str, present: bool) {
    if present {
        println!("  PASS {label}: {name}");
    } else {
        println!("  INFO {label}: {name} not found");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_and_runtime_diagnostics_are_explicit() {
        assert!(doctor_platform_line_for("linux").contains("PASS"));
        assert!(doctor_platform_line_for("macos").contains("Docker Desktop"));
        assert!(doctor_platform_line_for("windows").contains("WARN"));
        assert!(runtime_bridge_netfilter_line("1", "1").contains("PASS"));
        assert!(runtime_bridge_netfilter_line("0", "1").contains("WARN"));
    }
}
