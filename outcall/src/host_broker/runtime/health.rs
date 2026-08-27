use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::Result;

use crate::daemon_client::{Response, read_body};
use outcall::secure_fs::{existing_secure_subdir, read_regular_string_bounded};

use super::{
    BROKER_PROBE_TIMEOUT, MAX_BROKER_PID_BYTES, MAX_BROKER_PORT_BYTES, MAX_BROKER_TOKEN_BYTES,
};

pub(super) fn unix_host_broker_healthy(socket: &std::path::Path, auth_token: &str) -> bool {
    if !socket.exists() {
        return false;
    }
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    if stream.set_read_timeout(Some(BROKER_PROBE_TIMEOUT)).is_err()
        || stream
            .set_write_timeout(Some(BROKER_PROBE_TIMEOUT))
            .is_err()
    {
        return false;
    }
    probe_host_broker(&mut stream, auth_token)
}

pub(super) fn tcp_host_broker_healthy(addr: std::net::SocketAddr, auth_token: &str) -> bool {
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
    else {
        return false;
    };
    if stream.set_read_timeout(Some(BROKER_PROBE_TIMEOUT)).is_err()
        || stream
            .set_write_timeout(Some(BROKER_PROBE_TIMEOUT))
            .is_err()
    {
        return false;
    }
    probe_host_broker(&mut stream, auth_token)
}

fn probe_host_broker(stream: &mut (impl Read + Write), auth_token: &str) -> bool {
    if write!(
        stream,
        "GET /v1/health HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {auth_token}\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let Ok(body) = read_body(stream) else {
        return false;
    };
    let Ok(resp) = serde_json::from_str::<Response>(&body) else {
        return false;
    };
    resp.success
}

pub(super) fn wait_for_unix_host_broker(socket: &std::path::Path, auth_token: &str) -> Result<()> {
    for _ in 0..50 {
        if unix_host_broker_healthy(socket, auth_token) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("host broker did not become ready at {}", socket.display());
}

pub(super) fn wait_for_tcp_host_broker(addr: std::net::SocketAddr, auth_token: &str) -> bool {
    for _ in 0..50 {
        if tcp_host_broker_healthy(addr, auth_token) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

pub(crate) fn host_broker_diagnostic(project_dir: &std::path::Path) -> Result<String> {
    let Some((_, registry)) = outcall::host_resources::load_optional_for_project(project_dir)?
    else {
        return Ok("not configured".to_string());
    };
    if registry.tools.is_empty() && registry.files.is_empty() {
        return Ok("not configured (registry has no tools or files)".to_string());
    }
    let Some(run_dir) = existing_secure_subdir(project_dir, std::path::Path::new(".outcall/run"))?
    else {
        return Ok("configured; starts with the first agent run".to_string());
    };
    let Some(token) =
        read_regular_string_bounded(&run_dir.join("host-broker.token"), MAX_BROKER_TOKEN_BYTES)?
    else {
        return Ok("configured; runtime token is not initialized".to_string());
    };
    let token = token.trim();
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok("configured; runtime token is invalid".to_string());
    }

    let pid = read_regular_string_bounded(&run_dir.join("host-broker.pid"), MAX_BROKER_PID_BYTES)?
        .and_then(|value| value.trim().parse::<u32>().ok());
    let pid_detail = pid
        .map(|pid| format!("; recorded pid {pid}"))
        .unwrap_or_default();

    if std::env::consts::OS == "macos" {
        let port =
            read_regular_string_bounded(&run_dir.join("host-broker.port"), MAX_BROKER_PORT_BYTES)?
                .and_then(|value| value.trim().parse::<u16>().ok())
                .filter(|port| *port != 0);
        let Some(port) = port else {
            return Ok(format!("configured but inactive{pid_detail}"));
        };
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        return Ok(if tcp_host_broker_healthy(address, token) {
            format!("healthy on loopback TCP port {port}")
        } else {
            format!("configured but inactive on loopback TCP port {port}{pid_detail}")
        });
    }

    let socket = run_dir.join("host-broker.sock");
    Ok(if unix_host_broker_healthy(&socket, token) {
        format!("healthy at {}", socket.display())
    } else {
        format!(
            "configured but inactive at {}{pid_detail}",
            socket.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn tcp_health_probe_has_a_read_deadline() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept probe");
            std::thread::sleep(Duration::from_millis(700));
        });

        let started = Instant::now();
        assert!(!tcp_host_broker_healthy(address, "a".repeat(32).as_str()));
        assert!(started.elapsed() < Duration::from_millis(650));
        server.join().expect("join fixture");
    }

    #[test]
    fn diagnostic_reports_unconfigured_and_not_started_projects() {
        let project = tempfile::tempdir().expect("project");
        assert_eq!(
            host_broker_diagnostic(project.path()).expect("diagnostic"),
            "not configured"
        );

        std::fs::create_dir_all(project.path().join(".outcall")).expect("outcall dir");
        std::fs::write(
            project.path().join(".outcall/host-resources.yaml"),
            "version: \"1\"\ntools:\n  - id: echo\n    path: /bin/echo\nfiles: []\n",
        )
        .expect("registry");
        assert_eq!(
            host_broker_diagnostic(project.path()).expect("diagnostic"),
            "configured; starts with the first agent run"
        );
    }
}
