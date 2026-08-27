use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};

use crate::daemon_client::Response;

use super::http::write_json as write_http_json;

const MAX_ACTIVE_CONNECTIONS: usize = 16;

fn configure_unix_broker_stream(stream: &UnixStream) -> Result<()> {
    let timeout = Some(std::time::Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .context("failed to set host broker read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("failed to set host broker write timeout")
}

fn configure_tcp_broker_stream(stream: &std::net::TcpStream) -> Result<()> {
    let timeout = Some(std::time::Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .context("failed to set host broker read timeout")?;
    stream
        .set_write_timeout(timeout)
        .context("failed to set host broker write timeout")
}

pub(super) fn bind_broker_socket(socket: &str) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let path = std::path::Path::new(socket);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace non-socket entry at broker path {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to secure broker socket {}", path.display()))?;
    Ok(listener)
}

fn resolve_broker_config_path(
    project_dir: &std::path::Path,
    configured: Option<&str>,
) -> Result<std::path::PathBuf> {
    if let Some(configured) = configured {
        let path = std::path::PathBuf::from(configured);
        outcall::host_resources::load_from_path(&path)?;
        return Ok(path);
    }
    outcall::host_resources::load_optional_for_project(project_dir)?
        .map(|(path, _)| path)
        .with_context(|| {
            format!(
                "host resource registry {} does not exist",
                outcall::host_resources::default_config_path(project_dir).display()
            )
        })
}

#[derive(Clone)]
struct ServerState {
    daemon_socket: Arc<str>,
    config_path: Arc<std::path::PathBuf>,
    auth_token: Arc<str>,
    limiter: ConnectionLimiter,
}

impl ServerState {
    fn new(daemon_socket: &str, config_path: std::path::PathBuf, auth_token: String) -> Self {
        Self {
            daemon_socket: Arc::from(daemon_socket),
            config_path: Arc::new(config_path),
            auth_token: Arc::from(auth_token),
            limiter: ConnectionLimiter::new(MAX_ACTIVE_CONNECTIONS),
        }
    }
}

#[derive(Clone)]
struct ConnectionLimiter {
    active: Arc<AtomicUsize>,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn try_acquire(&self) -> Option<ConnectionPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()?;
        Some(ConnectionPermit {
            active: Arc::clone(&self.active),
        })
    }
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn serve_unix(
    daemon_socket: &str,
    socket: &str,
    config: Option<&str>,
    auth_token: Option<String>,
) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let config_path = resolve_broker_config_path(&project_dir, config)?;
    let token = super::auth::resolve_broker_auth_token(auth_token)?;
    let listener = bind_broker_socket(socket)?;
    let state = ServerState::new(daemon_socket, config_path.clone(), token);

    println!("Host broker listening on {socket}");
    println!("Config: {}", config_path.display());
    println!("Auth: bearer token configured");

    loop {
        let (stream, _) = listener.accept().context("host broker accept failed")?;
        configure_unix_broker_stream(&stream)?;
        dispatch_connection(stream, state.clone());
    }
}

pub(crate) fn serve_tcp(
    daemon_socket: &str,
    listen: &str,
    config: Option<&str>,
    auth_token: Option<String>,
) -> Result<()> {
    let project_dir = std::env::current_dir().context("failed to get current directory")?;
    let config_path = resolve_broker_config_path(&project_dir, config)?;
    let token = super::auth::resolve_broker_auth_token(auth_token)?;
    let listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("failed to bind loopback broker at {listen}"))?;
    let local_addr = listener
        .local_addr()
        .context("failed to inspect loopback broker address")?;
    if !local_addr.ip().is_loopback() {
        anyhow::bail!("host broker TCP listener must bind to a loopback address");
    }
    let state = ServerState::new(daemon_socket, config_path.clone(), token);

    println!("Host broker listening on http://{local_addr}");
    println!("Config: {}", config_path.display());
    println!("Auth: bearer token configured");

    loop {
        let (stream, _) = listener.accept().context("host broker accept failed")?;
        configure_tcp_broker_stream(&stream)?;
        dispatch_connection(stream, state.clone());
    }
}

fn dispatch_connection<S>(mut stream: S, state: ServerState)
where
    S: Read + Write + Send + 'static,
{
    let Some(permit) = state.limiter.try_acquire() else {
        if let Err(error) = write_http_json(
            &mut stream,
            503,
            &Response {
                success: false,
                data: None,
                error: Some("host broker is at its concurrent request limit".to_string()),
            },
        ) {
            eprintln!("failed to write host broker capacity response: {error:#}");
        }
        return;
    };

    if let Err(error) = std::thread::Builder::new()
        .name("outcall-host-broker".to_string())
        .spawn(move || {
            let _permit = permit;
            if let Err(error) = super::handler::handle_broker_connection(
                &mut stream,
                state.daemon_socket.as_ref(),
                state.config_path.as_ref(),
                state.auth_token.as_ref(),
            ) {
                eprintln!("host broker request failed: {error:#}");
                if let Err(write_error) = write_http_json(
                    &mut stream,
                    500,
                    &Response {
                        success: false,
                        data: None,
                        error: Some("internal host broker error".to_string()),
                    },
                ) {
                    eprintln!("failed to write host broker error response: {write_error:#}");
                }
            }
        })
    {
        eprintln!("failed to start host broker request worker: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().expect("first permit");

        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }
}
