use anyhow::{Context, Result};

mod bridge;
mod http;

use crate::daemon_client::{daemon_exec_socket_ready, daemon_requests_via_exec};
use bridge::{BridgeBackend, bridge_connection};

const MAX_ACTIVE_CONNECTIONS: usize = 64;

// ── UI command — local TCP → unix-socket bridge for the dashboard ──────────
//
// The host API is served on a Unix domain socket; browsers can't open Unix
// sockets directly. `outcall ui` listens on 127.0.0.1:<port> and forwards each
// connection into the daemon's host socket after validating the request. A raw
// TCP-to-Unix relay is not equivalent because it omits the controls below.
//
// One OS thread per connection. Fine for a single-operator dashboard;
// blocking I/O keeps the CLI free of an async runtime dependency.
//
// Security hardening (DNS-rebinding / cross-origin protection):
//
//   1. Bind explicitly to 127.0.0.1 (never 0.0.0.0).
//
//   2. For every request the bridge reads the HTTP request-line + headers,
//      then enforces:
//        a. Host header must be 127.0.0.1:<port> or localhost:<port>.
//           Any other value (e.g. "evil.com") → 403.
//        b. Origin header, if present, must start with
//           "http://127.0.0.1:<port>" or "http://localhost:<port>".
//           Any other origin → 403.
//      This stops DNS-rebinding: the attacker's page runs under a different
//      origin and/or sets Host to the rebound domain — both are rejected.
//
//   3. For /api/* and /v1/* paths the request must also carry:
//        X-Outcall-Token: <TOKEN>
//      TOKEN is a cryptographically random 256-bit value printed to stdout on
//      startup and passed to the dashboard in a URL fragment, which is never
//      sent to the HTTP server.
//
//   Static assets (HTML/JS/CSS) served without token so the browser can fetch
//   index.html, which must then attach the token to its API calls.

/// Generate a 32-byte (256-bit) random token from the OS RNG and hex-encode it.
fn generate_token() -> Result<String> {
    crate::random_token::hex::<32>()
}

pub(crate) fn cmd_ui(socket: &str, port: u16, auto_open: bool) -> Result<()> {
    use std::net::TcpListener;
    use std::sync::Arc;

    let backend = if daemon_requests_via_exec() {
        if !daemon_exec_socket_ready(socket)? {
            anyhow::bail!(
                "host socket not ready inside outcall-daemon at {socket}. Try `outcall daemon status`."
            );
        }
        BridgeBackend::DockerExec {
            socket: socket.to_string(),
        }
    } else {
        let socket_path = std::path::PathBuf::from(socket);
        if !socket_path.exists() {
            anyhow::bail!(
                "host socket not found at {socket}. Is the daemon running? Try `outcall daemon status`."
            );
        }
        BridgeBackend::Unix(socket_path)
    };

    // Always bind to loopback — never 0.0.0.0.
    let bind = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind)
        .with_context(|| format!("failed to bind {bind}; pick another port with --port"))?;

    let token = generate_token()?;
    let url = format!("http://127.0.0.1:{port}/ui/#token={token}");
    println!("Outcall UI listening on {url}");
    println!("Open this URL in your browser. The token expires when the bridge exits.");
    let transport = match &backend {
        BridgeBackend::Unix(_) => socket.to_string(),
        BridgeBackend::DockerExec { socket } => format!("outcall-daemon:{socket}"),
    };
    println!("Bridging 127.0.0.1:{port} → {transport}");
    println!("Press Ctrl-C to stop.");

    if auto_open && let Err(error) = open_in_browser(&url) {
        eprintln!("Could not open the browser automatically: {error}");
    }

    let token = Arc::new(token);
    let active_connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        if active_connections
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |active| (active < MAX_ACTIVE_CONNECTIONS).then_some(active + 1),
            )
            .is_err()
        {
            if let Err(error) = http::write_plain_response(
                &mut stream,
                503,
                "Service Unavailable",
                "Too many active dashboard connections.",
            ) {
                eprintln!("failed to write dashboard capacity response: {error:#}");
            }
            continue;
        }
        let target = backend.clone();
        let tok = Arc::clone(&token);
        let active = Arc::clone(&active_connections);
        std::thread::spawn(move || {
            let _permit = ConnectionPermit(active);
            if let Err(e) = bridge_connection(stream, &target, port, &tok) {
                eprintln!("bridge error: {e}");
            }
        });
    }
    Ok(())
}

struct ConnectionPermit(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn open_in_browser(url: &str) -> Result<()> {
    use std::process::Command;
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    let status = Command::new(opener).arg(url).status()?;
    if !status.success() {
        anyhow::bail!("browser opener exited with status {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::bridge::{BridgeBackend, bridge_connection};

    fn send_request(
        socket_path: &Path,
        token: &str,
        request: impl FnOnce(u16) -> String,
    ) -> String {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP listener");
        let port = listener.local_addr().expect("TCP listener address").port();
        let socket_path = socket_path.to_path_buf();
        let token = token.to_string();
        let bridge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept TCP client");
            bridge_connection(stream, &BridgeBackend::Unix(socket_path), port, &token)
                .expect("bridge request");
        });

        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect bridge");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        client
            .write_all(request(port).as_bytes())
            .expect("write request");
        client.shutdown(Shutdown::Write).expect("finish request");

        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        bridge.join().expect("join bridge");
        response
    }

    #[test]
    fn forwards_body_bytes_buffered_with_request_headers() {
        let temp = tempdir().expect("tempdir");
        let socket_path = temp.path().join("daemon.sock");
        let backend = UnixListener::bind(&socket_path).expect("bind Unix backend");
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let backend_thread = std::thread::spawn(move || {
            let (mut stream, _) = backend.accept().expect("accept bridge");
            let mut request = String::new();
            stream
                .read_to_string(&mut request)
                .expect("read forwarded request");
            request_tx.send(request).expect("send captured request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write backend response");
        });

        let body = r#"{"id":"demo"}"#;
        let response = send_request(&socket_path, "secret", |port| {
            format!(
                "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Outcall-Token: secret\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        });

        let forwarded = request_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("receive forwarded request");
        backend_thread.join().expect("join backend");
        assert_eq!(
            forwarded.split_once("\r\n\r\n").expect("request body").1,
            body
        );
        assert!(!forwarded.to_ascii_lowercase().contains("x-outcall-token"));
        assert!(forwarded.contains("Connection: close\r\n"));
        assert!(response.ends_with("\r\n\r\nok"));
    }

    #[test]
    fn rejects_non_loopback_host_header() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |_| {
            "GET /ui/ HTTP/1.1\r\nHost: evil.example\r\n\r\n".to_string()
        });
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.ends_with("Forbidden: Host header failed validation."));
    }

    #[test]
    fn rejects_cross_origin_browser_request() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |port| {
            format!(
                "GET /ui/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\n\r\n"
            )
        });
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.ends_with("Forbidden: Origin header failed validation."));
    }

    #[test]
    fn requires_token_for_api_request() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |port| {
            format!("GET /api/status HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
        });
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(response.ends_with("Unauthorized: missing or invalid X-Outcall-Token."));
    }

    #[test]
    fn query_token_does_not_authorize_api_request() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |port| {
            format!("GET /api/status?token=secret HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
        });
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn rejects_duplicate_security_headers() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |port| {
            format!("GET /ui/ HTTP/1.1\r\nHost: localhost:{port}\r\nHost: evil.example\r\n\r\n")
        });
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.ends_with("Duplicate Host header."));
    }

    #[test]
    fn rejects_ambiguous_request_framing() {
        let temp = tempdir().expect("tempdir");
        let response = send_request(&temp.path().join("missing.sock"), "secret", |port| {
            format!(
                "POST /api/status HTTP/1.1\r\nHost: localhost:{port}\r\nX-Outcall-Token: secret\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            )
        });
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.ends_with("Unsupported HTTP request framing."));
    }
}
