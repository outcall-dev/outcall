use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use super::http::{RequestDecision, read_and_validate, write_plain_response};
use crate::daemon_client::daemon_raw_http_request_via_exec;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(super) enum BridgeBackend {
    Unix(PathBuf),
    DockerExec { socket: String },
}

pub(super) fn bridge_connection(
    mut tcp: TcpStream,
    backend: &BridgeBackend,
    port: u16,
    token: &str,
) -> Result<()> {
    tcp.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    tcp.set_write_timeout(Some(CONNECTION_TIMEOUT))?;

    let request = match read_and_validate(&mut tcp, port, token)? {
        RequestDecision::Forward(request) => request,
        RequestDecision::Reject {
            status,
            reason,
            body,
        } => return write_plain_response(&mut tcp, status, reason, body),
    };

    let remaining = request
        .content_length
        .saturating_sub(request.buffered_body.len());
    let mut body = request.buffered_body;
    body.reserve(remaining);
    let mut request_body = Read::take(&mut tcp, remaining as u64);
    let copied = request_body.read_to_end(&mut body)?;
    if copied != remaining {
        anyhow::bail!("client closed after {copied} request-body bytes; expected {remaining} more");
    }

    match backend {
        BridgeBackend::Unix(socket_path) => {
            let mut unix = std::os::unix::net::UnixStream::connect(socket_path)
                .context("failed to connect to host socket")?;
            unix.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
            unix.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
            unix.write_all(&request.headers)?;
            unix.write_all(&body)?;
            unix.shutdown(Shutdown::Write)?;
            io::copy(&mut unix, &mut tcp)?;
        }
        BridgeBackend::DockerExec { socket } => {
            let body = (request.content_length > 0).then_some(body);
            let response = match daemon_raw_http_request_via_exec(
                socket,
                &request.method,
                &request.path,
                &request.forwarded_headers,
                body,
            ) {
                Ok(response) => response,
                Err(error) => {
                    write_plain_response(
                        &mut tcp,
                        502,
                        "Bad Gateway",
                        "The dashboard could not reach the daemon API.",
                    )?;
                    return Err(error.context("Docker dashboard transport failed"));
                }
            };
            tcp.write_all(&response)?;
        }
    }
    tcp.shutdown(Shutdown::Write)?;
    Ok(())
}
