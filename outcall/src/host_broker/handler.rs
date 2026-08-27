use std::io::{Read, Write};

use anyhow::Result;

use crate::daemon_client::Response;

use super::auth::request_is_authenticated;
use super::http::{read_http_request, write_json as write_http_json};
use super::operations::{broker_exec_tool, broker_read_file};
use super::protocol::{
    BrokerFileReadRequest, BrokerToolExecRequest, validate_file_request, validate_tool_request,
    write_broker_error, write_broker_result,
};

pub(crate) fn handle_broker_connection<S: Read + Write>(
    stream: &mut S,
    daemon_socket: &str,
    config_path: &std::path::Path,
    auth_token: &str,
) -> Result<()> {
    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(error) => {
            return write_broker_error(stream, 400, format!("invalid broker request: {error}"));
        }
    };
    if !request_is_authenticated(&request.headers, auth_token) {
        return write_broker_error(stream, 403, "forbidden: invalid broker token".to_string());
    }

    if request.path == "/v1/health" && request.method == "GET" {
        return write_http_json(
            stream,
            200,
            &Response {
                success: true,
                data: Some(serde_json::json!({"ok": true})),
                error: None,
            },
        );
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/tool/exec" | "/v1/file/read") => {}
        (_, "/v1/health" | "/v1/tool/exec" | "/v1/file/read") => {
            return write_broker_error(
                stream,
                405,
                format!(
                    "method {} is not allowed for {}",
                    request.method, request.path
                ),
            );
        }
        _ => {
            return write_broker_error(
                stream,
                404,
                format!("unknown broker path {}", request.path),
            );
        }
    }

    let config = outcall::host_resources::load_from_path(config_path)?;
    match request.path.as_str() {
        "/v1/tool/exec" => {
            let req: BrokerToolExecRequest = match serde_json::from_slice(&request.body) {
                Ok(request) => request,
                Err(error) => {
                    return write_broker_error(
                        stream,
                        400,
                        format!("invalid tool exec request: {error}"),
                    );
                }
            };
            if let Err(error) = validate_tool_request(&req) {
                return write_broker_error(stream, 400, error.to_string());
            }
            write_broker_result(stream, broker_exec_tool(daemon_socket, &config, req))
        }
        "/v1/file/read" => {
            let req: BrokerFileReadRequest = match serde_json::from_slice(&request.body) {
                Ok(request) => request,
                Err(error) => {
                    return write_broker_error(
                        stream,
                        400,
                        format!("invalid file read request: {error}"),
                    );
                }
            };
            if let Err(error) = validate_file_request(&req) {
                return write_broker_error(stream, 400, error.to_string());
            }
            write_broker_result(stream, broker_read_file(daemon_socket, &config, req))
        }
        _ => write_broker_error(stream, 404, "unknown broker path".to_string()),
    }
}
