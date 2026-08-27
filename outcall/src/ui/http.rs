use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::Result;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HEADERS: usize = 64;

pub(super) struct ValidatedRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) forwarded_headers: Vec<(String, String)>,
    pub(super) headers: Vec<u8>,
    pub(super) buffered_body: Vec<u8>,
    pub(super) content_length: usize,
}

pub(super) enum RequestDecision {
    Forward(ValidatedRequest),
    Reject {
        status: u16,
        reason: &'static str,
        body: &'static str,
    },
}

pub(super) fn read_and_validate(
    stream: &mut TcpStream,
    port: u16,
    token: &str,
) -> Result<RequestDecision> {
    let bytes = match read_headers(stream)? {
        Some(bytes) => bytes,
        None => {
            return Ok(reject(
                431,
                "Request Header Fields Too Large",
                "Request headers are too large.",
            ));
        }
    };
    let Some(header_end) = find_header_end(&bytes) else {
        return Ok(reject(
            400,
            "Bad Request",
            "Incomplete HTTP request headers.",
        ));
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = match request.parse(&bytes[..header_end]) {
        Ok(httparse::Status::Complete(length)) if length == header_end => length,
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {
            return Ok(reject(
                400,
                "Bad Request",
                "Malformed HTTP request headers.",
            ));
        }
        Err(httparse::Error::TooManyHeaders) => {
            return Ok(reject(
                431,
                "Request Header Fields Too Large",
                "Too many HTTP headers.",
            ));
        }
        Err(_) => {
            return Ok(reject(
                400,
                "Bad Request",
                "Malformed HTTP request headers.",
            ));
        }
    };

    let Some(method) = request.method else {
        return Ok(reject(400, "Bad Request", "Missing HTTP method."));
    };
    let Some(path) = request.path else {
        return Ok(reject(400, "Bad Request", "Missing HTTP request target."));
    };
    if request.version != Some(1) || !path.starts_with('/') {
        return Ok(reject(
            400,
            "Bad Request",
            "Only HTTP/1.1 origin-form requests are supported.",
        ));
    }

    let mut host = None;
    let mut origin = None;
    let mut provided_token = None;
    let mut content_length = None;
    let mut forwarded_headers = Vec::new();
    let mut forwarded = Vec::with_capacity(parsed + 32);
    write!(&mut forwarded, "{method} {path} HTTP/1.1\r\n")?;

    for header in request.headers.iter() {
        let name = header.name;
        let value = match std::str::from_utf8(header.value) {
            Ok(value) => value.trim(),
            Err(_) => return Ok(reject(400, "Bad Request", "Invalid HTTP header value.")),
        };
        match name.to_ascii_lowercase().as_str() {
            "host" if !set_once(&mut host, value) => {
                return Ok(reject(400, "Bad Request", "Duplicate Host header."));
            }
            "origin" if !set_once(&mut origin, value) => {
                return Ok(reject(400, "Bad Request", "Duplicate Origin header."));
            }
            "x-outcall-token" if !set_once(&mut provided_token, value) => {
                return Ok(reject(
                    400,
                    "Bad Request",
                    "Duplicate X-Outcall-Token header.",
                ));
            }
            "host" | "origin" | "x-outcall-token" => {}
            "content-length" => {
                if content_length.is_some() {
                    return Ok(reject(
                        400,
                        "Bad Request",
                        "Duplicate Content-Length header.",
                    ));
                }
                let length = match value.parse::<usize>() {
                    Ok(length) if length <= MAX_BODY_BYTES => length,
                    Ok(_) => {
                        return Ok(reject(
                            413,
                            "Content Too Large",
                            "Request body is too large.",
                        ));
                    }
                    Err(_) => {
                        return Ok(reject(400, "Bad Request", "Invalid Content-Length header."));
                    }
                };
                content_length = Some(length);
                write!(&mut forwarded, "Content-Length: {length}\r\n")?;
            }
            "transfer-encoding" | "expect" | "upgrade" => {
                return Ok(reject(
                    400,
                    "Bad Request",
                    "Unsupported HTTP request framing.",
                ));
            }
            "connection" | "proxy-connection" | "keep-alive" => {}
            _ => {
                forwarded_headers.push((name.to_string(), value.to_string()));
                forwarded.extend_from_slice(name.as_bytes());
                forwarded.extend_from_slice(b": ");
                forwarded.extend_from_slice(header.value);
                forwarded.extend_from_slice(b"\r\n");
            }
        }
    }

    let allowed_host_ip = format!("127.0.0.1:{port}");
    let allowed_host_name = format!("localhost:{port}");
    if !matches!(host, Some(value) if value.eq_ignore_ascii_case(&allowed_host_ip) || value.eq_ignore_ascii_case(&allowed_host_name))
    {
        return Ok(reject(
            403,
            "Forbidden",
            "Forbidden: Host header failed validation.",
        ));
    }

    let allowed_origin_ip = format!("http://127.0.0.1:{port}");
    let allowed_origin_name = format!("http://localhost:{port}");
    if !origin.is_none_or(|value| value == allowed_origin_ip || value == allowed_origin_name) {
        return Ok(reject(
            403,
            "Forbidden",
            "Forbidden: Origin header failed validation.",
        ));
    }

    if is_api_path(path)
        && !provided_token
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), token.as_bytes()))
    {
        return Ok(reject(
            401,
            "Unauthorized",
            "Unauthorized: missing or invalid X-Outcall-Token.",
        ));
    }

    let content_length = content_length.unwrap_or(0);
    let buffered_body = bytes[header_end..].to_vec();
    if buffered_body.len() > content_length {
        return Ok(reject(
            400,
            "Bad Request",
            "Unexpected bytes after the declared request body.",
        ));
    }

    forwarded.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(RequestDecision::Forward(ValidatedRequest {
        method: method.to_string(),
        path: path.to_string(),
        forwarded_headers,
        headers: forwarded,
        buffered_body,
        content_length,
    }))
}

pub(super) fn write_plain_response(
    stream: &mut impl Write,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn read_headers(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while bytes.len() < MAX_HEADER_BYTES {
        let remaining = MAX_HEADER_BYTES - bytes.len();
        let read_length = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_length])?;
        if count == 0 {
            return Ok(Some(bytes));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if find_header_end(&bytes).is_some() {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn set_once<'a>(slot: &mut Option<&'a str>, value: &'a str) -> bool {
    slot.replace(value).is_none()
}

fn is_api_path(path: &str) -> bool {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    path == "/api" || path.starts_with("/api/") || path == "/v1" || path.starts_with("/v1/")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn reject(status: u16, reason: &'static str, body: &'static str) -> RequestDecision {
    RequestDecision::Reject {
        status,
        reason,
        body,
    }
}
