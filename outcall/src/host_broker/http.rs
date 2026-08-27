use std::io::{Read, Write};

use anyhow::{Context, Result};

use crate::daemon_client::Response;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_PATH_BYTES: usize = 4_096;

pub(crate) struct RawHttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: std::collections::HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn read_http_request(stream: &mut impl Read) -> Result<RawHttpRequest> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            if position > MAX_HEADER_BYTES {
                anyhow::bail!("broker request headers exceed {MAX_HEADER_BYTES} bytes");
            }
            break position;
        }
        if raw.len() > MAX_HEADER_BYTES {
            anyhow::bail!("broker request headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading broker request headers");
        }
        raw.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8(raw[..header_end].to_vec()).context("invalid HTTP header")?;
    let mut lines = head.lines();
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing HTTP method")?.to_string();
    let path = parts
        .next()
        .context("missing HTTP request path")?
        .to_string();
    let version = parts.next().context("missing HTTP version")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        anyhow::bail!("invalid HTTP request line");
    }
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid HTTP method");
    }
    if !path.starts_with('/') || path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
        anyhow::bail!("invalid HTTP request path");
    }

    let mut headers = std::collections::HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').context("malformed HTTP header")?;
        if name.trim() != name || name.is_empty() || !name.bytes().all(valid_header_name_byte) {
            anyhow::bail!("invalid HTTP header name");
        }
        let value = value.trim();
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            anyhow::bail!("invalid HTTP header value");
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.to_string())
            .is_some()
        {
            anyhow::bail!("duplicate HTTP header {name}");
        }
        if headers.len() > 128 {
            anyhow::bail!("broker request has too many headers");
        }
    }
    if headers.contains_key("transfer-encoding") {
        anyhow::bail!("broker requests do not support Transfer-Encoding");
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("invalid Content-Length")?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        anyhow::bail!("broker request body exceeds {MAX_BODY_BYTES} bytes");
    }

    let body_start = header_end + 4;
    let message_end = body_start
        .checked_add(content_length)
        .context("broker request length overflow")?;
    if raw.len() > message_end {
        anyhow::bail!("broker request contains bytes after its declared body");
    }
    while raw.len() < message_end {
        let remaining = message_end - raw.len();
        let read_len = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_len])?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while reading broker request body");
        }
        raw.extend_from_slice(&chunk[..read]);
    }

    Ok(RawHttpRequest {
        method,
        path,
        headers,
        body: raw[body_start..message_end].to_vec(),
    })
}

fn valid_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(super) fn write_json<T: serde::Serialize>(
    stream: &mut impl Write,
    mut status: u16,
    body: &T,
) -> Result<()> {
    let mut json = serde_json::to_vec(body).context("failed to serialize broker response")?;
    if json.len() > MAX_RESPONSE_BYTES {
        status = 500;
        json = serde_json::to_vec(&Response {
            success: false,
            data: None,
            error: Some("host broker response exceeds configured limit".to_string()),
        })?;
    }
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        json.len()
    )?;
    stream.write_all(&json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_framing() {
        let duplicate =
            b"GET /v1/health HTTP/1.1\r\nAuthorization: first\r\nauthorization: second\r\n\r\n";
        assert!(read_http_request(&mut std::io::Cursor::new(duplicate)).is_err());

        let trailing = b"POST /v1/tool/exec HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}extra";
        assert!(read_http_request(&mut std::io::Cursor::new(trailing)).is_err());
    }

    #[test]
    fn rejects_header_terminator_beyond_limit() {
        let request = format!(
            "GET /v1/health HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_BYTES)
        );
        assert!(read_http_request(&mut std::io::Cursor::new(request)).is_err());
    }
}
