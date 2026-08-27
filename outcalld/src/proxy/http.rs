use std::collections::{HashMap, HashSet};

const MAX_HEADERS: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum RequestError {
    #[error("malformed HTTP request")]
    Malformed,
    #[error("unsupported HTTP request framing")]
    UnsupportedFraming,
    #[error("HTTP request contains duplicate {0} headers")]
    DuplicateHeader(&'static str),
    #[error("HTTP request is missing the Host header")]
    MissingHost,
    #[error("HTTP Host header does not match the request target")]
    HostMismatch,
    #[error("HTTP request body exceeds {0} bytes")]
    BodyTooLarge(u64),
}

pub(super) struct ParsedRequest {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) headers: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RequestTarget {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) path: String,
}

pub(super) fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

pub(super) fn parse_request(bytes: &[u8]) -> Result<ParsedRequest, RequestError> {
    if bytes.starts_with(b"\r\n") {
        return Err(RequestError::Malformed);
    }

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(bytes).map_err(|_| RequestError::Malformed)? {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => return Err(RequestError::Malformed),
    };
    if consumed != bytes.len() || !matches!(request.version, Some(0 | 1)) {
        return Err(RequestError::Malformed);
    }

    let method = request.method.ok_or(RequestError::Malformed)?.to_string();
    let uri = request.path.ok_or(RequestError::Malformed)?.to_string();
    if method.is_empty() || uri.is_empty() {
        return Err(RequestError::Malformed);
    }

    let headers = request
        .headers
        .iter()
        .map(|header| {
            let value = std::str::from_utf8(header.value).map_err(|_| RequestError::Malformed)?;
            if value
                .chars()
                .any(|character| character.is_control() && character != '\t')
            {
                return Err(RequestError::Malformed);
            }
            Ok((
                header.name.to_string(),
                value.trim_matches([' ', '\t']).to_string(),
            ))
        })
        .collect::<Result<Vec<_>, RequestError>>()?;

    Ok(ParsedRequest {
        method,
        uri,
        headers,
    })
}

pub(super) fn parse_connect_target(value: &str) -> Result<RequestTarget, RequestError> {
    let (host, port) = parse_authority(value, 443)?;
    Ok(RequestTarget {
        host,
        port,
        path: "/".to_string(),
    })
}

pub(super) fn parse_absolute_http_uri(value: &str) -> Result<RequestTarget, RequestError> {
    let url = url::Url::parse(value).map_err(|_| RequestError::Malformed)?;
    if url.scheme() != "http"
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(RequestError::Malformed);
    }
    let host = normalized_url_host(&url)?;
    let port = url.port_or_known_default().ok_or(RequestError::Malformed)?;
    if port == 0 {
        return Err(RequestError::Malformed);
    }
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(RequestTarget { host, port, path })
}

pub(super) fn require_matching_host(
    headers: &[(String, String)],
    target_host: &str,
    target_port: u16,
    default_port: u16,
) -> Result<(), RequestError> {
    let mut values = header_values(headers, "host");
    let value = values.next().ok_or(RequestError::MissingHost)?;
    if values.next().is_some() {
        return Err(RequestError::DuplicateHeader("Host"));
    }
    let (host, port) = parse_authority(value, default_port)?;
    if host != target_host || port != target_port {
        return Err(RequestError::HostMismatch);
    }
    Ok(())
}

pub(super) fn request_body_length(
    headers: &[(String, String)],
    limit: u64,
) -> Result<u64, RequestError> {
    if header_values(headers, "transfer-encoding").next().is_some()
        || header_values(headers, "expect").next().is_some()
        || header_values(headers, "upgrade").next().is_some()
    {
        return Err(RequestError::UnsupportedFraming);
    }
    let mut values = header_values(headers, "content-length");
    let Some(value) = values.next() else {
        return Ok(0);
    };
    if values.next().is_some() {
        return Err(RequestError::DuplicateHeader("Content-Length"));
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RequestError::UnsupportedFraming);
    }
    let length = value
        .parse::<u64>()
        .map_err(|_| RequestError::UnsupportedFraming)?;
    if length > limit {
        return Err(RequestError::BodyTooLarge(limit));
    }
    Ok(length)
}

pub(super) fn policy_headers(headers: &[(String, String)]) -> HashMap<String, String> {
    let mut normalized = HashMap::new();
    for (name, value) in headers {
        normalized
            .entry(name.to_ascii_lowercase())
            .and_modify(|existing: &mut String| {
                existing.push_str(", ");
                existing.push_str(value);
            })
            .or_insert_with(|| value.clone());
    }
    normalized
}

pub(super) fn connection_header_tokens(headers: &[(String, String)]) -> HashSet<String> {
    header_values(headers, "connection")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &'static str,
) -> impl Iterator<Item = &'a str> {
    headers.iter().filter_map(move |(header, value)| {
        header.eq_ignore_ascii_case(name).then_some(value.as_str())
    })
}

fn parse_authority(value: &str, default_port: u16) -> Result<(String, u16), RequestError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.contains(['/', '?', '#', '@'])
    {
        return Err(RequestError::Malformed);
    }
    let url = url::Url::parse(&format!("http://{value}/")).map_err(|_| RequestError::Malformed)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RequestError::Malformed);
    }
    let host = normalized_url_host(&url)?;
    let port = url.port().unwrap_or(default_port);
    if port == 0 {
        return Err(RequestError::Malformed);
    }
    Ok((host, port))
}

fn normalized_url_host(url: &url::Url) -> Result<String, RequestError> {
    let host = match url.host().ok_or(RequestError::Malformed)? {
        url::Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    if host.is_empty() {
        return Err(RequestError::Malformed);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_and_rejects_malformed_headers() {
        let raw =
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let request = parse_request(raw).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "http://example.com/path");
        assert_eq!(request.headers.len(), 2);

        assert!(parse_request(b"GET / HTTP/1.1\r\nNoColon\r\n\r\n").is_err());
        assert!(parse_request(b"\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());
        assert!(parse_request(&[0xff, 0xfe, b'G']).is_err());
    }

    #[test]
    fn finds_header_boundary() {
        let bytes = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(bytes), Some(27));
        assert_eq!(find_header_end(&bytes[..26]), None);
    }

    #[test]
    fn parses_structured_http_targets() {
        assert_eq!(
            parse_absolute_http_uri("http://example.com:9090/api?q=1").unwrap(),
            RequestTarget {
                host: "example.com".to_string(),
                port: 9090,
                path: "/api?q=1".to_string(),
            }
        );
        assert_eq!(
            parse_absolute_http_uri("http://[::1]/").unwrap().host,
            "::1"
        );
        assert!(parse_absolute_http_uri("https://example.com/").is_err());
        assert!(parse_absolute_http_uri("http://user@example.com/").is_err());
        assert!(parse_absolute_http_uri("http://example.com/#fragment").is_err());
    }

    #[test]
    fn parses_connect_authorities_including_ipv6() {
        assert_eq!(
            parse_connect_target("example.com:8443").unwrap(),
            RequestTarget {
                host: "example.com".to_string(),
                port: 8443,
                path: "/".to_string(),
            }
        );
        assert_eq!(parse_connect_target("[::1]:443").unwrap().host, "::1");
        assert!(parse_connect_target("example.com:notaport").is_err());
        assert!(parse_connect_target("user@example.com:443").is_err());
    }

    #[test]
    fn requires_exactly_one_matching_host() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert!(require_matching_host(&headers, "example.com", 80, 80).is_ok());
        assert_eq!(
            require_matching_host(&[], "example.com", 80, 80),
            Err(RequestError::MissingHost)
        );
        let duplicate = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("host".to_string(), "example.com".to_string()),
        ];
        assert_eq!(
            require_matching_host(&duplicate, "example.com", 80, 80),
            Err(RequestError::DuplicateHeader("Host"))
        );
        assert_eq!(
            require_matching_host(&headers, "evil.example", 80, 80),
            Err(RequestError::HostMismatch)
        );
    }

    #[test]
    fn body_framing_is_explicit_and_bounded() {
        let content_length = vec![("Content-Length".to_string(), "5".to_string())];
        assert_eq!(request_body_length(&content_length, 10).unwrap(), 5);
        assert_eq!(request_body_length(&[], 10).unwrap(), 0);
        assert!(request_body_length(&content_length, 4).is_err());
        assert!(request_body_length(
            &[("Transfer-Encoding".to_string(), "chunked".to_string())],
            10
        )
        .is_err());
        assert!(request_body_length(
            &[
                ("Content-Length".to_string(), "5".to_string()),
                ("content-length".to_string(), "5".to_string()),
            ],
            10
        )
        .is_err());
    }

    #[test]
    fn policy_headers_preserve_duplicate_values() {
        let headers = vec![
            ("X-Scope".to_string(), "one".to_string()),
            ("x-scope".to_string(), "two".to_string()),
        ];
        assert_eq!(policy_headers(&headers).get("x-scope").unwrap(), "one, two");
    }
}
