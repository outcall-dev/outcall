mod auth;
mod handler;
mod http;
mod operations;
mod protocol;
mod runtime;
mod server;

#[cfg(test)]
pub(crate) use handler::handle_broker_connection;
#[cfg(test)]
pub(crate) use http::read_http_request;
#[cfg(test)]
pub(crate) use operations::{broker_exec_tool, resolve_host_file_path};
#[cfg(test)]
pub(crate) use protocol::{BrokerError, BrokerToolExecRequest, broker_error_status};
#[cfg(test)]
pub(crate) use runtime::{
    host_broker_transport_rule_path, valid_host_broker_transport_rule,
    write_host_broker_transport_rule,
};

#[cfg(test)]
pub(crate) use auth::resolve_broker_auth_token;
pub(crate) use runtime::host_broker_diagnostic;
pub(crate) use runtime::{maybe_prepare_host_broker, remove_invalid_host_broker_transport_rule};
pub(crate) use server::{
    serve_tcp as cmd_host_broker_serve_tcp, serve_unix as cmd_host_broker_serve,
};

#[cfg(test)]
mod tests {
    use super::auth::resolve_broker_auth_token;
    use super::operations::{external_host_file_root, read_file_bounded, resolve_tool_cwd};
    use super::protocol::{
        BrokerError, BrokerResult, BrokerToolExecRequest, MAX_BROKER_ARG_BYTES,
        validate_tool_request, write_broker_result,
    };
    use super::server::bind_broker_socket;

    #[test]
    fn broker_token_rejects_short_values() {
        let error = resolve_broker_auth_token(Some("short".to_string()))
            .unwrap_err()
            .to_string();

        assert!(error.contains("32-256"));
    }

    #[test]
    fn broker_socket_does_not_replace_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("broker.sock");
        std::fs::write(&path, "keep").unwrap();

        let error = bind_broker_socket(path.to_str().unwrap())
            .unwrap_err()
            .to_string();

        assert!(error.contains("refusing to replace non-socket"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "keep");
    }

    #[test]
    fn tool_cwd_is_confined_to_the_project() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("subdir")).unwrap();
        let expected_project = std::fs::canonicalize(project.path()).unwrap();

        assert_eq!(
            resolve_tool_cwd(project.path(), None).unwrap(),
            expected_project
        );
        assert_eq!(
            resolve_tool_cwd(project.path(), Some("/workspace/subdir")).unwrap(),
            expected_project.join("subdir")
        );
        assert!(resolve_tool_cwd(project.path(), Some("/tmp")).is_err());
        assert!(resolve_tool_cwd(project.path(), Some("../")).is_err());
    }

    #[test]
    fn host_file_read_enforces_limit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file");
        std::fs::write(&path, "12345").unwrap();

        let error = read_file_bounded(&path, 4).unwrap_err().to_string();

        assert!(error.contains("exceeds 4 bytes"));
    }

    #[test]
    fn host_file_root_must_be_outside_project() {
        let project = tempfile::tempdir().unwrap();
        let file = project.path().join("notes");
        std::fs::write(&file, "private").unwrap();

        let error = external_host_file_root(project.path(), &file)
            .unwrap_err()
            .to_string();

        assert!(error.contains("inside the writable project"));
    }

    #[test]
    fn broker_requests_reject_unknown_fields_and_large_arguments() {
        let unknown = br#"{"id":"demo","args":[],"unexpected":true}"#;
        assert!(serde_json::from_slice::<BrokerToolExecRequest>(unknown).is_err());

        let request = BrokerToolExecRequest {
            id: "demo".to_string(),
            args: vec!["x".repeat(MAX_BROKER_ARG_BYTES + 1)],
            cwd: None,
        };
        assert!(validate_tool_request(&request).is_err());
    }

    #[test]
    fn internal_errors_do_not_leak_details_in_http_responses() {
        let mut response = Vec::new();
        let result: BrokerResult<serde_json::Value> = Err(BrokerError::internal(anyhow::anyhow!(
            "failed to access /Users/operator/private"
        )));

        write_broker_result(&mut response, result).unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(response.contains(r#""error":"internal host broker error""#));
        assert!(!response.contains("/Users/operator/private"));
    }
}
