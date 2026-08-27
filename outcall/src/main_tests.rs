use super::{
    BrokerToolExecRequest, Cli, CommandTimeoutError, Commands, HostBrokerAction, RecipeAuthMode,
    automatic_name_retry_candidate, broker_error_status, broker_exec_tool,
    command_output_with_timeout, daemon_build_inputs, doctor_platform_line_for,
    ensure_recipe_setup_state, handle_broker_connection, host_broker_transport_rule_path,
    is_container_name_conflict, protected_outcall_mount, read_http_request,
    remove_invalid_host_broker_transport_rule, resolve_broker_auth_token, resolve_host_file_path,
    resolve_recipe_auth_mode, retry_with_delay, rewrite_container_output_path,
    rewrite_recipe_entrypoint_args, runtime_bridge_netfilter_line,
    valid_host_broker_transport_rule, write_host_broker_transport_rule,
};
use crate::host_broker::BrokerError;
use clap::Parser;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn doctor_platform_message_covers_linux_macos_and_other_hosts() {
    assert_eq!(
        doctor_platform_line_for("linux"),
        "  PASS platform: Linux host (native daemon runtime available)"
    );
    assert_eq!(
        doctor_platform_line_for("macos"),
        "  INFO platform: macOS host detected; CLI runs locally and Outcall uses Docker Desktop's Linux runtime for the daemon and agent containers"
    );
    assert_eq!(
        doctor_platform_line_for("windows"),
        "  WARN platform: windows host detected; the isolated daemon runtime still requires Linux"
    );
}

#[test]
fn runtime_bridge_netfilter_message_reports_enforceability() {
    assert!(runtime_bridge_netfilter_line("1", "1").contains("PASS secure unattended mode"));
    assert!(runtime_bridge_netfilter_line("0", "1").contains("WARN secure unattended mode"));
}

#[test]
fn top_level_stop_accepts_keep_for_postmortem_inspection() {
    let cli = Cli::try_parse_from(["outcall", "stop", "agent-1", "--keep"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Commands::Stop { name, keep }) if name == "agent-1" && keep
    ));
}

#[test]
fn automatic_name_retries_with_incremented_candidate() {
    assert_eq!(
        automatic_name_retry_candidate(true, 0, "foobar-4"),
        Some("foobar-5".to_string())
    );
    assert_eq!(automatic_name_retry_candidate(false, 0, "fixed"), None);
    assert_eq!(
        automatic_name_retry_candidate(true, 1_000, "foobar-4"),
        None
    );
}

#[test]
fn automatic_name_retry_requires_numeric_suffix_for_fallback() {
    assert_eq!(automatic_name_retry_candidate(true, 0, "foobar"), None);
    assert_eq!(
        automatic_name_retry_candidate(true, 0, "foobar-final"),
        None
    );
    assert_eq!(
        automatic_name_retry_candidate(true, 0, "foobar-4294967295"),
        None
    );
}

#[test]
fn container_name_conflict_detection_is_specific() {
    assert!(is_container_name_conflict(
        "daemon request failed with status code 409: Conflict. The container name \"/foobar-4\" is already in use"
    ));
    assert!(is_container_name_conflict(
        "STATUS CODE 409: CONTAINER NAME /FOOBAR-4 IS ALREADY IN USE"
    ));
    assert!(!is_container_name_conflict(
        "daemon request failed with status code 500: container name lookup failed"
    ));
    assert!(!is_container_name_conflict(
        "daemon request failed with status code 409: image is already in use"
    ));
}

#[test]
fn automatic_auth_prefers_environment_credentials() {
    assert_eq!(
        resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, true, true),
        RecipeAuthMode::EnvOnly
    );
    assert_eq!(
        resolve_recipe_auth_mode(
            RecipeAuthMode::Auto,
            Some(RecipeAuthMode::Mount),
            true,
            false,
        ),
        RecipeAuthMode::Mount
    );
}

#[test]
fn automatic_auth_falls_back_to_project_copy_then_env_only() {
    assert_eq!(
        resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, false, true),
        RecipeAuthMode::Copy
    );
    assert_eq!(
        resolve_recipe_auth_mode(RecipeAuthMode::Auto, None, false, false),
        RecipeAuthMode::EnvOnly
    );
    assert_eq!(
        resolve_recipe_auth_mode(RecipeAuthMode::Copy, None, true, true),
        RecipeAuthMode::Copy
    );
    assert_eq!(
        resolve_recipe_auth_mode(
            RecipeAuthMode::Auto,
            Some(RecipeAuthMode::Auto),
            false,
            true,
        ),
        RecipeAuthMode::Copy
    );
}

#[test]
fn top_level_inspect_accepts_a_positional_managed_container_name() {
    let cli = Cli::try_parse_from(["outcall", "inspect", "foobar-1"])
        .expect("parse top-level inspect command");

    let Some(Commands::Inspect { name }) = cli.command else {
        panic!("expected inspect command");
    };
    assert_eq!(name, "foobar-1");
}

#[test]
fn command_output_with_timeout_returns_output_for_fast_command() {
    let output = command_output_with_timeout("sh", &["-c", "printf ok"], Duration::from_secs(1))
        .expect("fast command should succeed");
    assert!(
        output.status.success(),
        "fast command should exit successfully"
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
}

#[test]
fn command_output_with_timeout_times_out_slow_command() {
    let err = command_output_with_timeout("sh", &["-c", "sleep 2"], Duration::from_millis(100))
        .expect_err("slow command should time out");
    assert!(
        matches!(err, CommandTimeoutError::TimedOut { .. }),
        "expected timeout error, got: {err:?}"
    );
}

#[test]
fn retry_with_delay_recovers_from_transient_failures() {
    let mut attempts = 0;
    let result = retry_with_delay(3, Duration::ZERO, || {
        attempts += 1;
        if attempts < 3 {
            Err("not ready")
        } else {
            Ok("ready")
        }
    });

    assert_eq!(result, Ok("ready"));
    assert_eq!(attempts, 3);
}

#[test]
fn retry_with_delay_treats_zero_attempts_as_one() {
    let mut attempts = 0;
    let result = retry_with_delay(0, Duration::ZERO, || {
        attempts += 1;
        Err::<(), _>("not ready")
    });

    assert_eq!(result, Err("not ready"));
    assert_eq!(attempts, 1);
}

#[test]
fn rewrite_container_output_path_maps_absolute_workspace_paths() {
    let rewritten = rewrite_container_output_path(
        Path::new("/tmp/project"),
        "/workspace",
        "/tmp/project/out/last.txt",
    )
    .expect("workspace path should rewrite");
    assert_eq!(rewritten, "/workspace/out/last.txt");
}

#[test]
fn rewrite_container_output_path_rejects_paths_outside_workspace() {
    let err = rewrite_container_output_path(
        Path::new("/tmp/project"),
        "/workspace",
        "/tmp/elsewhere/last.txt",
    )
    .expect_err("external path should be rejected");
    assert!(
        err.to_string().contains("outside the mounted workspace"),
        "unexpected error: {err}"
    );
}

#[test]
fn rewrite_recipe_entrypoint_args_updates_output_flag_values() {
    let temp = tempdir().expect("tempdir");
    let rewritten = rewrite_recipe_entrypoint_args(
        temp.path(),
        "/workspace",
        vec![
            "exec".into(),
            "--output-last-message".into(),
            temp.path().join("out.txt").display().to_string(),
            format!(
                "--output-last-message={}",
                temp.path().join("out2.txt").display()
            ),
        ],
    )
    .expect("args should rewrite");
    assert_eq!(
        rewritten,
        vec![
            "exec",
            "--output-last-message",
            "/workspace/out.txt",
            "--output-last-message=/workspace/out2.txt",
        ]
    );
}

#[test]
fn ensure_recipe_setup_state_is_idempotent_without_force() {
    let temp = tempdir().expect("tempdir");
    let recipe = outcall::recipes::get_recipe("codex").expect("codex recipe");
    ensure_recipe_setup_state(temp.path(), recipe, false).expect("first setup should succeed");
    ensure_recipe_setup_state(temp.path(), recipe, false)
        .expect("second setup should keep existing files");
    let default_recipe = std::fs::read_to_string(temp.path().join(".outcall/default-recipe"))
        .expect("default recipe should exist");
    assert_eq!(default_recipe.trim(), "codex");
}

#[test]
fn broker_http_parser_finishes_without_client_eof() {
    let (mut client, mut server) = UnixStream::pair().expect("socket pair");
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    client
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");

    let request = read_http_request(&mut server).expect("parse request");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/v1/health");
    assert!(request.body.is_empty());
}

#[test]
fn broker_http_parser_reads_content_length_body() {
    let (mut client, mut server) = UnixStream::pair().expect("socket pair");
    let body = br#"{"id":"demo"}"#;
    let request = format!(
        "POST /v1/tool/exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    client
        .write_all(request.as_bytes())
        .expect("write request headers");
    client.write_all(body).expect("write request body");

    let parsed = read_http_request(&mut server).expect("parse request");
    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.path, "/v1/tool/exec");
    assert_eq!(parsed.body, body);
}

#[test]
fn broker_rejects_invalid_token_before_loading_config() {
    let (mut client, mut server) = UnixStream::pair().expect("socket pair");
    let body = br#"{"id":"demo"}"#;
    let request = format!(
        "POST /v1/tool/exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    client
        .write_all(request.as_bytes())
        .expect("write request headers");
    client.write_all(body).expect("write request body");
    client.shutdown(Shutdown::Write).expect("finish request");

    handle_broker_connection(
        &mut server,
        "/tmp/missing-outcall.sock",
        Path::new("/tmp/missing-host-resources.yaml"),
        "expected",
    )
    .expect("write forbidden response");
    drop(server);

    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(response.contains("invalid broker token"));
}

#[test]
fn broker_health_requires_the_shared_token() {
    let (mut client, mut server) = UnixStream::pair().expect("socket pair");
    client
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    client.shutdown(Shutdown::Write).expect("finish request");

    handle_broker_connection(
        &mut server,
        "/tmp/missing-outcall.sock",
        Path::new("/tmp/missing-host-resources.yaml"),
        "expected",
    )
    .expect("write forbidden response");
    drop(server);

    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(response.contains("invalid broker token"));
}

#[test]
fn broker_rejects_wrong_method_before_loading_config() {
    let (mut client, mut server) = UnixStream::pair().expect("socket pair");
    client
        .write_all(
            b"GET /v1/tool/exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer expected\r\n\r\n",
        )
        .expect("write request");
    client.shutdown(Shutdown::Write).expect("finish request");

    handle_broker_connection(
        &mut server,
        "/tmp/missing-outcall.sock",
        Path::new("/tmp/missing-host-resources.yaml"),
        "expected",
    )
    .expect("write method-not-allowed response");
    drop(server);

    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
}

#[test]
fn explicit_broker_token_takes_precedence() {
    let token = "0123456789abcdef0123456789abcdef";
    assert_eq!(
        resolve_broker_auth_token(Some(token.to_string())).unwrap(),
        token
    );
}

#[test]
fn broker_rejects_undeclared_tool_before_execution() {
    let config = outcall::host_resources::HostResourcesConfig::default();
    let error = broker_exec_tool(
        "/tmp/missing-outcall.sock",
        &config,
        BrokerToolExecRequest {
            id: "missing".to_string(),
            args: Vec::new(),
            cwd: None,
        },
    )
    .err()
    .expect("undeclared tool should fail");
    assert!(error.to_string().contains("host tool not declared"));
}

#[test]
fn broker_file_resolution_rejects_parent_traversal() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    std::fs::create_dir(&root).expect("create root");
    std::fs::write(temp.path().join("outside.txt"), "secret").expect("write fixture");

    let error = resolve_host_file_path(&root, Some("../outside.txt"))
        .expect_err("parent traversal should fail");
    assert!(
        error
            .to_string()
            .contains("escapes declared host file root")
    );
}

#[test]
fn broker_cli_keeps_daemon_and_listener_sockets_distinct() {
    let cli = Cli::try_parse_from([
        "outcall",
        "--socket",
        "/tmp/daemon.sock",
        "host-broker",
        "serve",
        "--broker-socket",
        "/tmp/broker.sock",
    ])
    .expect("parse broker command");
    assert_eq!(cli.socket, "/tmp/daemon.sock");
    let Some(Commands::HostBroker {
        action: HostBrokerAction::Serve { broker_socket, .. },
    }) = cli.command
    else {
        panic!("expected host broker serve command");
    };
    assert_eq!(broker_socket, "/tmp/broker.sock");
}

#[test]
fn broker_cli_parses_loopback_tcp_listener() {
    let cli = Cli::try_parse_from([
        "outcall",
        "--socket",
        "/tmp/daemon.sock",
        "host-broker",
        "serve-tcp",
        "--listen",
        "127.0.0.1:19001",
    ])
    .expect("parse TCP broker command");
    assert_eq!(cli.socket, "/tmp/daemon.sock");
    let Some(Commands::HostBroker {
        action: HostBrokerAction::ServeTcp { listen, .. },
    }) = cli.command
    else {
        panic!("expected host broker serve-tcp command");
    };
    assert_eq!(listen, "127.0.0.1:19001");
}

#[test]
fn broker_transport_rule_allows_only_the_selected_proxy_port() {
    let temp = tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join(".outcall/rules")).expect("create rules dir");

    write_host_broker_transport_rule(temp.path(), 17890).expect("write transport rule");

    let path = host_broker_transport_rule_path(temp.path());
    let rule = std::fs::read_to_string(path).expect("read transport rule");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&rule).expect("transport rule should be valid YAML");
    assert_eq!(
        document["rules"]
            .as_sequence()
            .expect("rules should be a sequence")
            .len(),
        1
    );
    assert!(valid_host_broker_transport_rule(&rule));
    assert!(rule.contains("http.host == \"host.docker.internal\""));
    assert!(rule.contains("network.port == 17890"));
    assert!(rule.contains("mode: proxy"));
    assert!(rule.contains("ports: [17890]"));
    assert!(rule.contains("allow_private_ips: true"));
    assert!(!rule.contains("direct"));
}

#[test]
fn invalid_generated_broker_rule_is_removed_before_reload() {
    let temp = tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join(".outcall/rules")).expect("create rules dir");
    let path = host_broker_transport_rule_path(temp.path());
    std::fs::write(
        &path,
        "version: \"1\"\nrules:\n- id: bad\ndescription: invalid\n",
    )
    .expect("write invalid rule");

    assert!(
        remove_invalid_host_broker_transport_rule(temp.path())
            .expect("remove invalid generated rule")
    );
    assert!(!path.exists());
}

#[test]
fn project_policy_is_overlay_mounted_read_only() {
    let temp = tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join(".outcall")).expect("create policy dir");
    let source =
        std::fs::canonicalize(temp.path().join(".outcall")).expect("canonicalize policy dir");

    let mount = protected_outcall_mount(temp.path(), "/workspace/").expect("build protected mount");

    assert_eq!(
        mount,
        format!("{}:/workspace/.outcall:ro", source.display())
    );
}

#[test]
fn broker_errors_use_security_appropriate_http_statuses() {
    assert_eq!(
        broker_error_status(&BrokerError::Forbidden("blocked by rules".to_string())),
        403
    );
    assert_eq!(
        broker_error_status(&BrokerError::Forbidden(
            "resolved path escapes declared host file root".to_string()
        )),
        403
    );
    assert_eq!(
        broker_error_status(&BrokerError::BadRequest(
            "relative_path is required for directory resources".to_string()
        )),
        400
    );
    assert_eq!(
        broker_error_status(&BrokerError::Internal(anyhow::anyhow!(
            "failed to execute host tool at /secret/path"
        ))),
        500
    );
    assert_eq!(
        broker_error_status(&BrokerError::TooLarge(
            "host file exceeds 10 bytes".to_string()
        )),
        413
    );
    assert_eq!(
        broker_error_status(&BrokerError::Timeout(
            "host tool timed out after 60 seconds".to_string()
        )),
        504
    );
    assert_eq!(
        BrokerError::Internal(anyhow::anyhow!("host path /secret/path")).to_string(),
        "internal host broker error"
    );
}

#[test]
fn daemon_build_uses_dockerfile_parent_as_context() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source");
    std::fs::create_dir(&source).expect("create source");
    let dockerfile = source.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM scratch\n").expect("write Dockerfile");

    let (resolved_dockerfile, context) =
        daemon_build_inputs(&dockerfile).expect("resolve build inputs");
    let expected_source = std::fs::canonicalize(&source).expect("canonicalize source");

    assert_eq!(resolved_dockerfile, expected_source.join("Dockerfile"));
    assert_eq!(context, expected_source);
}
