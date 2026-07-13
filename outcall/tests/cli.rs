//! CLI unit tests — S012-FR-006.
//!
//! Tests clap argument parsing correctness.
//! These tests spawn the actual `outcall` binary; no daemon required.

use std::process::Command;
use tempfile::tempdir;

fn outcall(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "-q", "--"])
        .args(args)
        .output()
        .expect("cargo run failed")
}

fn outcall_in_dir(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let manifest = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    Command::new("cargo")
        .args(["run", "-q", "--manifest-path", &manifest, "--"])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("cargo run failed")
}

fn outcall_in_dir_clean_env(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let manifest = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    Command::new("cargo")
        .args(["run", "-q", "--manifest-path", &manifest, "--"])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("CODEX_ACCESS_TOKEN")
        .env_remove("CODEX_API_KEY")
        .output()
        .expect("cargo run failed")
}

fn outcall_in_dir_with_env(
    dir: &std::path::Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let manifest = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new("cargo");
    command
        .args(["run", "-q", "--manifest-path", &manifest, "--"])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("CODEX_ACCESS_TOKEN")
        .env_remove("CODEX_API_KEY");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("cargo run failed")
}

fn assert_connect_or_success(err: &str, status: std::process::ExitStatus, label: &str) {
    assert!(
        status.success()
            || err.contains("cannot connect")
            || err.contains("permission denied")
            || err.contains("daemon API request"),
        "{label}: expected connect or success, got {:?}: {err}",
        status
    );
}

// ── Clap argument parsing ───────────────────────────────────────────────────

#[test]
fn cli_without_subcommand_prints_onboarding() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_clean_env(temp.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "expected onboarding output: {stderr}");
    assert!(
        stdout.contains("Recommended first command:\n  outcall run claude"),
        "expected explicit recipe recommendation, got: {stdout}"
    );
    assert!(
        stdout.contains("outcall setup"),
        "expected setup shortcut in onboarding output, got: {stdout}"
    );
}

#[test]
fn cli_without_subcommand_with_ambiguous_auth_prints_explicit_choices() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &[],
        &[
            ("ANTHROPIC_API_KEY", "test-anthropic"),
            ("CODEX_API_KEY", "test-codex"),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "expected onboarding output: {stderr}");
    assert!(
        stdout.contains("Recommended first command:\n  outcall run claude\n  outcall run codex"),
        "expected explicit recipe choices, got: {stdout}"
    );
}

#[test]
fn cli_unknown_subcommand_exits_nonzero() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "foobar"]);
    assert!(!out.status.success(), "should fail with unknown subcommand");
}

#[test]
fn cli_bridge_subcommand_parses() {
    for action in ["status", "up", "down"] {
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "bridge", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_connect_or_success(&stderr, out.status, &format!("bridge {action}"));
    }
}

#[test]
fn cli_dns_subcommand_parses() {
    for action in ["status", "cache", "flush"] {
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "dns", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_connect_or_success(&stderr, out.status, &format!("dns {action}"));
    }
}

#[test]
fn cli_dns_test_requires_hostname() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "dns", "test"]);
    assert!(
        !out.status.success(),
        "dns test with no hostname should fail"
    );
}

#[test]
fn cli_dns_test_with_hostname_parses() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "dns",
        "test",
        "google.com",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "dns test google.com");
}

#[test]
fn cli_dns_test_record_type_flag() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "dns",
        "test",
        "--type",
        "AAAA",
        "google.com",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "dns test --type AAAA");
}

#[test]
fn cli_proxy_subcommand_parses() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "proxy", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "proxy status");
}

#[test]
fn cli_network_subcommands_parse() {
    for action in ["list", "create"] {
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "network", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_connect_or_success(&stderr, out.status, &format!("network {action}"));
    }
}

#[test]
fn cli_network_create_with_options() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "network",
        "create",
        "--name",
        "testnet",
        "--subnet",
        "10.201.0.0/24",
        "--gateway",
        "10.201.0.1",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "network create with all options");
}

#[test]
fn cli_container_subcommands_parse() {
    {
        let action = "list";
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_connect_or_success(&stderr, out.status, &format!("container {action}"));
    }
}

#[test]
fn cli_container_create_requires_image() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", "create"]);
    assert!(
        !out.status.success(),
        "container create with no image should fail"
    );
}

#[test]
fn cli_custom_socket_flag() {
    let out = outcall(&["--socket", "/tmp/custom.sock", "bridge", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "custom --socket");
}

#[test]
fn cli_default_socket_flag_is_optional() {
    // Pass nothing — should use DEFAULT_HOST_SOCKET
    let out = outcall(&["bridge", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(
        &stderr,
        out.status,
        "default socket should be used when --socket omitted",
    );
}

#[test]
fn cli_container_inspect_requires_name() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", "inspect"]);
    assert!(
        !out.status.success(),
        "container inspect with no name should fail"
    );
}

#[test]
fn cli_container_stop_requires_name() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", "stop"]);
    assert!(
        !out.status.success(),
        "container stop with no name should fail"
    );
}

#[test]
fn cli_container_remove_requires_name() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", "remove"]);
    assert!(
        !out.status.success(),
        "container remove with no name should fail"
    );
}

#[test]
fn cli_network_destroy_with_name() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "network",
        "destroy",
        "--name",
        "testnet",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "network destroy --name");
}

#[test]
fn cli_network_status_with_name() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "network",
        "status",
        "--name",
        "testnet",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "network status --name");
}

#[test]
fn cli_container_create_with_all_options() {
    let out = outcall(&[
        "--socket",
        "/tmp/nonexistent.sock",
        "container",
        "create",
        "--image",
        "outcall-dev/agent:latest",
        "--network",
        "outcall-default",
        "--name",
        "my-agent",
        "--memory",
        "256m",
        "--cpu-shares",
        "512",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_connect_or_success(&stderr, out.status, "container create with all options");
}

#[test]
fn cli_recipe_subcommands_parse_without_daemon() {
    for args in [
        vec!["recipe", "list"],
        vec!["recipe", "show", "claude"],
        vec!["recipe", "doctor", "codex"],
        vec!["recipe", "test", "claude", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "recipe command {:?} should not require daemon: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_recipe_unknown_recipe_exits_nonzero() {
    let out = outcall(&["recipe", "show", "missing"]);
    assert!(
        !out.status.success(),
        "unknown recipe should fail with a useful error"
    );
}

#[test]
fn cli_top_level_doctor_parses_without_daemon() {
    for args in [vec!["doctor"], vec!["doctor", "codex"]] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "doctor command {:?} should not require daemon: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_top_level_init_help_parses() {
    for args in [vec!["init", "--help"], vec!["init", "claude", "--help"]] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "init help {:?} should parse: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_top_level_setup_help_parses() {
    for args in [
        vec!["setup", "--help"],
        vec!["setup", "claude", "--help"],
        vec!["setup", "--auth", "mount", "--help"],
        vec!["setup", "codex", "--auth", "mount", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "setup help {:?} should parse: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_top_level_run_help_parses() {
    for args in [
        vec!["run", "--help"],
        vec!["run", "claude", "--help"],
        vec!["run", "codex", "--auth", "mount", "--help"],
        vec!["run", "codex", "--name", "review-1", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "run help {:?} should parse: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_auth_stages_detected_env_credentials_without_docker() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &["auth", "codex", "--auth", "env-only"],
        &[("CODEX_API_KEY", "test-codex-key")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "auth should succeed: {stderr}");
    assert!(
        stdout.contains("Authentication ready for Codex CLI"),
        "expected auth confirmation, got: {stdout}"
    );
    assert!(
        temp.path().join(".outcall/default-recipe").exists(),
        "auth should persist the selected project recipe"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".outcall/auth/codex/mode"))
            .expect("read saved auth mode"),
        "env-only",
        "auth should persist the explicit mode for subsequent auto runs"
    );
}

#[test]
fn cli_allow_edits_project_rule_yaml_without_docker() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_clean_env(temp.path(), &["allow", "codex", "https://api.sentry.io"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "allow should succeed: {stderr}");
    assert!(
        stdout.contains("Default deny remains active"),
        "expected default deny reminder, got: {stdout}"
    );
    let rules = std::fs::read_to_string(temp.path().join(".outcall/rules/codex.yaml"))
        .expect("read generated rules");
    assert!(rules.contains("codex-host-api-sentry-io"));
    assert!(rules.contains("codex-github"));
}

#[test]
fn cli_first_run_convenience_commands_render_help() {
    for args in [
        vec!["doctor", "--fix", "--help"],
        vec!["auth", "--help"],
        vec!["allow", "--help"],
        vec!["policy", "explain", "--help"],
        vec!["ps", "--help"],
        vec!["logs", "--help"],
        vec!["stop", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "help {:?} should parse: {stderr}",
            args
        );
    }
}

#[test]
fn cli_start_alias_is_not_available() {
    let temp = tempdir().expect("tempdir");
    for args in [&["start"][..], &["recipe", "run", "codex"][..]] {
        let out = outcall_in_dir_clean_env(temp.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "launch alias should fail: {args:?}");
        assert!(
            stderr.contains("unrecognized subcommand"),
            "expected removed alias error for {args:?}, got: {stderr}"
        );
    }
}

#[test]
fn cli_top_level_doctor_reports_project_default_recipe() {
    let temp = tempdir().expect("tempdir");
    let init = outcall_in_dir(temp.path(), &["init", "codex"]);
    let init_stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        init.status.success(),
        "init codex should succeed: {init_stderr}"
    );

    let out = outcall_in_dir_clean_env(temp.path(), &["doctor"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "doctor should succeed: {stderr}");
    assert!(
        stdout.contains("selected recipe: codex"),
        "doctor should report the saved default recipe, got: {stdout}"
    );
    assert!(
        stdout.contains("project default recipe: codex"),
        "doctor should recommend the explicit saved recipe, got: {stdout}"
    );
}

#[test]
fn cli_top_level_init_recipe_works_in_clean_project() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir(temp.path(), &["init", "claude"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "init claude should succeed: {stderr}");

    assert!(
        temp.path().join(".outcall/agent.yaml").exists(),
        "recipe init should create agent.yaml"
    );
    assert!(
        temp.path()
            .join(".outcall/recipes/claude/recipe.yaml")
            .exists(),
        "recipe init should create recipe manifest"
    );
}

#[test]
fn cli_top_level_init_without_recipe_points_to_explicit_runs() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_clean_env(temp.path(), &["init"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "init should succeed: {stderr}");
    assert!(
        stdout.contains("outcall run claude") && stdout.contains("outcall run codex"),
        "init should recommend explicit recipe runs, got: {stdout}"
    );
}

#[test]
fn cli_top_level_init_without_recipe_saves_single_detected_provider() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(temp.path(), &["init"], &[("ANTHROPIC_API_KEY", "test-key")]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "init should succeed: {stderr}");
    assert!(
        stdout.contains("selected default recipe: claude"),
        "init should save the detected provider for later setup commands, got: {stdout}"
    );
}

#[test]
fn cli_top_level_doctor_recommends_recipe_for_single_detected_provider() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &["doctor"],
        &[("ANTHROPIC_API_KEY", "test-key")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "doctor should succeed: {stderr}");
    assert!(
        stdout.contains("auth candidate found"),
        "doctor should report detected auth candidates, got: {stdout}"
    );
    assert!(
        stdout.contains("Recommended first command:\n  outcall run claude"),
        "doctor should recommend the detected explicit recipe, got: {stdout}"
    );
}

#[test]
fn cli_top_level_setup_without_recipe_uses_detected_provider() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &["setup", "--no-build"],
        &[("ANTHROPIC_API_KEY", "test-key")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("Setting up recipe: claude"),
        "setup should auto-detect claude before deeper checks, got stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn cli_top_level_setup_without_recipe_shows_explicit_ambiguity_guidance() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &["setup"],
        &[
            ("ANTHROPIC_API_KEY", "test-anthropic"),
            ("CODEX_API_KEY", "test-codex"),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "ambiguous setup should fail");
    assert!(
        stderr.contains("outcall run claude") && stderr.contains("outcall run codex"),
        "setup ambiguity should explain explicit recipe choices, got: {stderr}"
    );
}
