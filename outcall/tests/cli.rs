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

// ── Clap argument parsing ───────────────────────────────────────────────────

#[test]
fn cli_missing_subcommand_exits_nonzero() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock"]);
    assert!(!out.status.success(), "should fail with no subcommand");
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
        assert!(
            out.status.success() || stderr.contains("cannot connect"),
            "bridge {action}: expected connection error or success, got {:?}: {}",
            out.status,
            stderr
        );
    }
}

#[test]
fn cli_dns_subcommand_parses() {
    for action in ["status", "cache", "flush"] {
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "dns", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || stderr.contains("cannot connect"),
            "dns {action}: expected connection error or success"
        );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "dns test google.com should parse"
    );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "dns test --type AAAA should parse"
    );
}

#[test]
fn cli_proxy_subcommand_parses() {
    let out = outcall(&["--socket", "/tmp/nonexistent.sock", "proxy", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "proxy status should parse"
    );
}

#[test]
fn cli_network_subcommands_parse() {
    for action in ["list", "create"] {
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "network", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || stderr.contains("cannot connect"),
            "network {action} should parse"
        );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "network create with all options should parse"
    );
}

#[test]
fn cli_container_subcommands_parse() {
    {
        let action = "list";
        let out = outcall(&["--socket", "/tmp/nonexistent.sock", "container", action]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || stderr.contains("cannot connect"),
            "container {action} should parse"
        );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "custom --socket should be accepted"
    );
}

#[test]
fn cli_default_socket_flag_is_optional() {
    // Pass nothing — should use DEFAULT_HOST_SOCKET
    let out = outcall(&["bridge", "status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "default socket should be used when --socket omitted"
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "network destroy --name should parse"
    );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "network status --name should parse"
    );
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
    assert!(
        out.status.success() || stderr.contains("cannot connect"),
        "container create with all options should parse"
    );
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
fn cli_top_level_start_help_parses() {
    for args in [
        vec!["start", "--help"],
        vec!["start", "claude", "--help"],
        vec!["start", "codex", "--auth", "mount", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "start help {:?} should parse: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_top_level_recipe_alias_help_parses() {
    for args in [
        vec!["claude", "--help"],
        vec!["claude", "--auth", "mount", "--help"],
        vec!["codex", "--help"],
        vec!["codex", "--detach", "--help"],
    ] {
        let out = outcall(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "recipe alias help {:?} should parse: {}",
            args,
            stderr
        );
    }
}

#[test]
fn cli_top_level_start_without_detectable_auth_exits_usefully() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_clean_env(temp.path(), &["start"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "start with no auth should fail");
    assert!(
        stderr.contains("could not infer which agent to start"),
        "expected a useful detection error, got: {stderr}"
    );
}

#[test]
fn cli_top_level_start_forwards_agent_args_without_treating_them_as_recipe() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_with_env(
        temp.path(),
        &["start", "--", "--version"],
        &[("ANTHROPIC_API_KEY", "test-key")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unknown recipe \"--version\""),
        "start should not treat forwarded args as a recipe: {stderr}"
    );
    assert!(
        stdout.contains("Starting with recipe: claude"),
        "start should auto-detect claude before forwarding args, got stdout: {stdout}"
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
fn cli_top_level_init_without_recipe_points_to_start() {
    let temp = tempdir().expect("tempdir");
    let out = outcall_in_dir_clean_env(temp.path(), &["init"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "init should succeed: {stderr}");
    assert!(
        stdout.contains("outcall start"),
        "init should recommend outcall start, got: {stdout}"
    );
}

#[test]
fn cli_top_level_doctor_recommends_start_for_single_detected_provider() {
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
        stdout.contains("Recommended first command:\n  outcall start"),
        "doctor should recommend outcall start for a single provider, got: {stdout}"
    );
}
