use super::*;

fn temp_project(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("outcall-recipe-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn finds_builtin_recipe() {
    assert!(get_recipe("claude").is_some());
    assert!(get_recipe("codex").is_some());
    assert!(get_recipe("missing").is_none());
}

#[test]
fn claude_recipe_supports_official_unattended_auth_variables() {
    let recipe = get_recipe("claude").unwrap();
    assert_eq!(
        recipe.auth_env,
        &[
            "CLAUDE_CODE_OAUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
        ]
    );
    assert_eq!(recipe.credential_paths, &["~/.claude/.credentials.json"]);
    assert_eq!(recipe.user_paths, &["~/.claude/.credentials.json"]);
    assert!(
        recipe
            .global_config_paths
            .contains(&"~/.claude/settings.json")
    );
    assert!(recipe.manifest.contains("default_mode: auto"));
    assert!(recipe.readme.contains("claude setup-token"));
    assert!(!recipe.readme.contains("outcall recipe doctor"));
}

#[test]
fn portable_credentials_are_distinct_from_general_user_config() {
    let home = temp_project("portable-credential");
    let recipe = get_recipe("claude").unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();

    assert!(!has_credential_file_in_home(recipe, &home));
    std::fs::write(home.join(".claude/.credentials.json"), "{}").unwrap();
    assert!(has_credential_file_in_home(recipe, &home));

    let _ = std::fs::remove_dir_all(home);
}

#[cfg(unix)]
#[test]
fn staged_credential_symlink_is_not_detected_or_chmodded() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = temp_project("credential-symlink");
    let host_home = dir.join("host-home");
    let staged_dir = dir.join(".outcall/home/claude/.claude");
    std::fs::create_dir_all(&host_home).unwrap();
    std::fs::create_dir_all(&staged_dir).unwrap();
    let sentinel = dir.join("sentinel");
    std::fs::write(&sentinel, "host-data").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&sentinel, staged_dir.join(".credentials.json")).unwrap();

    let recipe = get_recipe("claude").unwrap();
    assert!(!has_credential_file_in_home(
        recipe,
        &dir.join(".outcall/home/claude")
    ));
    stage_auth_copy_with_home(&dir, recipe, Some(&host_home), false).unwrap();

    let mode = std::fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claude_default_policy_allows_api_and_login_endpoints() {
    let rules = get_recipe("claude").unwrap().rules;
    for host in ["api.anthropic.com", "claude.ai", "platform.claude.com"] {
        assert!(rules.contains(host));
    }
}

#[test]
fn generated_proxy_policies_scope_http_hosts_to_https() {
    for recipe_id in ["claude", "codex"] {
        let recipe = get_recipe(recipe_id).unwrap();
        assert!(recipe.rules.contains("network.port == 443"));
        for template in recipe.policy_templates {
            assert!(
                template.condition.contains("network.port == 443"),
                "{} grant {} must require HTTPS",
                recipe.id,
                template.name
            );
        }
    }
}

#[test]
fn recipe_images_verify_agent_binary_during_build() {
    assert!(
        get_recipe("claude")
            .unwrap()
            .dockerfile
            .contains("&& claude --version")
    );
    assert!(
        get_recipe("codex")
            .unwrap()
            .dockerfile
            .contains("&& codex --version")
    );
}

#[test]
fn codex_recipe_uses_the_managed_container_as_its_sandbox_boundary() {
    let recipe = get_recipe("codex").unwrap();
    assert!(recipe.manifest.contains("entrypoint: outcall-codex"));
    assert!(
        recipe
            .dockerfile
            .contains("codex --sandbox danger-full-access")
    );
    assert!(recipe.dockerfile.contains("ENTRYPOINT [\"outcall-codex\"]"));
    assert!(recipe.readme.contains("outer security boundary"));
}

#[test]
fn claude_image_uses_anthropic_signed_stable_repository() {
    let dockerfile = get_recipe("claude").unwrap().dockerfile;
    assert!(dockerfile.contains("https://downloads.claude.ai/claude-code/apt/stable"));
    assert!(dockerfile.contains("signed-by=/etc/apt/keyrings/claude-code.asc"));
    assert!(dockerfile.contains("31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"));
    assert!(dockerfile.contains("apt-get install -y --no-install-recommends claude-code"));
    assert!(!dockerfile.contains("@anthropic-ai/claude-code"));
}

#[test]
fn init_recipe_writes_expected_files() {
    let dir = temp_project("init");
    let recipe = get_recipe("codex").unwrap();
    let written = init_recipe(&dir, recipe, false).unwrap();
    assert_eq!(written.len(), 8);
    assert!(dir.join(".outcall/recipes/codex/recipe.yaml").exists());
    assert!(dir.join(".outcall/recipes/codex/Dockerfile").exists());
    assert!(dir.join(".outcall/rules/codex.yaml").exists());
    assert!(dir.join(".outcall/agent.yaml").exists());
    assert!(dir.join(".outcall/host-resources.yaml").exists());
    assert!(dir.join(".outcall/.gitignore").exists());
    let agent_config = std::fs::read_to_string(dir.join(".outcall/agent.yaml")).unwrap();
    assert!(
        !agent_config.contains("name: codex-agent"),
        "generated agent config should not pin a provider-specific container name"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ensure_recipe_repairs_missing_files_and_preserves_existing_content() {
    let dir = temp_project("ensure");
    let recipe = get_recipe("codex").unwrap();
    init_recipe(&dir, recipe, false).unwrap();
    let manifest = dir.join(".outcall/recipes/codex/recipe.yaml");
    let dockerfile = dir.join(".outcall/recipes/codex/Dockerfile");
    std::fs::write(&manifest, "custom: true\n").unwrap();
    std::fs::remove_file(&dockerfile).unwrap();

    let written = ensure_recipe(&dir, recipe).unwrap();

    assert_eq!(std::fs::read_to_string(manifest).unwrap(), "custom: true\n");
    assert_eq!(
        std::fs::read_to_string(&dockerfile).unwrap(),
        recipe.dockerfile
    );
    assert_eq!(written, vec![std::fs::canonicalize(dockerfile).unwrap()]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn init_recipe_appends_auth_gitignore_entry() {
    let dir = temp_project("gitignore");
    std::fs::create_dir_all(dir.join(".outcall")).unwrap();
    std::fs::write(dir.join(".outcall/.gitignore"), "cache/\n").unwrap();

    let recipe = get_recipe("claude").unwrap();
    init_recipe(&dir, recipe, false).unwrap();

    let gitignore = std::fs::read_to_string(dir.join(".outcall/.gitignore")).unwrap();
    assert!(gitignore.contains("cache/\n"));
    assert!(gitignore.contains("auth/\n"));
    assert!(gitignore.contains("run/\n"));
    assert!(gitignore.contains("rules/.outcall-host-broker.yaml\n"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn init_recipe_switches_owned_agent_config_and_preserves_host_registry() {
    let dir = temp_project("switch");
    let codex = get_recipe("codex").unwrap();
    let claude = get_recipe("claude").unwrap();
    init_recipe(&dir, codex, false).unwrap();
    let registry = dir.join(".outcall/host-resources.yaml");
    std::fs::write(&registry, "version: \"1\"\ntools: []\nfiles: []\n").unwrap();

    init_recipe(&dir, claude, false).unwrap();

    assert_eq!(
        std::fs::read_to_string(dir.join(".outcall/agent.yaml")).unwrap(),
        claude.agent_config
    );
    assert_eq!(
        std::fs::read_to_string(registry).unwrap(),
        "version: \"1\"\ntools: []\nfiles: []\n"
    );
    assert!(dir.join(".outcall/recipes/codex/recipe.yaml").exists());
    assert!(dir.join(".outcall/recipes/claude/recipe.yaml").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn force_init_preserves_user_host_resource_registry() {
    let dir = temp_project("force-preserves-host-registry");
    let recipe = get_recipe("codex").unwrap();
    init_recipe(&dir, recipe, false).unwrap();
    let registry = dir.join(".outcall/host-resources.yaml");
    let custom = "version: \"1\"\ntools:\n  - id: browser\n    path: /usr/bin/browser\nfiles:\n  - id: notes\n    path: /tmp/notes\n";
    std::fs::write(&registry, custom).unwrap();

    let written = init_recipe(&dir, recipe, true).unwrap();

    assert_eq!(std::fs::read_to_string(&registry).unwrap(), custom);
    assert!(!written.contains(&registry));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn init_recipe_preserves_custom_shared_config() {
    let dir = temp_project("custom-shared");
    std::fs::create_dir_all(dir.join(".outcall")).unwrap();
    let config = dir.join(".outcall/agent.yaml");
    std::fs::write(&config, "resources:\n  memory: 2g\n").unwrap();

    init_recipe(&dir, get_recipe("codex").unwrap(), false).unwrap();

    assert_eq!(
        std::fs::read_to_string(config).unwrap(),
        "resources:\n  memory: 2g\n"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stage_auth_copy_preserves_home_relative_paths() {
    let dir = temp_project("auth-copy");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::write(home.join(".codex/auth.json"), "{}").unwrap();

    let recipe = get_recipe("codex").unwrap();
    let staged = stage_auth_copy_with_home(&dir, recipe, Some(&home), true).unwrap();

    assert_eq!(staged.copied.len(), 1);
    assert!(dir.join(".outcall/home/codex/.codex/auth.json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(".outcall/home/codex/.codex/auth.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn global_provider_config_is_copied_only_when_requested() {
    let dir = temp_project("auth-copy-global-config");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::write(home.join(".codex/auth.json"), "{}").unwrap();
    std::fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.host_only]\ncommand = '/Applications/host-tool'\n",
    )
    .unwrap();

    let recipe = get_recipe("codex").unwrap();
    let staged = stage_auth_copy_with_home(&dir, recipe, Some(&home), true).unwrap();
    assert_eq!(staged.copied.len(), 1);
    assert!(!dir.join(".outcall/home/codex/.codex/config.toml").exists());

    let staged = stage_auth_copy_with_home_options(&dir, recipe, Some(&home), true, true).unwrap();
    assert_eq!(staged.copied.len(), 2);
    assert!(dir.join(".outcall/home/codex/.codex/config.toml").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn global_provider_config_can_be_staged_without_copying_credentials() {
    let dir = temp_project("global-config-only");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::write(home.join(".codex/auth.json"), "{}").unwrap();
    std::fs::write(home.join(".codex/config.toml"), "model = 'gpt-5'\n").unwrap();

    let recipe = get_recipe("codex").unwrap();
    let staged = stage_global_config_copy_with_home(&dir, recipe, Some(&home), true).unwrap();

    assert_eq!(staged.copied.len(), 1);
    assert!(dir.join(".outcall/home/codex/.codex/config.toml").exists());
    assert!(!dir.join(".outcall/home/codex/.codex/auth.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stage_auth_copy_migrates_legacy_runtime_home_without_data_loss() {
    let dir = temp_project("auth-copy-legacy-home");
    let host_home = dir.join("host-home");
    std::fs::create_dir_all(&host_home).unwrap();
    let legacy = dir.join(".outcall/auth/claude/home/.claude");
    std::fs::create_dir_all(legacy.join("projects")).unwrap();
    std::fs::write(legacy.join(".credentials.json"), "{}").unwrap();
    std::fs::write(legacy.join("projects/session.jsonl"), "session").unwrap();

    let staged =
        stage_auth_copy_with_home(&dir, get_recipe("claude").unwrap(), Some(&host_home), false)
            .unwrap();

    assert_eq!(
        staged.home_dir,
        std::fs::canonicalize(&dir)
            .unwrap()
            .join(".outcall/home/claude")
    );
    assert!(staged.home_dir.join(".claude/.credentials.json").exists());
    assert!(
        staged
            .home_dir
            .join(".claude/projects/session.jsonl")
            .exists()
    );
    assert!(!dir.join(".outcall/auth/claude/home").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn stage_auth_copy_rejects_a_symlinked_legacy_home() {
    use std::os::unix::fs::symlink;

    let dir = temp_project("auth-copy-legacy-symlink");
    let host_home = dir.join("host-home");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&host_home).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(dir.join(".outcall/auth/claude")).unwrap();
    symlink(&outside, dir.join(".outcall/auth/claude/home")).unwrap();

    let error =
        stage_auth_copy_with_home(&dir, get_recipe("claude").unwrap(), Some(&host_home), false)
            .unwrap_err()
            .to_string();

    assert!(error.contains("must be a real directory"));
    assert!(!dir.join(".outcall/home/claude").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn stage_auth_copy_skips_broken_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = temp_project("auth-copy-broken-symlink");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".claude/agents")).unwrap();
    symlink(
        home.join("missing-template.md"),
        home.join(".claude/agents/README.md"),
    )
    .unwrap();

    let recipe = get_recipe("claude").unwrap();
    let staged = stage_auth_copy_with_home_options(&dir, recipe, Some(&home), true, true).unwrap();

    assert_eq!(staged.copied.len(), 1);
    assert!(dir.join(".outcall/home/claude/.claude/agents").exists());
    assert!(
        !dir.join(".outcall/home/claude/.claude/agents/README.md")
            .exists()
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn stage_auth_copy_does_not_follow_valid_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = temp_project("auth-copy-valid-symlink");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".claude/agents")).unwrap();
    std::fs::write(home.join("outside-secret"), "must-not-copy").unwrap();
    symlink(
        home.join("outside-secret"),
        home.join(".claude/agents/secret-link"),
    )
    .unwrap();

    let recipe = get_recipe("claude").unwrap();
    stage_auth_copy_with_home_options(&dir, recipe, Some(&home), true, true).unwrap();

    assert!(
        !dir.join(".outcall/home/claude/.claude/agents/secret-link")
            .exists()
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stage_auth_copy_rejects_oversized_files_before_copying() {
    let dir = temp_project("auth-copy-oversized");
    let home = dir.join("host-home");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    let auth = home.join(".codex/auth.json");
    let file = std::fs::File::create(&auth).unwrap();
    file.set_len(MAX_AUTH_COPY_FILE_BYTES + 1).unwrap();

    let error = stage_auth_copy_with_home(&dir, get_recipe("codex").unwrap(), Some(&home), true)
        .unwrap_err()
        .to_string();

    assert!(error.contains("--auth mount"));
    assert!(!dir.join(".outcall/home/codex/.codex/auth.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn auth_mount_plan_maps_broad_host_paths_into_container_home() {
    let home = temp_project("auth-mount-home");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(home.join(".claude.json"), "{}").unwrap();

    let recipe = get_recipe("claude").unwrap();
    let plan = auth_mount_plan_with_home(recipe, Some(&home), Path::new("/home/node"));

    assert!(plan.mounts.iter().any(|mount| mount
        == &format!(
            "{}:{}",
            home.join(".claude").display(),
            "/home/node/.claude"
        )));
    assert!(plan.mounts.iter().any(|mount| mount
        == &format!(
            "{}:{}",
            home.join(".claude.json").display(),
            "/home/node/.claude.json"
        )));
    let _ = std::fs::remove_dir_all(home);
}
