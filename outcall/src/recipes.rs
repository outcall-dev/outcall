//! Built-in recipe registry for common agent runtimes.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Recipe {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub manifest: &'static str,
    pub dockerfile: &'static str,
    pub rules: &'static str,
    pub readme: &'static str,
    pub context: &'static str,
    pub agent_config: &'static str,
    pub auth_env: &'static [&'static str],
    pub user_paths: &'static [&'static str],
    pub project_paths: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStaging {
    pub home_dir: PathBuf,
    pub copied: Vec<(PathBuf, PathBuf)>,
    pub missing: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMountPlan {
    pub mounts: Vec<String>,
    pub home_override: Option<String>,
}

const CLAUDE_AUTH_ENV: &[&str] = &["ANTHROPIC_API_KEY"];
const CLAUDE_USER_PATHS: &[&str] = &["~/.claude", "~/.claude.json"];
const CLAUDE_PROJECT_PATHS: &[&str] = &["CLAUDE.md", ".claude/settings.json"];

const CODEX_AUTH_ENV: &[&str] = &["CODEX_ACCESS_TOKEN", "CODEX_API_KEY"];
const CODEX_USER_PATHS: &[&str] = &[
    "~/.codex/auth.json",
    "~/.codex/config.toml",
    "~/.codex/AGENTS.md",
];
const CODEX_PROJECT_PATHS: &[&str] = &["AGENTS.md", ".codex/config.toml"];

const CLAUDE_MANIFEST: &str = r#"schema: outcall.recipe/v1
id: claude
name: Claude Code
version: 0.1.0
description: Run Claude Code inside an Outcall-managed project container.
image:
  local_name: outcall-recipe-claude:local
  dockerfile: .outcall/recipes/claude/Dockerfile
agent:
  entrypoint: claude
workspace:
  host: .
  container: /workspace
  mode: rw
auth:
  default_mode: copy
  env:
    - ANTHROPIC_API_KEY
  user_paths:
    - ~/.claude
    - ~/.claude.json
context:
  project_paths:
    - CLAUDE.md
    - .claude/settings.json
egress:
  rules: .outcall/rules/claude.yaml
verify:
  checks:
    - claude --version
    - auth material present
    - project context present
"#;

const CODEX_MANIFEST: &str = r#"schema: outcall.recipe/v1
id: codex
name: Codex CLI
version: 0.1.0
description: Run Codex CLI inside an Outcall-managed project container.
image:
  local_name: outcall-recipe-codex:local
  dockerfile: .outcall/recipes/codex/Dockerfile
agent:
  entrypoint: codex
workspace:
  host: .
  container: /workspace
  mode: rw
auth:
  default_mode: copy
  env:
    - CODEX_ACCESS_TOKEN
    - CODEX_API_KEY
  user_paths:
    - ~/.codex/auth.json
    - ~/.codex/config.toml
    - ~/.codex/AGENTS.md
context:
  project_paths:
    - AGENTS.md
    - .codex/config.toml
egress:
  rules: .outcall/rules/codex.yaml
verify:
  checks:
    - codex --version
    - auth material present
    - project instructions present
"#;

const CLAUDE_DOCKERFILE: &str = r#"FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

WORKDIR /workspace
ENTRYPOINT ["claude"]
"#;

const CODEX_DOCKERFILE: &str = r#"FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex

WORKDIR /workspace
ENTRYPOINT ["codex"]
"#;

const CLAUDE_RULES: &str = r#"version: "1"
rules:
  - id: claude-anthropic-api
    description: Claude Code may call Anthropic APIs over HTTPS.
    condition: 'http.host == "api.anthropic.com" || dns.query == "api.anthropic.com"'
    action: allow
    egress:
      mode: proxy

  - id: claude-github
    description: Claude Code may access GitHub for repository operations.
    condition: 'http.host == "github.com" || http.host.endsWith(".github.com") || dns.query == "github.com" || dns.query.endsWith(".github.com")'
    action: allow
    egress:
      mode: proxy
"#;

const CODEX_RULES: &str = r#"version: "1"
rules:
  - id: codex-openai-api
    description: Codex may call OpenAI and ChatGPT endpoints over HTTPS.
    condition: 'http.host == "api.openai.com" || http.host == "chatgpt.com" || dns.query == "api.openai.com" || dns.query == "chatgpt.com"'
    action: allow
    egress:
      mode: proxy

  - id: codex-github
    description: Codex may access GitHub for repository operations.
    condition: 'http.host == "github.com" || http.host.endsWith(".github.com") || dns.query == "github.com" || dns.query.endsWith(".github.com")'
    action: allow
    egress:
      mode: proxy
"#;

const CLAUDE_README: &str = r#"# Outcall Claude Code Recipe

This recipe prepares a project-local Outcall profile for Claude Code.

Generated files:

- `.outcall/recipes/claude/recipe.yaml`
- `.outcall/recipes/claude/Dockerfile`
- `.outcall/recipes/claude/context.md`
- `.outcall/rules/claude.yaml`
- `.outcall/agent.yaml`

Context and auth candidates:

- Project context: `CLAUDE.md`, `.claude/settings.json`
- User config/auth: `~/.claude`, `~/.claude.json`
- Environment auth: `ANTHROPIC_API_KEY`

Use `outcall recipe doctor claude` before running the container.
"#;

const CODEX_README: &str = r#"# Outcall Codex Recipe

This recipe prepares a project-local Outcall profile for Codex CLI.

Generated files:

- `.outcall/recipes/codex/recipe.yaml`
- `.outcall/recipes/codex/Dockerfile`
- `.outcall/recipes/codex/context.md`
- `.outcall/rules/codex.yaml`
- `.outcall/agent.yaml`

Context and auth candidates:

- Project context: `AGENTS.md`, `.codex/config.toml`
- User config/auth: `~/.codex/auth.json`, `~/.codex/config.toml`, `~/.codex/AGENTS.md`
- Environment auth: `CODEX_ACCESS_TOKEN`, `CODEX_API_KEY`

Use `outcall recipe doctor codex` before running the container.
"#;

const CLAUDE_CONTEXT: &str = r#"# Claude Context Transfer

Recommended default: copy selected user configuration into an isolated Docker
volume or recipe directory, then mount it into the container. Avoid mounting the
entire home directory.

Transfer candidates:

- `CLAUDE.md` from the project root for project memory.
- `.claude/settings.json` for project-scoped settings.
- `~/.claude` and `~/.claude.json` for user-level Claude Code state.
- `ANTHROPIC_API_KEY` for environment-variable authentication.

Treat copied auth state as secret material. Do not commit `.outcall/auth/`.
"#;

const CODEX_CONTEXT: &str = r#"# Codex Context Transfer

Recommended default: copy selected Codex state into an isolated Docker volume
or recipe directory, then mount it into the container. Avoid mounting the entire
home directory.

Transfer candidates:

- `AGENTS.md` from the project root for project instructions.
- `.codex/config.toml` for trusted project settings.
- `~/.codex/auth.json` for cached login credentials.
- `~/.codex/config.toml` and `~/.codex/AGENTS.md` for user defaults.
- `CODEX_ACCESS_TOKEN` or `CODEX_API_KEY` for non-interactive authentication.

Treat `auth.json` and access tokens as secret material. Do not commit
`.outcall/auth/`.
"#;

const CLAUDE_AGENT_CONFIG: &str = r#"# Generated by `outcall recipe init claude`.
image: outcall-recipe-claude:local
workspace: /workspace
network: outcall-default
detach: false
auto_pull: false
entrypoint:
  - claude
volumes: []
env: {}
"#;

const CODEX_AGENT_CONFIG: &str = r#"# Generated by `outcall recipe init codex`.
image: outcall-recipe-codex:local
workspace: /workspace
network: outcall-default
detach: false
auto_pull: false
entrypoint:
  - codex
volumes: []
env: {}
"#;

const HOST_RESOURCES_TEMPLATE: &str = r#"# Generated by `outcall recipe init`.
#
# Declare host-side resources that should be considered part of the project's
# Outcall setup plan. Mounted workspace files remain normal container files;
# list only host resources outside the workspace that may need controlled
# access later.
#
# This registry is intentionally explicit:
# - tools: host-native binaries, CLIs, or wrappers you may want exposed later
# - files: host file/directory roots outside /workspace
# - auth/session: provider-specific session handoff notes
#
# The current release uses this file for setup visibility and documentation.

version: "1"

tools: []
# tools:
#   - id: chrome-mcp
#     path: /Users/mark/bin/chrome-mcp
#     notes: Host-native tool; requires a future host broker path.

files: []
# files:
#   - id: claude-home
#     path: ~/.claude
#     mode: read-only
#   - id: browser-profile
#     path: ~/Library/Application Support/Google/Chrome
#     mode: read-only

auth:
  notes:
    - Prefer environment tokens for unattended runs.
    - Mount only selected auth/config paths, never the entire home directory.
"#;

pub static RECIPES: &[Recipe] = &[
    Recipe {
        id: "claude",
        name: "Claude Code",
        summary: "Run Claude Code with explicit project context and Anthropic auth transfer.",
        manifest: CLAUDE_MANIFEST,
        dockerfile: CLAUDE_DOCKERFILE,
        rules: CLAUDE_RULES,
        readme: CLAUDE_README,
        context: CLAUDE_CONTEXT,
        agent_config: CLAUDE_AGENT_CONFIG,
        auth_env: CLAUDE_AUTH_ENV,
        user_paths: CLAUDE_USER_PATHS,
        project_paths: CLAUDE_PROJECT_PATHS,
    },
    Recipe {
        id: "codex",
        name: "Codex CLI",
        summary: "Run Codex CLI with explicit project instructions and OpenAI auth transfer.",
        manifest: CODEX_MANIFEST,
        dockerfile: CODEX_DOCKERFILE,
        rules: CODEX_RULES,
        readme: CODEX_README,
        context: CODEX_CONTEXT,
        agent_config: CODEX_AGENT_CONFIG,
        auth_env: CODEX_AUTH_ENV,
        user_paths: CODEX_USER_PATHS,
        project_paths: CODEX_PROJECT_PATHS,
    },
];

pub fn get_recipe(id: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|recipe| recipe.id == id)
}

pub fn recipe_ids() -> impl Iterator<Item = &'static str> {
    RECIPES.iter().map(|recipe| recipe.id)
}

pub fn init_recipe(project_dir: &Path, recipe: &Recipe, force: bool) -> Result<Vec<PathBuf>> {
    let recipe_dir = project_dir.join(".outcall").join("recipes").join(recipe.id);
    let rules_dir = project_dir.join(".outcall").join("rules");
    std::fs::create_dir_all(&recipe_dir)
        .with_context(|| format!("failed to create {}", recipe_dir.display()))?;
    std::fs::create_dir_all(&rules_dir)
        .with_context(|| format!("failed to create {}", rules_dir.display()))?;

    let mut written = Vec::new();
    write_new(
        &recipe_dir.join("recipe.yaml"),
        recipe.manifest,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("Dockerfile"),
        recipe.dockerfile,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("README.md"),
        recipe.readme,
        force,
        &mut written,
    )?;
    write_new(
        &recipe_dir.join("context.md"),
        recipe.context,
        force,
        &mut written,
    )?;
    write_new(
        &rules_dir.join(format!("{}.yaml", recipe.id)),
        recipe.rules,
        force,
        &mut written,
    )?;
    write_new(
        &project_dir.join(".outcall").join("agent.yaml"),
        recipe.agent_config,
        force,
        &mut written,
    )?;
    write_new(
        &project_dir.join(".outcall").join("host-resources.yaml"),
        HOST_RESOURCES_TEMPLATE,
        force,
        &mut written,
    )?;
    if let Some(path) = ensure_outcall_gitignore(project_dir)? {
        written.push(path);
    }

    Ok(written)
}

pub fn recipe_image_name(recipe: &Recipe) -> String {
    format!("outcall-recipe-{}:local", recipe.id)
}

pub fn recipe_dockerfile(project_dir: &Path, recipe: &Recipe) -> PathBuf {
    project_dir
        .join(".outcall")
        .join("recipes")
        .join(recipe.id)
        .join("Dockerfile")
}

pub fn stage_auth_copy(project_dir: &Path, recipe: &Recipe, force: bool) -> Result<AuthStaging> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    stage_auth_copy_with_home(project_dir, recipe, home.as_deref(), force)
}

fn stage_auth_copy_with_home(
    project_dir: &Path,
    recipe: &Recipe,
    home: Option<&Path>,
    force: bool,
) -> Result<AuthStaging> {
    let home_dir = project_dir
        .join(".outcall")
        .join("auth")
        .join(recipe.id)
        .join("home");
    std::fs::create_dir_all(&home_dir)
        .with_context(|| format!("failed to create {}", home_dir.display()))?;
    secure_dir(&project_dir.join(".outcall").join("auth"))?;
    secure_dir(&project_dir.join(".outcall").join("auth").join(recipe.id))?;
    secure_dir(&home_dir)?;

    let mut copied = Vec::new();
    let mut missing = Vec::new();
    for candidate in recipe.user_paths {
        let src = expanded_path_with_home(candidate, home);
        if !src.exists() {
            missing.push(*candidate);
            continue;
        }
        let relative = candidate.strip_prefix("~/").unwrap_or(candidate);
        let dest = home_dir.join(relative);
        copy_path(&src, &dest, force)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
        copied.push((src, dest));
    }

    Ok(AuthStaging {
        home_dir,
        copied,
        missing,
    })
}

pub fn auth_mount_plan(recipe: &Recipe, preserve_home_layout: bool) -> AuthMountPlan {
    let host_home = std::env::var_os("HOME").map(PathBuf::from);
    auth_mount_plan_with_home(recipe, preserve_home_layout, host_home.as_deref())
}

fn auth_mount_plan_with_home(
    recipe: &Recipe,
    preserve_home_layout: bool,
    host_home: Option<&Path>,
) -> AuthMountPlan {
    let mut mounts = Vec::new();
    for candidate in recipe.user_paths {
        let src = expanded_path_with_home(candidate, host_home);
        if !src.exists() {
            continue;
        }
        let dest = if preserve_home_layout {
            if candidate.starts_with("~/") {
                src.clone()
            } else {
                PathBuf::from(candidate)
            }
        } else {
            let relative = candidate.strip_prefix("~/").unwrap_or(candidate);
            PathBuf::from("/home/node").join(relative)
        };
        mounts.push(format!("{}:{}", src.display(), dest.display()));
    }

    let home_override = if preserve_home_layout {
        host_home.and_then(|path| path.as_os_str().to_str().map(ToOwned::to_owned))
    } else {
        None
    };

    AuthMountPlan {
        mounts,
        home_override,
    }
}

fn copy_path(src: &Path, dest: &Path, force: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(src)
        .with_context(|| format!("failed to stat {}", src.display()))?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(src)
            .with_context(|| format!("failed to read symlink {}", src.display()))?;
        let resolved = if target.is_absolute() {
            target
        } else {
            src.parent().unwrap_or_else(|| Path::new(".")).join(target)
        };
        if !resolved.exists() {
            return Ok(());
        }
        return copy_path(&resolved, dest, force);
    }

    if dest.exists() {
        if force {
            if dest.is_dir() {
                std::fs::remove_dir_all(dest)
                    .with_context(|| format!("failed to remove {}", dest.display()))?;
            } else {
                std::fs::remove_file(dest)
                    .with_context(|| format!("failed to remove {}", dest.display()))?;
            }
        } else {
            return Ok(());
        }
    }

    if src.is_dir() {
        std::fs::create_dir_all(dest)
            .with_context(|| format!("failed to create {}", dest.display()))?;
        for entry in
            std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
        {
            let entry = entry?;
            let child_src = entry.path();
            let child_dest = dest.join(entry.file_name());
            copy_path(&child_src, &child_dest, force)?;
        }
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::copy(src, dest)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
    }

    Ok(())
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn write_new(path: &Path, contents: &str, force: bool, written: &mut Vec<PathBuf>) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite generated recipe files",
            path.display()
        );
    }
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    written.push(path.to_path_buf());
    Ok(())
}

pub fn ensure_outcall_gitignore(project_dir: &Path) -> Result<Option<PathBuf>> {
    let path = project_dir.join(".outcall").join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let has_auth = existing.lines().any(|line| line.trim() == "auth/");
    let has_run = existing.lines().any(|line| line.trim() == "run/");
    if has_auth && has_run {
        return Ok(None);
    }

    let mut next = existing;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    if !has_auth {
        next.push_str("auth/\n");
    }
    if !has_run {
        next.push_str("run/\n");
    }
    std::fs::write(&path, next).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

pub fn expanded_path(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expanded_path_with_home(path, home.as_deref())
}

fn expanded_path_with_home(path: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
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
        assert!(
            dir.join(".outcall/auth/codex/home/.codex/auth.json")
                .exists()
        );
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
        let staged = stage_auth_copy_with_home(&dir, recipe, Some(&home), true).unwrap();

        assert_eq!(staged.copied.len(), 1);
        assert!(
            dir.join(".outcall/auth/claude/home/.claude/agents")
                .exists()
        );
        assert!(
            !dir.join(".outcall/auth/claude/home/.claude/agents/README.md")
                .exists()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn auth_mount_plan_preserves_home_layout_when_requested() {
        let home = temp_project("auth-mount-home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude.json"), "{}").unwrap();

        let recipe = get_recipe("claude").unwrap();
        let plan = auth_mount_plan_with_home(recipe, true, Some(&home));

        assert_eq!(plan.home_override.as_deref(), home.to_str());
        assert!(plan.mounts.iter().any(|mount| mount
            == &format!(
                "{}:{}",
                home.join(".claude").display(),
                home.join(".claude").display()
            )));
        assert!(plan.mounts.iter().any(|mount| mount
            == &format!(
                "{}:{}",
                home.join(".claude.json").display(),
                home.join(".claude.json").display()
            )));
        let _ = std::fs::remove_dir_all(home);
    }
}
