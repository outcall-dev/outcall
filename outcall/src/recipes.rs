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
name: claude-agent
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
name: codex-agent
workspace: /workspace
network: outcall-default
detach: false
auto_pull: false
entrypoint:
  - codex
volumes: []
env: {}
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

    Ok(written)
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

pub fn expanded_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
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
        assert_eq!(written.len(), 6);
        assert!(dir.join(".outcall/recipes/codex/recipe.yaml").exists());
        assert!(dir.join(".outcall/recipes/codex/Dockerfile").exists());
        assert!(dir.join(".outcall/rules/codex.yaml").exists());
        assert!(dir.join(".outcall/agent.yaml").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
