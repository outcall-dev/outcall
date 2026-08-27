use super::{PolicyTemplate, Recipe};

const CLAUDE_AUTH_ENV: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
];
const CLAUDE_CREDENTIAL_PATHS: &[&str] = &["~/.claude/.credentials.json"];
const CLAUDE_USER_PATHS: &[&str] = &["~/.claude/.credentials.json"];
const CLAUDE_GLOBAL_CONFIG_PATHS: &[&str] = &[
    "~/.claude/settings.json",
    "~/.claude/CLAUDE.md",
    "~/.claude/agents",
    "~/.claude/commands",
    "~/.claude/hooks",
];
const CLAUDE_MOUNT_PATHS: &[&str] = &["~/.claude", "~/.claude.json"];
const CLAUDE_PROJECT_PATHS: &[&str] = &["CLAUDE.md", ".claude/settings.json"];

const CODEX_AUTH_ENV: &[&str] = &["CODEX_ACCESS_TOKEN", "CODEX_API_KEY"];
const CODEX_CREDENTIAL_PATHS: &[&str] = &["~/.codex/auth.json"];
const CODEX_USER_PATHS: &[&str] = &["~/.codex/auth.json"];
const CODEX_GLOBAL_CONFIG_PATHS: &[&str] = &["~/.codex/config.toml", "~/.codex/AGENTS.md"];
const CODEX_MOUNT_PATHS: &[&str] = &["~/.codex"];
const CODEX_PROJECT_PATHS: &[&str] = &["AGENTS.md", ".codex/config.toml"];

const CLAUDE_GITHUB_POLICY: PolicyTemplate = PolicyTemplate {
    name: "github",
    id: "claude-github",
    description: "Claude Code may access GitHub for repository operations.",
    condition: "((http.host == \"github.com\" || http.host.endsWith(\".github.com\")) && network.port == 443) || dns.query == \"github.com\" || dns.query.endsWith(\".github.com\")",
};

const CODEX_GITHUB_POLICY: PolicyTemplate = PolicyTemplate {
    name: "github",
    id: "codex-github",
    description: "Codex may access GitHub for repository operations.",
    condition: "((http.host == \"github.com\" || http.host.endsWith(\".github.com\")) && network.port == 443) || dns.query == \"github.com\" || dns.query.endsWith(\".github.com\")",
};

const CLAUDE_API_POLICY: PolicyTemplate = PolicyTemplate {
    name: "anthropic",
    id: "claude-anthropic-api",
    description: "Claude Code may call Anthropic APIs and sign-in endpoints over HTTPS.",
    condition: "((http.host == \"api.anthropic.com\" || http.host == \"claude.ai\" || http.host == \"platform.claude.com\") && network.port == 443) || dns.query == \"api.anthropic.com\" || dns.query == \"claude.ai\" || dns.query == \"platform.claude.com\"",
};

const CODEX_API_POLICY: PolicyTemplate = PolicyTemplate {
    name: "openai",
    id: "codex-openai-api",
    description: "Codex may call OpenAI and ChatGPT endpoints over HTTPS.",
    condition: "((http.host == \"api.openai.com\" || http.host == \"chatgpt.com\") && network.port == 443) || dns.query == \"api.openai.com\" || dns.query == \"chatgpt.com\"",
};

const CLAUDE_POLICY_TEMPLATES: &[PolicyTemplate] = &[CLAUDE_API_POLICY, CLAUDE_GITHUB_POLICY];
const CODEX_POLICY_TEMPLATES: &[PolicyTemplate] = &[CODEX_API_POLICY, CODEX_GITHUB_POLICY];

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
  default_mode: auto
  env:
    - CLAUDE_CODE_OAUTH_TOKEN
    - ANTHROPIC_API_KEY
    - ANTHROPIC_AUTH_TOKEN
  user_paths:
    - ~/.claude/.credentials.json
  optional_global_paths:
    - ~/.claude/settings.json
    - ~/.claude/CLAUDE.md
    - ~/.claude/agents
    - ~/.claude/commands
    - ~/.claude/hooks
  mount_paths:
    - ~/.claude
    - ~/.claude.json
  credential_paths:
    - ~/.claude/.credentials.json
context:
  project_paths:
    - CLAUDE.md
    - .claude/settings.json
egress:
  rules: .outcall/rules/claude.yaml
verify:
  checks:
    - claude --version
    - auth transfer inspected
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
  entrypoint: outcall-codex
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
  optional_global_paths:
    - ~/.codex/config.toml
    - ~/.codex/AGENTS.md
  mount_paths:
    - ~/.codex
  credential_paths:
    - ~/.codex/auth.json
context:
  project_paths:
    - AGENTS.md
    - .codex/config.toml
egress:
  rules: .outcall/rules/codex.yaml
verify:
  checks:
    - codex --version
    - auth transfer inspected
    - project instructions present
"#;

const CLAUDE_DOCKERFILE: &str = r#"FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl gnupg \
  && install -d -m 0755 /etc/apt/keyrings \
  && curl -fsSL https://downloads.claude.ai/keys/claude-code.asc \
    -o /etc/apt/keyrings/claude-code.asc \
  && gpg --batch --show-keys --with-colons /etc/apt/keyrings/claude-code.asc \
    | grep -q ':31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE:' \
  && printf '%s\n' \
    'deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main' \
    > /etc/apt/sources.list.d/claude-code.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends claude-code \
  && rm -rf /var/lib/apt/lists/* /root/.gnupg \
  && claude --version

WORKDIR /workspace
ENTRYPOINT ["claude"]
"#;

const CODEX_DOCKERFILE: &str = r#"FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash curl \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex \
  && codex --version

# Outcall's hardened Docker container is the security boundary. Codex's Linux
# bwrap sandbox needs capabilities that managed agent containers intentionally
# do not receive, so avoid a fragile nested sandbox while retaining approvals.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'exec codex --sandbox danger-full-access "$@"' \
    > /usr/local/bin/outcall-codex \
  && chmod 0755 /usr/local/bin/outcall-codex

WORKDIR /workspace
ENTRYPOINT ["outcall-codex"]
"#;

const CLAUDE_RULES: &str = r#"version: "1"
rules:
  - id: claude-anthropic-api
    description: Claude Code may call Anthropic APIs and sign-in endpoints over HTTPS.
    condition: '((http.host == "api.anthropic.com" || http.host == "claude.ai" || http.host == "platform.claude.com") && network.port == 443) || dns.query == "api.anthropic.com" || dns.query == "claude.ai" || dns.query == "platform.claude.com"'
    action: allow
    egress:
      mode: proxy

  - id: claude-github
    description: Claude Code may access GitHub for repository operations.
    condition: '((http.host == "github.com" || http.host.endsWith(".github.com")) && network.port == 443) || dns.query == "github.com" || dns.query.endsWith(".github.com")'
    action: allow
    egress:
      mode: proxy
"#;

const CODEX_RULES: &str = r#"version: "1"
rules:
  - id: codex-openai-api
    description: Codex may call OpenAI and ChatGPT endpoints over HTTPS.
    condition: '((http.host == "api.openai.com" || http.host == "chatgpt.com") && network.port == 443) || dns.query == "api.openai.com" || dns.query == "chatgpt.com"'
    action: allow
    egress:
      mode: proxy

  - id: codex-github
    description: Codex may access GitHub for repository operations.
    condition: '((http.host == "github.com" || http.host.endsWith(".github.com")) && network.port == 443) || dns.query == "github.com" || dns.query.endsWith(".github.com")'
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
- `.outcall/host-resources.yaml`

Context and auth candidates:

- Project context: `CLAUDE.md`, `.claude/settings.json`
- Default copy: any Linux `~/.claude/.credentials.json`
- Optional `--include-global-config`: selected settings, instructions, and
  extensions; history and caches are excluded
- Explicit mount: `~/.claude`, `~/.claude.json`
- Subscription auth: `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`
- API auth: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`

On macOS, the host `/login` credential remains in Keychain. Run
`outcall run claude` once and complete `/login` in the container to persist a
project-local Linux credential, or use a setup token for unattended startup.

Use `outcall doctor claude` before running the container.
"#;

const CODEX_README: &str = r#"# Outcall Codex Recipe

This recipe prepares a project-local Outcall profile for Codex CLI.

Generated files:

- `.outcall/recipes/codex/recipe.yaml`
- `.outcall/recipes/codex/Dockerfile`
- `.outcall/recipes/codex/context.md`
- `.outcall/rules/codex.yaml`
- `.outcall/agent.yaml`
- `.outcall/host-resources.yaml`

Context and auth candidates:

- Project context: `AGENTS.md`, `.codex/config.toml`
- Default auth copy: `~/.codex/auth.json`
- Optional `--include-global-config`: `~/.codex/config.toml`, `~/.codex/AGENTS.md`
- Environment auth: `CODEX_ACCESS_TOKEN`, `CODEX_API_KEY`

Use `outcall doctor codex` before running the container.

The image runs Codex with `--sandbox danger-full-access` inside the container.
This disables only Codex's nested `bubblewrap` sandbox: Docker's read-only root
filesystem, dropped capabilities, mount allowlist, and Outcall network policy
remain the outer security boundary.
"#;

const CLAUDE_CONTEXT: &str = r#"# Claude Context Transfer

Recommended default: copy selected user configuration into an isolated Docker
volume or recipe directory, then mount it into the container. Avoid mounting the
entire home directory.

Transfer candidates:

- `CLAUDE.md` from the project root for project memory.
- `.claude/settings.json` for project-scoped settings.
- Selected files under `~/.claude` for user-level settings without copying
  history, logs, caches, session transcripts, or machine-specific state.
- `--include-global-config` to opt into copying those selected global files.
- `--auth mount` to explicitly mount the complete `~/.claude` directory and
  `~/.claude.json` instead.
- `CLAUDE_CODE_OAUTH_TOKEN` for unattended subscription authentication. Generate
  it on the host with `claude setup-token`, then export it in the launch shell.
- `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` for API authentication.

Treat copied auth state as secret material. Do not commit `.outcall/home/`.
Treat setup tokens as long-lived secrets; Outcall forwards them to the managed
container but does not write their values into the project scaffold.
On macOS, Keychain credentials do not transfer to Linux. An interactive `/login`
inside `outcall run claude` writes a persistent project-local Linux credential.

Declared host resources are exposed only through the tokenized Outcall broker.
Use `outcall allow claude tool:<id>` or `outcall allow claude file:<id>` before
accessing them. The container receives `OUTCALL_HOST_BROKER_TOKEN` plus
`OUTCALL_HOST_BROKER_SOCKET` on Linux or `OUTCALL_HOST_BROKER_URL` on macOS
when the registry is non-empty. The mounted `.outcall` policy directory is
read-only inside the agent container.
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
- `--include-global-config` to opt into copying those global defaults; review
  host-only MCP command paths before using them in Linux.
- `CODEX_ACCESS_TOKEN` or `CODEX_API_KEY` for non-interactive authentication.

Treat `auth.json` and access tokens as secret material. Do not commit
`.outcall/home/`.

The recipe intentionally lets Codex use everything already present inside the
hardened container. Host files outside `/workspace` require an explicit Docker
mount or broker declaration; host tools require a broker declaration; egress
requires an allow rule.

Declared host resources are exposed only through the tokenized Outcall broker.
Use `outcall allow codex tool:<id>` or `outcall allow codex file:<id>` before
accessing them. The container receives `OUTCALL_HOST_BROKER_TOKEN` plus
`OUTCALL_HOST_BROKER_SOCKET` on Linux or `OUTCALL_HOST_BROKER_URL` on macOS
when the registry is non-empty. The mounted `.outcall` policy directory is
read-only inside the agent container.
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
  - outcall-codex
volumes: []
env: {}
"#;

pub(super) const HOST_RESOURCES_TEMPLATE: &str = r#"# Generated by `outcall recipe init`.
#
# Declare host-side resources outside /workspace that an agent may request
# through Outcall's tokenized host broker.
#
# Declaration does not grant access. After adding an entry, allow it explicitly:
#
#   outcall allow <recipe> tool:<id>
#   outcall allow <recipe> file:<id>
#
# Every broker request is still evaluated by the daemon rule engine. Undeclared
# resources and declared resources without a matching allow rule are blocked.
# When this registry is non-empty, `outcall run` starts the project broker and
# injects OUTCALL_HOST_BROKER_TOKEN plus OUTCALL_HOST_BROKER_SOCKET on Linux or
# OUTCALL_HOST_BROKER_URL on macOS. The `.outcall` directory is read-only in the
# agent container, so the registry and rules cannot be rewritten from within it.
#
# From inside an agent container on Linux:
#
#   curl --unix-socket "$OUTCALL_HOST_BROKER_SOCKET" \
#     -H "Authorization: Bearer $OUTCALL_HOST_BROKER_TOKEN" \
#     -H "Content-Type: application/json" \
#     -d '{"id":"chrome-mcp","args":["--help"]}' \
#     http://localhost/v1/tool/exec
#
#   curl --unix-socket "$OUTCALL_HOST_BROKER_SOCKET" \
#     -H "Authorization: Bearer $OUTCALL_HOST_BROKER_TOKEN" \
#     -H "Content-Type: application/json" \
#     -d '{"id":"notes","relative_path":"today.md"}' \
#     http://localhost/v1/file/read
#
# On macOS with Docker Desktop, omit `--unix-socket` and use the broker URL:
#
#   curl -H "Authorization: Bearer $OUTCALL_HOST_BROKER_TOKEN" \
#     -H "Content-Type: application/json" \
#     -d '{"id":"chrome-mcp","args":["--help"]}' \
#     "$OUTCALL_HOST_BROKER_URL/v1/tool/exec"
#
# Resource types:
# - tools: host-native binaries, CLIs, or wrappers; a grant permits caller-
#   supplied arguments within the project cwd, so use a narrow wrapper for
#   sensitive tools and explicitly list any host environment variables to pass
# - files: host file/directory roots outside /workspace
# - auth/session: provider-specific session handoff notes

version: "1"

tools: []
# tools:
#   - id: chrome-mcp
#     path: ~/bin/chrome-mcp
#     default_args: []
#     forward_env: [] # e.g. [HOME] when the tool intentionally needs host state
#     env: {}         # explicit literal values; do not commit secrets
#     notes: Host-native tool exposed only after an explicit allow rule.

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
        policy_templates: CLAUDE_POLICY_TEMPLATES,
        auth_env: CLAUDE_AUTH_ENV,
        credential_paths: CLAUDE_CREDENTIAL_PATHS,
        user_paths: CLAUDE_USER_PATHS,
        global_config_paths: CLAUDE_GLOBAL_CONFIG_PATHS,
        mount_paths: CLAUDE_MOUNT_PATHS,
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
        policy_templates: CODEX_POLICY_TEMPLATES,
        auth_env: CODEX_AUTH_ENV,
        credential_paths: CODEX_CREDENTIAL_PATHS,
        user_paths: CODEX_USER_PATHS,
        global_config_paths: CODEX_GLOBAL_CONFIG_PATHS,
        mount_paths: CODEX_MOUNT_PATHS,
        project_paths: CODEX_PROJECT_PATHS,
    },
];
