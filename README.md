# Outcall

![Outcall Banner](https://raw.githubusercontent.com/outcall-dev/assets/main/banner.png)

## Badges

[![CI](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml/badge.svg)](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.36-blue.svg)](https://github.com/outcall-dev/outcall/releases)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Foutcall--dev%2Foutcalld-blue.svg)](https://github.com/outcall-dev/outcall/pkgs/container/outcalld)

## Workspace

Five Cargo crates:

| Crate | Role |
|---|---|
| `outcalld` | Host daemon — bridge, nftables, network management, DNS filter, HTTP proxy, agent API, dynamic rules |
| `outcall` | CLI client — talks to `outcalld` via Unix socket |
| `outcall-api` | Shared types and constants |
| `outcall-agent` | Container-side shim |
| `outcall-ui` | Dashboard web UI |

## Build

```sh
cargo build --workspace
```

Run the review gates locally with:

```sh
cargo test --workspace --all-targets --locked
make spec-check
make coverage
```

`make coverage` writes `target/coverage/lcov.info` and enforces the current
workspace regression floor. Privileged tests remain separate because they
require a Linux runtime with network administration capabilities.

Linux is still the native daemon runtime, but macOS is supported for the
first-run Claude/Codex recipe flow by running `outcalld` and the agent
containers inside Docker Desktop's Linux VM.

## Fast install

```sh
curl -fsSL https://outcall.dev/install.sh | sh
```

When you are changing the installer or release packaging locally, use the same
`file://` flow as CI:

```sh
sh scripts/local-install-smoke.sh
```

That builds release binaries, packages a local release directory, runs
`scripts/install.sh` against it, and verifies the installed binary versions
from a clean temporary home.

For quicker iteration during installer work:

```sh
make install-smoke
make install-smoke-doctor-codex
make install-smoke-doctor-claude
make install-smoke POST_INSTALL='outcall run codex -- --version'
```

For CLI-only iteration when a compatible daemon image is already present:

```sh
OUTCALL_SKIP_IMAGE_PRELOAD=1 make install-smoke
```

Any extra command passed to `scripts/local-install-smoke.sh` runs after install
inside a fresh temporary project with the newly installed binaries on `PATH`.

On Linux and macOS, the installer preloads the matching Linux `outcalld`
Docker image when Docker is available, so `outcall run <recipe>` does not need a
first-run registry pull.

## First-time agent flow

The CLI ships a small built-in recipe registry for common agent runtimes.
Choose the provider explicitly:

```sh
outcall run claude
outcall run codex
```

Run either recipe at any time to switch providers in the same project. Outcall
keeps each recipe's files and rules separate and preserves shared host-resource
configuration.

`outcall run <recipe>` is the only agent launch command. It writes the
project-local `.outcall/` scaffold, checks Docker and generated files, stages
selected authentication, pulls the version-matched prebuilt recipe image,
ensures the daemon and managed network exist, and then starts the isolated
agent container. If the published image is unavailable, Outcall falls back to
the bundled Dockerfile unless `--no-build` was requested. It persists the
selected recipe for policy and setup commands, but every launch remains
explicit.

Managed agent processes run as the invoking user's numeric non-root UID/GID so
project and staged-auth bind mounts remain usable on Linux and macOS. The
daemon rejects root identities and uses `65532:65532` for older clients that do
not send an identity.

If the first run stops on a prerequisite, inspect the host and recipe checks
directly:

```sh
outcall doctor --fix claude
outcall doctor --fix codex
```

The lower-level flow is:

```sh
outcall init <recipe>
outcall doctor <recipe>
outcall recipe test <recipe>
outcall run <recipe>
```

The intermediate shortcut is:

```sh
outcall setup <recipe>
```

You can still pin the provider explicitly when needed:

```sh
outcall run claude --detach
outcall run codex --detach
```

Detached interactive launches allocate a container TTY and remain available
through `outcall attach <name>`. Detach without stopping the agent with
Ctrl+P, then Ctrl+Q; use `outcall logs <name> --follow` and
`outcall inspect <name>` / `outcall stop <name>` for the rest of its lifecycle.
Top-level `stop` removes the stopped agent so its numeric name can be reused;
pass `--keep` to retain it for postmortem logs or inspection.

Built-in images are versioned with the CLI and published for Linux amd64 and
arm64 as `ghcr.io/outcall-dev/outcall-recipe-<recipe>:v<version>`. Editing a
generated `.outcall/recipes/<recipe>/Dockerfile` automatically switches that
recipe to `outcall-recipe-<recipe>:local` and restores fingerprinted local
builds. An explicit image in `.outcall/agent.yaml` remains the final override.

Recipes do not mount your whole home directory. Auto auth uses non-empty
provider environment credentials when present. Otherwise it copies only the
portable credential into ignored `.outcall/home/<id>` state. Pass
`--include-global-config` to additionally copy the recipe's bounded allowlist of
global settings, instructions, and hooks after reviewing host-only MCP and hook
commands. Symlinks are skipped; files over 16 MiB, more than 10,000 entries, or
more than 100 MiB total are rejected. The project-local home is mounted at the
validated Linux home (`/home/node`) inside the container. Provider CLIs resolve
`~` there; Outcall does not rewrite host-absolute executable paths, which
generally do not work in the Linux runtime.

`--auth mount` is a read-write opt-in for the complete provider directory, not
the complete host home. macOS Keychain-backed Claude login state is not portable
into Linux. Run `outcall run claude` once and complete `/login` in the container,
or use a setup token for unattended work. Batch and detached inference commands
fail before image build when no portable credential is available.

For unattended Claude subscription runs, generate a long-lived token on the
host and export it only in the launch environment:

```sh
claude setup-token
export CLAUDE_CODE_OAUTH_TOKEN=...
outcall run claude
```

Claude API users can instead set `ANTHROPIC_API_KEY` or
`ANTHROPIC_AUTH_TOKEN`. Treat every credential as a secret; Outcall forwards
environment credentials to the managed container without writing their values
into the project scaffold.

Codex unattended runs accept an expiring `CODEX_ACCESS_TOKEN` or an API key in
`CODEX_API_KEY` or `OPENAI_API_KEY`. Prefer a short-lived access token for
trusted automation and scope any API key to the individual invocation.

Each project scaffold also includes `.outcall/host-resources.yaml` as the
explicit registry for host tools, host file roots, and auth/session handoff
notes that sit outside `/workspace`.

When the registry contains a tool or file declaration, `outcall run` starts the
project broker automatically and injects its authenticated endpoint into the
container. `outcall host-broker serve` remains available for low-level broker
development and diagnostics.

The broker is deny-by-default:

- only resources declared in `.outcall/host-resources.yaml` exist
- every request is still evaluated against the active daemon rules before the
  host action runs

The v1 broker executes bounded, one-shot tool commands and returns their
captured output. It does not transparently forward long-lived stdio, SSE, or
Streamable HTTP MCP sessions. Install an MCP server in the Linux recipe image
when possible so normal Outcall egress rules govern it, or expose a narrow host
wrapper that completes one operation per broker request.

## Running `outcalld`

`outcalld` requires a Docker socket bind-mount. Its managed container receives
only the capabilities needed by the selected transport.

### Required runtime flags

| Flag | Why |
|---|---|
| `--cap-drop ALL` | Remove Docker's default Linux capability set |
| `--cap-add NET_ADMIN` | Create bridges, configure interfaces, apply nftables |
| `--cap-add NET_BIND_SERVICE` | Bind the managed DNS listener on port 53 |
| `--security-opt no-new-privileges` | Prevent privilege gains through image executables |
| `--pids-limit 512` | Bound daemon process creation |
| `--network host` | Daemon must see the host network namespace |
| `--pid host` | Resolve host network PIDs to their Docker container identities |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Manage Docker networks and look up containers by PID |

Native Unix-socket transport on Linux additionally receives `CHOWN` and
`DAC_OVERRIDE` so the daemon can create operator-owned sockets in the mounted
runtime directory. Docker-exec transport on macOS does not receive those two
capabilities. `SYS_ADMIN` is **not** required; do not broaden the capability set
to work around a failed preflight.

### Example

```sh
outcall daemon start
outcall daemon status
```

The CLI also applies a read-only root filesystem, bounded `/tmp` tmpfs,
`unless-stopped` restart policy, persistent state volume, identity labels, and
the correct rules/socket mounts. Prefer it to maintaining a raw `docker run`
invocation by hand.

`Dockerfile.test` remains available for local debug builds. Release images are
published from `Dockerfile`.

### Optional flags

| Flag | Default | Notes |
|---|---|---|
| `--socket <path>` | `/tmp/outcall/host.sock` | Host API Unix socket |
| `--bridge <name>` | `outcall0` | Bridge interface name |
| `--rules-dir <path>` | `/etc/outcall/rules.d` | Directory of rule YAML files |
| `--dns-listen <ip>` | `10.200.0.1` | DNS filter bind address (bridge gateway IP) |
| `--dns-port <port>` | `53` | DNS filter bind port |
| `--dns-upstream <list>` | `/etc/resolv.conf` | Comma-separated upstream DNS servers |
| `--proxy-addr <host:port>` | `10.200.0.1:8080` | HTTP proxy bind address (bridge gateway IP:port) |
| `--no-proxy` | _off_ | Disable the HTTP proxy entirely |
| `--agent-socket-host-path <path>` | `/tmp/outcall/agent.sock` | Agent API Unix socket |
| `--shim-host-path <path>` | `/usr/local/bin/outcall-agent` | Path to the `outcall-agent` shim binary that's bind-mounted into agent containers |
| `--agent-timeout-secs <n>` | `5` | Server-side rule-evaluation timeout (S004-FR-015) |
| `--agent-perm-rate <count/seconds>` | `100/10` | Sliding-window rate limit for permission checks per container |
| `--agent-rule-rate <count/seconds>` | `10/60` | Sliding-window rate limit for rule submissions per container |
| `--subnet-block <cidr>` | `10.200.0.0/16` | RFC 1918 block for `/24` auto-allocation |

If port `8080` is already bound on the host, pass `--no-proxy` (or change `--proxy-addr`) to avoid the bind error.

TLS interception is not available yet. `egress.mode: intercept` and the draft
S011 daemon flags are rejected rather than accepted as inert security settings.
Use `egress.mode: proxy` for HTTPS hostname policy until S011 ships.

## Specifications

Full functional and interface specs live in the [`outcall-dev/specs`](https://github.com/outcall-dev/specs) repo, organised as `S000`–`S015`.

## Security

Outcall is security-critical infrastructure. Before deploying it, read:

- [Threat model](https://github.com/outcall-dev/docs/blob/main/security/threat-model.md) — what Outcall protects against, what it does not, and the trust boundaries you rely on.
- [Most recent audit](https://github.com/outcall-dev/docs/blob/main/security/audit-2026-05-14.md) — findings, severities, and what's fixed.
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability.
- [Outcall security review skill](./.agents/skills/outcall-security-review/SKILL.md) — the repeatable release and runtime checklist used by maintainers and agents.

For a worked example of a tightly-scoped agent ruleset (Sentry → GitHub PR
agent), see [`outcall-dev/root/rules.d/examples/sentry-github-agent/`](https://github.com/outcall-dev/root/tree/main/rules.d/examples/sentry-github-agent).

## License

[Apache-2.0](./LICENSE).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Repository layout (top level)

```
application/   ← this repo (outcall-dev/outcall)
specs/         ← outcall-dev/specs
docs/          ← outcall-dev/docs
website/       ← outcall-dev/website
```
