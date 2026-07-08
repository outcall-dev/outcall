# Outcall

![Outcall Banner](https://raw.githubusercontent.com/outcall-dev/assets/main/banner.png)

## Badges

[![CI](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml/badge.svg)](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.26-blue.svg)](https://github.com/outcall-dev/outcall/releases)
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
make install-smoke POST_INSTALL='outcall codex -- --version'
```

Any extra command passed to `scripts/local-install-smoke.sh` runs after install
inside a fresh temporary project with the newly installed binaries on `PATH`.

On Linux and macOS, the installer preloads the matching Linux `outcalld`
Docker image when Docker is available, so `outcall start` does not need a
first-run registry pull.

## First-time agent flow

The CLI ships a small built-in recipe registry for common agent runtimes:

```sh
outcall
```

Running bare `outcall` is the default first-run entrypoint. When the current
project or host clearly matches Claude or Codex, it runs the same flow as
`outcall start`. When detection is ambiguous or no provider auth/config is
available yet, it prints the recommended next commands instead.

If Outcall cannot infer the provider cleanly, choose one explicitly:

```sh
outcall claude
outcall codex
```

`outcall start` remains the explicit equivalent. When the machine clearly
matches Claude or Codex, it writes the project-local `.outcall/` scaffold,
checks Docker and generated files, inspects likely auth/context sources, builds
the recipe image, ensures the daemon and default network exist, runs a smoke
container with the recipe entrypoint, and then starts the real isolated agent
container.

`outcall claude` and `outcall codex` run the same flow, but skip provider
detection. They also persist the project's default recipe, so after you choose
once on a mixed-provider machine, later runs can go back to `outcall start`.

If the first run stops on a prerequisite, inspect the host and recipe checks
directly:

```sh
outcall doctor claude
outcall doctor codex
```

Under the hood, `outcall claude` / `outcall codex` are aliases for
`outcall run <recipe>`. The lower-level flow is:

```sh
outcall init <recipe>
outcall doctor <recipe>
outcall recipe test <recipe>
outcall recipe run <recipe>
```

The intermediate shortcut is:

```sh
outcall setup
outcall start
```

You can still pin the provider explicitly when needed:

```sh
outcall setup claude
outcall setup codex
```

Recipes do not mount your whole home directory. By default they copy only the
selected provider auth/config paths into `.outcall/auth/<id>/home`. On macOS,
Claude auto-auth prefers mounting the selected `~/.claude` paths instead of
copying them because session-backed login state is often not portable into a
separate Linux home directory. For unattended Claude runs, prefer
`ANTHROPIC_API_KEY`; mounted login state may still require interactive `/login`.

Each project scaffold also includes `.outcall/host-resources.yaml` as the
explicit registry for host tools, host file roots, and auth/session handoff
notes that sit outside `/workspace`.

For host-native tools or host files outside `/workspace`, run the manual broker
on the host:

```sh
outcall host-broker serve
```

The broker is deny-by-default:

- only resources declared in `.outcall/host-resources.yaml` exist
- every request is still evaluated against the active daemon rules before the
  host action runs

## Running `outcalld`

`outcalld` requires several capabilities and a Docker socket bind-mount.

### Required runtime flags

| Flag | Why |
|---|---|
| `--cap-add NET_ADMIN` | Create bridges, configure interfaces, apply nftables |
| `--network host` | Daemon must see the host network namespace |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Manage Docker networks and look up containers by PID |

`SYS_ADMIN` is **not** required by the daemon's current code paths
(verified against `outcalld/src/bridge.rs`); some kernels are stricter
about netlink and may surface `EPERM` on bridge bringup. Add
`--cap-add SYS_ADMIN` only if that happens.

### Example

```sh
docker run -d --rm \
    --name outcall-daemon \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp/outcall:/tmp/outcall \
    -v /etc/outcall:/etc/outcall \
    ghcr.io/outcall-dev/outcalld:latest \
    --bridge outcall0
```

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

For the TLS-interception flags (`--ca-cert`, `--ca-key`, `--intercept-leaf-ttl-secs`, `--intercept-body-cap-bytes`) — accepted today but no-op until S011 ships — see the [Configuration guide](https://outcall.dev/docs/guides/configuration).

## Specifications

Full functional and interface specs live in the [`outcall-dev/specs`](https://github.com/outcall-dev/specs) repo, organised as `S000`–`S015`.

## Security

Outcall is security-critical infrastructure. Before deploying it, read:

- [Threat model](https://github.com/outcall-dev/docs/blob/main/security/threat-model.md) — what Outcall protects against, what it does not, and the trust boundaries you rely on.
- [Most recent audit](https://github.com/outcall-dev/docs/blob/main/security/audit-2026-05-14.md) — findings, severities, and what's fixed.
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability.

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
