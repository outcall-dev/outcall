# Outcall

![Outcall Banner](https://raw.githubusercontent.com/outcall-dev/assets/main/banner.png)

## Badges

[![CI](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml/badge.svg)](https://github.com/outcall-dev/outcall/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.8-blue.svg)](https://github.com/outcall-dev/outcall/releases)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Foutcall--dev%2Foutcall-blue.svg)](https://github.com/outcall-dev/outcall/pkgs/container/outcall)

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

Linux only. macOS will build the workspace (cross-platform types compile) but `outcalld` requires Linux for nftables and bridge management.

## Running `outcalld`

`outcalld` requires several capabilities and a Docker socket bind-mount.

### Required runtime flags

| Flag | Why |
|---|---|
| `--cap-add NET_ADMIN` | Create bridges, configure interfaces, apply nftables |
| `--cap-add SYS_ADMIN` | Mount /sys writes used by nftables |
| `--network host` | Daemon must see the host network namespace |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Manage Docker networks and look up containers by PID |

### Example

```sh
# Production image (from registry or local build):
docker run -d --rm \
    --name outcall-daemon \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    -v /var/run/docker.sock:/var/run/docker.sock \
    outcall-daemon \
    outcalld --bridge outcall0
```

For local E2E testing, the test harness builds a separate image tagged
`outcall-e2e` (see `Makefile` at the workspace root). Use that tag only in
test environments — do not use it for production deployments.

### Optional flags

| Flag | Default | Notes |
|---|---|---|
| `--socket <path>` | `/run/outcall/host.sock` | Host API Unix socket |
| `--bridge <name>` | `outcall0` | Bridge interface name |
| `--rules-dir <path>` | `/etc/outcall/rules.d` | Directory of rule YAML files |
| `--dns-listen <ip>` | `0.0.0.0` | DNS filter bind address |
| `--dns-port <port>` | `53` | DNS filter bind port |
| `--dns-upstream <list>` | `/etc/resolv.conf` | Comma-separated upstream DNS servers |
| `--proxy-addr <host:port>` | `0.0.0.0:8080` | HTTP proxy bind address |
| `--no-proxy` | _off_ | Disable the HTTP proxy entirely |
| `--agent-socket-host-path <path>` | `/run/outcall/agent.sock` | Agent API Unix socket |
| `--agent-timeout-secs <n>` | `5` | Server-side rule-evaluation timeout |
| `--subnet-block <cidr>` | `10.200.0.0/16` | RFC 1918 block for `/24` auto-allocation |

If port `8080` is already bound on the host, pass `--no-proxy` (or change `--proxy-addr`) to avoid the bind error.

## Specifications

Full functional and interface specs live in the [`outcall-dev/specs`](https://github.com/outcall-dev/specs) repo, organised as `S000`–`S015`.

## Security

Outcall is security-critical infrastructure. Before deploying it, read:

- [Threat model](https://github.com/outcall-dev/docs/blob/main/security/threat-model.md) — what Outcall protects against, what it does not, and the trust boundaries you rely on.
- [Most recent audit](https://github.com/outcall-dev/docs/blob/main/security/audit-2026-05-14.md) — findings, severities, and what's fixed.
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability.

For a worked example of a tightly-scoped agent ruleset (Sentry → GitHub PR
agent), see [`rules.d/examples/sentry-github-agent/`](../rules.d/examples/sentry-github-agent/).

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
