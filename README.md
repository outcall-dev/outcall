# Outcall

Host-level firewall daemon that governs all outbound traffic from Docker agent containers. Creates isolated networks, applies nftables policies via a managed bridge, and gives operators CLI + API control over what containers can reach.

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
docker run -d --rm \
    --name outcall-daemon \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    -v /var/run/docker.sock:/var/run/docker.sock \
    outcall-e2e \
    outcalld --bridge outcall0
```

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

Full functional and interface specs live in the [`outcall-dev/specs`](https://github.com/outcall-dev/specs) repo, organised as `S000`–`S010`.

## Repository layout (top level)

```
application/   ← this repo (outcall-dev/outcall)
specs/         ← outcall-dev/specs
docs/          ← outcall-dev/docs
website/       ← outcall-dev/website
```
