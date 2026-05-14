# Outcall v0.1.0

Initial public release. Outcall is a host-level firewall daemon that governs
all outbound traffic from Docker agent containers. It creates isolated
networks, applies nftables policies via a managed bridge, and gives operators
CLI + API control over what containers can reach.

## What's in v0.1.0

### Daemon (`outcalld`)

- nftables-driven default-deny bridge for agent containers (S001/S002).
- CEL-based rule engine with hot reload via the host API (S003).
- Agent shim API on a dedicated Unix socket — permission checks, check-in,
  rule requests (S004/S005).
- HTTP/HTTPS proxy with SNI peeking (no decryption by default; opt-in TLS
  interception via operator-provisioned CA, S006/S011).
- DNS filter with allow/deny by query, optional cache, and graceful
  degradation if the listener can't bind (S007).
- Docker manager that creates, lists, inspects, and tears down agent
  containers; auto-applies the `managed-by=outcalld` label (S008).
- Dynamic nftables rules with bidirectional CEL ↔ nftables coordination (S009).
- Read-only operator dashboard served from the host socket (S010).
- `agent.name` CEL context — write rules per-agent, not just per-image (S013).

### CLI (`outcall`)

- `outcall bridge {status,up,down}`
- `outcall dns {status,test,cache,flush}`
- `outcall proxy status`
- `outcall container {create,list,inspect,stop,remove,pull}`
- `outcall network {create,status,list,destroy}`
- `outcall ca {init,bundle,status}`
- `outcall daemon {start,stop,status,logs}` — drives the daemon container
  via Docker; `--build-from <Dockerfile>` for local builds.
- `outcall rules reload` — atomic reload from `rules.d/`.
- `outcall ui [--port 8080]` — built-in TCP↔Unix-socket bridge that opens
  the dashboard in your browser. No socat needed.
- `outcall --version` / `outcalld --version`.

### Install

```bash
brew tap outcall-dev/outcall
brew install outcall
outcall daemon start --build-from scripts/e2e/Dockerfile  # or use --image
outcall ui
```

### Tests

- `cargo test --workspace` — 21 lib tests + Linux-only integration tests
  (proxy HTTP/HTTPS, bridge, dynamic rules).
- `scripts/full-test.sh` — release-grade Linux harness that does
  `brew uninstall → brew tap → brew install`, drives the daemon container
  via the new `outcall daemon start`, applies a rule set covering every
  documented condition (default-deny, DNS allow, HTTPS SNI allow, CIDR
  allow, deny precedence, agent-name, HTTP method, dynamic add/remove),
  and runs 12 real-traffic assertions including `apt-get update`,
  `apt-get install ca-certificates`, GET-vs-POST split, container-to-container
  isolation, and S013 `agent.name` allow/deny.

## Known limits

- **Linux only.** outcalld needs `NET_ADMIN` and Linux netfilter. macOS
  development requires running the daemon inside a Linux VM
  (lima/colima/UTM) or a privileged Docker container.
- **No bottle yet.** The brew formula builds from source via cargo
  (~1-2 minutes on first install). A pre-built bottle is on the v0.2 list.
- **Agent shim path still uses caller-supplied `container_id`** (issue #4).
  Real HTTPS/apt traffic is unaffected — that transits the proxy path,
  which fully resolves `agent.name` from the TCP peer IP.

## Upgrading

This is the first public release; no upgrade path applies. Install with
`brew tap outcall-dev/outcall && brew install outcall`.

## Contributors

- @marktopper

---

For the full changelog, see [CHANGELOG.md](CHANGELOG.md).
For specifications, see the [specs repo](https://github.com/Outcall-dev/specs).
