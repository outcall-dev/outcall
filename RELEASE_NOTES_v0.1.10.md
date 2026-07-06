# Outcall v0.1.10

Recipe runner release. Outcall is a host-level firewall daemon that governs all
outbound traffic from Docker agent containers. It creates isolated networks,
applies nftables policies via a managed bridge, and gives operators CLI + API
control over what containers can reach.

This release adds runnable built-in agent recipes and clears CI release
blockers found after v0.1.9.

## What's in v0.1.10

### Recipes

- Added `outcall recipe run <claude|codex>`.
- `recipe run` initializes missing recipe files, builds the local recipe image,
  stages selected provider auth/config, and starts the agent through the normal
  `outcall agent` container boot path.
- Added auth transfer modes:
  - `--auth copy` copies selected provider files into
    `.outcall/auth/<recipe>/home` and mounts that as `/home/node`.
  - `--auth mount` mounts selected provider files directly from the host home.
  - `--auth env-only` passes matching auth environment variables only.
- Generated `.outcall/.gitignore` now ensures `.outcall/auth/` is ignored.
- Added built-in Claude Code and Codex CLI Dockerfiles, rules, context notes,
  and doctor checks.

### CI and Dependencies

- Updated `anyhow` to `1.0.103` to clear `RUSTSEC-2026-0190`.
- Privileged sudo CI now invokes the explicit installed Cargo binary under
  sudo instead of relying on root rustup defaults.
- Privileged Docker CI mounts the host Docker socket and serializes ignored
  e2e tests that share bridge/proxy state.

## Still included from v0.1.9

### Daemon (`outcalld`)

- nftables-driven default-deny bridge for agent containers (S001/S002).
- CEL-based rule engine with hot reload via the host API (S003).
- Agent shim API on a dedicated Unix socket — permission checks, check-in,
  rule requests (S004/S005).
- HTTP/HTTPS proxy with SNI peeking. TLS interception is not implemented in
  this beta; HTTPS method/path/body matching is not available yet.
- DNS filter with allow/deny by query, bounded cache, A/AAAA handling, and
  private-IP response stripping to block DNS rebinding by default (S007).
- Docker manager that creates, lists, inspects, and tears down agent
  containers; auto-applies the `managed-by=outcalld` label (S008).
- Dynamic nftables rules with bidirectional CEL ↔ nftables coordination (S009).
- Read-only operator dashboard served from the host socket (S010).
- `agent.name` CEL context — write rules per-agent, not just per-image (S013).
- Bridge and proxy default bind addresses now use `10.200.0.1` instead of
  `0.0.0.0`, limiting exposure to the managed agent bridge by default.
- `--no-proxy` now refuses to start when loaded rules require
  `egress.mode: proxy`, avoiding silent enforcement gaps.
- Agent API session tokens now require OS cryptographic randomness; there is
  no predictable fallback RNG.
- Agent API rate-limit maps now reap stale container entries.
- Plain HTTP requests with mismatched absolute-form URI authority and `Host:`
  header are rejected.
- CONNECT rejects known non-HTTPS service ports by default while still allowing
  rule-approved custom TLS ports.

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
- `outcall requests list|approve|reject` — operator approval flow for
  agent-submitted rule requests.
- `outcall ui [--port 8080]` — built-in TCP↔Unix-socket bridge that opens
  the dashboard in your browser. No socat needed.
- `outcall --version` / `outcalld --version` / `outcall-agent --version`.

### Install

```bash
docker run -d --rm \
  --name outcall-daemon \
  --network host \
  --cap-add NET_ADMIN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /run/outcall:/run/outcall \
  -v /etc/outcall:/etc/outcall \
  ghcr.io/outcall-dev/outcalld:latest \
  --bridge outcall0
```

The release image contains `outcalld`, `outcall`, and `outcall-agent` on
`PATH`. Binary tarballs include the same three binaries for each release target.

### Tests

- `cargo test --workspace` — unit and integration tests across all five crates
  (proxy HTTP/HTTPS, bridge, DNS, dynamic rules, API, CLI, agent shim, UI).
- CI runs `cargo check`, `cargo test`, `cargo fmt`, `cargo clippy`,
  `cargo audit`, `cargo geiger`, and `cargo deny` in the application repo.
- Root CI runs the Docker E2E, bypass, and payload suites against the full
  multi-repo workspace.
- Release verification includes source builds, workspace tests, the Linux test
  Dockerfile, the first-party release image, and website production builds.

## Known limits

- **Linux only.** outcalld needs `NET_ADMIN` and Linux netfilter. macOS
  development requires running the daemon inside a Linux VM
  (lima/colima/UTM) or a privileged Docker container.
- **No system package yet.** Docker and source installs are supported. A
  systemd unit, deb/rpm packages, and Homebrew bottle are on the post-beta list.
- **TLS interception is not shipped yet.** The proxy sees HTTPS CONNECT host
  and SNI only; method/path/body filtering requires the future S011 work.
- **No signed release artifacts yet.** SHA256 sums are produced; Sigstore/SBOM
  signing is deferred to v0.2.

## Upgrading

Install from the published Docker image or release tarballs. If you tested an
earlier `0.1.x` tag, review the bind-default change in `CHANGELOG.md`: the
daemon now binds DNS and proxy services to the managed bridge IP by default
instead of `0.0.0.0`.

## Contributors

- @marktopper

---

For the full changelog, see [CHANGELOG.md](CHANGELOG.md).
For specifications, see the [specs repo](https://github.com/outcall-dev/specs).
