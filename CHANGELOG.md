# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CLI:** when Claude or Codex detection is unambiguous, bare `outcall` now
  runs the first-time setup and launch flow directly instead of stopping at
  printed onboarding output.
- **CLI:** bare `outcall` now prints project-aware onboarding instead of
  exiting on a missing subcommand.
- **CLI:** top-level `outcall start [claude|codex]` command. With an explicit
  provider it behaves like the provider alias; without one it auto-selects
  Claude or Codex only when the host has an unambiguous matching auth setup.
- **CLI:** top-level `outcall run <claude|codex>` command for the shortest
  first-run path. It performs scaffold generation, prerequisite checks, smoke
  verification, and then launches the actual isolated agent container.
- **Install script:** `https://outcall.dev/install.sh` installs release
  binaries directly into `~/.local/bin` without cloning the repository or
  building from source first.
- **Release assets:** publish Docker-loadable daemon image archives for
  `linux/amd64` and `linux/arm64` so first-time installs can preload the
  matching `outcalld` image from the GitHub Release itself.

### Changed

- **First-run UX:** `outcall run <claude|codex>` is now the preferred explicit
  launch path, reruns cleanly on an existing project scaffold, and rewrites
  container output-file paths when the target file lives inside the mounted
  workspace.
- **Non-Linux first run:** recipe setup and launch now stop before Docker
  build, daemon startup, or GHCR pulls on non-Linux hosts, with a direct
  message that scaffolding/auth checks are ready but runtime launch requires a
  Linux host or VM.
- **First-run failures:** recipe setup now checks Docker access before build or
  daemon work begins, so first-time users get a direct Docker socket error
  instead of a later `docker build` failure.
- **CLI:** `outcall setup` now accepts an optional provider and follows the
  same saved-default, project-context, and host-auth detection order as
  `outcall start`.
- **Onboarding docs:** README, installation, quickstart, CLI reference, and
  website copy now lead with `curl -fsSL https://outcall.dev/install.sh | sh`
  followed by `outcall`, then `outcall start`, with explicit
  `outcall run claude` / `outcall run codex` fallbacks when detection is
  ambiguous.
- **Daemon bootstrap:** the CLI now defaults to the matching versioned daemon
  image tag instead of `latest`, and the installer preloads that image when
  Docker is available.
- **CI:** installer smoke now proves the one-command first-run path for both
  Claude and Codex, not just Claude.
- **Release automation:** tag creation now follows the workspace version in
  `outcall/Cargo.toml`, and the release workflow reads the matching versioned
  release-notes file dynamically.

## [0.1.9] - 2026-07-06

### Added

- **Release image:** Add a first-party `ghcr.io/outcall-dev/outcalld` Docker
  image build that ships `outcalld`, `outcall`, and `outcall-agent`.
- **Release packaging:** Include `outcall-agent` in release tarballs and publish
  prerelease notes from the versioned `RELEASE_NOTES_v0.1.9.md` file.

### Changed

- **Install docs:** Point clean installs at the public GHCR image and remove
  stale local test-harness assumptions from the README and docs.
- **Website:** Make the Vercel build path run the docs sync script directly and
  force webpack builds while the local Turbopack build hangs.
- **CLI:** Default generated agent configs to the actual `outcall-default`
  network.

### Fixed

- **Agent shim:** `outcall-agent --version` and `--help` now work before the
  runtime socket exists, which lets release tarballs and container images verify
  cleanly.

### Changed — 2026-05-20 (BREAKING)

- **Daemon:** `--dns-listen` default changed from `0.0.0.0` to `10.200.0.1`
  (the outcall bridge IP).  On a multi-NIC host (laptop with Ethernet + Wi-Fi,
  cloud VM with a public interface, server with a management plane) the previous
  default exposed the DNS resolver on every network interface, including public
  ones.  The new default restricts the service to the managed bridge so only
  agent containers can reach it.  **Operators who relied on the old behaviour
  must add `--dns-listen 0.0.0.0` (or a specific interface address) to their
  deployment manifest.**  The effective address is now logged at INFO on startup.
- **Daemon:** `--proxy-addr` default changed from `0.0.0.0:8080` to
  `10.200.0.1:8080` (the outcall bridge IP).  Same rationale as `--dns-listen`
  above — the HTTP proxy was previously reachable from any network interface.
  **Operators who relied on the old behaviour must add
  `--proxy-addr 0.0.0.0:8080` (or a specific interface address) to their
  deployment manifest.**  The effective address is now logged at INFO on startup.
  If you override `--subnet-block` you must also override both flags to match
  the new bridge IP.

### Security — 2026-05-19 hardening wave

- **Daemon:** Lock down host control socket (`SO_PEERCRED` enforcement, `umask 077`,
  `chmod 0600`) so only root processes on the host can connect.
  ([`5c5b1a8`](https://github.com/Outcall-dev/outcall/commit/5c5b1a8))
- **CLI:** Harden `outcall ui` TCP bridge against DNS rebinding: enforce
  `Host`/`Origin` header checks, require the dashboard token on every request,
  and bind only to `127.0.0.1`.
  ([`9c68b59`](https://github.com/Outcall-dev/outcall/commit/9c68b59))
- **API:** Deny unknown fields on all trust-boundary structs — 29 structs gained
  `#[serde(deny_unknown_fields)]` to reject smuggled keys at deserialization.
  ([`b6829c7`](https://github.com/Outcall-dev/outcall/commit/b6829c7))
- **UI:** Escape API-sourced strings in the dashboard to prevent stored XSS.
  ([`e20325f`](https://github.com/Outcall-dev/outcall/commit/e20325f))

### Fixed — 2026-05-19

- **Daemon:** Move `require_operator_uid` out of `unsafe` block in the lib crate
  (was incorrectly wrapped); no behaviour change.
  ([`c6f7391`](https://github.com/Outcall-dev/outcall/commit/c6f7391))

### Fixed — 2026-05-19 (test harness, outer repo)

- **Tests:** `test-bypass.sh` and `test-payloads.sh` were silently swallowing
  failures — 24 `|| true` removed from `test-bypass.sh`, 36 from
  `test-payloads.sh`, 19 head-pipe invocations now use `pipefail`. Bypass and
  payload suites now actually validate.
  ([`4e2673d`](https://github.com/Outcall-dev/outcall/commit/4e2673d))

### Changed — 2026-05-19 (docs)

- **Docs:** Fix phantom CLI commands, CEL field-name drift, TLS intercept
  overclaims, and dashboard endpoint accuracy across the docs repo.
  ([`c617f5a`](https://github.com/Outcall-dev/docs/commit/c617f5a))
- **Docs:** Fix `Outcall-dev` GitHub org casing in `installation.md`.
  ([`ad6eeb1`](https://github.com/Outcall-dev/docs/commit/ad6eeb1))
- **Website:** Fix CEL field names, remove phantom CLI commands, downgrade TLS
  intercept claim to match current implementation.
  ([`2c76a9e`](https://github.com/Outcall-dev/website/commit/2c76a9e))

### Added — release-prep round 1 (2026-05-10)

- **CLI:** `outcall daemon start | stop | status` — wraps `docker run` of
  the daemon container (NET_ADMIN/SYS_ADMIN, host network, mounts
  `/var/run/docker.sock` and the rules directory). Supports
  `--build-from <Dockerfile>` for local image builds and `--image` for
  registry pulls. Defaults: image `ghcr.io/outcall-dev/outcalld:latest`,
  name `outcall-daemon`, bridge `outcall0`. Closes the brew-install →
  run-the-daemon UX gap (the CLI was previously socket-only).
- **CLI:** `outcall rules reload` — wraps the existing
  `POST /api/v1/rules/reload` host endpoint and prints reloaded files /
  rules count plus any warnings. Lets operators (and tests) trigger atomic
  rule reload after editing `rules.d/`.
- **CLI:** `outcall ui [--port 8080] [--no-open]` — built-in TCP↔Unix-socket
  bridge that opens the dashboard in your browser. No more `socat` dance —
  closes the largest first-impression gap for v0.1 operators.
- **CLI:** `outcall daemon logs [--follow] [--tail N]` — convenience wrapper
  for `docker logs outcall-daemon`. Used by `full-test.sh` for clearer
  failure diagnostics when the daemon socket doesn't come up.
- **Proxy:** `agent.name` is now populated on `EvalContext` for
  proxy-routed traffic (S013-FR-005 fully implemented). The proxy resolves
  the TCP peer's source IP via `DockerManager::lookup_container_name_by_ip`
  (filtered on `managed-by=outcalld`), strips the `-N` replica suffix via
  `derive_agent_name`, and binds it to CEL evaluation. Rules like
  `agent.name == "ci"` now match real HTTPS traffic, not just shim-path
  permission checks.
- **Tests:** `scripts/full-test.sh` — release-grade harness that does
  `brew uninstall → brew untap → brew tap outcall-dev/outcall → brew
  install`, starts the daemon container via the new `outcall daemon
  start`, applies a 6-file rule set covering every documented condition
  (default-deny, DNS allow, HTTPS SNI allow, CIDR allow, deny precedence,
  agent.name match, HTTP method match, dynamic add/remove), and runs 12
  real-traffic assertions including `apt-get update`, `apt-get install
  ca-certificates`, GET-vs-POST split, container-to-container isolation,
  and S013 `agent.name` allow/deny. Linux-guarded with macOS instructions.
- **Docs:** `docs/dashboard.md` — operator guide for S010. Covers Unix
  socket access (socat/nginx shim required), the 6 dashboard views, the
  rule-request approve/reject flow, security model, platform notes, and
  v0.1 limits.
- **Docs:** `docs/rules.md` — corrected the Agent context section
  (removed fictional `agent.container_id`/`agent.image` fields), added
  resolution-path explanation (proxy vs shim) and 3 worked examples
  (per-agent allow, per-agent deny, deny-unidentified safety net).

### Changed

- **Spec S013:** all 14 FR/IF/EC/SC rows updated from Draft to
  Implemented (or Partial, with file:line evidence). FR-003 SO_PEERCRED
  in the agent_api path remains tracked in issue #4 but does not block
  v0.1 because real apt/curl/HTTPS traffic transits the proxy.

### Known limits going into v0.1

- Daemon requires Linux (NET_ADMIN). macOS support is via Linux VM only.
- No bottle for the brew formula yet — install builds from source via
  cargo (~1-2 minutes on first install).
- Agent_api shim path still uses caller-supplied `container_id` instead
  of SO_PEERCRED (issue #4). Affects only shim-issued permission checks,
  not proxy-routed traffic.
