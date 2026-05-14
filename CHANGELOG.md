# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
