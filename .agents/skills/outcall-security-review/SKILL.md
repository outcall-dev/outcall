---
name: outcall-security-review
description: Review Outcall container isolation, default-deny egress, provider recipes, installer integrity, and release readiness. Use for Outcall security changes, Docker or network policy changes, recipe or authentication changes, release preparation, security regressions, and post-reset runtime validation.
---

# Outcall Security Review

Use repository scripts and CI as the source of truth. Do not recreate security probes in the skill.

## Workflow

1. Inspect `git status` and preserve unrelated changes.
2. Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and the relevant tests.
3. Run ShellCheck and syntax checks for every `scripts/**/*.sh` file.
4. Run `make spec-check` when behavior, policy, auth, or release contracts change.
5. Run the local installer and Docker security suite for runtime-affecting changes. Use these canonical probes:
   - `scripts/test-container-isolation.sh`
   - `scripts/test-managed-container-security.sh`
   - `scripts/test-egress-policy.sh`
   - `scripts/test-daemon-outage-fail-closed.sh`
   - `scripts/test-netfilter-preflight.sh`
6. Confirm all temporary containers and networks are removed. Keep only a deliberately active `outcall-daemon`.
7. Require the GitHub check named `secure install + runtime + security validation` on the exact release commit. `scripts/verify-release-security-gate.sh` enforces this in release automation.
8. Verify release manifests and anonymous pulls for the daemon, Codex, and Claude images.

## Invariants

- Keep egress default-deny. Do not weaken a test to make a release pass.
- Require both bridge netfilter hooks and restore them after negative tests.
- Force managed DNS and HTTP(S) paths and test direct-IP bypass denial.
- Run agents non-root with all capabilities dropped, no-new-privileges, read-only rootfs, bounded PIDs, and bounded memory.
- Treat `/workspace` and explicitly staged provider state as the only routine writable host-backed mounts.
- Keep live provider credentials out of pull-request jobs and repository-controlled build steps. Use the protected `provider-smoke` environment.
- Treat local Docker state as disposable because the scheduled Docker Desktop reset can remove it.

## Release Decision

Block release on any failed or missing security check, missing image architecture, anonymous pull failure, installer checksum failure, leaked secret, or leftover privileged test resource. Report environmental credential absence separately from product failures.
