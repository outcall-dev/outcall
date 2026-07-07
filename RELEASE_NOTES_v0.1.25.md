# Outcall v0.1.25

Mac recipe runtime and first-run hardening.

This patch publishes the merged runtime path from `#14` so the public installer
and release assets expose the actual Docker-backed macOS flow, not the older
Linux-only first-run boundary.

## What's fixed in v0.1.25

- macOS first-run recipe launch now uses Docker Desktop's Linux runtime for
  the daemon and managed agent containers instead of stopping before runtime.
- daemon startup from the CLI no longer passes a misplaced `-v` mount argument
  into `outcalld`, which fixes the release smoke path on Linux.
- the default managed container name now follows the project name pattern
  `<folder>-1`, `<folder>-2`, ... and CI smoke coverage now validates that
  real naming behavior.
- project host-resource registries can now auto-start a host broker for
  declared tools and files, with deny-by-default gating and daemon rule
  evaluation before host access.
- the Rust dependency graph now includes the `crossbeam-epoch` advisory fix
  required by the current audit database.

## Verification

- full GitHub Actions CI passed on PR `#14`, including:
  - `installer smoke (linux)`
  - `secure install + runtime + security validation`
- local macOS validation on the merged branch:
  - daemon-managed Codex recipe path started through Docker Desktop's Linux runtime
  - website and installer endpoint checks passed on `outcall.dev`
- local workspace checks:
  - `cargo build --workspace --locked`
  - `cargo audit`
  - `cargo deny check`

## Notes

- the public installer default version now points at `v0.1.25`.
- first-time Docker detection on macOS still depends on the local Docker CLI
  being usable from the invoking shell environment.
