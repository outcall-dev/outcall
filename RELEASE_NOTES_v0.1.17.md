# Outcall v0.1.17

Recipe-first onboarding release.

This patch follows v0.1.16 and makes the first-time path for isolating
Claude Code or Codex significantly simpler. The focus is not new daemon
capabilities; it is reducing setup ambiguity for new users.

## What's in v0.1.17

### First-run CLI flow

- Added top-level `outcall init` to scaffold `.outcall/` for the current
  project.
- Added top-level `outcall doctor` for generic first-run checks, with
  `outcall doctor <recipe>` for Claude/Codex-specific checks.
- Added top-level `outcall setup <claude|codex>` to run scaffold creation,
  recipe checks, and the smoke test in one command.
- Added `outcall recipe test <claude|codex>` as a smoke test for the recipe
  image, auth staging, daemon reachability, default network readiness, and
  entrypoint execution.

### Recipe run simplification

- `outcall recipe run` now auto-starts `outcall-daemon` when it is missing.
- `outcall recipe run` now ensures the default managed network exists instead
  of assuming the user created it manually first.
- The public onboarding path is now:
  - `outcall setup claude`
  - `outcall recipe run claude`

### Documentation and website

- Updated the application README to show the recipe-first onboarding flow.
- Updated installation, quickstart, and CLI docs to lead with Claude/Codex
  isolation instead of lower-level bridge/network mechanics.
- Updated website messaging to present Outcall as the easiest way to put
  Claude Code or Codex in a default-deny container.

## Verification

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test -p outcall`
- website production build via `npm run build`
- application CI run `28773837610` passed, including privileged sudo and
  privileged docker lanes

## Notes

- The release workflow for `v0.1.16` still showed the container-image publish
  job as in progress when last checked, but the `v0.1.16` release itself was
  already published with assets. This patch does not change daemon networking
  behavior; it improves the user path into the existing model.
