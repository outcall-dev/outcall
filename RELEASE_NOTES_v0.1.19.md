# Outcall v0.1.19

First-run regression fix.

This patch follows v0.1.18 and fixes a regression in the new install-and-run
path for clean projects.

## What's fixed in v0.1.19

- `outcall init claude` and `outcall init codex` no longer fail on a clean
  project because the generic `.outcall/agent.yaml` template collided with the
  recipe-specific `agent.yaml`.
- `outcall run <claude|codex>` now works correctly on a clean project because
  its scaffold phase no longer trips that collision.
- Added a regression test that runs recipe init in a clean temp project.

## Verification

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test -p outcall`
- direct source check: `cargo run --manifest-path ... -- init claude` in a
  clean temp directory now succeeds

## Notes

- `v0.1.18` introduced the install script and `outcall run` path, but the
  clean-project recipe init collision made that path unreliable for first-time
  use. `v0.1.19` is the corrective patch release.
