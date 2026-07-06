# Outcall v0.1.23

Bare `outcall` release.

This patch turns bare `outcall` into the shipped first-run entrypoint when the
current project or host clearly matches Claude Code or Codex.

## What's fixed in v0.1.23

- Bare `outcall` now runs the same first-run flow as `outcall start` when
  recipe detection is unambiguous.
- Ambiguous or missing provider detection still falls back to explicit
  onboarding guidance instead of guessing.
- Recipe setup now stops early with an actionable Docker access error when the
  current user cannot reach the Docker socket.
- README and installer guidance now describe bare `outcall` as the default
  entrypoint and `outcall start` as the explicit equivalent.

## Verification

- `cargo fmt --all --check`
- `cargo test -p outcall --locked`
- public install verification for `v0.1.22` from `https://outcall.dev/install.sh`
- manual smoke of the new branch behavior: bare `outcall` auto-selected Codex
  from project context and failed early with the improved Docker access message
  on this host

## Notes

- `v0.1.22` repaired the public install path and published release assets.
- `v0.1.23` is the release that makes the simpler bare-`outcall` workflow the
  shipped behavior, not just the documented intent.
