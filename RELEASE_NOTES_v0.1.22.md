# Outcall v0.1.22

First-run onboarding release.

This patch makes the default Claude Code / Codex install path simpler and
aligns the release pipeline with what the website and installer tell users to
do.

## What's fixed in v0.1.22

- Bare `outcall` now prints the recommended first command for the current
  project and host instead of failing with a missing-subcommand error.
- `outcall setup` now accepts an optional provider and uses the same saved
  default, project-context, and host-auth detection order as `outcall start`.
- First-run guidance now consistently points users at:
  - `outcall`
  - `outcall start`
  - `outcall setup`
- `cargo deny` policy no longer carries stale unmatched license allowances that
  were adding noise to CI without protecting anything.
- Release metadata now follows the actual workspace version:
  - tag-on-merge reads the version from `outcall/Cargo.toml`
  - release builds read `RELEASE_NOTES_<tag>.md` dynamically

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p outcall --locked`
- application CI run `28782552833`
  - `cargo fmt`
  - `cargo clippy`
  - `cargo geiger`
  - `cargo check`
  - `cargo test (unit)`
  - `cargo test (integration)`
  - `cargo test (privileged e2e - docker)`
  - `cargo test (privileged e2e - sudo)`
  - `cargo deny`
  - `cargo audit`
  - installer smoke in progress at release-note creation time

## Notes

- `v0.1.21` fixed first-run socket paths and daemon startup races.
- `v0.1.22` makes the public onboarding story coherent enough that the website,
  install script, docs, and shipped binary can all tell the same user story.
