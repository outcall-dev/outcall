# Outcall v0.1.18

Install-and-run onboarding release.

This patch follows v0.1.17 and removes another layer of first-run friction for
new users who just want Claude Code or Codex running in an isolated container.

## What's in v0.1.18

### One-command project launch

- Added top-level `outcall run <claude|codex>` as the recommended first-run
  path.
- `outcall run` performs:
  - `outcall init <recipe>`
  - `outcall doctor <recipe>`
  - `outcall recipe test <recipe>`
  - `outcall recipe run <recipe>`
- Lower-level `setup` and `recipe run` commands remain available for operators
  who want to split the flow.

### Public install script

- Added `https://outcall.dev/install.sh` for release-binary installation.
- The script downloads the correct release tarball for Linux/macOS
  x86_64/aarch64 and installs `outcall`, `outcalld`, and `outcall-agent` into
  `~/.local/bin` by default.

### Documentation and website

- Updated README, installation, quickstart, and CLI docs to lead with:
  - `curl -fsSL https://outcall.dev/install.sh | sh`
  - `outcall run claude`
  - `outcall run codex`
- Updated website marketing and docs landing copy to present the install script
  and `outcall run` as the default first-run path.

## Verification

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test -p outcall`
- website production build via `npm run build`

## Notes

- `outcalld` remains Linux-only. The install script also supports macOS
  binaries for CLI-only use, but isolated agent containers still require a
  Linux host or VM.
