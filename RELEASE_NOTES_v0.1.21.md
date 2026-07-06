# Outcall v0.1.21

First-run socket-path fix.

This patch follows v0.1.20 and fixes the remaining one-command run failure on
non-root hosts and CI runners.

## What's fixed in v0.1.21

- The default host-side daemon sockets now live under `/tmp/outcall/`, which is
  writable on standard user shells and GitHub runners.
- `outcall run` now waits for the daemon socket to become reachable before the
  first API call, instead of racing daemon startup.
- `outcall daemon start` now passes explicit host and agent socket paths into
  the daemon container, so custom socket locations and the first-run flow stay
  aligned.
- Onboarding docs and the website now show the writable socket defaults.

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p outcall-api -p outcall`
- `sh -n scripts/install.sh`
- `sh -n website/public/install.sh`
- `node scripts/sync-docs.mjs`
- `./node_modules/.bin/next build --webpack`

## Notes

- `v0.1.20` introduced release-backed daemon image preload, but the default
  host socket path still assumed a root-writable `/run/outcall` directory.
- `v0.1.21` keeps the release-asset flow and makes the default one-command path
  work on ordinary Linux user accounts.
