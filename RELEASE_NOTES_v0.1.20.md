# Outcall v0.1.20

Self-contained first-run release.

This patch follows v0.1.19 and removes the remaining registry dependency from
the advertised install-and-run path.

## What's fixed in v0.1.20

- The Linux installer now preloads a matching `outcalld` Docker image archive
  from the GitHub Release when Docker is available.
- Release builds now publish `outcalld-image-linux-amd64.tar.gz` and
  `outcalld-image-linux-arm64.tar.gz` alongside the binary tarballs.
- `outcall daemon start` now defaults to the matching versioned daemon image
  tag (`ghcr.io/outcall-dev/outcalld:vX.Y.Z`) instead of `latest`.
- The installer smoke job now exercises the actual public first-run promise:
  install from release artifacts and run `outcall run claude -- --version` in a
  clean project.
- Daemon startup errors now give a direct hint when the failure is an image
  pull/auth problem.

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p outcall`
- `sh -n scripts/install.sh`
- `sh -n website/public/install.sh`
- local installer simulation with a fake Linux host confirmed that
  `scripts/install.sh` downloads the release tarball, installs the binaries,
  and invokes `docker load` for `outcalld-image-linux-amd64.tar.gz`
- local website build using the checked-in toolchain:
  `node scripts/sync-docs.mjs`
  `./node_modules/.bin/next build --webpack`

## Notes

- This release is intended to make `curl -fsSL https://outcall.dev/install.sh | sh`
  followed by `outcall run claude` or `outcall run codex` work from public
  release artifacts alone on Linux hosts with Docker.
- Final end-to-end proof still depends on the new GitHub Actions release and CI
  runs after the tag is pushed.
