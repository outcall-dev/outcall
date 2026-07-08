## Outcall v0.1.27

This patch publishes the macOS daemon image preload fix for the public
installer.

### Included changes

- macOS installs now preload the matching Linux daemon image archive for Docker
  Desktop, just like Linux installs already did
- first-run macOS agent launch no longer depends on an authenticated GHCR pull
  for `ghcr.io/outcall-dev/outcalld:v0.1.27`
- local installer smoke remains aligned with the public installer behavior

### Verification

- `sh -n scripts/install.sh`
- `sh -n scripts/local-install-smoke.sh`
- modified installer against published `v0.1.26` assets on macOS loaded
  `ghcr.io/outcall-dev/outcalld:v0.1.26` locally
- fresh temp-project `outcall codex -- --version` reached daemon startup and
  then failed only on missing Codex auth material
