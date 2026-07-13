## Outcall v0.1.30

This patch makes release packaging and release verification more reliable.

### Release packaging

- The release workflow now exports the amd64 and arm64 daemon archives from
  the already-published multi-architecture image manifest. It no longer
  recompiles the daemon separately for each archive.
- Container release jobs publish a duration summary and emit a warning when
  image publication plus archive export exceeds 45 minutes.

### Verification

- Local installer and secure-runtime CI images are assembled from the
  runner-built release binaries and the shared Debian Bookworm runtime stage.
- The two jobs use Ubuntu 22.04 so their host-built binaries remain compatible
  with the Debian Bookworm runtime image.
- Full CI covers local installation, Claude and Codex recipe startup, bridge
  isolation, network leak checks, and the secure unattended-mode preflight.
