## Outcall v0.1.31

This patch repairs deterministic container release tagging.

### Release packaging

- The release workflow now explicitly publishes both the immutable release tag
  and the rolling `latest` tag when it is dispatched from `main`.
- The workflow verifies the immutable image manifest before exporting platform
  archives, so a tag mismatch fails before any release archive work begins.

### Verification

- Release builds retain the fast archive export path introduced in v0.1.30:
  export each platform from the already-published multi-architecture manifest.
- The container job keeps its duration summary and warning threshold so slow
  cross-platform builds remain visible in the release run.
