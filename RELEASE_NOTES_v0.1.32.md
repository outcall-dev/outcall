## Outcall v0.1.32

This patch makes subsequent daemon image releases faster and more reliable.

### Release performance

- The multi-architecture daemon build now imports and exports a dedicated
  GitHub Actions Buildx cache across release tags.
- The cache retains intermediate Rust compilation layers for both Linux
  architectures, avoiding unnecessary cold recompilation on later releases.
- Cache export failures are non-fatal, so verified release publication still
  completes when the cache service is unavailable.

### Verification

- The immutable release-tag manifest remains verified before platform archive
  export.
- The release continues to publish both platform daemon archives and checksums.
