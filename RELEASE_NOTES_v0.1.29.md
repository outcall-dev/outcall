## Outcall v0.1.29

This release makes first-time installation and managed agent runs practical on
macOS Docker Desktop as well as Linux.

### First-run workflow

- `outcall doctor --fix <recipe>` starts Docker Desktop when possible, creates
  the project scaffold, preloads/checks the daemon runtime, starts the managed
  network, and verifies the secure bridge preflight.
- `outcall auth <recipe>` stages provider access explicitly. `env-only` uses a
  project-local writable home with no copied host credentials; `copy` and
  `mount` remain available when provider configuration is needed.
- `outcall run <recipe>` is the only provider launch command. `--name` gives a
  predictable container name; otherwise concurrent runs are named from the
  project folder (`<folder>-1`, `<folder>-2`, and so on).
- `outcall ps`, `outcall logs <name>`, and `outcall stop <name>` cover the
  normal container lifecycle.

### Policy workflow

- `outcall allow codex github` and `outcall allow claude github` add
  recipe-defined grants to the project YAML file.
- Exact HTTPS hosts can be granted with `outcall allow codex https://api.sentry.io`.
- `outcall policy explain [recipe]` shows the active rule file and retains a
  default-deny posture for destinations not explicitly allowed.

### Installer and verification

- The public installer verifies SHA-256 checksums for the CLI archive and the
  daemon image archive before installation.
- When Docker is available, it preloads the matching verified Linux daemon
  image, avoiding a first-run registry dependency.
- macOS uses Docker Desktop's Linux VM for both the daemon and agent runtime.

### Verification

- Rust workspace tests and Clippy with warnings denied.
- macOS Docker Desktop end-to-end: repair, auth staging, YAML policy update,
  managed Codex launch, named concurrent containers, logs, and stop lifecycle.
- Local release-layout installer smoke with SHA-256 verification and daemon
  image preload.
