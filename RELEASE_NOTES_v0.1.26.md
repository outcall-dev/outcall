## Outcall v0.1.26

This patch publishes the first-run Mac usability fixes that landed after
`v0.1.25`.

### Included changes

- `outcall doctor` and first-run setup now fail fast when Docker is installed
  but the daemon is not responding, instead of hanging on `docker info`.
- failure output now includes the active Docker context and a direct operator
  action: restart Docker Desktop and rerun
- the repository now includes a maintainer-local installer loop:
  - `scripts/local-install-smoke.sh`
  - `make install-smoke`
  - post-install smoke commands such as `make install-smoke-doctor-codex`
- application `Makefile` now includes the `build` / `stop` targets expected by
  the security validation workflow, with a fallback `CARGO_TARGET_DIR` path for
  root-owned or otherwise unwritable default Cargo target directories

### Verification

- `cargo test -p outcall command_output_with_timeout --locked`
- `cargo test -p outcall doctor_platform_message_covers_linux_macos_and_other_hosts --locked`
- `cargo fmt --all --check`
- `make install-smoke-doctor-codex`
- `make install-smoke POST_INSTALL='outcall codex -- --version'`
