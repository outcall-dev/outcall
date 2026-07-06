# Outcall v0.1.24

Non-Linux first-run guard.

This patch keeps the simpler bare-`outcall` entrypoint from wandering into
runtime launch steps on hosts where `outcalld` cannot run.

## What's fixed in v0.1.24

- Non-Linux hosts now stop before recipe build, daemon startup, or daemon-image
  pulls when a first-run flow reaches runtime launch.
- The CLI still scaffolds `.outcall`, detects project/auth context, and prints
  doctor output first, so users leave with a prepared project and a clear next
  step instead of a late Docker or GHCR failure.
- Installer defaults now point at `v0.1.24` once the release is published.

## Verification

- `cargo fmt --all --check`
- `cargo test -p outcall --locked`
- local macOS smoke with `AGENTS.md` present:
  - bare `outcall` auto-selected Codex from project context
  - scaffold generation completed
  - doctor output completed
  - command stopped with an explicit Linux-host requirement before runtime work

## Notes

- `v0.1.23` shipped the bare-`outcall` first-run path publicly.
- `v0.1.24` tightens that path so first-time users on macOS or other non-Linux
  hosts get the correct boundary immediately.
