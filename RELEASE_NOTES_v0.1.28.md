## Outcall v0.1.28

This patch makes the explicit first-run command path simpler and fixes repeat
launches in already-initialized projects.

### Included changes

- the preferred explicit command is now `outcall run claude` or
  `outcall run codex`
- onboarding, installer output, README guidance, and website copy now point at
  `outcall run <recipe>` instead of the older provider aliases
- `outcall run <recipe>` is now idempotent on an existing project scaffold
  instead of failing on pre-existing generated recipe files
- containerized Codex output-file paths now work when the target file lives
  inside the mounted project workspace

### Verification

- focused Rust tests for:
  - onboarding text updates
  - idempotent setup on existing recipe files
  - workspace output-path rewrite and rejection rules
- macOS end-to-end smoke:
  - `curl -fsSL https://outcall.dev/install.sh | sh`
  - `outcall doctor`
  - `outcall run codex --auth copy -- exec --skip-git-repo-check --ephemeral -o out.txt "Reply with exactly: hi"`
  - repeated `outcall run codex ...` on the same project returned `hi` again
    and no longer failed on existing scaffold files
