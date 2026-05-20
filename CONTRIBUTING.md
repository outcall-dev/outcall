# Contributing to Outcall

Thanks for taking a look. Outcall is a security-critical piece of
infrastructure — code style and review depth reflect that.

## Quick start

```sh
git clone https://github.com/Outcall-dev/outcall
cd outcall
cargo test --workspace --all-targets
```

Linux is required for full integration testing — most of `outcalld`
shells out to `nftables` and `ip` and uses Linux-specific socket APIs.
On macOS, `cargo check`, `cargo fmt`, and the library/unit tests work,
but daemon tests are gated behind `#[cfg(target_os = "linux")]`.

## Filing a bug

Open an issue with:

- What you ran (exact `outcall` and `outcalld` invocations).
- What you expected.
- What happened — full output, please.
- `outcall --version`.
- Linux distro + kernel (`uname -a`).

For suspected security issues, **do not file a public issue**. See
[`SECURITY.md`](./SECURITY.md).

## Filing a feature request

Tell us the *use case* first, the proposed mechanism second. We tend to
push back on rule-language extensions that can be expressed with
existing CEL bindings, and we tend to push back on changes that widen
the trust surface (e.g. operator-supplied scripts in the daemon path).

## Filing a pull request

1. Fork, branch from `main` (no forced pushes to `main`).
2. Write a failing test for the change, then the change.
3. Run the full pre-PR checks (below) — green CI is a hard requirement.
4. Open the PR. Reference the spec it implements (S0xx-FR-yyy) or the
   issue it fixes.
5. Address review. Squash to a clean history before merge.

## Pre-PR checklist

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit         # if installed
cargo deny check    # if installed
```

For security-sensitive changes (the rule engine, the proxy, the DNS
filter, nftables, agent identity resolution), also run:

```sh
./scripts/test-bypass.sh
./scripts/e2e/run.sh
```

These require Docker and root.

## Code style

- Rust 2024 edition. Format on save with `rustfmt`.
- No `unsafe` without a comment explaining why.
- No `unwrap()` in production code paths (tests are fine). Use `?` or
  explicit error handling.
- Logs go through `tracing::info!`, `warn!`, `error!`. No `println!` in
  the daemon.
- Public items get a `///` doc comment that explains *why* the item
  exists, not just what it does.

## Specs come before code

Outcall has a numbered spec corpus in the [specs](https://github.com/Outcall-dev/specs)
repository. For non-trivial features, write or update the spec first,
land it, then implement. Bug fixes don't need a new spec; behavior
changes do.

## Security-sensitive paths

When you touch any of the following, expect a slower review and an
explicit security checklist on the PR:

- `outcalld/src/rules/engine.rs` — CEL evaluation, default-deny behavior.
- `outcalld/src/proxy/mod.rs` — HTTP/HTTPS proxy, SNI handling.
- `outcalld/src/dns/mod.rs` — DNS filter, rebinding protection.
- `outcalld/src/bridge.rs` — nftables base ruleset.
- `outcalld/src/agent_api/mod.rs` — SO_PEERCRED identity resolution.
- `outcall-agent/src/main.rs` — agent shim. Anything here runs in an
  untrusted container; treat input accordingly.

## License

By contributing, you agree your contribution will be licensed under
Apache-2.0 (see [LICENSE](./LICENSE)).
