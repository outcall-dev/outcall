# Outcall v0.1.16

Privileged test harness hardening release.

This patch follows v0.1.15 and focuses on the remaining ignored e2e suites
that were still using brittle daemon startup assumptions under the privileged
GitHub Actions lanes.

## What's in v0.1.16

### Privileged e2e stability

- Dynamic rules, mixed-modes, and intercept e2e helpers now start `outcalld`
  with `--no-proxy` when the test only exercises the Unix socket APIs.
- Those helpers now poll for socket readiness instead of sleeping for a fixed
  300ms.
- Startup helpers now capture daemon stderr and surface it on early exit or
  readiness timeout, making CI failures actionable instead of collapsing into
  later `ENOENT` or connect errors.
- The placeholder mixed-modes `direct_ip` test now explicitly kills its daemon
  instead of leaving a background process running for the rest of the ignored
  test lane.

## Verification

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test --workspace --tests --locked`
- `cargo test -p outcall`

## Notes

- This release does not add product features. It reduces flakiness and makes
  the remaining privileged CI failures easier to diagnose if any still remain.
