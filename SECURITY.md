# Security policy

## Reporting a vulnerability

If you believe you have found a security issue in Outcall, please
**do not file a public GitHub issue**. Email `security@outcall.dev` with
a description, reproducer, and the version you're running
(`outcall --version`).

We acknowledge within 3 business days and aim to publish a fix within
30 days for high/critical issues. If you do not hear back within 5
business days, please escalate via a private GitHub Security Advisory
at <https://github.com/Outcall-dev/outcall/security/advisories>.

## Supported versions

Outcall is pre-1.0; only the latest tagged release receives security
updates.

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Scope

Outcall is a host-level firewall daemon for containers. It is designed
to fail closed and to keep an agent inside a container limited to a
named set of network destinations.

For the threat model, what we protect against and what we explicitly do
not, see [`docs/security/threat-model.md`](../docs/security/threat-model.md)
in the docs repository.

The most recent internal audit is at
[`docs/security/audit-2026-05-14.md`](../docs/security/audit-2026-05-14.md).

## Coordinated disclosure

We follow a 90-day default disclosure window. If we can't fix in 90
days we'll communicate before the window expires and ask for an
extension.

We will credit reporters in the release notes unless asked not to.
