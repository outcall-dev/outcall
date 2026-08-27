# Specification Traceability

[`spec-traceability.tsv`](./spec-traceability.tsv) maps every current subsystem
spec (`S000` through `S015`) to its primary implementation and executable test
artifact. `partial` means the linked test covers only the implemented subset;
it must not be read as full acceptance of that specification.

Security requirements are also exercised close to their implementation: proxy
framing, SNI, managed-peer, and restricted-address tests live under
`outcalld/src/proxy/`; DNS answer filtering, address-family matching, and
TTL-bounded direct grants under `outcalld/src/dns/`; dynamic-rule expiry and
cleanup under `outcalld/src/dynamic/`; container identity caching under
`outcalld/src/docker/identity.rs`; and full Docker creation/lifecycle hardening
under `outcalld/src/docker/`, `outcalld/src/bind_mount.rs`, and
`scripts/test-managed-container-security.sh`. Full bridge enforcement is
covered by `scripts/test-container-isolation.sh` and
`scripts/test-daemon-outage-fail-closed.sh`.

Validate the map locally with:

```sh
make spec-check
```

CI checks that every spec is represented, each path exists, IDs are unique,
and statuses use the defined vocabulary. Detailed functional requirements and
acceptance status remain authoritative in the separate
[`outcall-dev/specs`](https://github.com/outcall-dev/specs) repository.
