# AIVM Secrets: validation record

Date: 2026-10-09. Base commit: `32344b67110b6d3877bd33c52848ed38d6d5c37d`.
Source: `aivm-source-2026-10-09T202126-5-32344b67110b.tar.gz`.
This records execution in the development container, not a production deployment
or a formal proof result.

## Executed checks

| Check | Result |
| --- | --- |
| New secret-management tests | **149 passed** |
| Complete `tests/` suite, non-E2E, unprivileged UID | **1,489 passed, 8 skipped, 11 deselected** |
| Generated architecture documentation | **Passed**, 12 generated outputs checked |
| Python compilation | **Passed** for the new package and modified adapters |
| Wheel build | **Passed**, `aivm-0.6.2-py3-none-any.whl` |
| Wheel inspection | New modules match source bytes; CLI entry point and optional crypto dependency present |
| Standalone CLI lifecycle | Dummy credential, one-second grant, clean expiry/socket cleanup; no provider request |
| Policy and AIVM CLI smoke checks | Example policy parses; SSH help exposes the three opt-in options |
| Whitespace/diff check | Passed |

The unprivileged full test run reported two existing configuration-validation
warnings for deliberately invalid enum values. The initial root run exposed
three privilege tests whose assumptions do not hold for root; all three also
failed against the unmodified archived base. The unprivileged full run passes
without suppressing those tests. An architecture-classification omission from
the new adapter was found and fixed, including regenerated dependency metadata.

The focused command was:

```bash
python -m pytest -o addopts='' -q tests/test_secrets_*.py
```

The complete ordinary-test command was:

```bash
python -m pytest -o addopts='' -q -m 'not e2e' tests
```

The recorded unprivileged run additionally selected private temporary/cache
directories because the first root run had left a root-owned pytest cache.
`addopts=''` disables the repository's automatic package-doctest collection;
it does not deselect ordinary tests. A broader package/doctest attempt did not
complete within the execution window and is not counted as a passing check.

Environment: Python 3.13.5, pytest 9.0.2, cryptography 46.0.4. Missing kwconf and
xdoctest were installed offline from the supplied submodules; no source changes
to those submodules are included. The tests extra now includes the secrets
extra so a normal test installation obtains its crypto dependency.

## Security behaviors exercised

Tests cover strict duplicate-key/type/depth/size validation, normalized repository
and PR scope, method/route construction, both write gates, live provider-fact
checks, encryption round trips, every-byte ciphertext tampering, wrong keys,
wrong channels, policy digests, half-open expiry, clock rollback, expiry during
audit/preflight, admission budgets, simultaneous requests, revocation, safe
errors, reflection tripwires, audit failures before/after writes, unknown write
outcomes, private file modes/symlinks/hard links/FIFOs, fixed-origin verified TLS,
redirect/retry rejection, bounded responses, actual Unix sockets and peer UID
checks, and mocked foreground AIVM setup/failure/cleanup.

The tests use deliberately fake provider credentials and mocked provider I/O.
No real credential was used and no credentialed GitHub operation was performed.
A simulated SSH command runner plus a real local socket tests the AIVM adapter;
it is not a live SSH or libvirt test. Finite enumeration and tamper tests are
regressions, not machine-checked proofs of the implementation.

## Not established by this delivery

No Rust/Aeneas/Lean extraction or proof was attempted; no verified-binary claim
is made. No mTLS/non-exportable-key mechanism, OAuth refresh, durable revocation,
per-request human approval, generic API proxy or stock-gh compatibility is
implemented. No live GitHub permission or VM forwarding audit has been done.

Ruff, a type checker and Sphinx/docutils were not installed in this environment;
those checks were not run. Compilation, the available tests, CLI smoke checks
and wheel inspection do not substitute for them. Before wider deployment, run
the operator guide's live read-only VM smoke test and the project's normal CI
in its supported developer environment.

The architecture and formal-assurance documents specify the remaining evidence
needed to move beyond this experimental release. An important operational gap:
changing or disabling an AIVM access identity does not yet notify existing
brokers; explicitly close their host foreground sessions to revoke them.
