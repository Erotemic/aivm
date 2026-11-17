# GPT-6 engineering journal

## 2026-10-12 14:19:44 -0400

Worked against AIVM source `41c1f8a` on the decision to retain **parallel
Python-reference and Rust/formal-verification backends** instead of replacing
the former. I favor this because Python enables quick protocol iteration and
real TLS fault tests, while verified Rust can eventually give stronger,
explicitly scoped guarantees. The distinction between empirical parity and
mathematical equivalence is important: agreement across the planned two
programs is useful evidence but it cannot confer Lean proofs on Python.

Implemented an *opt-in library*, not a new VM feature: a pure identity model
with explicit time and epoch inputs; a bounded Ed25519 JWT containing an
AES-GCM-encrypted **existing** broker capability; and a one-connection TLS 1.3
`CERT_REQUIRED` gate that obtains the actual peer certificate and sends accepted
requests through `Broker.handle`. `delegate` is deliberately forbidden here:
the existing delegate reply would otherwise expose a usable unbound child
capability. Wrote frozen JSONL decision vectors and a future Rust-runner parity
test that explicitly skips, rather than pretending a Rust implementation exists.

The important uncertainty is deployment: host-owned CA/key provisioning,
certificate enrollment, endpoint authentication, listener and guest lifecycle,
clone/snapshot policy, and persistent epochs are **not** solved in this slice.
No real cloud/GitHub token and no VM key is needed by these tests. The new
classes are deliberately not wired to `aivm ssh` until those trust boundaries
are reviewed. The local credentialed broker's admission and audit must never
be bypassed by a certificate-authenticated request.

The focused Python crypto, mTLS and parity-runner tests pass with the local
submodule dependencies on `PYTHONPATH`. Broad isolated CLI tests in this
container still cannot launch the broker using `python -I` because the source
checkout is not installed into that isolated interpreter's trusted site path.
Do not weaken this launch restriction merely to make a test green; retest in a
properly installed, trusted, non-guest-writable environment. No Rust/Lean
proof, vTPM non-exportability or full Garrett OAuth flow is claimed.

Next: independently implement `identity-v1` in Rust, add live source-port
parity gates, review verified TLS routing/issuer enrollment with synthetic
credentials, then continue P4b/P4c without assigning broad `gh` authority to
an agent before it earns that trust.

## 2026-10-12: P4a managed-VM enrollment/transport

Prepared an opt-in managed-VM binding and identity-only launcher as a delta
against the prior P4a enrollment overlay. Subject inputs are derived from host
store and domain UUID; the forced helper operates on the guest-owned software
key, the CA/envelope operations use isolated host subprocesses, and only the
mTLS Unix socket is reverse forwarded. The implementation is Python-only and
real libvirt/SSH testing remains a gate; no Rust assurance is claimed.


The integration review caught a critical extensibility concern: directly
importing the P4a Python authority or kernel in AIVM would defeat the
independent-backend/process-only design. Refactored the CA signing, CSR
inspection, registry inspection, revocation and public chain retrieval into
fixed JSON subprocess verbs behind an isolated interpreter, leaving the
AIVM process free of implementation-specific imports. Added the host binding
parity check and cleanup fault injection. This does not yet provide proof of
Rust/Python agreement or hardware VM attestation.
## 2026-10-15: remove non-optional secrets distribution coupling

Worked from the clean `bee5239` branch snapshot after the maintainer's
repository-boundary decision. The previous runtime lazy-import gate was real,
but the AIVM wheel and sdist still co-shipped the entire experimental
`aivm_secrets` package and its console script. The `all` and `tests` extras
also pulled in secrets cryptography, making ordinary packaging and validation
unnecessarily dependent on the experiment.

Created an independent, explicitly installed `aivm-secrets` Python distribution
in the existing `aivm_secrets/` source folder while keeping the code on this
branch. AIVM's package discovery now includes only `aivm` and its descendants;
the root distribution no longer owns the broker CLI or any secret-specific
extras/dependencies. The sibling build owns the 65 broker Python modules, its
CLI, and its cryptography dependency. I deliberately **did not** point any
AIVM extra at a not-yet-published package: doing so could break resolution of
otherwise unrelated AIVM environments. An opt-in operator installs from the
trusted checkout using `python -m pip install ./aivm_secrets`.

Added no-secrets CI smoke and archive-content checks for two independent wheels
and the core sdist, retaining the combined experimental test suite for now.
Explicit secrets SSH sessions preflight the optional package and crypto before
a foreground SSH invocation can bootstrap a VM. Normal SSH remains free of
secrets imports. Regenerated the one changed architecture dependency inventory.
Agent guidance and the extraction plan reflect that packaging separation is
complete *within this checkout*, while repository extraction and independent
security audit are still future work. The optional AIVM integration adapters
and guest identity helper remain temporary code debt, not a production claim.

The wheel/sdist builds, repository-boundary checks, focused SSH/CLI tests,
architecture check and offline `uv lock --check` succeeded in the work
container. One wider CLI identity test requires a non-root guest UID; this
container runs as root, so I did not treat that environment-dependent failure
as evidence of a code regression. Full user CI and a real-VM experiment remain
unverified here.

## 2026-10-29 11:36:44 -0400

Investigated a shared-host failure in which a non-sudo principal attempted a
new persistent `aivm ssh .` attachment, was denied the privileged host replay
manifest installation, deleted the source directory, and then could no longer
enter a different, previously mounted workspace without another sudo prompt.
The foreground path saved the new attachment before privileged reconciliation,
while replay rewrote the VM-global approved manifest on every scoped visit.

Changed foreground replay to verify the one requested, already-approved and
mounted host export before considering global manifest installation. The check
requires a trusted root-owned manifest, an exact match to the requested stored
record, and a live descriptor-pinned bind with the correct access mode. The
full/global reconciliation paths remain unchanged. Added conservative rollback
of newly registered persistent records on host sudo denial, but only when
neither approved state nor a live mount could own the record; partial successes
retain their recovery coordinates. Applied the same rollback to explicit
`vm attach`. The tradeoff is that an existing out-of-sync record remains in
the desired-state store until an administrator repairs/detaches it; foreground
SSH should no longer be blocked by that unrelated mismatch when its own bind
is already approved. Genuine requested mount changes still require sudo.

Tests cover denied new-session registration, an independent working session,
foreign/stale root-manifest entries, exact approved-record mismatch, retained
partial state, and the explicit attach error path. The attachment/persistent
suite passed (302 passed, 1 skipped); these are simulated host/guest tests,
not a live shared-machine sudo experiment. The next operational check should
use a non-sudo principal with one previously approved mount and one denied new
persistent mount, then confirm no stale attachment appears after denial and
that foreground access to the old mount remains functional.

## 2026-11-17 15:35:05 -0500

Implemented an explicit administrator-side `aivm vm access onboard USER`
workflow for a second account on an existing shared VM. The operator had
already granted libvirt access to a colleague, but sudoers did not permit
`sudo -u` to that colleague and the normal AIVM join path required the
colleague to initialize a personal profile and verify the key manually.

The new command uses a root-installed, stdlib-only helper whose user-specific
filesystem and SSH operations drop to the target account's UID/GID. This
preserves the existing bootstrap channel, avoids reading another person's
private SSH key in the admin process, and only records `active` after an SSH
proof as the target user succeeds. A dry run has no writes or sudo. The
administrator can optionally register a persistent project attachment owned
by the new principal, without automatically exporting the entire home.
Existing SSH keys/profiles and disabled principals are not overwritten; repeat
attempts preserve the same key and pending enrollments can resume. Host sudo
and systemwide executable installation are not granted as side effects.

This is an administrative helper, not a privileged daemon or new auth policy.
It assumes an existing trusted sudo-capable operator and the current shared
libvirt-group trust model. Restricted sudoers setups may need to authorize
installation/execution of the fixed root-owned helper. Home directories that
cannot be safely created are a documented prerequisite, and the host still
needs a shared AIVM executable for users to operate it later. Tests cover
the user-home/key/profile path, dry-run safety, active-after-proof semantics,
revoked/key-mismatch refusal, CLI attachment forwarding, and existing access
lifecycle; a live VM/sudo experiment is still needed on the target host.

## 2026-11-17 16:14:00 -0500

Addressed the 34 `ty check aivm tests/` diagnostics reported after the
administrator onboarding work. The issues were annotation mismatches in the
onboarding preflight, an optional `lstat` result in the root-installed helper,
fixture state inferred as broad unions, and tests accessing optional lookup or
XML results without an explicit existence assertion. The `ty` rule rename
was also applied. These changes preserve runtime behavior; assertions in tests
now make previously assumed invariants explicit, and the helper always obtains
its final metadata after optional directory creation.

The seven relevant test modules passed locally (123 tests plus four subtests)
using the vendored `kwconf` and `xdoctest` sources on the Python path. The `ty`
executable is not available in this isolated environment, so the exact
reported static-check command still needs to run in the developer's
installation. Packaging is a context-aware patch ZIP to avoid overwriting any
subsequent local changes to shared files. There is no live VM test involved.

## 2026-11-17 16:24:00 -0500

Reconciled the administrator onboarding feature with the repository's
architecture and command-execution policies after the CI suite reported two
failures. The root-installed helper is a standalone program: its ssh-keygen
and SSH subprocesses run under the target host UID after privilege dropping.
Moved the unchanged helper into `aivm.rc.host.onboard_user`, alongside other
standalone host payloads, and made the installer load it from that packaged
resource. The installed helper path, privilege boundary, and enrollment
behavior are unchanged.

Registered `aivm.admin_onboarding` and `aivm.guest_bootstrap_install` as
access-identity modules in the architecture specification, and regenerated
the derived module/import inventories. Added a regression test for the
installer source path. Relevant tests passed locally (65 tests, four
subtests), as did the architecture generator's check. The full test suite
was attempted but did not finish in this container. The first unrelated
failure was a file-writability test run as root, and that test passed when
rerun as a non-root user. No live VM operations were run.

## 2026-11-17 16:37:49 -0500

AIVM mypy diagnostics cleanup (34 reported errors). The changes give empty
collections explicit types, retain literal types for credential backend/state
constants, and distinguish guest and agent credential locals during
parsing/rendering. Tests use explicit types where inference was insufficient.
This is intended to be behavior-preserving. The remaining uncertainty is an
actual mypy run on the developer environment: mypy was unavailable in the
isolated working container. Focused non-E2E validation exercised 287 passing
tests (7 skips), including architecture checks, credentials, attachment replay,
and store round trips. The broader suite also encountered an existing command
execution test whose missing-executable exit status differed (126 vs 127).

## AIVM final mypy/ty follow-up

Removed an incomplete type inference of kwconf's dynamic ModalCLI.version
attribute, and returned typed backend literals directly instead of using
a redundant cast. Focused CLI and credential backend tests passed (32).
mypy and ty remain to be verified in the developer environment.
