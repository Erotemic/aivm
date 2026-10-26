# Garrett identity: extracted pure protocol and reusable primitives

Status: **implemented Python refactor, 2026-10-12**. Python reference only;
no Rust implementation, Lean proof, or real-VM validation is claimed. See
[the modular proof plan](aivm-secrets-modular-proof-architecture.md),
[Garrett identity plan](aivm-secrets-garrett-identity.md), and
[parallel backend decision](aivm-secrets-parallel-implementations.md).

## Intent and boundary

The **pure Garrett identity protocol** now lives at
`aivm_secrets.identity.garrett`. It is self-contained with respect to the
AIVM VM manager, authorization kernel, provider integrations, host broker,
filesystem, cryptography and TLS. It imports only `aivm_secrets.primitives`,
`aivm_secrets.errors`, and pure standard-library value code. It can be
imported and exercised in a Python process without initializing any host
service. The sibling `identity` package retains the *trusted adapters* that
actually enroll, encrypt, sign and transmit credentials. This does **not**
make the entire identity service a standalone distribution or a formally
verified runtime.

```text
AIVM managed-VM adapter (process-only)
    |
    v
identity/cli.py / enrollment.py / token.py / mtls.py / service.py
    |    |           |                     |
    |    +-- host file/audit ownership, crypto and broker transport (trusted)
    v
identity/garrett/               kernel/ policy and effects (separate)
    claims.py     <--+                        ^
    registry.py   <--+--- primitives/         |
    vm.py         <--+    grammar/codec/wire   |
    protocol.py   <--+    validity/epochs/     |
                          binding             |

TLS/certificate adapter -> pure presentation decision -> original broker
Host issuer/registry  -> pure issuance decision     -> signed bound JWT
Original broker is still the ONLY provider credential/effect executor.
```

There is **one canonical implementation** of `grammar`, `codec` and `wire`:
under `primitives/`. The previous `kernel` paths explicitly re-export those
same functions and classes, so existing callers and cryptographic bytes remain
initially. The former `identity/model.py`, `registry_model.py` and `vm_model.py`
likewise re-export the same Garrett model and state-transition functions.
Moving the implementation instead of copying it avoids two subtly divergent
validators. The shared bounded framing utility lives in `transport/` (not
inside a pure primitive), and both server and mTLS client consume it.

## Pure contract, externally supplied witnesses

* `primitives.validity.require_active`: a half-open interval, exact integer
  types, explicit time sample (`PRIM-TIME-01`). A verified clock or service
  deadline is an external assumption.
* `primitives.epochs.advance` and `require_current`: bounded monotonic
  increments and stale-epoch rejection (`PRIM-EPOCH-01`). An epoch or
  maximum outside `[0, 2^63 - 1]` is refused rather than compared. Durable
  store linearizability and rollback resistance are external assumptions.
* `primitives.binding.require_match`: exact typed identity equality
  (`PRIM-BIND-01`). It **does not** authenticate signatures or TLS peers.
* `garrett.claims.IdentityClaims`, `IdentityExpectation`, `assess_binding`:
  closed token claim grammar and binding acceptance. `iat` is at most
  `MAX_ISSUED_AT = 2^63 - 1 - MAX_IDENTITY_LIFETIME`, so `exp` always fits a
  signed 64-bit word.
* `garrett.registry`: enrollment/revocation/lookup state transitions over
  caller-supplied snapshots. No filesystem operations or locks.
* `garrett.vm.subject`: deterministic versioned managed-VM subject computed
  from trusted host metadata. It never queries libvirt itself.
* `garrett.protocol.prepare_issue`: creates an immutable **claim intent**
  only after inspecting an active enrollment, its epoch, certificate thumbprint,
  and bounded lifetime. Token ID and time come from the trusted caller.
* `garrett.protocol.present`: accepts only matching peer/claim/expectation
  values and returns an immutable **presentation intent**. Cryptographic
  signature, AEAD, TLS and registry verification occur in the outer adapters.

These pure intents cannot execute an operation or contain a provider token.
The host adapter still obtains the real credential only in the existing
broker, not in `garrett.protocol`. An agent must not use a pure `present()`
result as a substitute for the actual TLS and token checks. In the Python
reference, types and process separation aid review but do not constitute
unforgeable proof witnesses.

## Pre-deployment API consolidation

The original modularization increment temporarily kept
`identity/model.py`, `identity/registry_model.py` and `identity/vm_model.py`
as compatibility facades. The subsequent single-root CA refactor **deleted**
all three before any VM enrollment or public deployment. Canonical imports
are `identity.garrett.claims`, `identity.garrett.registry`, and
`identity.garrett.vm`. There is intentionally no migration API or facade for
unused experimental layouts. Token/signature and broker authorization formats
remain separate contracts; ordinary AIVM VM defaults are unchanged.

## Independent test and proof contract

* Old identity binding, enrollment registry, managed-VM, canonical JSON and
  cryptographic fixtures continue to be regression oracles.
* The new `tests/secrets_vectors/garrett-protocol-v1.jsonl` corpus freezes
  issue/present decisions and failures independent of the future Rust runner.
* `python -m aivm_secrets.identity.garrett_runner` consumes one input JSON
  per line and emits one closed result per line. It has no authority to sign,
  enroll or use provider credentials. `AIVM_SECRETS_RUST_GARRETT_RUNNER`
  selects a separately built Rust runner for differential comparison once
  available; absence is explicitly skipped, **not** labeled parity.
* `tests/secrets_vectors/primitives/*-v1.jsonl` state the validity, epoch,
  binding, digest and wire primitives one at a time, for
  `python -m aivm_secrets.primitives_runner` (a closed table of primitive
  names, one flushed reply per line). `AIVM_SECRETS_RUST_PRIMITIVES_RUNNER`
  selects the future Rust runner; unset, that comparison is skipped. The
  runner does I/O, so it sits beside the pure package, not in it, and the
  kernel purity gates now cover `primitives/` as well. Budget and scope
  primitives (M3) do not exist yet and have no corpus.
* Structural gates reject imports from `aivm_secrets.host`, `kernel`,
  `transport` or the AIVM package inside the pure Garrett and primitives
  modules. Mutation tests explicitly remove interval, epoch, binding and
  active-enrollment checks; their test gates must reject those mutations.

These tests establish selected behavioral consistency, **not** mathematical
proof of Python or equivalence on all inputs. The future Rust implementation
should use the same versioned grammar and records with its **own** source.
Aeneas/Lean would verify Rust implementations of bounded values, time,
epoch and binding first; the higher-level presentation/issuance proofs would
then discharge those lemmas' input-authenticity and state assumptions.

## Remaining decomposition

1. Extract broker budget/scope rules into proof-sized primitives with no
   policy digest changes (M3). The new Garrett core intentionally does not
   use grant or provider-specific authorization functions.
2. Define explicit typed interfaces for the trusted `IdentityAuthority`
   persistence/audit adapters and the certificate, signing and TLS backends.
   Those modules still depend on shared host safety utilities; do not
   duplicate the filesystem security implementation merely to rename imports.
3. Add the independently maintained Rust crate and JSONL runner, then
   implementation-linked proofs for named primitive theorems and compositions.
4. The eventual composed effect proof must show that accepted certificate-
   bound identities still receive *only* the existing broker's authorized
   effects, accounting for host and TLS assumptions. This refactor alone
   makes no stronger deployment claim.

Current manual enrollment and managed-VM limitations (software-exportable
keys, non-atomic new-request revocation, snapshot rollback, missing
vTPM/attestation and no live-VM evidence) remain unchanged.
