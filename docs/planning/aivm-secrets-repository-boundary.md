# AIVM / aivm-secrets repository boundary and extraction plan

Status: **maintainer direction, 2026-10-14**. `aivm-secrets` remains an
**experimental, unaudited Python implementation**. This document is the
current integration/repository policy. It takes precedence over older
statements that co-distribution or a process boundary alone makes the system
ready for general AIVM users. The immediate decision is **not** to extract the
repository on this branch: development may continue here temporarily.

## Decision

1. **AIVM is a usable, independently maintainable VM manager.** No ordinary
   AIVM install, CLI import, VM creation, start, attachment, `aivm ssh`,
   `aivm code`, repository credential management, or status command may
   require `aivm_secrets`, `cryptography` for secrets, a running broker,
   a certificate authority, a vault, mTLS, TPM, or vTPM.
2. **Secrets use is experimental and explicit.** For now, existing opt-in
   `aivm ssh --secrets_policy`, identity enrollment, and bound-session paths
   may be exercised on this development branch; do not add more implicit
   hooks, normal-workflow dependencies, default provisioning, agent forwarding,
   auto-enrollment, provider authorization, or default credential access.
   Missing optional components must fail clearly **when selected**, with no
   automatic fallback to weaker transports, credentials, or identity.
3. **`aivm_secrets` must remain independent of `aivm`.** The broker owns
   authorization, effect dispatch, credential custody, audit, transport,
   identity, and OAuth state. The VM manager may provide host-authenticated
   identity facts and start/stop a child process, but may not import its
   broker/kernel/identity implementation in production. AIVM adapter code
   is temporary and narrowly scoped; no additional secrets imports in
   ordinary AIVM modules. Do not add secrets-specific persistent state to
   the AIVM machine-store schema or couple VM creation to issuer lifecycle.
4. **Separate repository is the intended destination, not a prerequisite for
   immediate security fixes.** Create `Erotemic/aivm-secrets` (or another
   maintainer-approved name) in a later, explicitly reviewed migration.
   Carry code, tests, fixtures, docs, versioning and release ownership with
   it. Keeping code on the current feature branch is temporary, not an
   endorsement for release as part of ordinary AIVM.
5. **Claims follow evidence.** Do not advertise the Python broker as formally
   verified, independently security-audited, hardware-attested, or approved
   for production credentials. The Rust/Lean work is separate and not yet
   a deployed backend. A local broker can work without a TPM, second VM,
   container, or hardware identity; mTLS/TPM are optional higher-assurance
   identity modes, not dependencies of local authorization.

## Audited state of this branch

| Boundary | Present code | Assessment / required direction |
| --- | --- | --- |
| Co-distribution | `pyproject.toml` includes both `aivm*` Python packages and the `aivm-secrets` console script; `aivm[secrets]` adds cryptography | **Temporary packaging debt.** Do not add secrets to `project.dependencies`. Separate distribution before a general AIVM release carrying this work. |
| Default CLI imports | `aivm/cli/vm.py` registers `vm_identity` on ordinary CLI startup | Identity implementation must be imported only after explicit selection; the ordinary CLI must start with `aivm_secrets` unavailable. |
| Foreground SSH | `aivm/cli/vm_connect.py` offers `--secrets_policy`, plus bound identity and OAuth flags | Existing flags are experimental opt-ins. Normal SSH dispatch stays independent and no secrets services launch by default. |
| Broker/identity adapters | `aivm/secrets_transport.py`, `secrets_identity_transport.py`, `secrets_identity_vm.py`, `cli/vm_identity.py` | Exception for existing experimental adapters, not an invitation to expand AIVM's trust boundary. Remove or move appropriate pieces at extraction. |
| Guest bootstrap | `aivm/rc/guest/guestctl.py` has opt-in identity CSR and key rotation operations | Keep them isolated and non-default; plan an independently installable helper or protocol when extracting. |
| Dependencies direction | `aivm_secrets/` has no direct `aivm` imports | Maintain that invariant. AIVM must never depend on secret authorization types or implementation details. |
| Testing | Secret test modules, protocol vectors and real-VM integration tests are currently interleaved with AIVM CI | Preserve coverage now; move broker-specific suites to independent CI later, leaving a small cross-project integration matrix. |
| Assurance | Python reference + synthetic TLS/provider tests; no shipped independent Rust backend, no implementation-linked Lean proof, no live managed-VM identity/provider validation | Keep experimental label and require explicit security/e2e gates before broader release. |

The existing AIVM package itself still contains the `aivm_secrets` source.
A successful **no-import smoke test** is therefore only evidence of runtime
independence, **not** evidence of separate wheel contents or an independently
published package.

## Rules for all work while sharing this branch

- Every new AIVM-to-secrets dependency must be justified as an **existing
  explicit opt-in adapter**; otherwise implement it inside `aivm_secrets` or
  postpone it. Never add `from aivm_secrets ...` to CLI registration, module
  initializers, VM provision/create paths, core machine-store code, default
  SSH/code preparation, or default dependency metadata.
- Do not turn a security experiment into a requirement to create VMs, install
  guest tools, join a machine store, or use repository SSH keys. Keep existing
  Git/SSH agent grants conceptually separate; don't claim broker policy
  restricts any independent credential already available in the guest.
- Preserve the standalone `aivm-secrets serve` interface and its versioned,
  fail-closed command/wire contract. The broker cannot import AIVM internals.
  Do not make a Python-internal call contract mandatory for integrating AIVM.
- Prefer the simple host-local model first: host-only Unix socket, short-lived
  session and restricted named operations. Treat certificate binding, OAuth,
  TPM/vTPM, issuer services and multi-tenant deployment as separately scoped,
  optional research tracks. No transparent escalation to these facilities.
- A PR that adds to an opt-in adapter should explain why it cannot remain in
  the independent package, what the optional dependency is, which default
  workflows it demonstrably leaves unchanged, and what must be moved when
  extraction happens. Keep tests for deny/fail-closed behavior.
- Changes to the contract, credential custody, authorization/effect mediation,
  revocation or auditing need focused adversarial tests and maintainers'
  security review. Passing tests are evidence, not proof of safety.

## Work plan and gates

### Now: preserve experimental development without new AIVM obligations

- Keep current feature branch available for broker fixes, narrow `gh` policy
  development, auditable protocol/authorization tests and documentation.
  Continue resolving remaining review/CI failures, but **do not** widen the
  default VM product surface.
- Ensure normal AIVM imports and CLI startup succeed when `aivm_secrets` cannot
  be imported. Explicit secrets actions should report missing optional
  dependencies rather than crash or degrade to unbound/unaudited execution.
- Gate `project.dependencies` against new secrets dependencies. Keep
  `aivm_secrets -> aivm` imports forbidden and AIVM imports limited to named
  opt-in adapters. Test default-workflow behavior and that no service starts
  without selecting secrets.
- For an initial real-credential `gh` pilot, require a deliberately constrained
  host credential, narrow read-only policy, no other guest GitHub credentials,
  audit inspection, and explicit approval for any write. An ordinary AIVM
  guest may have separate SSH/deploy-key authority; this must be reviewed.

### Before extraction: freeze and document the portable contract

- Record the CLI/process protocol, capability/wire versions, identity fact
  provenance, authority directory format, transport/exit semantics, and
  meaning of ambiguous provider writes; pin a compatible versioned contract.
- Inventory package references and tests. Establish standalone installation,
  dependency declaration, typed public inputs, security-negative tests and
  operating documentation without importing or running AIVM.
- Decide the guest helper deployment boundary; replacing the in-guest helper
  must not silently change ordinary AIVM guest provisioning.
- Define handling of already-created authorities, guest certificates and OAuth
  vaults (no silent deletion, conversion or automatic credential migration).

### Extraction PR(s): move responsibility, do not redesign security

- Move `aivm_secrets/`, `aivm-secrets` CLI, standalone docs, conformance
  vectors and broker/identity/OAuth test suites to the new repository. Keep
  author attribution and meaningful history where feasible.
- Make `aivm` depend on the separately published distribution **only via a
  version-constrained optional extra**, if AIVM integration is still desired
  and approved; a minimal, no-secrets installation must install/run cleanly.
  Preserve an explicit executable/process interface so a Rust backend can be
  selected deliberately in the future. No implicit Python or weaker fallback.
- Reduce or remove the temporary `aivm` secrets adapters. Keep only reviewed,
  optional VM/SSH integration and small end-to-end contract tests, or remove
  the integration entirely until it passes the product security gate.
- Separate AIVM core CI from `aivm-secrets` CI; define a small, explicit
  compatibility workflow pinned to released or selected commits of both.
  Never mislabel skipped Rust runner tests as cross-language parity.

### Release/security gates (separate decisions)

- **AIVM release gate:** `pip install aivm` contains neither a hard dependency
  on `aivm-secrets` nor a default secrets startup path; normal CLI/VM/SSH/code
  behavior is tested with the secrets package absent. The experimental
  implementation must not remain bundled in a general AIVM wheel without
  a separate, explicit maintainer security/release decision. An ordinary
  AIVM user must not need to understand Garrett identity, certificates or OAuth.
- **Secrets release gate:** security review of complete mediation, credential
  sources and process boundary, transport outcome ambiguity, revocation,
  time/budget limits, filesystem trust, logging and crash recovery, followed
  by disposable-VM smoke tests and narrowly constrained real-provider tests.
  Publish assurance limits; an initial experimental distribution need not
  assert formal verification, but cannot claim production approval.
- **Proof/attestation gate:** optional, independent Rust+Lean evidence and
  optional TPM-backed identities add assurances only once code and tests
  substantiate the specific claims. Neither gates the simple local broker.

## Decisions reserved for the maintainer

- When to extract, repository ownership/name and whether the AIVM adapter
  survives extraction or remains absent until an independent audit.
- Whether and when any experimental secrets feature is endorsed for general
  AIVM users, and what credentials/operations that endorsement covers.
- Who reviews the security-sensitive protocol and which independent audit
  evidence is sufficient. Do not infer approval from merging a feature PR.

Related: [main design](aivm-secrets-design.md),
[parallel implementations](aivm-secrets-parallel-implementations.md),
[assurance plan](aivm-secrets-formal-assurance.md), and
[operator guide](../source/secrets.rst).
