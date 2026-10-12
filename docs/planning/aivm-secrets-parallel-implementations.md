# AIVM Secrets: two independent implementations, one security contract

**Decision (2026-10-12):** Keep a maintained **Python reference implementation**
*and* develop a separate **safe-Rust implementation** of `aivm-secrets` with
implementation-linked Lean proofs via Charon/Aeneas. Neither replaces the other.
Python is the iteration-friendly reference and can be selected under an
explicitly documented threat model; Rust is an alternative backend that aims
to discharge specified formal obligations. Both must follow the same externally
versioned protocol and use the same conformance corpus.

This supersedes earlier language saying the Rust crate is the *single*
executable source of truth. A future compiled Rust binary is the executable
source for **its own extracted Lean proofs**; Python remains independently
maintained and is not thereby formally verified.

## Why two implementations

- Python supports rapid protocol and operator-experience iteration, concise
  reviews, and broad tests, including VM and TLS fault injection.
- Rust has a smaller intended trusted effect boundary, strong type privacy,
  and a viable source-to-Lean proof path for the pure state machine.
- Two independent implementations exercised against a **third, frozen
  specification/corpus** can reveal divergence. Agreement on test inputs is
  useful *empirical evidence*, not proof of Python correctness, proof of
  equivalence for all inputs, or proof of the Rust networking stack.
- A default must **never** silently fall back from Rust to Python on startup,
  recovery, or an unsupported operation. Changing backends changes the
  operator's selected assurance level and requires explicit consent.

## Modular implementation and parity contracts (2026-10-12)

Adopt [the modular proof architecture](aivm-secrets-modular-proof-architecture.md) as the proposed decomposition.
Keep `aivm_secrets.primitives` **inside** the Python distribution, with
a separately implemented Rust `aivm-secrets-primitives` crate. Rust
must not call the Python implementation; Python must not silently route
decisions to Rust. Both consume reviewed, versioned, language-neutral
input/output specifications and frozen negative as well as positive
vectors. Shared proof statements are not automatically executable
guarantees of the Python implementation.

Promote a primitive to a reusable contract only once its boundary is
stable: closed input/output types and fixed denials, precise overflow
and time/epoch conventions, independently run vectors, and named
premises for external adapters. Python can continue evolving its host
services while a Rust proof for that isolated contract is developed.
A downstream Rust theorem may use the primitive proof as a lemma
**only after discharging its premises** (authenticated inputs, exact
state/effect refinement and any concurrency assumptions).

Do not claim cross-backend parity if a Rust runner was skipped. Do not
invent an active backend-selection flag until a Rust binary exists.
If a new module simply reexports a domain-dependent function, leave it
in that domain rather than creating a nominal primitive.

## Shared security contract, not shared shortcuts

```text
                 normative, versioned wire/schema + frozen vectors
                             /             \
     Python broker + pure Python kernel     Rust broker + verified Rust kernel
              |                                       |
        host-held credential                       host-held credential
              +-------  same permitted effects, no arbitrary escape -------+
```

The protocol, canonicalization, bounds, denial codes, credential secrecy,
operation scope, authorization, accounting, epoch, response disclosure and
failure semantics must be specified independently from either implementation.
Conformance and adversarial tests should be data-driven, but the two runtime
implementations must not both call the same unverified Python policy function.
Shared **data** is good; a common mutable implementation hidden under two
names defeats independent review.

The same separation applies to P4 identity: public certificate-binding claims
and decisions are pure; JWT signing, authenticated encryption, TLS certificate
validation, key custody, clock, and revocation are explicit impure adapters.
`aivm_secrets/identity/model.py` is the Python reference to port; its wire
corpus lives in `tests/secrets_vectors/identity-v1.jsonl`, and a deterministic Ed25519/AES-GCM golden
fixture in `tests/secrets_vectors/identity-crypto-v1.json`. The JSONL runner
at `python -m aivm_secrets.identity.runner`. The first Rust runner must consume
identical JSONL requests and emit identical JSONL decisions. Once Rust exists,
CI must supply `AIVM_SECRETS_RUST_IDENTITY_RUNNER` and treat missing executables,
differences or unexpected skips as failures.

### What parity means, and what it does not

| Evidence | Supports | Does not support |
| --- | --- | --- |
| Frozen positive/negative vectors | Agreement on enumerated inputs | All-input equivalence |
| Differential testing, seeded mutations and generated traces | Broad behavioral agreement, regression detection | Proof of noninterference or absent shared bugs |
| Live TLS / fault / restart tests on each backend | Practical deployment behavior | Proof of all TLS and OS assumptions |
| Rust -> Charon/Aeneas -> Lean proofs of named theorems | Mathematical guarantees for the extracted Rust code under named axioms | Python proofs, Rust I/O correctness without refinement |
| Verified executable/effect call graph + audited trust assumptions | Stronger deployed Rust assurance | Safety from a malicious *authorized* operation |

Require **bidirectional** negative testing: valid inputs must succeed in both
and disallowed/malformed inputs must fail in both. Compare canonical outputs,
result codes, counts and effect traces, not just process exit status. Keep
cryptographic deterministic fixtures separately from public-policy vectors;
make entropy injectable in isolated tests only, never in a production CLI.
Always test signature, AEAD, certificate and TLS failures against real crypto.

### Runtime selection (future)

Expose an explicit backend choice at secrets-session creation once Rust exists,
for example `--secrets-backend=python` or `--secrets-backend=rust`, rather than
overloading a policy or falling back implicitly. Do **not** introduce an inert
choice before two runnable implementations exist. For each backend:

- pin code/version and protocol profile in the session's audit header;
- display which is selected; reject unsupported protocol versions;
- never migrate a live session's secret-bearing state from one backend to
  another without a specified handoff, explicit approval and tests;
- keep existing VM defaults unchanged: secrets are still opt-in;
- allow an operator to choose Python with clear unverified-boundary wording;
- advertise Rust properties by theorem name only after extraction and proof
  generation is reproducible and tied to the shipped binary.

A Rust implementation could be preferred for high-risk adversarial VMs, but
Rust by itself is not a certificate of correct policy, cryptography, TLS,
provider semantics, vTPM isolation or soundness of assumed models.

## Independent work streams and merge gates

**Python P4a (active):** closed identity claims, pure registry and managed-VM
subject models, signed encrypted local broker capability, real TLS 1.3
client-certificate validation, host-managed CA/enrollment and an opt-in
identity-only AIVM launcher. No OAuth, vTPM key custody, rollback-safe
distributed ledger, or validated live-libvirt deployment yet. The bridge
never receives an authorization bypass verb. The next decomposition
moves protocol decisions into a pure Garrett model without bypassing the
existing authorization broker.

**Rust P1/P2:** first implement `identity-v1` model and JSONL runner, then the
existing authorization kernel and conformance vectors. Prove typed binding,
epoch, temporal rejection and policy-transition invariants from extracted Rust.
Add typed effects and prove complete mediation separately. Do not block Python
identity research on Rust compilation.

**Cross-language gate:** source-independent fixtures and property-based traces
must run in both implementations. Introduce a `rust-required` CI job that fails
when Rust is promised but absent; no green Python-only status may be labeled
"cross-language parity". Record compiler, dependencies, extracted Lean hashes,
assumed functions and external model versions in a proof manifest.

**P4b/P4c later:** full host/browser credential acquisition, hardened
issuer service, authenticated enrollment lifecycle, key custody, interoperable
sealed token profiles, renewal, rollback-resistant revocation and snapshot/
clone authority. Both
backends must implement or explicitly reject each protocol feature; no default
pass-through behavior for unknown token/header/operation variants.

## Provenance and related plans

- Matthew Garrett, [*Securing agentic identity* (2026-07-02)](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/): signed surrogate tokens carrying encrypted credentials, issuer/broker, proxy substitution, cert-bound mTLS and hardware/hypervisor-backed identities.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) for `cnf.x5t#S256` and proof-of-possession context (does not mandate our token profile).
- [Aeneas](https://github.com/AeneasVerif/aeneas) and [h5i](https://github.com/h5i-dev/h5i) are Rust/Lean research and tooling options, not currently build dependencies.
- [Garrett identity increment](aivm-secrets-garrett-identity.md), [kernel specification](aivm-secrets-kernel-spec.md), [formal assurance](aivm-secrets-formal-assurance.md), and [assumption ledger](aivm-secrets-assumptions.json).

## 2026-10-12: enrollment transition contract

The Python reference now also exposes a **pure** enrollment state machine at
`aivm_secrets/identity/registry_model.py`: versioned bounded registry
validation, enrollment (including explicit replacement), revocation epoch
transitions, and current certificate-to-identity lookup. This lives outside
filesystem, X.509 and TLS code. Its frozen JSONL contract is
`tests/secrets_vectors/identity-registry-v1.jsonl` (69 cases).

The future Rust runner must produce the same canonical JSON output under the
explicit `AIVM_SECRETS_RUST_REGISTRY_RUNNER` test gate; absence of a Rust
runner is a reported skip, **not** a parity pass. Port these pure functions
first. Compare real cryptographic fixtures independently, and enumerate
parsing/FS/TLS assumptions before moving the host effect interpreter. The
Python reference and verified Rust code will be **maintained concurrently**;
neither backend silently becomes a fallback for the other.

## 2026-10-12: authoritative managed-VM binding contract (Python P4a)

The host adapter `aivm/secrets_identity_vm.py` derives a stable certificate
subject from authoritative machine-store identity, current active principal,
and the live libvirt domain UUID; the pure sibling-package reference is
`aivm_secrets/identity/vm_model.py`. Its 104 frozen decision cases are in
`tests/secrets_vectors/identity-managed-vm-v1.jsonl`. The corresponding Rust
parity runner is deliberately unimplemented and skipped until an independent
executable is configured through `AIVM_SECRETS_RUST_VM_RUNNER`.

The protocol does **not** claim VM attestation or cloned-key resistance. See
[`aivm-secrets-p4a-managed-vm.md`](aivm-secrets-p4a-managed-vm.md) for its
trust boundaries and the explicitly opt-in session lifecycle. The future Rust
adapter should preserve the pure subject decision exactly, while treating
libvirt, machine-store loading and forced SSH as explicitly trusted inputs.

### Managed-VM deployment as a process contract

The initial opt-in launcher is now in `aivm/secrets_identity_transport.py`,
but the independent `aivm_secrets` implementation is **not imported** into the
AIVM orchestrator, except for the shared error table. Host credential and
identity operations are fixed `identity` subcommands run in isolated child
processes with JSON responses. These verbs will become the integration points
for the future Rust backend; do not accidentally introduce Python-object ABI
contracts between the host launcher and the service.

AIVM's host-side VM subject hash is tested against the independently maintained
Python identity vectors. The tests compare this contract but are not Rust
parity tests: no Rust executable exists yet.
