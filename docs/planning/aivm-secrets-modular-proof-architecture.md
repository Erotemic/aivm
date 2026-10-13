# AIVM Secrets: primitive contracts and compositional proof architecture

Status: **M1 and selected M2/M4 Python modules implemented (2026-10-12).**
The `primitives` package and self-contained *pure* Garrett protocol now exist;
see [implementation record](aivm-secrets-garrett-modular-refactor.md). This
remains the target design for unfinished M3, M5 and M6. No Rust crate,
extracted Lean theorem, or end-to-end proof is delivered. Existing protocol
bytes and CLI behavior remain the compatibility contract.

Related plans: [overall design](aivm-secrets-design.md),
[dual implementations](aivm-secrets-parallel-implementations.md),
[formal assurance](aivm-secrets-formal-assurance.md),
[kernel specification](aivm-secrets-kernel-spec.md),
[Garrett identity](aivm-secrets-garrett-identity.md), and
[managed-VM P4a](aivm-secrets-p4a-managed-vm.md).

## 1. Decision: composable units, not premature distributions

Introduce **`aivm_secrets.primitives`** as an *internal* package in the
existing `aivm-secrets` distribution. Each submodule is an independently
specified verification unit with a narrow, stable, effect-free API. Do **not**
create a separately published `aivm-secrets-primitives` distribution now, or
fork a second copy of the Python logic. Split distributions only after there
are independent consumers, a useful compatibility policy, and validated
versioning requirements.

The names `primitives` and `identity.garrett` describe distinct roles:

- A **primitive** is a small domain-neutral, deterministic function or
  transition (interval membership, budget reservation, scope subset, binding
  equality, epoch advance, bounded normalization). It must not open files,
  read the clock, hold secrets, perform secret-key cryptography, contact a service, or
  depend on AIVM-specific VM concepts.
- A **domain model** combines primitives into authorization and identity
  decisions, with explicitly typed input assumptions.
- A **protocol** (including the Garrett-style credential workflow) combines
  domain decisions and declared effects. It can be modeled as pure
  transitions, but the *actual* issuer, TLS handshake, ledger and provider
  request are trusted effect adapters, not primitives.
- A **host service** owns the real provider credential and executes only
  authorized effects. AIVM orchestrates this service through the existing
  process boundary, without importing its Python internals.

The goal is to reuse both code and proof lemmas without permitting a general
extension mechanism to create new credentialed routes. The Python reference
and Rust implementation must continue to be independently implemented and
validated against a third, versioned contract. Only Rust-derived Lean proofs
can establish the properties proved for the extracted Rust code.

## 2. Dependency rules and intended package shape

Current Python layout, with pending verification units called out separately:

```text
aivm_secrets/
    primitives/               # implemented; pure, no host/kernel imports
        grammar.py            # bounded fields, closed alphabets
        codec.py              # strict canonical JSON and hashes
        wire.py               # v1 broker frames
        validity.py           # exclusive expiry
        epochs.py             # bounded monotonically increasing epochs
        binding.py            # exact identity comparisons
    kernel/
        grammar.py            # compatible re-export of primitives.grammar
        codec.py              # compatible re-export of primitives.codec
        wire.py               # compatible re-export of primitives.wire
        ...                   # still owns policy, grants, effects
    identity/
        model.py              # compatible re-export
        registry_model.py     # compatible re-export
        vm_model.py           # compatible re-export
        garrett/
            claims.py         # public claim validation and peer binding
            registry.py       # pure enrollment/revocation/lookup
            vm.py             # pure managed-VM subject construction
            protocol.py       # pure issue/present intents
        garrett_runner.py     # versioned JSONL conformance runner
        token.py              # authenticated JWT/AEAD adapter
        enrollment.py         # X.509/CA, host-owned persistence and audit
        mtls.py, service.py   # authenticated transport to existing broker
    transport/
        framing.py            # bounded, impure socket reads
        names.py              # fixed Unix socket names
    host/                     # original broker, credential custody, egress

Future:
    primitives/budgets.py, scope.py
    rust/crates/aivm-secrets-primitives, aivm-secrets-core, ...
    proofs/Primitives, Identity, Authorization, Composition, ...
```

The internal Python package is `aivm_secrets.primitives`, **not** a new
top-level install requirement. Rust crates are proposed workspace units, not
separate release obligations. Revisit module names before writing code if a
meaningful Rust type boundary argues for combining two tiny modules.

Dependency direction must be acyclic:

```text
AIVM CLI/orchestration --> fixed service process/wire protocol
host and identity adapters --> domain models --> primitives
kernel service models ---> domain models and primitives
primitives -----------> pure standard-library value types only
```

No primitive may import `aivm`, `aivm_secrets.host`,
`aivm_secrets.identity`, `aivm_secrets.kernel`, a plugin, a transport,
or a crypto/TLS implementation. Avoid coupling every primitive to a central
mutable registry. Define local, closed input/output types or a small shared
pure value-types module. Convert primitive result variants to existing
`SecretsError` codes at a higher compatibility facade; keep current public
errors and protocol bytes unchanged during refactoring.

The present `identity.garrett` core no longer imports `kernel` or `host`.
`identity.enrollment` still uses the trusted shared host filesystem/audit
adapters. `tests/test_secrets_purity.py` now allows kernel-to-primitives imports
and retains the sole-`AuthorizedEffect` constructor gate. Separate structural
checks forbid imports in the opposite direction. Those checks are not proofs
of every possible dynamic Python import behavior.

## 3. Primitive specifications and proof targets

Some contracts now have Python APIs; others remain planned as below.
Use versioned, immutable value records; closed enums/results; bounded input
sizes; and no ambient reads. A primitive receives `now`, `epoch`, `peer`,
`claims`, and identifiers as explicit parameters. Define failure and overflow
behavior, not only the successful path. Avoid a generic 'policy predicate'
that runs user-provided code.

| Proposed unit | Existing source to examine | Contract / first theorem | Assumptions deliberately outside |
| --- | --- | --- | --- |
| `bounded` | `kernel/grammar.py` | Accepted values satisfy exactly the stated byte/length/integer bounds; rejection is total (`PRIM-BOUNDS-01`) | Actual byte-to-value parser |
| `canonical` | `kernel/codec.py` | One canonical encoding per admitted structured value; no accepted duplicate keys (`PRIM-CANON-01`) | Input JSON decoding, hash collision resistance |
| `validity` | `identity/model.py`, `kernel/machine.py` | At an explicit time sample, acceptance implies `not_before <= now < expires`; expiration is exclusive (`PRIM-TIME-01`) | Correctness/monotonicity of sampled clocks |
| `epochs` | `identity/registry_model.py`, `kernel/machine.py` | For successful transitions, the epoch never decreases; stale-epoch claims are rejected (`PRIM-EPOCH-01`) | Durable linearizable store, rollback prevention |
| `budgets` | `kernel/machine.py` | Each reservation consumes strictly bounded authority and cannot silently refund it (`PRIM-BUDGET-01`) | Serial dispatch or atomic state commit |
| `binding` | `identity/model.py`, `kernel/model.py` | Acceptance requires equality of the expected subject/peer binding/epoch (`PRIM-BIND-01`) | Verified token signature, TLS peer authenticity |
| `scope` | `kernel/scope.py` | Semantic child permission set is a subset of the parent; subset is transitive (`PRIM-SCOPE-01`) | Compiler faithfully maps a manifest into a closed scope |

Do not introduce duplicates just because existing modules combine related
functions. For example, move *one* implementation of time-window checking
into `primitives.validity`, redirect existing Python callers through stable
facades, and prove behavior matches old vectors. Do not change JWT formats,
wire framing, policies, grant formats or API outputs as a side effect.

`canonical` is a candidate for an early *refinement* proof, but it need not
be ported to Aeneas in the first spike if JSON parsing or standard-library
models are unsupported. A small closed-value `validity` or `epochs` module
may be the lowest-risk first extraction target; select based on a real toolchain
spike, not an assumption that every Rust library translates.

## 4. Garrett protocol is a domain model, not a leaf primitive

Matthew Garrett's [*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
separates provider credential acquisition, signed encrypted substitute tokens,
and certificate-bound use through mTLS. AIVM adds independent authorization,
resource constraints, audit and a reference monitor at the point of effect.

`aivm_secrets.identity.garrett` is now the conceptual owner of the
**protocol**, consuming primitive contracts without implementing crypto, TLS,
file storage or provider-specific calls itself. Keep the present
`identity/model.py`, `token.py`, `registry_model.py`, and the current service
entrypoints operational during migration; a new module must not create a
second live authorization route.

A pure state machine should describe separate steps such as:

```text
Enroll(verified_vm_subject, validated_public_key, authority_epoch)
Issue(authenticated_operator, active_enrollment, requested_scope,
      opaque_credential_handle, clock_sample)
Present(verified_tls_peer, authenticated_token_claims, clock_sample)
Authorize(presented_identity, broker_grant, bounded_request, provider_facts)
Revoke(enrollment_id, next_epoch)
Renew(active_enrollment, permitted_key_rotation)
```

Each transition either rejects with a stable code or returns `(next_state,
DeclaredEffects)` (or a typed intent for a trusted adapter). External adapters
must validate the origin of privileged inputs. In particular:

- `VerifiedTlsPeer` means the adapter validated the actual peer certificate
  through TLS, **not** that the guest supplied a thumbprint field.
- `AuthenticatedClaims` means the signature, issuer, audience, key ID and
  cryptographic envelope were checked, **not** that JSON successfully parsed.
- `ActiveEnrollment` means the authoritative registry was consulted at the
  required linearization point; a cached record has different semantics.
- `AuthorizedEffect` remains constructible only by the trusted authorization
  transition, with a request/resource witness; no primitive returns a host
  credential or general-purpose network capability.
- An encrypted bearer-like token plus a software key is not proof of VM
  non-exportability, and certificate possession is not an agent-process
  identity proof.

Treat the workflow as a sequence of state transitions plus external effects,
**not** as one ACID transaction across OAuth, mTLS, local persistence and
GitHub/GitLab APIs. An external write may have happened even if its response
failed. Token issuance, audit, effect dispatch, revocation and ledger update
need explicit linearization points, replay/duplicate rules and `outcome_unknown`
semantics. Current P4a uses an encrypted inner broker capability, not a
completed general OAuth issuance or durable distributed transaction.

## 5. Compositional verification: what a higher-level claim must establish

A proof of `PRIM-BIND-01` alone establishes an equality condition *when its
inputs are authentic*. A proof of `PRIM-BUDGET-01` alone establishes a
sequential transition invariant *when its state updates are committed in the
specified order*. Neither proves that the deployed network handler supplies
those inputs, nor that effects cannot be emitted elsewhere.

Proposed theorem dependency structure:

```text
PRIM-BOUNDS/CANON --> typed, unambiguous request and claim decoding
PRIM-TIME/EPOCH/BIND --> identity acceptance contract
PRIM-SCOPE/BUDGET --> grant admission / attenuation contracts
identity + grant + effect-constructor refinement
    --> protocol trace admission invariant
protocol trace + sole-executor and audit-before-dispatch contracts
    --> mediated credentialed-effect invariant (conditional on TCB)
```

Target composition statement (specification sketch, not proved):

```text
For every credentialed external effect e in an accepted execution trace,
there exists an authenticated peer/token, an active enrollment, an
authorized grant/request, and a matching budget reservation that justify e
at the effect's stated linearization point.
```

Formalize preconditions including: trusted TLS and signature verification,
correct issuer/subject/VM metadata, manifest-to-effect compilation, atomic
or serialized state transitions, protected signing/decryption keys,
non-bypassable executor access, audit failure policy, and sound serialization.
A verified Rust `Result<Permit, Denial>` is **not** itself a complete mediation
proof if an unverified caller can fabricate a permit or reach a credentialed
socket without it. The Rust executor must own credentials and enforce a
closed, nonforgeable authorization-to-effect path. A typed constructor is a
useful design restriction, not a substitute for the trace theorem.

A proof can be *reused* as a lemma by a larger proof that discharges its
premises; it is not automatically inherited by Python callers, imported
modules, network handlers or plugin implementations. Every layer must have an
explicit refinement or trusted-assumption edge. Use the existing assumption
ledger to record those edges, not a generic 'all crypto is verified' claim.

## 6. Independent Python and Rust implementations

Keep Python and Rust as separate executable implementations, with a third,
language-neutral normative contract. They share **versioned data and tests**,
not a common unverified decision implementation. Keep names, result variants,
integer bounds, normalization, canonical bytes, epoch overflow policy,
clock-boundary conventions, and effect ordering explicit in each contract.

Every extracted primitive gets:

1. A written `PRIM-...` contract with precise inputs, outputs, errors,
   limits, and externally supplied assumptions.
2. Python reference tests including boundaries, invalid values, and model-based
   state traces; the old behavior and preexisting vectors stay green.
3. A new `tests/secrets_vectors/primitives/<name>-v1.jsonl` corpus and a
   source-independent generation/review policy. **Do not create empty
   vectors or pretend nonexistent Rust runners are passing.**
4. A compiled Rust implementation and JSONL runner returning the same canonical
   results (separate source, no calls into Python).
5. An implementation-linked Rust -> Charon/Aeneas -> Lean proof artifact with
   version pins, axiom inventory and no `sorry`, when extraction supports it.
6. Higher-level property-based and adversarial integration tests for the
   composed service, in both runtimes when both are available.

Use the existing `identity-v1.jsonl`, `identity-registry-v1.jsonl`,
`identity-managed-vm-v1.jsonl` and cryptographic fixture as regression oracles
for the higher-level models; primitives must not silently redefine these
contracts. Crypto fixtures additionally need real signature/AEAD/TLS tests.
A vector passing in both implementations demonstrates agreement for that case
only. Even broad differential fuzzing does not formally verify the Python
implementation or prove the Rust code's external adapters.

Maintain two distinct CI labels: `python-reference` (tests/vector conformance)
and `rust-verified` (Rust vectors, extracted proofs, refinement gates). A
cross-language job that promises parity **fails** if either backend is missing;
Python-only development may mark the Rust job pending, never green. Neither
runtime silently falls back to the other. Do not select a Rust backend until
it is runnable; the operator's chosen threat model must remain explicit.

## 7. Migration campaign, in dependency order

| Increment | Scope | Exit gate |
| --- | --- | --- |
| M0 - Plan (completed earlier) | Record internal primitives and Garrett protocol boundary, theorem graph and two-backend contract | Planning overlay accepted |
| M1 - Primitive boundary (implemented) | Shared grammar/codec/wire, validity/epochs/binding, pure import gates and compatibility facades | Selected existing conformance and broker tests remain the gate |
| M2 - Leaf extraction (identity portion implemented) | Validity, epoch, binding and bounded validators with old-path facades; budget/scope still future | Identity, registry and canonical-byte vectors stay unchanged |
| M3 - Authorization extraction | Extract budget and scope rules, refactor large `kernel/machine.py` only at stable state boundaries | Existing grant, revocation, audit and mutation tests still detect bypasses |
| M4 - Garrett protocol model (pure part implemented) | Closed claims/registry/VM decisions and issue/present intents; issuer, TLS, X.509, persistence remain adapters | Frozen issue/present vectors, identity TLS tests; no second egress route |
| M5 - Rust/Lean primitives | Implement matching independent Rust units and Aeneas extraction of one representative theorem, then extend | Pinned proof manifest, nonvacuous witnesses, Lean kernel checks and Rust/Python parity |
| M6 - Composed effect assurance | Prove typed authorization and protocol composition; connect to constrained Rust executor | Named effect-trace theorem plus declared trust assumptions; no end-to-end claim before this |

M2-M4 Python refactoring and independent P4b issuer/OAuth research need not
wait for Rust. M5 can start in parallel as soon as a primitive contract is
frozen. Prefer **small behavioral refactors** over simultaneously redesigning
wire formats, cryptographic tokens and authorization policy. Keep normal AIVM
VM sessions unchanged and secrets access explicitly opt-in at every increment.

Do not split the `aivm_secrets` distribution, add a new generic plugin execution
framework, or replace the existing process-only AIVM-to-secrets boundary in
this campaign. Preserve the current restriction that AIVM only orchestrates
isolated identity service commands, rather than importing Python secret
handling into the AIVM CLI process.

## 8. Security and review gates for every increment

- Inventory the exact old and new entrypoints and verify that public CLI,
  policy and token protocol output is identical unless an intentional versioned
  change has a separately reviewed migration plan.
- Prove the new dependency graph is acyclic using AST/import review, and
  enforce purity without allowing backdoors through callbacks, plugin lookups,
  dynamic imports, mutable globals or host-controlled effect constructors.
- Keep effect issuance, credential custody and privileged socket access outside
  guest-controlled code. Preserve `AuthorizedEffect` sole-construction tests.
- Record local and live-VM test coverage honestly: no real-VM result is
  established by a simulated libvirt or SSH test.
- Keep isolated Python environment, path ownership, runtime/CA roots and
  input type-validation protections intact; extracting a primitive must not
  weaken the host trust boundary.
- For each new theorem, record implementation and theorem hash, assumptions,
  proof dependencies and which downstream claim may reuse it. No proof may
  silently assume the conclusion of a higher-level theorem.
- Review each module for real standalone usefulness. If a 'primitive' is a
  one-line adapter for a domain-only type, prefer leaving it in that domain.

## References

- Matthew Garrett, *Securing agentic identity* (2026-07-02):
  https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/
- Aeneas / Charon: https://github.com/AeneasVerif/aeneas
- h5i: https://github.com/h5i-dev/h5i
- RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound
  Access Tokens: https://www.rfc-editor.org/rfc/rfc8705
- AIVM plans linked in the opening paragraph, especially the independent
  implementation and assurance contracts.
