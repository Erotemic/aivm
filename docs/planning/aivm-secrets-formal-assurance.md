# AIVM Secrets: formal assurance and refinement plan

Status: obligations to implement, not completed proofs (updated 2026-10-10).
The delivered system is Python with executable contracts and adversarial
tests. There are no Lean proof artifacts, extracted Rust functions or
verified-binary claims in this release. This document is the acceptance
contract for that next stage. What exists today toward it: a pure,
extraction-shaped kernel, [its specification](aivm-secrets-kernel-spec.md), a
frozen conformance corpus, a mutation gate, and
[a machine-readable assumption ledger](aivm-secrets-assumptions.json).

See [the architecture](aivm-secrets-design.md) and the
[provider-neutral plan](aivm-secrets-agnostic-integrations.md) for source
references, the threat model, deployment assumptions and milestones. This document's mathematical
notation is a specification sketch, not executable Lean.

## 1. What should be proved

The central theorem should concern **all emitted credentialed effects**, not
only a policy function's return value. Every emitted effect must correspond to
a currently valid, correctly bound capability, a budget reservation and a
permitted operation on the checked resource. A rejected request must not create
an alternate credentialed route. Provider authentication is an effect of the
trusted interpreter, not a value exposed by the client protocol.

Use a small labeled transition system with explicit inputs:

```text
step : State -> Event -> Result (State, List Effect)

Event = Receive(authenticatedChannel, boundedBytes, timeSample)
      | ProviderResult(requestId, boundedResult)
      | Revoke(grantId, nextEpoch)
      | Approve(exactRequestDigest, expiry)
      | Tick(timeSample)

Effect = FetchServiceFacts(requestId, serviceId, canonicalResource)
       | ServiceRead(requestId, serviceId, typedEffect)
       | ServiceWrite(requestId, serviceId, typedEffect)
       | AppendAudit(redactedEvent)
       | Reply(publicProjection)
```

Of these events, the Python kernel implements `Receive` (as `admit` and the
two emissions), `Revoke`, `Approve` and explicit time samples, as separate
total functions rather than one `step`. Durable epochs remain a future
feature: revocation and approvals live in the memory of one session's broker.
The budget is attached to one session and is shared across its delegated
grant tree, each admission debiting every ancestor; accounting across
*sessions* does not exist.

The kernel never receives raw provider secrets. It can reference an opaque
credential identity only after the trusted envelope verifier authenticates it.
An authenticated claim does not by itself authorize an effect: binding, policy,
time, epoch, request syntax, resource facts and host write permission must also
match. Provider results are data, not ambient authority to choose a URL.

## 2. Theorem inventory

Use stable theorem identifiers in code review and test reports. The statements
below quantify over *well-formed modeled state and authenticated inputs*, with
parser and authentication refinement proved or explicitly assumed separately.

| ID | Property to prove | Current evidence / gap |
| --- | --- | --- |
| AUTH-01 | Every admitted request is within normalized resource, operation and payload bounds; writes also require host write authority | 2^9-case independent oracle, generated traces against a reference model, vectors; no proof |
| EFFECT-01 | Every credentialed effect has a matching admission/reservation and is exactly the effect authorized for that request | Effects are computed inside the kernel under a ticket bound to the request digest; sole-constructor and sole-caller checks; interpreter refinement unproved |
| BIND-01 | A grant bound to one channel/identity/epoch cannot authorize an effect on a distinct channel/identity/epoch | Per-component equality tests, cross-session and post-crash replay on a real VM; local channel assignment trusted |
| TIME-01 | Admission/dispatch validation requires `issued <= now < expires` and a live monotonic deadline | Boundary and rollback tests at every emission, expiry on a real VM; trusted clock sampling and scheduling |
| REVOKE-01 | No new effect is authorized after revocation linearizes for that grant/ancestor | Revocation observed between preflight and write, cascade over the grant tree, host revoke and identity disable on live sessions; in-memory epochs only |
| BUDGET-01 | The number of reservations is bounded; no admission reuses a reservation; failed preflight does not refund authority | Invariant checked after every generated step; concurrent clients in-process, over sockets and from a real guest; no cross-session quota |
| ATTEN-01 | A child policy permits no operation outside its parent's semantic permission set | Exhaustive `spec_subset` against set inclusion, brute-force scope oracle, delegated grants with shared budget, expiry clamp and bounded depth; no proof |
| APPROVAL-01 | A one-shot approval authorizes at most one effect with exactly the approved canonical bytes | Implemented: digest binds policy, grant and request; consumed with admission; unreachable from the guest socket. In-memory only |
| CODEC-01 | Accepted bytes have one canonical meaning, and encoded effect bytes preserve that meaning | Regex-free validators checked against regex oracles, strictness negatives, canonical-encoding vectors; no byte-to-Rust-to-Lean refinement |
| CONF-01 | Public errors/audit/protocol outputs contain no raw credential under the specified declassification model | Fixed error table, reflection tripwire, a search of a live guest's disk and process environments; no noninterference proof |
| AUDIT-01 | Required intent durability acknowledgment precedes each dispatch; audit failure prevents later admissions | Ordering test, fault injection at each record, hash-chain verification; filesystem and external atomicity trusted |
| RESTART-01 | A stale capability cannot regain authority after an epoch change or ordinary restart | Fresh per-process key; a killed session's capability refused by the next session on a real VM; snapshot rollback not covered |

Each row is also attacked by at least one mutant in
`tests/test_secrets_mutation.py`: a single deleted check that the named tests
must detect. All 48 current mutants are detected. That is evidence the tests
are not vacuous; it says nothing about checks nobody thought to write.

### AUTH-01 and EFFECT-01: meaningful authorization

For a normalized policy `p`, channel `b`, grant `g`, request `r` and state `s`:

```text
admit(p, g, b, r, s) = Accepted(s', ticket)
  -> b = g.binding
  /\ r.resource in p.allowedResources
  /\ serviceOf(r) = p.serviceId
  /\ r.operation in p.operations
  /\ payloadWithinBounds(p, r)
  /\ (isWrite(r) -> hostAllowsWrites)
```

That is necessary but not sufficient. For every trace prefix `t` ending in an
emitted provider request, prove the existence of a matching unconsumed ticket
and a previously checked, appropriately bound provider fact record. Tickets
must carry the exact request/resource/payload digest and epoch; they must not
be interchangeable across requests or obtainable through an untrusted FFI.

There are two denial classes. A syntax, capability or scope denial must emit no
provider I/O. A resource-metadata mismatch may occur **after** the authorized
read-only metadata fetch, but must emit no subsequent read/write effect.
Conflating these classes would make a false theorem about the implementation.

Routes must be constructed from canonical resource identifiers, not response
URLs, user-controlled headers or an unconstrained string. Prove the method,
provider host, resource and body projection as part of effect construction,
quantifying over all installed/approved adapters and their typed manifests.
HTTP serialization remains in the trusted boundary until separately refined.

### TIME-01 and REVOKE-01: linearization, not magic cancellation

Choose the authorization linearization point explicitly. A time sample is taken
immediately before an effect is admitted to the trusted interpreter. The model
can prove validity at that point. It cannot promise GitHub receives the network
packet before expiry despite arbitrary process scheduling or network delay.
Recheck after potentially blocking audit/preflight operations; do not reuse a
stale sample from the start of a multi-step request.

The current lock means revoke waits for an active request to finish. The target
may allow a revoke event between preflight and mutation, provided the final epoch
check is serialized with dispatch admission. In either design, no theorem claims
to undo a write already accepted by GitHub. Remote outcomes remain uncertain
when a response is lost. Retrying requires reconciliation, not a proof label.

Wall-clock rollback is not a grant extension: the local monotonic deadline also
must hold. A VM/host snapshot may roll back both state and clocks. Address that
separately with an external epoch authority or a stated assumption excluding
rollback; never infer anti-rollback from use of a monotonic API alone.

### BUDGET-01 and ATTEN-01: no amplification

For one local session, start with `used = 0`, allow reservation only if
`used < limit` for the grant and each ancestor, and increment each exactly
once before provider I/O. Inductively
prove `0 <= used <= limit` and an injection from accepted operations into
reservations. A second provider request within one operation must reuse its
own reservation, not create an extra admission or bypass final checks.

For delegation, permission-set inclusion is only one obligation. Require the
child's absolute expiration not to exceed the parent's expiration, all ancestor
epochs to remain active, and all children to debit an authoritative common
budget or a proven disjoint allocation. Minting many children each with the
parent's full budget violates non-amplification even if every policy predicate
individually says "subset". The delivered kernel takes the first route: a
child holds no budget of its own, and the state invariant
`sum(children.used) <= parent.used` is checked after every generated step.

### CONF-01: specify information release honestly

Separate three claims. A syntactic API property says raw provider credentials
are not protocol return values, log fields or client-owned filesystem writes.
A relational information-flow property says two executions with the same public
inputs and same explicitly declassified provider results have equivalent public
observations, despite different secret storage contents. A computational
cryptographic argument says sealed tokens do not reveal their payload, under
an authenticated-encryption security assumption and correct nonce/key handling.
These are not interchangeable.

Ciphertexts, length, timing, rate-limit responses and provider data require
explicit treatment. Changing a GitHub credential can change which account or
resource is visible, so unconstrained equality of all real-world outputs is not
a reasonable theorem. Model the permitted provider response as declassified;
state whether lengths are public or padded and whether timing is out of scope.
An exact-string reflection test is not evidence of general noninterference.
A compromised provider receiving the plaintext token is outside the confinement
claim; this architecture necessarily trusts the intended credential recipient.

### APPROVAL-01 and AUDIT-01: binding human decisions to effects

An approval is identified by a digest of the policy, the grant and the
canonical request -- operation, resource arguments and exact body bytes -- and
carries its own expiry. Any change yields a different digest. Consumption must be atomic with effect admission; losing an
external response does not restore an approval. The public guest endpoint must
not expose approval issuance.

An audit intent acknowledgment precedes dispatch in the model. After dispatch,
a failed completion record yields unknown outcome and stops further authority.
The log can show intent, not prove external success. Local `fsync` is modeled as
a trusted durability acknowledgment; no formal claim should silently turn it
into a distributed atomic commit with GitHub.

## 3. Trusted computing base and assumption ledger

A machine-readable assumption manifest is published as
[aivm-secrets-assumptions.json](aivm-secrets-assumptions.json): each entry has
an owner, the consequence of the assumption failing, and the tests that
exercise the boundary. Version pins and hashes are to be added with the first
proof results. It covers at least:

| Boundary | Explicit assumption / additional work |
| --- | --- |
| Specification | The operation grammar and allowed disclosures match the human requirement |
| Extraction | Charon/Aeneas translation and all supplied external models faithfully represent the pinned Rust subset |
| Proof checking | Lean kernel and declared axioms; avoid claiming zero axioms when standard foundational axioms are present |
| Binary build | Rust compiler, dependencies, target ABI and link process match the proved sources |
| Cryptography | AEAD/signature security, entropy, nonce/key separation, correct library use; primitive internals unproved here |
| Channel identity | SSH or mTLS binds the real peer to the assigned listener/certificate; no spoofable header substitute |
| Host isolation | Untrusted guest cannot modify broker binaries, keys, runtime paths or owning host process |
| Time and persistence | Clock samples and epoch store meet documented semantics; rollback assumptions explicit |
| Provider | TLS peer identity and endpoint semantics; metadata checks are not atomic with later mutations |
| Executor | Only kernel-issued effects reach credentialed egress; no alternate debug/admin/generic HTTP bypass |
| Files and audit | Ownership, no-symlink rules and acknowledged writes enforce the modeled access/durability contract |

Digest binding also needs a cryptographic assumption: do not assert that SHA-256
is injective over arbitrary strings. Treat authenticated policy identity
abstractly, then justify its digest-based implementation under collision
resistance. Similarly, model fresh identifiers/keys explicitly and account for
the probabilistic CSPRNG refinement rather than declaring random values
mathematically guaranteed unique.

Memory safety from safe Rust is valuable, but does not prove these assumptions,
cryptographic soundness, freedom from supply-chain attacks or absence of
side channels. Verification should shrink and expose the trusted base, not
hide it behind the word "core".

## 4. Implementation-linked proof workflow

Use the Rust crate as the single executable source for the kernel. Generate
LLBC using the pinned Charon/Aeneas preset, then generate Lean definitions and
prove properties about those definitions. Keep a small independent declarative
specification for refinement, not a second independently maintained algorithm
that can drift from the executable. The architecture's Aeneas reference gives
the upstream command forms; this overlay intentionally does not fabricate
working version pins or pretend extraction has been run.

Start with closed data types, explicit results and bounded collections. Keep
clock reads, randomness, secrets, syscalls, async runtimes and socket handles out
of the extractable kernel. Model expected failures, overflow, size limits and
malformed input; do not prove only the successful happy path by assuming all
inputs valid. Any normalization assumed by `admit` must be guaranteed by the
actual external parser or included in its refinement theorem.

Use h5i-app in the spike to evaluate its kernel/effect architecture and proof
workflow. If using its database engine later, identify transaction/isolation
semantics as part of the proof boundary rather than assuming the web framework
makes the whole application verified. Keep local mode independent of PostgreSQL
and retain the option to use Aeneas directly.

For deployed complete mediation, the Rust service owns both tokens and egress.
The Python layer submits untrusted requests; it does not receive plaintext
tokens or an unconstrained permission bit with which it can construct another
HTTP request. Make privileged effect constructors private and model the entire
interpreter call graph. Type privacy supports the implementation boundary but
is not itself a substitute for proving the trace invariant.

## 5. Evidence and CI gates

Commit a proof manifest containing source commit/hash, crate/lockfile hashes,
Rust and target triple, Charon and Aeneas commits, Lean toolchain, generated
source hashes, theorem names, external model list, allowed axioms and trusted
adapter revisions. Pin h5i too when used. A successful proof against stale
generated Lean files is a failed release gate.

The verification job must regenerate into a clean directory, compare generated
artifacts, check all named theorems, inspect axiom dependencies, and fail on
`sorryAx`, admitted obligations or undeclared security-relevant axioms. Use Lean's
kernel-checked proofs for release obligations; do not replace them with an
unchecked evaluation result. External function models need explicit provenance
and a refinement argument or a visible trusted assumption.

Add positive witnesses to catch vacuity: at least one authorized read, one
explicitly authorized write, one legal narrowing and one budget-exhaustion
trace. Mutation tests remove a resource constraint or service-specific host check, drop a channel comparison,
refund a failed reservation, allow a redirect or accept a duplicate JSON key.
The associated test/proof gate must fail. Mutation success is supporting
evidence, not a completeness proof of the specification. For the Python
implementation both gates exist today: the vector corpus is checked for the
required witnesses, and `tests/test_secrets_mutation.py` applies each of those
deletions.

Run the same independent vectors through Python, compiled Rust and extracted
Lean definitions; the corpus is `tests/secrets_vectors/` and the replay
harness is `aivm_secrets/kernel/trace.py`. Tests separate grammar, policy,
kernel, envelope, executor, broker, Unix socket transport, operator CLI and
AIVM orchestration, and include generated traces, crash injection and a
real-VM suite. Extend that with coverage-guided fuzzing of the codec and the
frame parser. Do not let optional formatting failures
prevent collecting security or benchmark evidence, but do not waive a proof
failure for a release advertised as verified.

## 6. Publication levels

1. **Experimental:** Python prototype, tested behavior, clear deployment limits.
2. **Verified kernel:** enumerated theorems about pinned extracted Rust, with
   assumptions and generated artifacts published; host stack still trusted.
3. **Composed mediation:** execution/codec refinement plus integration evidence
   connects those theorems to credentialed effects of a pinned service build.
4. **Instance-bound deployment:** reviewed key custody, mTLS, rotation, epoch and
   restore behavior meet the documented deployment assumptions.

These are evidence levels, not dates. Do not call level 1 formally verified.
Do not use level 2 to imply level 4. A useful public claim names the theorem,
the implementation revision, the trust assumptions and the excluded effects.


## 7. Service-neutral proof and plugin-conformance additions (2026-10-09)

The GitHub-specific statements above are historical examples of the first
prototype; the intended theorem domain is **every registered service adapter**.
A plugin cannot inherit a security claim solely because it implements the
right Python method names. It must satisfy a typed effect contract included
in the compiled/extracted Rust and Lean models.

The Python `kernel.machine` holds the common transitions. `admit` checks
authenticated channel/policy binding, time and monotonically bounded lifetime,
budget, operation membership, typed resource arguments, host write mode and
bounded payload size, for the grant and each ancestor. Resource arguments are
checked against a `Scope` the service spec compiles to, so the check is the
same code for every service. The kernel also computes and grammar-checks each
effect, and refuses one whose class differs from the admitted operation, so a
defective service compiler cannot turn a read into a write or leave the
effect grammar. It does **not** verify that a compiler's route is the route
the operator meant: there is no machine-checked refinement connecting a
spec's route to its manifest, and the interpreter around the kernel is
trusted Python. The tests therefore cannot establish end-to-end complete
mediation against a compromised service spec or interpreter.

Add proof obligations PLUGIN-01, RESOLVER-01, ROUTE-01, COMP-01, EXT-01, and
REFINE-01 as specified in
[aivm-secrets-agnostic-integrations.md](aivm-secrets-agnostic-integrations.md).
Future kernel extraction should use a **closed declarative ServiceSpec** and
proof-producing checked effect interpreter, avoiding dynamic function pointers
inside the Aeneas-translated proof surface. An untrusted third-party plugin
may propose a bounded `Intent`, but cannot hold the underlying credential or
mint `AuthorizedEffect`.

Proof boundaries must explicitly account for any adapter that performs
service-specific metadata preflights, API semantically meaningful GETs, token
refresh, signature requests, or delegated operations. A generic HTTP GET is
not necessarily observationally pure. A destination-pinning theorem must be
paired with a TLS/egress assumption and a statement about host DNS and proxy
behavior. Every claim must distinguish the proved extracted Rust function
from the unproved Python orchestration and network runtime.
