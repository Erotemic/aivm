# AIVM Secrets: credential-use capabilities with a verifiable core

Status: proposed architecture plus an experimental Python vertical slice.
Research date: 2026-10-09. No part of this implementation is formally verified.
The companion [provider-neutral integration plan](aivm-secrets-agnostic-integrations.md)
defines schema 2 and supersedes GitHub-specific assumptions below. The
[assurance plan](aivm-secrets-formal-assurance.md) defines proof
obligations and the evidence needed before making stronger claims. See
[the operator guide](../source/secrets.rst) for commands that work in this slice.

## 1. Decision and scope

Build `aivm-secrets` as an independent secret-*use* service, not a mechanism for
copying provider tokens into VMs. Initially ship `aivm_secrets` beside `aivm`
inside the existing Python distribution, with its own `aivm-secrets` executable.
Keep imports one-way: the package does not import AIVM. The AIVM adapter resolves
an access identity, establishes a channel, and controls the session lifetime.
A later distribution split must not change the capability protocol.

The preferred eventual security core is a small safe-Rust state machine,
translated with Charon/Aeneas and verified in Lean 4. Keep this core independent
of the HTTP framework, VM manager, identity provider, persistence engine, and
agent harness. Evaluate h5i-app as a compatible framework and development tool,
not as a prerequisite for running a local broker.

The first compatibility integration is GitHub (schema 1); new installations
should prefer the provider-neutral HTTPS manifest (schema 2). The initial
workload was inspecting selected TauCeti
PRs, reviews and checks, with optional narrowly scoped comments and title/body
edits. Git push remains a separate capability using AIVM's existing repository
SSH credential backends. No existing credential is migrated, replaced or
forwarded more broadly by enabling this feature.

The product goal is an auditable boundary with precise, machine-checked
properties. It is not a claim that arbitrary agent behavior becomes safe, or
that verification of one function verifies a VM, operating system or provider.

## 2. Foundation: Garrett, and the extension needed here

Matthew Garrett's July 2, 2026 proposal puts credential acquisition outside the
agent, returns a signed token carrying an encrypted provider credential, and
substitutes that credential only at a trusted proxy. He then binds the token to
a client certificate checked through mTLS, ideally backed by a non-exportable
hardware or hypervisor key. He credits earlier Fly.io work. That is the
architectural starting point, not an AIVM invention. [G1, G2]

AIVM should add a **reference monitor for the meaning of each authenticated
request**. Hiding a broad GitHub token does not stop a running agent from asking
its proxy to use that token for an unwanted operation. Identity proves which
channel may ask; policy decides what may be done; resource validation decides
which object the request actually targets; the effect executor must implement
only the decision it was given.

The target pipeline is:

```text
Host operator / identity provider
        | authenticates; authorizes a bounded grant
        v
Credential issuer ---- sealed credential-bearing capability ----> Guest
        |                                                         |
        | issuer / decryption keys                                | typed request
        |                                                         | + capability
        v                                                         v
Trusted credential service <--- authenticated, instance-bound channel
        |
        +--> decode / authenticate / bind / authorize / reserve
        +--> obtain narrowly requested provider facts
        +--> revalidate / construct an approved effect
        +--> audit intent / attach credential / execute fixed destination
        +--> project permitted response / audit outcome
```

The guest may replace the client, forge requests, steal its capability, and run
arbitrary network tools. Security must reside in the host service, not in a
shell wrapper, an agent instruction, an executable allowlist, or obscurity.

## 3. Threat model and claim boundaries

### Adversary and trusted elements

Assume guest root and every process in the guest can be malicious. Assume PR
text and provider response bodies can contain prompt injection or malformed
data. An attacker can submit arbitrary protocol bytes, replay ciphertext,
concurrently request permitted operations, and deliberately exhaust budgets.
A separate host UID must not gain authority merely by learning a socket path.

For the initial slice, trust the owning host UID, host kernel, installed broker
code and dependencies, Python runtime, entropy source, cryptographic library,
OpenSSH transport and host-key state, TLS implementation and certificate roots,
and GitHub's endpoint semantics. Trust the operator to select the right host
account, policy and workspace. Root and unrestricted hypervisor administrators
remain outside this boundary, as they already do for AIVM.

In particular, do not install the host broker from an editable source tree that
the guest can modify. Do not share the host home, credential store, runtime
socket directory, or audit directory with an untrusted guest. Checking the
currently attached workspace cannot detect every exposure from earlier mounts.
A narrowly authorized proxy cannot repair an independently exposed host secret.

### Security distinctions

| Property | Intended interpretation | Important exclusion |
| --- | --- | --- |
| Credential confinement | Provider credential stays on trusted host paths and approved provider connection | Host memory compromise, swap/core dumps, or a compromised provider are not prevented |
| Channel binding | A grant is accepted only by its assigned authenticated session | A malicious guest can relay its own authorized service while alive |
| Authorization | Every emitted effect belongs to a bounded grant and current epoch | A permitted comment may trigger an external bot or leak other guest data |
| Revocation | Requests after the revocation linearization point cannot begin new effects | An already dispatched effect cannot be rolled back |
| Budget | Admission consumes bounded authority before I/O | Budget exhaustion and service denial are possible |
| Audit | Required audit writes precede dispatch; failures stop authority | Local JSONL is neither immutable nor a distributed transaction with GitHub |

Read-only is the default. A write grant is explicitly a grant to send its allowed
content to the selected PR; it is not proof that the content is appropriate.
For example, denying the merge API does **not** prove that posting a comment
cannot trigger a repository's merge bot. One-shot, exact-content approvals are
a later capability, not something the first implementation silently claims.

## 4. Package and trust-boundary layout

The delivered Python package is split deliberately:

| Module | Responsibility | Eventual destination |
| --- | --- | --- |
| `kernel.py` | Provider-independent binding, claims, budget, time and write authorization | Extractable safe-Rust kernel |
| `core.py` | Legacy GitHub-specific policy, PR facts and route mapping | Optional service adapter; keep outside common kernel |
| `adapters.py` | Explicit host-selected service registry and legacy GitHub adapter | Closed, verified service spec compilation |
| `http_service.py` | Declarative fixed-host HTTPS operation adapter, schema 2 | Verified route interpreter plus trusted TLS egress |
| `wire.py` | Bounded, duplicate-rejecting protocol parser and serialization | Bounded codec with refinement contract |
| `envelope.py` | Library-backed authenticated encryption and strict capability decoding | Credential service; audited crypto dependency |
| `broker.py` | Serialized grant state, checks, budget reservation, effect sequencing | Verified transition system plus small trusted interpreter |
| `provider.py` | Fixed-origin TLS egress; bounded responses; no redirects/retries | Small Rust I/O boundary |
| `audit.py`, `files.py`, `sources.py` | Private host files, audit durability, host credential acquisition | Host adapters with explicit assumptions |
| `server.py` | Session-local Unix socket, kernel peer UID check, framing | Transport adapter |
| `guest.py` | Replaceable, dependency-light client | Untrusted convenience layer |
| `cli.py` | Explicit host administration and standalone lifecycle | Operator interface |
| `aivm/secrets_transport.py` | Existing resolved context -> foreground SSH capability | AIVM integration only |

Longer term, use separate Rust crates for `secrets-kernel`, `secrets-protocol`
and `secrets-host`, with a Lean proof package and an independent conformance
corpus. Those are planned boundaries, not empty crates included in this slice.
The trusted service should eventually own credential material and egress in
its own process. Merely returning `True` from a verified Rust policy function
to arbitrary Python that still owns the token does not establish complete
mediation. The executor must be constrained to kernel-generated effects.

Keep optional integrations optional. The initial crypto dependency is an
`aivm[secrets]` extra; importing ordinary AIVM or running existing SSH paths does
not initialize a credential service or require crypto. The package can be
extracted into its own repository/distribution without carrying libvirt code.

## 5. Credential lifecycle and Garrett-style envelopes

### Delivered local profile: `aivs1`

Schema 1 defaults to the owning host's `gh auth token --hostname github.com`
or an explicitly supplied private file / standalone stdin. Schema 2 instead
uses an operator-approved host-only command-argv resolver or private file,
independent of the remote service or guest CLI.
No login is performed inside the guest. Do not call guest-controlled programs
to acquire credentials. The host executable and its configuration are trusted.

For each session, generate an independent 256-bit key. Use the cryptography
library's AES-GCM implementation with a fresh nonce and fixed protocol/provider
associated data. The encrypted payload contains the provider credential,
access identity, host UID, VM label, unpredictable channel ID, grant ID, policy
digest, issue time and expiration. The guest receives a versioned opaque
ciphertext, not the key or usable provider token. The host authenticates and
decodes it on each request. Cryptographic primitives are not implemented here.
[C1]

This captures encrypted credential carriage without a persistent token-mapping
store. It is **not a JWT, JOSE implementation, mTLS system, or RFC 8705 profile**.
The host has in-memory policy, counters, clocks and revocation state. Calling
the whole service stateless would be wrong. One key per short-lived session
also makes normal restart fail closed: old ciphertext cannot be reopened by a
new broker. Python does not guarantee erasure of old byte/string copies.

### Target interoperable profile

Before remote or multi-host deployment, define a separate, explicitly versioned
profile using reviewed JOSE libraries. Carry encrypted provider credentials
inside an issuer-authenticated envelope, with fixed allowed algorithms and
explicit issuer, audience, token type, provider, grant, policy digest, epoch,
validity interval and certificate confirmation. Use separate signing,
encryption and audit keys, with bounded key IDs and reviewed rotation rules.
Reject algorithm substitution, unknown critical fields, mixed-profile tokens
and guest-supplied key-discovery URLs. JWT security guidance applies. [J1]

Do not blindly copy upstream claims into authoritative top-level claims.
Namespace any informational provider claims and preserve their provenance;
our issuer/audience/subject/policy meanings must remain unambiguous. Upstream
claims may also contain personal data. Opaque provider tokens need no parsing.

Bind admission to the actual certificate established by the mTLS terminator,
using the certificate-thumbprint confirmation mechanism and certificate
validation rules from RFC 8705. Never accept an unauthenticated JSON field or
an internet-supplied header as evidence of the TLS peer. A separate terminator
requires an authenticated internal handoff and becomes part of the trusted
computing base. [M1]

The instance key must be inaccessible to the guest as exportable key bytes.
A vTPM is not automatically a complete answer: decide who owns its state,
whether snapshots can clone it, how restored instances acquire a fresh epoch,
and what host administrators are trusted to do. Identity attestation and
non-exportability are distinct from software integrity; a compromised guest
may still invoke its legitimate key and relay requests. Do not claim code
integrity merely from possession of an instance identity.

### Refresh, revocation, and persistence

The prototype does not refresh credentials or grants. Re-entering a session is
an explicit new host action. Future OAuth acquisition must validate redirect
state and use an appropriate provider flow, keep refresh tokens host-side,
serialize rotation, redact errors and never widen the existing grant on refresh.
A shorter upstream lifetime always limits effective authority.

Stateless encrypted credential carriage does not remove the need for state
when promising immediate revocation, shared quotas, reusable approvals or
crash-recovery semantics. For durable mode, keep a strongly consistent grant
ledger with monotonically increasing epochs and a defined transaction boundary.
An inability to read authoritative revocation state must deny admission. Choose
local single-writer storage before introducing a distributed service. Avoid
claiming exact-once writes to an external API without its cooperation.

## 6. AIVM integration and principal ownership

The existing foreground session preparation remains the entry point. It already
resolves VM selection, workspace attachment and the owning access identity.
The new adapter begins only after that succeeds. It requires an active resolved
principal whose recorded host UID equals the kernel UID; environment variables
such as `USER` do not establish ownership. Administrator access is not permission
to borrow another principal's provider identity.

The adapter loads a host-owned policy outside the currently shared source,
obtains the credential, creates a private host socket and audit file, and copies
only the inspectable guest client and sealed capability through SSH stdin.
It opens a dedicated reverse Unix-socket forward on the foreground SSH process.
Secret sessions disable SSH multiplexing and ambient SSH config; require the
already-established host key; and require forwarding setup to succeed. Existing
explicit VM identity and dedicated repository-agent options are retained.

The listener is created for exactly one server-side binding. Linux
`SO_PEERCRED` checks the local connection's host UID. For an SSH-forwarded
connection, that peer is the **host SSH process**, not the guest user. The
assignment of that listener to the selected SSH session is therefore essential.
A client-supplied VM name or username has no authority. The proof plan must not
mistake the peer-UID check for attestation of a guest process.

Closing the foreground session shuts down the listener and revokes the broker
before best-effort guest cleanup. Keys are not persisted. Expired sessions deny
operations even if their interactive shell remains open. Host cleanup and SSH
transport are currently tested with fakes plus real local sockets, not a live
libvirt VM; an operator must perform the documented VM smoke test before relying
on the integration. Some guest sshd configurations may forbid streamlocal
forwarding; setup then fails rather than broadening sshd permissions.

Access-identity state is checked at session creation, not continuously watched.
Disabling that identity in another AIVM command does not yet signal an existing
broker. Terminate its foreground host session to revoke it immediately; its TTL
still bounds subsequent admissions. Connecting disable/delete events to active
secret sessions is a P3 lifecycle obligation, not an implemented guarantee.

Only `aivm ssh` is integrated initially. VS Code, long-lived services, detached
agents and remote hosts need explicit lifecycle designs rather than silently
inheriting authority through an old socket. No persistent machine-store schema
is added. Audit files live in the owning profile state; private runtime sockets
live in fresh host temporary directories.

## 7. Authorization as data, not executable policy

Version 1 grants contain one canonical GitHub repository, an explicit nonempty
set of PR numbers, allowed operation names, required PR author, required head
repository, lifetime, request budget and maximum body length. No wildcards,
regex policies, executable policy code, arbitrary paths or guest delegation
are accepted. Invalid and unknown fields fail closed. Repository spelling is
normalized under an ASCII grammar before policy comparison and URL construction.

A request names an operation, repository and PR, with only operation-specific
page/body/title fields. It cannot supply a host, URL, HTTP method, header,
authentication field, provider credential, identity assertion or GraphQL query.
The policy digest is derived from deterministic canonical JSON; duplicate JSON
keys, nonfinite numbers, excessive nesting, booleans masquerading as integers,
and oversized frames are rejected.

Admission checks binding and policy, active state, half-open wall-clock validity
and monotonic deadline, budget, repository/PR membership, operation and payload
bounds. Writes require **both** policy membership and an independent host
`allow_writes` opt-in. The request budget is reserved before any provider I/O;
a failed provider preflight consumes the admission. Invalid traffic also has a
separate attempt cap, bounding per-session audit growth.

Every admitted request first fetches the selected PR metadata from a constructed
REST path. Require the expected PR number, base repository, author and head
repository. Treat returned URLs as data, never destinations. A commit SHA used
for checks is validated before path construction. Recheck expiry/revocation
before any second dispatch, including after audit I/O. The lock serializes
budget reservation and dispatch, rather than allowing concurrent requests to
observe the same remaining budget.

This preflight is not an atomic GitHub transaction. Repository transfer,
metadata change, or remote actions can occur after it. Future grants should pin
immutable repository/PR identities and use a provider-supported conditional
update only where its actual semantics meet the requirement. Do not invent an
`If-Match` guarantee for an endpoint. For now the stated condition is that
freshly fetched metadata matched at the check, not throughout an external write.

Attenuation is defined as semantic subset: same provider/resource ownership
constraints, subset of PRs and operations, no longer lifetime, no larger budget
or body limit. The pure function is included for conformance tests, but no
endpoint mints child grants yet. In a future hierarchy, absolute expiration,
ancestor revocation, epoch matching and a shared budget ledger are also required;
independent copies of a parent's budget would amplify total authority.

## 8. GitHub operations and client compatibility

| Client operation | Constructed provider operation | Caveat |
| --- | --- | --- |
| `pr view` | Get selected PR | Broker-native JSON, not stock `gh --json` |
| `pr diff` | Get selected PR with diff media type | Bounded size; binary/large cases can fail |
| `pr comments` | List issue comments on selected PR | Explicit page of at most 100 |
| `pr reviews` | List submitted reviews | Not a GraphQL review-thread model |
| `pr review-comments` | List PR review comments | Does not resolve threads |
| `pr checks` | List check runs for validated head SHA | Not combined status contexts or workflow logs |
| `pr comment` | Create issue comment | Write policy and host opt-in required |
| `pr edit` | Change only title/body | Cannot change base/state, labels or assignees |

Routes follow GitHub's PR, issue-comment and check-run REST APIs. The adapter
pins the documented API version `2026-03-10`; an API upgrade needs contract and
fixture review rather than automatic acceptance. [GH1, GH2, GH3]

The guest executable is deliberately gh-shaped, not a transparent replacement
for stock `gh`. It supports only the table above, requires `--repo` and an
explicit PR number, and has no fallback. Existing `campaign_ops.py` code using
`gh api`, GraphQL, arbitrary `--json` selection or workflow logs will need a
separate adapter. Do not advertise drop-in campaign compatibility.

Supporting the actual stock CLI later is a separate project. An ordinary HTTPS
CONNECT proxy cannot edit encrypted authorization headers. Interception requires
a narrowly trusted TLS endpoint or client cooperation, correct certificate
validation in both directions, and safe treatment of redirects, CONNECT, SNI,
Host, HTTP versions and connection reuse. GitHub GraphQL needs semantic parsing
of operation type, selected fields, variables, aliases, fragments, mutations and
batching. Allowing `POST /graphql` is not a read-only policy. A restricted
broker-native API remains available even if that compatibility layer is added.

The initial provider creates a direct TLS connection to `api.github.com`, does
not read HTTP proxy environment variables, sends fixed authorization and API
headers, refuses redirects and does not retry. Transport, timeout, response
parsing or audit failure after a write dispatch produces an unknown-outcome
response. The operator must inspect GitHub before retrying. Pagination includes
an explicit `possibly_more` flag; the client never implies a single page is all
feedback.

## 9. Audit, resource bounds and residual risks

Use private append-only-in-process JSONL with event IDs, channel, timestamp,
operation, repository, PR and fixed outcome codes. Never log tokens, ciphertext,
request bodies, titles, arbitrary upstream errors or debug HTTP headers. Required
audit records are flushed/fsynced before dispatch; an audit failure revokes the
session. Completion failure after an external write is still an unknown outcome.
A later durable audit design can hash-chain events and anchor them outside the
writer, but a local hash chain alone cannot prove that a malicious host did not
truncate history.

Wire frames are limited to 64 KiB; provider responses to 2 MiB; list pages to 100;
policies to 512 PRs, 1,000 admissions and one hour. Defaults are smaller. Socket
framing has a deadline, malformed attempts have a cap, and the service serializes
requests. Provider socket timeouts are not a hard total wall-clock bound against
a peer that trickles data. There is no current service-availability theorem.
Host resource limits, bounded total transport time, peer flood controls and
workload performance measurements belong in hardening.

Private file readers reject unsafe ownership/modes, symlinks at the final path,
hard links and nonregular files. Ancestor directories and the trusted user's
other processes are assumptions. A production hardening pass should use held
no-symlink directory descriptors throughout and reject unsafe ancestor ownership,
in line with AIVM's existing privileged-path principles. No custom keychain,
password vault, generic filesystem secret fetch, or encrypted storage service is
introduced in this slice.

The response serializer includes a literal-credential reflection tripwire.
That catches accidental exact echo, not encoding transformations, statistical
leakage, timing channels, or arbitrary confidential provider content. Formal
noninterference must specify allowed declassification and adversary observations;
a redaction function is not a secrecy proof.

## 10. Verification technology decision

h5i's `h5i-app` is an Axum-based application framework whose Rust-to-Lean workflow
already uses Aeneas. It is not an alternative extraction backend. Its pure-kernel
versus I/O-engine split is relevant; its full web/database stack need not become
a dependency of a local credential broker. Use its extraction, proof-development
and mutation-testing workflow in an isolated spike, then decide whether the
runtime framework provides enough benefit to justify its trusted surface. [H1]

Aeneas uses Charon's LLBC representation to translate a supported subset of safe
Rust into a functional model. Its documentation lists Lean and HOL4 as mature
backends and identifies unsafe code and concurrency as current limitations.
That favors a deterministic sequential kernel with explicit events, not an
attempt to extract an async TLS stack. Lean 4 is the default because it fits this
pipeline; an extraction failure is a reason to simplify the Rust boundary or
compare another supported backend, not to axiomatize the desired result. [A1]

Before committing to versions, complete a representative spike containing
canonical parsing, a policy check, a budget decrement and provider-route
construction. Pin Rust, Charon, Aeneas, Lean, libraries and h5i if used. Include
unsupported standard-library models in the assumption ledger; generated code
must not quietly replace an important function with an unconstrained axiom.
This overlay has not selected or exercised that toolchain.

Proofs should attach to the actual extracted implementation and then to a trace
semantics for the executor. A separate elegant Lean policy model is useful as a
specification, but not evidence that the deployed Rust or Python realizes it.
The detailed theorem inventory, refinement obligations and release gates are in
[the assurance plan](aivm-secrets-formal-assurance.md).

## 11. Delivery milestones and acceptance gates

### P0 - Python vertical slice (original overlay and service-neutral follow-up)

Deliver the independent package, local encrypted capability, strict bounded
policy, broker-native GitHub operations, schema 2 declarative HTTPS integrations,
provider-neutral admission kernel, generic guest invocation, audit, foreground
SSH adapter and tests.
Keep all writes opt-in. Record the tests actually run and the lack of live
libvirt/provider integration and formal proofs. Existing deploy-key and agent
workflows must remain available. This is a reviewable prototype, not a hardened
multi-tenant deployment.

### P1 - Specification and extraction spike

Freeze protocol version 1 with an independent test-vector corpus and negative
cases. Write an explicit effect grammar and abstract state machine. Port one
representative slice to safe Rust and extract it into Lean. Prove one positive
admission example and one nontrivial denial/refinement theorem without `sorry`.
Pin tools and list all axioms/external models. Exit only when the compiled Rust
and extracted functions consume the same canonical test inputs.

### P2 - Verified kernel

Port authorization, byte normalization, effect construction and grant state
transitions. Prove the assurance plan's authorization, binding, attenuation,
epoch, expiry and budget properties, including composed traces. Add generated
adversarial tests and mutation checks demonstrating that missing checks break
theorems. CI must fail on stale extraction, unexpected axioms and proof failures.
Release wording may describe these *named kernel properties*, not end-to-end
verified secret handling.

### P3 - Complete mediation and host service hardening

Move credential custody and egress into a constrained Rust service. Establish
that untrusted/Python clients cannot forge privileged effects or bypass the
kernel. Prove or enumerate the interpreter/codec assumptions. Add real libvirt
and SSH lifecycle tests, hard total deadlines, crash and audit fault injection,
whole-path safety, restrictive service privileges and provider mock-contract
coverage. Validate one live read-only GitHub session with an explicitly approved
throwaway/narrow credential. Do not automate live writes during ordinary tests.

### P4 - Remote identity and durable authority

Add Garrett-style broker acquisition, standardized sealed envelopes, mTLS
certificate binding and instance-key custody. Specify restore/clone/epoch
behavior before enabling vTPM or remote attestation claims. Implement revocation,
refresh and optional one-shot approvals against a durable ledger. Test CA/key
rotation, dropped/duplicated requests, restart, stale replicas and snapshot
rollback. Local mode must remain available without a cloud account.

### P5 - Compatibility and broader providers

Evaluate stock `gh` support and GraphQL policy separately, using captured
sanitized request fixtures. Expand only named operations with reviewed semantic
contracts. Add other providers through typed operation/effect modules rather
than a generic authenticated HTTP escape hatch. Benchmark startup latency,
per-request overhead and bounded memory; do not put performance estimates in
product claims before measurement.

## 12. Positioning and contribution policy

Docker already documents host-side credential resolution and substitution for
sandboxed tools, including a `gh auth token` resolver. Token hiding alone is not
a defensible claim of differentiation. AIVM's proposed difference is an open,
reviewable, self-hosted authorization boundary with reproducible proofs of
specific properties and a plainly stated trusted computing base. [D1]

Licensing and source-availability comparisons require a separately dated review
of the actual component licenses and terms. This plan does not assert that all
Docker local use requires payment or evaluate contractual enforceability. Compare
capabilities and obligations with evidence, not a blanket statement that a
competitor is insecure. Keep the implementation's license aligned with AIVM;
review any vendored dependency separately and preserve upstream attribution.

Do not expose a broad token to get an early demo working. Do not add arbitrary
`gh api` as a workaround for missing operations. Do not label tests as proofs.
Every expansion should identify the new effects, authorization rule, failure
behavior, adversarial test and affected theorem before it ships.

The provider-neutral protocol, credential source and CLI-extension design is
documented in [the companion plan](aivm-secrets-agnostic-integrations.md).

## References

These are primary sources consulted on 2026-10-09; linked project heads may
change. Reproduce future proof builds using committed hashes, not these links.

- [G1] Matthew Garrett, *Securing agentic identity*, 2026-07-02:
  https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/
- [G2] Fly.io, *Tokenized Tokens*:
  https://fly.io/blog/tokenized-tokens/
- [M1] RFC 8705, especially certificate-bound tokens and TLS termination:
  https://datatracker.ietf.org/doc/html/rfc8705
- [J1] RFC 8725, JSON Web Token Best Current Practices:
  https://datatracker.ietf.org/doc/html/rfc8725
- [H1] h5i repository and h5i-app documentation:
  https://github.com/h5i-dev/h5i
  https://github.com/h5i-dev/h5i/tree/main/crates/h5i-app
- [A1] Aeneas README: usage, supported subset, backend support and external models:
  https://github.com/AeneasVerif/aeneas
- [C1] cryptography authenticated-encryption API:
  https://cryptography.io/en/latest/hazmat/primitives/aead/
- [GH1] GitHub REST pull requests:
  https://docs.github.com/en/rest/pulls/pulls
- [GH2] GitHub REST issue comments:
  https://docs.github.com/en/rest/issues/comments
- [GH3] GitHub REST check runs:
  https://docs.github.com/en/rest/checks/runs
- [D1] Docker Sandboxes, authenticate command-line tools:
  https://docs.docker.com/ai/sandboxes/workflows/authentication/
