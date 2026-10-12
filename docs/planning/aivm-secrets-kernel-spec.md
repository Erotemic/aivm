# AIVM Secrets: kernel specification for the Rust port

Status: **implemented in Python, specified here for extraction.** This is the
contract the planned safe-Rust kernel must meet. It describes what the code in
`aivm_secrets/kernel/` does today, precisely enough to be ported function by
function and checked against the frozen vectors in `tests/secrets_vectors/`.
Nothing in this document is a proof, and no Lean artifact exists yet; see
[the assurance plan](aivm-secrets-formal-assurance.md) for what is to be
proved and [the design](aivm-secrets-design.md) for the threat model.

## 1. Shape of the system

```text
        untrusted guest                      trusted host
  ┌──────────────────────┐   v1 frame   ┌───────────────────────────────────┐
  │ guest.py (stdlib)    │ ───────────► │ host/server.py   peer-UID, framing │
  │ or any other client  │ ◄─────────── │ host/broker.py   the interpreter   │
  └──────────────────────┘    reply     │      │      ▲                      │
                                        │      ▼      │ State, AuthorizedEffect
                                        │ ┌───────────────────────────────┐  │
                                        │ │ kernel/   PURE                │  │
                                        │ │ grammar codec model scope     │  │
                                        │ │ https github service machine  │  │
                                        │ └───────────────────────────────┘  │
                                        │ host/envelope  audit  egress ──────┼─► one TLS
                                        │ host/sources   files  session      │   destination
                                        └───────────────────────────────────┘
```

Two rules give the picture its meaning, and both are enforced by tests rather
than by convention (`tests/test_secrets_purity.py`):

1. **`kernel/` is pure.** It imports only `dataclasses`, `typing`, `json`,
   `hashlib`, `ipaddress` and the fixed error table. It reads no clock, file,
   socket, environment variable or random source; uses no regular expression,
   closure, lambda, generator, global or dynamic attribute access; and every
   dataclass is frozen. This is the subset Charon/Aeneas translate.
2. **Only the kernel can authorize an effect.** `AuthorizedEffect`, `Ticket`
   and `Grant` are constructed in `kernel/machine.py` and nowhere else; the
   executor is called from `host/broker.py` and nowhere else, and only with a
   value a kernel emission returned. In Rust these become private
   constructors and a single consuming `execute(AuthorizedEffect, ..)`.

Planned crate split (unchanged from the design document):

| Crate | Python today | Contents |
| --- | --- | --- |
| `secrets-kernel` | `kernel/{model,scope,machine,service,https,graphql,source}.py` | data, scope algebra, state machine, service specs, effect compiler |
| `secrets-protocol` | `kernel/{grammar,codec,wire,trace}.py` | alphabets, strict JSON, canonical encoding, frames, trace replay |
| `secrets-host` | `host/*.py` | AEAD envelope, TLS egress, audit, files, resolvers, sockets |

AIVM itself is not in this picture. It starts the broker as a child process
(`aivm-secrets serve`) and talks to it only through that command line, one
JSON line of stdout, and the lifetime of its stdin. Replacing the Python
broker with a Rust binary therefore changes no AIVM code.

## 2. Data

All integers are non-negative and bounded; all strings are UTF-8. Bounds are
part of the specification, not implementation limits.

```text
Binding   { owner_uid: u32, access_identity, vm, channel: text[1..128] }
Claims    { binding, policy_digest: hex64, grant_id: hex32,
            issued_at: u63, expires_at: issued_at+1 ..= issued_at+3600 }
Clock     { wall: u63, mono: u63 }                 -- whole seconds, supplied
Value     = Int(0 ..= 2^31-1) | Text(1..16384 bytes, no NUL)
Request   { operation: name, arguments: sorted [(arg_name, Value)], ≤16 }
Effect    { method: GET|POST|PATCH, path, query: [(arg_name, segment)],
            accept: media_type, response: json|text,
            body: None | [(arg_name, Text)] }
Egress    { host, port, address?, ca_file?, authentication, headers }

ParamSpec = IntSet(sorted unique ints, ≤512) | IntRange(low ≤ high)
          | StrSet(sorted unique strings, ≤512)
FieldSpec { name, max_bytes, required }
OperationScope { name, write: bool, parameters: [(arg_name, ParamSpec)],
                 fields: [FieldSpec] }
Scope     = [OperationScope]                       -- unique names

Grant     { grant_id, parent ("" = root), depth ≤ 4, scope,
            issued_at, expires_at, deadline, max_requests, max_body_bytes,
            used, active }
Ticket    { serial, grant_id, operation, resource, request_digest, write,
            phase: reserved|preflight|final }
Approval  { digest: hex64, expires_at }
State     { binding, policy_digest, write_mode: deny|approve|allow,
            max_attempts, grants (≤64, root first), approvals (≤16),
            ticket: Option<Ticket>, serial, attempts, active }
AuthorizedEffect { serial, grant_id, request_digest, final: bool,
                   write: bool, effect }
```

A `Claims` value carries **no scope**. It names a grant held in `State`, so
presenting different bytes can never widen authority; it can only fail to
match.

There is **one** service mechanism, `HTTPSpec`: a declarative manifest
interpreted by the kernel. A policy reaches it by one of two routes, chosen
by its explicit schema number and ending in the same type:

| Schema | Meaning |
| --- | --- |
| 2 | a manifest, parsed directly |
| 1 | shorthand for the built-in GitHub pull-request manifest: `presets.github_pr` *expands it into a schema-2 manifest*, which is then parsed like any other |

`presets.py` is data construction only. It imports no mechanism, and the
schema-1 policy and its expansion have the same digest (pinned in
`tests/secrets_vectors/v1/policy.json`). Nothing else in the package names a
provider (`tests/test_secrets_purity.py`).

A manifest is a fixed TLS destination plus:

```text
Check      { name, path template, accept,
             require: [Requirement], bind: [Capture] }
Requirement{ at: [key], literal | parameter, fold: bool }
Capture    { name, at: [key], format: hex|integer|segment }
Operation  { name, write: bool,            -- declared, never inferred
             requires: Option<check>, returns_check: bool,
             method, path template, parameters, query, body fields,
             response, accept, defaults, fold, page, static GraphQL query }
CLICommand { words, operation, positional, options, output, bounded JSON projection,
             independently granted alternative read, repository inference }   -- inert data
```

`HTTPSpec` provides the total functions the kernel is written against:
`scope()`, `parse_request(wire)` (which folds and defaults, once, before any
check), `preflight(request)`, `final(request, facts)` and
`reply_meta(request, result)`. `final` first verifies the check -- every
`Requirement` must hold, by exact type -- and extracts each `Capture` in its
declared format; only then does it build the effect, from the template, the
allowlisted arguments and the validated captures. There is no registry
lookup by name, no dynamic import and no trait object.

**Effect class.** `Operation.write` comes from the manifest's required
`effect` field. The parser refuses an ordinary body-carrying method declared `read`,
but accepts a pinned, named GraphQL **query** as a declared read. It accepts
a `GET` declared `write`. GraphQL endpoint semantics remain assumed (SPEC-02). The class is what admission checks
against the host write mode, what an approval is required for, and what
`AuthorizedEffect.write` carries to the executor. `Effect.is_write` (an ordinary body-carrying method that is not an admitted
static GraphQL query) is a backstop: an ordinary read cannot emit a write.
A GraphQL query is considered read-only only under SPEC-02.

## 3. Encodings and identities

**Alphabets** (`grammar.py`) are loops over fixed character sets. The two that
matter most:

* *segment* -- one path segment or query value: 1..128 characters from
  `A-Z a-z 0-9 - . _ ~`, and not `.` or `..`. Because nothing else can appear
  in a constructed path or query, the request target needs no percent-encoding
  and is an injective function of its typed parts.
* *credential* -- 16..4096 bytes in `!`..`~`. No space, CR or LF, which is
  what makes it safe to place in exactly one header value.

**Strict JSON** (`codec.py`). Reject: duplicate object keys, `NaN`/`Infinity`,
numbers with no finite value, invalid UTF-8, trailing data, more than 64 levels
of nesting, more than 65,536 bytes per frame.

**Canonical encoding**: object keys sorted by code point, no whitespace, ASCII
output with `\uXXXX` escapes (surrogate pairs above the BMP). Digested
documents contain only objects, arrays, strings and integers.

**Digests** are SHA-256 over canonical encodings, as lowercase hex:

```text
policy_digest    = H(canonical(policy.to_dict()))
request_digest   = H(canonical({"operation": .., "arguments": {..}}))
approval_digest  = H(canonical({"policy": policy_digest, "grant": grant_id,
                                "request": {..}}))
```

Proofs must treat `H` as an abstract collision-resistant identity. They must
not assume it is injective.

**Request target**: `path` if there is no query, else
`path + "?" + k1=v1 & k2=v2 ...` in the effect's own order.

## 4. Transitions

Every transition is a total function. It returns a new `State` (and possibly a
value) or fails with one fixed code, **and a failure never changes state**: the
caller keeps the state it had. That one rule replaces every "rollback" case.

Two helpers are shared.

`authenticate(state, claims, binding)` → lineage (leaf first):

| # | Check | Code |
| --- | --- | --- |
| 1 | `state.active` | `revoked` |
| 2 | `claims.binding = binding = state.binding` and `claims.policy_digest = state.policy_digest` | `wrong_binding` |
| 3 | `claims.grant_id` names a grant; its parent chain reaches the root within 5 steps | `wrong_binding` |
| 4 | `claims.issued_at`/`expires_at` equal the grant's | `wrong_binding` |

`require_live(state, lineage, clock)`:

| # | Check, for the grant and every ancestor | Code |
| --- | --- | --- |
| 1 | `state.active` and each `grant.active` | `revoked` |
| 2 | `issued_at ≤ clock.wall < expires_at` | `expired` |
| 3 | `clock.mono < deadline` | `expired` |

### `admit(state, claims, binding, request, clock) → State`

Checks, in this order. The first failure is the answer; a caller learns
nothing about later ones.

| # | Check | Code |
| --- | --- | --- |
| 1 | no ticket is open | `internal_error` |
| 2 | `authenticate` | `revoked` / `wrong_binding` |
| 3 | `require_live` | `revoked` / `expired` |
| 4 | `used < max_requests` for every grant in the lineage | `exhausted` |
| 5 | for every grant in the lineage: the operation is in its scope, the arguments lie inside it, and the body size is within `max_body_bytes` | `denied` / `invalid_request` |
| 6 | if the operation is a write: mode `deny` | `denied` |
| 7 | if the operation is a write: mode `approve` and no unexpired approval for `approval_digest(policy, leaf, request)` | `approval_required` |

On success: `used + 1` on every grant in the lineage; the matching approval,
if any, removed; `ticket = Ticket(serial, leaf, .., phase = reserved)`;
`serial + 1`. No I/O has happened. Nothing later refunds the reservation.

Argument checking (`scope.check_arguments`) separates shape from permission:
an unknown argument, a missing parameter, a missing required field, a
non-string field or a write with no field is `invalid_request`; a value
outside its `ParamSpec` or a field over its byte cap is `denied`. Membership is
type-exact: the string `"23"` is never the integer `23`.

### `emit_preflight(state, spec, request, clock) → (State, Option<AuthorizedEffect>)`

Requires the open ticket to be the one made for exactly this request
(`request_digest`) under exactly this policy (`policy_digest`), in phase
`reserved`. If the spec has no preflight for the request, returns `None` and
the state unchanged. Otherwise the effect must pass the effect grammar and be
a `GET`; `require_live` is evaluated on `clock`; phase becomes `preflight`.

### `emit_final(state, spec, request, facts, clock) → (State, Option<AuthorizedEffect>)`

Requires phase `preflight` when the spec has a preflight (so the fact fetch
cannot be skipped) and `reserved` otherwise. **Computes the effect itself**
from `(spec, request, facts)`; a caller cannot supply a route. `final` may fail
with `resource_mismatch`. The effect must pass the grammar and its write-ness
must equal the ticket's. `require_live` is evaluated on `clock` -- this sample
is the linearization point of dispatch. Phase becomes `final`. `None` means the
request has no second effect and the validated facts are its answer.

### `settle(state) → State`

Clears the ticket. Its budget stays spent.

### `delegate(state, claims, binding, narrowing, grant_id, clock) → (State, Claims)`

`authenticate`, `require_live`; then fewer than 64 grants (`exhausted`), parent
depth below 4 (`denied`), a fresh well-formed `grant_id`; requested
`max_requests`/`max_body_bytes` no larger than the parent's (`denied`). The
child scope is built *from the parent's operations* with some parameters
replaced by requested subsets, then checked with `is_subset` (`denied`).
`expires_at`/`deadline` are the parent's, or earlier if a lifetime was
requested. The child has no budget of its own: admissions under it debit every
ancestor.

### `approve(state, digest, clock, ttl) → State`

Only in mode `approve` (`denied`). Drops expired approvals and any existing one
for the same digest, refuses a 17th (`exhausted`), records
`Approval(digest, clock.wall + ttl)` with `1 ≤ ttl ≤ 900`. **No guest frame
maps to this transition**: it is reachable only from the host control socket.

### `revoke(state, grant_id = "") → State`, `renounce(state, claims, binding) → State`

`revoke("")` deactivates the session; otherwise the named grant
(`invalid_request` if unknown). Descendants are revoked by `require_live`
walking the lineage, not by rewriting them. Idempotent; there is no inverse.
`renounce` is `authenticate` followed by `revoke` of the presented grant.

### `note_attempt(state) → State`, `describe(..) → view`

`note_attempt` charges one received frame against `max_attempts =
4·max_requests + 16` (`exhausted`, permanently). `describe` is read-only and
reports the tightest limits in the lineage and the leaf scope; nothing about
the destination, credential source or host.

## 5. Invariants of every reachable state

Checked after every step of every generated trace
(`tests/test_secrets_machine.py::invariants`):

```text
grants[0] is the root (parent = "", depth = 0);  grant ids are unique;  |grants| ≤ 64
serial = grants[0].used                          -- one ticket per admission, ever
∀ g:  0 ≤ g.used ≤ g.max_requests   ∧   g.issued_at < g.expires_at
∀ child c of p:  c.depth = p.depth + 1 ≤ 4
                 is_subset(c.scope, p.scope)
                 c.expires_at ≤ p.expires_at   ∧   c.deadline ≤ p.deadline
                 c.max_requests ≤ p.max_requests ∧ c.max_body_bytes ≤ p.max_body_bytes
∀ p:  Σ (used of p's children) ≤ p.used          -- no budget amplification
0 ≤ attempts ≤ max_attempts;   |approvals| ≤ 16
```

## 6. What the interpreter must do

The broker (`host/broker.py`) makes no authorization decision. For one request
frame it must perform exactly this sequence, and the audit lines must be
durable (`fsync`) before the step after them:

```text
note_attempt                          (unaudited when the cap is hit)
parse frame → open capability → parse request
admit                                 budget reserved
audit "authorized"
emit_preflight ──► execute            read-only facts, when the spec has them
audit "dispatch"                      only if a final effect will follow
emit_final ──► execute                fresh clock: the linearization point
audit "completed"
settle                                always, success or failure
```

It must sample a fresh `Clock` for each emission, hold the state lock only
across a transition (never across I/O, so `revoke`/`approve` are not delayed
by a slow provider), treat any audit failure as `revoke("")`, and report a
failure after a write was handed to the executor as `outcome_unknown` unless
the executor proved that nothing was sent (`unreachable`). No HTTP status is
proof that a sent write was not applied -- a service may act and then answer
409 or 422 -- so `upstream_rejected` is reported for reads only. "Write" here
is `AuthorizedEffect.write`, the declared class, not the method.

These obligations are tested (`tests/test_secrets_broker.py`) but are **not**
part of the pure kernel. They are the refinement gap the assurance plan calls
COMP-01, and they stay in the trusted base until an interpreter refinement is
proved.

## 7. Evidence, by theorem

"Vectors" are frozen traces any implementation can replay. "Mutants" are
single deleted checks that the named tests must detect
(`tests/test_secrets_mutation.py`); all are currently detected.

| Theorem | Kernel functions | Tests | Vectors | Mutants |
| --- | --- | --- | --- | --- |
| AUTH-01 | `admit`, `scope.check_arguments`, `Check.verify`, `Requirement.holds` | 2⁹-case oracle, generated traces, fact-mismatch tables for two manifests | 01–04, 13, 15–17 | 11 |
| EFFECT-01 | `emit_preflight`, `emit_final`, `Ticket` | ticket/phase tests, hostile-compiler tests, declared-write `GET` | 01, 04, 13–17 | 5 |
| COMP-01 | `Capture.extract`, `check_effect` | hostile bound facts, hostile-compiler tests | 17 | 2 |
| ROUTE-01 | `model.check_effect`, `HTTPOperation.effect`, `Effect.target` | grammar negatives, exhaustive manifest routing, real-TLS executor | 01, 10, 13, 17 | 7 |
| BIND-01 | `authenticate` | per-component binding tests, peer-UID socket test | 07 | 4 |
| TIME-01 | `require_live` | boundary tests, rollback tests | 06, 14 | 4 |
| REVOKE-01 | `revoke`, `require_live` | cascade tests, mid-flight revoke | 08, 11 | 4 |
| BUDGET-01 | `admit`, `note_attempt` | exhaustion, no-refund, concurrency | 05, 09, 13 | 4 |
| ATTEN-01 | `delegate`, `scope.narrow`, `scope.is_subset` | exhaustive `spec_subset`, brute-force scope oracle, invariants | 09–11 | 4 |
| APPROVAL-01 | `approve`, `admit` | one-shot, exact-bytes, expiry, grant-bound | 12 | 3 |
| CODEC-01 | `codec.loads`, `codec.dumps`, `grammar.*` | regex oracles, strictness negatives | `codec`, `grammar` | 2 |
| CONF-01 | (interpreter) | reflection tripwire, guest disk/env search in the e2e suite | — | 2 |
| AUDIT-01 | (interpreter, executor) | ordering test, fault injection, chain verification, apply-then-4xx provider | — | 7 |
| RESTART-01 | (envelope) | cross-session and post-crash replay, unit and e2e | `envelope` | — |

The generated-trace test (`tests/test_secrets_trace.py`) replays about 38,000
random steps against an independent reference model and checks the invariants
of section 5 after each one.

## 8. Porting notes

* **Errors.** `SecretsError(code)` becomes `Result<T, Denial>` with `Denial` a
  fieldless enum of the codes in `aivm_secrets/errors.py`. The "failure never
  changes state" rule is then free: transitions take `&State`.
* **Integers.** Clock values fit `u64`; counters and limits fit `u32`. The only
  additions are `wall + lifetime`, `mono + lifetime`, `wall + ttl` and
  `used + 1`, each bounded by the type's range given the stated input bounds.
  State the bounds as preconditions; do not rely on wrapping.
* **Strings.** Length limits are in UTF-8 bytes. Python's `str` can hold lone
  surrogates and Rust's cannot; the Python code rejects them at the boundary so
  that the two agree.
* **Collections.** Tuples kept sorted and unique map to `Vec` with those as
  invariants. Lookups are linear scans over at most 64 elements; keep them so,
  rather than introducing a map type with its own model.
* **External models.** `sha256` and IP-literal parsing should be the only
  modelled externals in the kernel. The JSON *decoder* is in the protocol
  crate's trusted base until a bounded parser is written and refined.
* **Vectors are the acceptance test.** The P1 exit criterion is that compiled
  Rust and the extracted Lean definitions produce the outcomes in
  `tests/secrets_vectors/v1` from the same files.

## 9. Known gaps in this specification

* The interpreter sequence of section 6 is specified in prose and tested, not
  modelled as a transition system with effects. A trace semantics that
  includes `AppendAudit` and `Execute` events is the next specification step.
* A manifest's declared `effect` is taken on trust (assumption SPEC-02). The
  kernel refuses arbitrary body-carrying methods declared `read`, while admitting
  single host-pinned GraphQL queries under the provider nonmutation assumption.
  It cannot prove that a `GET` or GraphQL resolver is read-only at the provider.
* Remote outcomes are conservative, not resolved: every failed write is
  `outcome_unknown`. Idempotency keys and provider-specific reconciliation,
  which could turn some of those into definite answers, are not implemented.
* Requirements are equalities on values reached through object keys. There
  is no array indexing, no ordering comparison and no disjunction; a fact
  that needs one cannot be stated, which is preferable to a predicate
  language with its own semantics to verify.
* Epochs are in-memory. A grant does not survive its broker, which is what
  makes restart safe, but it means there is no durable revocation record and no
  claim about host snapshot rollback.
* Approvals are host-memory state too: an approval is lost, not replayed, if
  the broker dies before it is used.

## 10. Parallel implementations and P4 identity (2026-10-12)

The Python program remains a maintained reference beside, not replaced by,
the planned safe-Rust implementation. Both implement an independent, versioned
contract and run the same frozen inputs. Parity in tests is evidence, not proof
of Python. The Lean proof obligations must remain attached to the extracted
Rust program, not a separately written Lean mirror.

The initial P4a identity decision is in `aivm_secrets/identity/model.py`, with
64 frozen cases under `tests/secrets_vectors/identity-v1.jsonl` and one
deterministic signed/encrypted byte-level fixture under `identity-crypto-v1.json`. Its pure inputs
are signed public claims, trusted issuer/audience/subject/epoch expectations,
an authenticated mTLS certificate thumbprint and a sampled wall-clock time.
It either accepts or returns one fixed denial. The actual signature, AEAD,
TLS chain validation and certificate identity provisioning are **trusted**
outside this pure decision and require separate Rust/test/refinement work.
See [the dual-backend decision](aivm-secrets-parallel-implementations.md)
and [the P4a protocol](aivm-secrets-garrett-identity.md).

## 11. Planned primitive-level specification and proof dependencies

The existing kernel specification remains the normative description of the
**current Python state machine**. An incremental refactor is proposed in
[the modular proof architecture](aivm-secrets-modular-proof-architecture.md);
its new `aivm_secrets.primitives` package is **not implemented yet**.

Porting should move one behavior at a time behind a compatibility facade,
not change `aivs1`, policy digests, error codes, or effect bytes. Candidate
subcontracts are explicit value bounds, time-window membership, epoch
advance/rejection, certificate/subject binding, semantic scope subset and
reservation accounting. For each, define the accepted input subset, all
error variants, overflow cases, and the exact function's role in the higher
state machine. The domain model must consume the checked result, not recompute
its own subtly different validation.

The `AuthorizedEffect` and `Ticket` constructors remain confined to
`kernel/machine.py` until a reviewed authorization transition relocates
them to an equally restricted Rust module. A primitive may establish a
semantic scope relation; it must **not** mint an execution permit or invoke
a provider adapter. Likewise, extracting a validity predicate cannot permit
calling the effect executor directly.

Extend the AST import and purity gates so `kernel -> primitives` is allowed
while `primitives -> kernel/identity/host/AIVM` is forbidden. Existing Python
`tests/test_secrets_purity.py` currently assumes all pure code lives in the
`kernel` directory; that enforcement must evolve *with* the refactor rather
than being disabled. Independent Rust modules will consume reviewed shared
vectors; proofs of their extracted functions become lemmas for later domain
and trace theorems only after their preconditions are discharged.
