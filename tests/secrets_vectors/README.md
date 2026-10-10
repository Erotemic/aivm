# aivm-secrets conformance vectors

Protocol version 1, frozen. These files are the implementation-independent
statement of what the secret-use kernel accepts, refuses and emits. The Python
reference replays them in `tests/test_secrets_vectors.py`; the planned Rust
kernel and its Lean extraction must produce the same answers **from these
same files**, which is the P1 exit criterion in
`docs/planning/aivm-secrets-design.md`.

| File | What it fixes | Theorems |
| --- | --- | --- |
| `v1/codec.json` | strict JSON acceptance and the canonical encoding | CODEC-01 |
| `v1/grammar.json` | the closed alphabets of names, hosts, segments, credentials | CODEC-01, ROUTE-01 |
| `v1/policy.json` | policy acceptance, canonical form, digest and derived scope | PLUGIN-01, ROUTE-01 |
| `v1/traces/*.json` | kernel behaviour over scripted event sequences | AUTH, EFFECT, BIND, TIME, REVOKE, BUDGET, ATTEN, APPROVAL |
| `v1/envelope.json` | one sealed `aivs1` capability for interoperability | RESTART-01 (format only) |

## Reading a trace

A trace is a policy, a host write mode and a list of steps. Replaying it needs
no clock, network, randomness or credential: time is the `clock` of each step,
provider metadata is its `facts`, and grants are referred to by name
(`root`, or the `as` name of an earlier `delegate`). The step grammar is
documented in `aivm_secrets/kernel/trace.py`.

Each step has an `expect`. An implementation conforms when its outcome
*includes* the expectation: every key present in `expect` is present in the
outcome with an equal value, recursively for objects. `code` is `ok` or one of
the fixed denial codes of `aivm_secrets/errors.py`. For a request, `preflight`
and `effect` are the provider requests the kernel authorized, exactly as the
executor would send them (`method`, `target`, `accept`, `response`, `body`).

## What was specified by hand, and what is a pin

Acceptance (`valid`, `accept`/`reject`), canonical encodings, every `expect`
code and every expected effect were written by hand as the specification.
`sha256` fields, the `canonical`/`scope` renderings of valid policies and the
envelope ciphertext were produced by the reference implementation and are
regression pins: they make drift visible, they do not independently justify
themselves.

A passing vector run is evidence of conformance on these inputs. It is not a
proof, and adding vectors must never be described as one.

## Changing them

Version 1 files change only to add cases. A change to an existing expectation
is a protocol change: it needs a new version directory, an entry in the
changelog, and a review of the affected theorem in
`docs/planning/aivm-secrets-formal-assurance.md`.
