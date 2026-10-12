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
