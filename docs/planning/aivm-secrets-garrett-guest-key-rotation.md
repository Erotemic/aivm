# Garrett P4c: opt-in managed-VM guest-key rotation (Python reference)

**Status:** implementation increment; synthetic and simulated-VM tests, no
live libvirt or GitHub credentials. The original static P-256 private key can
now be replaced deliberately without using `identity_enroll --replace` or
changing ordinary session defaults. This is **not** vTPM provisioning, remote
attestation, CA rollover, or rollback-resistant authority state.

## Invariant and minimal transition

`identity.garrett.key_rotation.authorize_key_rotation` is a pure, independent
contract. It receives the current and expected registry epochs/certificate
thumbprints plus SHA-256 fingerprints of the *verified* active certificate's
public key and the newly signed CSR's public key. Acceptance implies that the
CAS fields match, the public keys differ, and a next epoch is available. It
returns that next epoch but performs no I/O or cryptography. The host authority
performs this check under the existing enrollment registry lock, then uses the
existing `registry.renew` transition to commit the new certificate. Both
implementations must use the same frozen `identity-key-rotation-v1.jsonl`
corpus; the Rust runner has not been built and its test is skipped explicitly.
A separate `registry.revoke_if_current` contract guarantees a failed session
cleanup cannot revoke another operator's later enrollment; its
`identity-revoke-cas-v1.jsonl` corpus is also frozen for Rust parity.

This primitive cannot prove possession of the guest private key. The trusted
host accepts an authenticated forced-bootstrap reply containing a P-256 CSR
whose signature has been checked. The private key is generated under the guest
UID and never sent to the host. The host resolves the identity subject from
its machine store, owning principal and live libvirt UUID, *never the guest's
claimed subject*.

## Managed operator workflow

A host operator with an already-enrolled managed VM and an updated forced
bootstrap helper runs:

```bash
aivm vm identity_rotate_key --vm=lab \
  --identity_root="$HOME/.config/aivm/secrets/identity"
```

1. Read and pin current enrollment epoch and certificate thumbprint before
   SSH. Require an active enrollment.
2. Use the existing strictly pinned, forced SSH bootstrap path with a new
   **`identity-key-rotate-csr`** closed request and fresh response nonce. The
   helper creates `client.rotate.key` and `client.rotate.csr` under the
   non-root guest account. It refuses to overwrite a pending staged key.
3. Recheck VM incarnation/ownership. The isolated host authority validates
   CSR signature, checks key fingerprint against the active leaf's public
   key, and enforces the epoch/thumbprint CAS under its lock. A new cert
   advances epoch; old client certs and JWTs fail subsequent bridge checks.
4. Fetch only the public certificate and CA chain from the isolated service.
   The logged-in guest verifies the public-key match between the newly issued
   certificate and the pending new private key, plus inequality with the old
   key. It activates the new files without transferring private material to
   the host. The host does not forward the unbound broker socket.
5. If certificate delivery/activation fails, attempt epoch/thumbprint
   guarded revocation of the newly issued enrollment; **never** restore the old epoch or silently reuse old
   credentials. Report manual repair as needed.

### Failure and recovery

A failed pre-issuance bootstrap step can leave pending `.rotate.*` files.
The helper deliberately refuses to overwrite them. Inspect them through an
explicit trusted administrative process before cleanup and retry. A failure
*after* new-epoch issuance may require manual guest repair, and the host attempts a conditional revocation of exactly its new
enrollment if installation fails; it must not revoke a concurrent replacement.
If the guarded cleanup cannot be confirmed, manual reconciliation is required. A fresh operator-approved
enrollment is then required, and with key custody it cannot reuse the old
key: the host committed the new key K2 and retired the old key K1 before the
guest activated K2, so after the compensating revocation a re-enrollment of
K1 (the guest's `client.key` and `client.csr`) is `denied`, while renewal and
rotation are refused because the row is inactive. Reset the guest identity
(remove `client.key`, `client.csr`, `client.rotate.key` and
`client.rotate.csr` from `~/.config/aivm/identity` inside the guest), then
run `identity_enroll`, which generates a fresh key. Input for the
guest-helper increment: a re-enrollment after a failed activation could use
the staged `client.rotate.csr`, whose key K2 is the row's current, unretired
key. An in-flight request previously admitted by
the bridge is not canceled by epoch replacement; revoke/stop the original
broker too when immediate cancellation is required.

The shell performs a sequence of file renames; it cannot atomically swap a
multi-file key+certificate+CA bundle across a sudden guest power failure.
Such a partial installation must fail closed and may require operator repair.
Use a versioned, atomically selected guest identity bundle in a later
increment if power-loss recovery needs to be automatic. Do not claim
transactionality of the entire host/guest operation.

### Scope of security claim

A malicious guest process with access to the software private key can use any
legitimately granted identity capability while its certificate is active.
Software-key rotation does not prevent key copying, VM cloning, or replay of
host authority backups. A recovered clone with an obsolete certificate is
blocked only if the host registry has retained its newer epoch. Guest-bound
identity still requires explicit secrets-enabled sessions and the host's
operation-level authorization policy.

Key renewal under a still-trusted CA also does not solve CA expiry or CA key
compromise. The next Python milestones are deliberate CA rollover with a
bounded trust transition, and explicit host-state rollback detection. Only
after those should we evaluate vTPM-backed, non-exportable keys and live VM
attestation claims. The Rust primitive can be ported independently of libvirt,
SSH, TLS, cryptography and the filesystem adapters.

## Acceptance gates

- A same-key candidate must be refused even if it has a new certificate.
- A newer epoch or thumbprint cannot be overwritten by stale issuance.
- On activation failure the host attempts a CAS-guarded revocation of the
  enrollment it just issued, without invalidating a concurrent replacement.
- A copied key or misbound certificate is rejected at guest installation.
- The forced helper executes only fixed programs as the unprivileged guest.
- An existing VM does not gain secret access or trigger key rotation without
  an explicit operator command.
- `identity_renew` keeps reusing the existing key, and the host now enforces
  that (REN-07 in `aivm-secrets-garrett-certificate-lifecycle.md`): a renewal
  CSR for any other key is `denied`, and the rotated-away key is retired for
  the subject. The current helper leaves the original `client.csr` in place
  after a rotation, so renewing (or, once revoked, re-enrolling) a rotated
  guest is refused until `client.csr` is regenerated from `client.key`: by
  hand for now, by the helper in a later increment (see
  `aivm-secrets-garrett-certificate-lifecycle.md`). Rotating again instead
  is not a safe substitute: after nine rotations the original key ages out
  of the bounded retired list and the stale CSR would be certified again.
- No provider credential or private guest key appears in host command stdout.
