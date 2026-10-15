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
   non-root guest account: both are written under per-request scratch names
   and the key is published with `ln`, which refuses an existing name, so
   of two concurrent requests only one stages a key. It refuses to
   overwrite a pending staged key.
3. Recheck VM incarnation/ownership. The isolated host authority validates
   CSR signature, checks key fingerprint against the active leaf's public
   key, and enforces the epoch/thumbprint CAS under its lock. A new cert
   advances epoch; old client certs and JWTs fail subsequent bridge checks.
4. Fetch only the public certificate and CA chain from the isolated service.
   The logged-in guest -- over principal SSH pinned to the VM's bootstrap
   `known_hosts` -- verifies the public-key match between the newly issued
   certificate and the pending new private key, plus inequality with the old
   key. It activates the new files without transferring private material to
   the host, and moves `client.rotate.csr` over `client.csr`, so the cached
   request always belongs to the active key. The host does not forward the
   unbound broker socket.
5. If certificate delivery/activation fails, attempt epoch/thumbprint
   guarded revocation of the newly issued enrollment; **never** restore the
   old epoch or silently reuse old credentials. If that revocation cannot
   complete, the error names the exact
   `python -I -m aivm_secrets identity revoke-if-current ...` command. If
   the user *declines* (or interrupts) a step after issuance, AIVM runs
   nothing more -- not even the revocation -- and logs that same command at
   WARNING before re-raising the refusal unchanged.

### Renewal after rotation

`identity_renew` (and `identity_enroll --replace`) must certify the key the
guest *uses*. Two guest-side mechanisms keep the CSR and the key together:

- The forced helper's `identity-csr` re-signs a fresh CSR with the installed
  `client.key` on every request instead of replaying `client.csr`, and
  replies with the CSR it just made.
- Guests keep the helper they were created with until an explicit upgrade,
  and the older helper does replay `client.csr`; every guest that rotated
  under the original activation script still holds the CSR of its *retired*
  key there. So before every non-rotating enrollment AIVM first runs a fixed
  step over the same pinned principal SSH channel that regenerates
  `client.csr` from `client.key` as the guest user (scratch name, then
  rename). With it, even an old helper presents the active key.

Independently, every install -- not only rotation -- compares the issued
certificate's SubjectPublicKeyInfo with the private key it will be used with
before moving anything into place. A certificate for any other key fails the
install, which triggers the guarded revocation above.

### Failure and recovery

A failed pre-issuance bootstrap step can leave pending `.rotate.*` files.
The helper deliberately refuses to overwrite them. Inspect them through an
explicit trusted administrative process before cleanup and retry. A failure
*after* new-epoch issuance may require manual guest repair, and the host
attempts a conditional revocation of exactly its new enrollment if
installation fails; it must not revoke a concurrent replacement. If the
guarded cleanup cannot be confirmed, the error names the exact guarded
revocation to run; a fresh operator-approved enrollment is then required.
With key custody that enrollment cannot reuse the old key: the host
committed the new key K2 and retired the old key K1 before the guest
activated K2, so after the compensating revocation a re-enrollment of K1
(the guest's `client.key`, from which `client.csr` is regenerated) is
`denied`, while renewal and rotation are refused because the row is
inactive. Reset the guest identity (remove `client.key`, `client.csr`,
`client.rotate.key` and `client.rotate.csr` from `~/.config/aivm/identity`
inside the guest), then run `identity_enroll`, which generates a fresh key.
A future recovery step could instead re-enroll the staged
`client.rotate.csr`, whose key K2 is the row's current, unretired key.

The issuance child itself can fail *after* committing: a timeout, a crash, a
failed audit record or directory sync after the registry write, or a
malformed reply. Its exit status does not tell those apart from a refusal,
so every failure of the issuing child (not of the CSR inspection before it,
which issues nothing) re-reads the registry. If the subject now holds an
active certificate it did not hold before the attempt -- compared by
certificate, not epoch, because a removed and re-created row restarts at
epoch 0 -- the operation fails with `outcome_unknown`, naming the subject,
that epoch, its certificate thumbprint and the guarded revocation command.
The detail says that the certificate is either this attempt's undelivered
issuance or another operator's concurrent enrollment (a competing renewal is
also what makes a renewal fail its compare-and-swap), and to check which
before revoking. AIVM never revokes it itself. An interrupt while the issuing
child runs reaches the child too; AIVM runs nothing further, logs at WARNING
the registry read and the guarded revocation (with the epoch and thumbprint
to fill in), and re-raises the interrupt.

Every `identity` argv AIVM builds or prints passes a thumbprint as one
`--expected-certificate-sha256=<thumbprint>` word: base64url thumbprints
begin with `-` about once in 64 certificates, which a separate argv word
would make the CLI parse as an option.

An in-flight request previously admitted by the bridge is not canceled by
epoch replacement; revoke/stop the original broker too when immediate
cancellation is required.

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
compromise; that is the separate, explicit, fail-closed `identity rotate-ca`
(see [the CA lifecycle](aivm-secrets-garrett-ca-lifecycle.md)), which has no
dual-root transition. Host-state rollback detection is still missing. Only
after it should we evaluate vTPM-backed, non-exportable keys and live VM
attestation claims. The Rust primitive can be ported independently of libvirt,
SSH, TLS, cryptography and the filesystem adapters.

## Acceptance gates

- A same-key candidate must be refused even if it has a new certificate.
- A newer epoch or thumbprint cannot be overwritten by stale issuance.
- On activation failure the host attempts a CAS-guarded revocation of the
  enrollment it just issued, without invalidating a concurrent replacement.
- A copied key or misbound certificate is rejected at guest installation;
  so is a renewed or replaced certificate for any key other than the
  installed `client.key` (checked before anything is moved into place).
- The forced helper executes only fixed programs as the unprivileged guest.
- An existing VM does not gain secret access or trigger key rotation without
  an explicit operator command.
- `identity_renew` reuses the guest's *active* key -- after a rotation, the
  rotated one -- even with an old forced helper, because AIVM first
  regenerates `client.csr` from `client.key` over the pinned principal
  channel. The host enforces it too (REN-07 in
  `aivm-secrets-garrett-certificate-lifecycle.md`): a renewal CSR for any
  other key is `denied`, and the rotated-away key is retired for the
  subject.
- A declined or interrupted step after issuance runs no further command and
  is re-raised unchanged; the manual guarded revocation is logged instead.
- No provider credential or private guest key appears in host command stdout.

Evidence: the real-shell trial
`test_enroll_rotate_renew_keeps_guest_key_csr_and_certificate_consistent`
runs enroll, rotate and renew through the real guest helper code, `openssl`,
the install scripts under `/bin/sh` and the isolated authority (only `ssh`
and `virsh` are faked). Before the renewal it puts back the `client.csr`
the original activation script left behind -- the retired key's request --
and then checks that `client.csr`, `client.key` and `client.pem` share one
public key that the registry thumbprint names. Its `legacy-helper` case
answers `identity-csr` by replaying `client.csr`, as old helpers do, so
there only the host-delivered CSR refresh can make the renewal certify the
active key; with that refresh made a no-op the case fails (checked by hand,
not by the automated mutation gate, which covers only `aivm_secrets`). The
new helper's own re-signing, from a stale cached CSR, is shown separately by
`test_helper_openssl_argv_yields_csrs_the_authority_accepts`. Neither is a
live-VM test.
