# Garrett certificate lifecycle: Python reference P4c increment

**Status: experimental, opt-in, synthetic tests only (2026-10-12).** This
increment adds explicit client-certificate renewal with enrollment
compare-and-swap (CAS) and host TLS leaf renewal under the **existing CA**.
It does not claim non-exportable private keys, guest key rotation, CA rollover,
rollback-resistant authority, production VM validation, or formal proofs.

The motivation is operational: a Garrett-style certificate-bound surrogate
stops working when either the client certificate (seven days) or host TLS
certificate (30 days) expires. Separately, an unconditional enrollment
replacement can race another operator and revoke a newer certificate. This
increment makes those transitions explicit and testable without broadening a
VM's default permissions or exposing provider tokens to it.

## Boundary and behavior

The pure `aivm_secrets.identity.garrett.registry.renew` transition consumes
validated registry state, an expected epoch and certificate thumbprint, a new
thumbprint and expiration, and an explicit clock sample. It cannot create a
certificate, identify a VM, sign a token, write storage, or perform TLS. It
requires an active matching enrollment and atomically advances the epoch.
An old certificate or surrogate JWT becomes invalid at the *next* bridge
request after the persisted state update. This is an enrollment-epoch property,
not an in-flight operation cancellation guarantee.

The Python host authority adapter validates and signs the supplied CSR under
its existing CA, then commits the new registry under the host enrollment lock.
A fingerprint must still be confirmed by the trusted operator/bootstrap
path. Current managed-VM renewal retrieves the existing CSR via the pinned,
forced-bootstrap SSH key and derives the subject from the managed VM record,
principal and live libvirt UUID. It never accepts a guest-supplied subject,
identity epoch or trust root. The host snapshots the expected enrollment
**before** the authenticated CSR round trip. The final transition rejects
concurrent replacement rather than overwriting it.

The routine renewal path **reuses the existing software client key**, and the
host enforces it: `renew-client` reads the enrolled key from the stored leaf
certificate the registry names, checks it against the registry's
`key_sha256`, and refuses (`denied`) a CSR for any other key (REN-07, the
pure `garrett.key_rotation.authorize_key_reuse`). A missing or unparsable
stored leaf fails closed (`invalid_capability`, "use identity enroll
--replace"). A refusal writes no certificate, registry change or audit file.
Without this rule a renewal after a key rotation re-certified the
rotated-away key whenever the guest sent its stale `client.csr` (an old
helper, a reverted snapshot), leaving a certificate for the old key next to
the new `client.key`.

**Guests rotated before the CSR fix.** The original activation script left
the original key's CSR in `client.csr`. REN-07 refuses that stale CSR
(`denied`) instead of re-certifying the rotated-away key, and while that key
is retired for the subject `identity_enroll` (with or without `--replace`)
refuses it too. AIVM therefore regenerates `client.csr` from `client.key`
over the pinned principal channel before every non-rotating enrollment, and
the updated forced helper signs a fresh CSR with `client.key` on every
request, so managed renewals present the active key even on a guest whose
helper predates the fix. Only the standalone path (an operator-supplied CSR
for `identity enroll`/`renew-client`) still needs the manual step, run inside
the guest as the guest user:

```bash
cd ~/.config/aivm/identity && umask 077 &&
  openssl req -new -key client.key -out client.csr -subj /CN=aivm-guest
```

The custody rules refuse a stale CSR only while its key is still retired
*for that subject*; under a subject with no retired keys (a renamed VM, or a
row that was forgotten) nothing refuses it, which is why the regeneration
must precede every enrollment rather than rely on custody.

**A failed rotation activation** strands the guest the same way. The host
committed the new key K2 and retired K1 before the guest activates K2; on
failure AIVM's revoke-if-current compensation leaves the row inactive with
K1 retired, while the guest still holds K1 as `client.key` and `client.csr`.
Re-enrolling K1 is `denied`, renewal and rotation are refused because the
row is inactive, and regenerating the CSR from `client.key` would still
carry K1. The recovery is to reset the guest identity: remove `client.key`,
`client.csr`, `client.rotate.key` and `client.rotate.csr` from
`~/.config/aivm/identity` inside the guest, so the helper generates a fresh
key, then run `identity_enroll`. (The staged `client.rotate.csr` carries K2,
which is the row's current, unretired key; a later guest-helper increment
could re-enroll from it instead.)

### Key custody (REN-08)

Each registry row records `key_sha256`, the SHA-256 of the certified public
key (the lowercase hexadecimal `inspect-csr` prints), and `retired_keys`, the
fingerprints replaced for that subject by `rotate-client-key`,
`enroll --replace` or a re-enrollment with a different key (oldest first, at
most 8; the oldest is dropped). `enroll`, `enroll --replace`, `renew-client`
and `rotate-client-key` all refuse (`denied`) a key that is retired for the
subject, or that is the certified key of a *different active* subject, so a
cloned VM's copied key cannot gain a second subject. A revoked subject's key
may be enrolled for another subject: revocation does not retire a key. The
registry itself is rejected (`invalid_capability`) if two active rows carry
one key. The two custody refusals carry distinct operator details ("key is
retired for this subject", "key is certified for another active subject",
the latter naming no subject); the code, which is all a client or the corpus
sees, is `denied` for both. The bounded list is a deliberate limit: after
nine replacements the oldest retired key is forgotten and could be certified
again, and forgetting the row (REG-02) discards the whole list. Like the
other pre-deployment format changes, there is no migration: an experimental
`enrollments.json` written before these fields existed is refused
(`invalid_capability`), and a new authority must be initialized.

Retirement is per subject, and a managed subject hashes the store, the VM
name, the domain UUID, the principal, its host uid and guest user
(`aivm/secrets_identity_vm.py`). A rename, a move between store roots, a
principal change, or a clone made from a snapshot gives the VM a new subject
with no retired keys. Two consequences:

- If the old row is still active and holds the guest's current key, enrolling
  under the new subject is `denied` by the other-active-subject rule. That is
  the clone rule working as specified, since a rename is indistinguishable
  from a clone here. Until AIVM prompts to revoke on rename, the operator
  revokes the old row by hand: compute the key fingerprint in the guest
  (`openssl pkey -in client.key -pubout -outform DER | sha256sum`), find the
  row with that `key_sha256` in `identity status`, and run
  `identity revoke --subject` on it.
- A key retired only for the *old* subject is not refused under the new one
  (the corpus row `key_retired_for_other_subject_allowed` pins this). A VM
  that ran `identity_rotate_key` still sends its stale CSR for the original
  key K1; the old row holds K2, so K1 is neither retired for the new subject
  nor held by an active row, and is certified at once, before or after the
  old row is revoked. The same holds for a clone of a pre-rotation snapshot.
  This is a known gap against the goal of never certifying a rotated-away
  key: the operator must regenerate the CSR from `client.key` before such an
  enrollment, and a later increment should decide whether retirement must be
  checked across every row.

`identity enroll --replace` also takes an optional compare-and-swap,
`--expected-epoch N --expected-certificate-sha256 T` (both, and only with
`--replace`): the replacement commits only if the row is still at that epoch
and thumbprint, active or not, and is otherwise refused (`revoked`). Plain
`--replace` remains the unconditional emergency path. AIVM does not pass the
CAS yet.

### Revocation and registry reuse (REG-01, REG-02)

Revocation always deactivates. A row at the maximum epoch (2^31 - 1) cannot
advance, so it is deactivated without advancing; a later enrollment of it is
`exhausted`. The registry holds at most 128 rows, revoked ones included, so
two locked, audited operator verbs remove rows that can no longer matter:

```bash
root="$HOME/.config/aivm/secrets/identity"
python -I -m aivm_secrets identity forget --root "$root" --subject S
python -I -m aivm_secrets identity prune --root "$root"
```

`forget` removes one row and `prune` every row that is **inactive and whose
certificate `not_after` has passed**; anything else is refused (`denied`) or
skipped. Both print `{"forgotten": [{subject, epoch, certificate_sha256}]}`
and audit each removed row before committing (`prune` with nothing eligible
writes nothing). Public client certificates stay under `clients/`.

Forgetting restarts that subject at epoch 0 with no retired keys if it is
ever enrolled again. The epoch restart is harmless: the forgotten
certificate has expired and can never be presented again, and every bound
token was capped at that certificate's `not_after`, so no artifact carrying
the old epochs is still valid. Managed-VM subjects embed the libvirt domain
UUID, so a *recreated* VM is a new subject and never reuses a forgotten one.

The custody loss is **not** harmless in general. A VM that still exists
keeps its domain UUID, and therefore its subject, through revocation,
`rotate-ca`, operator `identity revoke` and install-failure compensation;
once such a row is inactive and its last certificate has expired, `prune`
removes it with its retired keys. Re-enrolling that VM then certifies
whatever key its CSR carries, including a key it rotated away from: with
the current guest helper's stale `client.csr` after a rotation
(above), AIVM approves that CSR's fingerprint automatically and the host
re-certifies the original key. Before re-enrolling a VM whose row was
forgotten, regenerate its CSR from `client.key` or reset its guest identity.
Keeping custody across `forget` (for example `prune` skipping rows with a
non-empty `retired_keys`, or a custody tombstone) would change the agreed
`forget`/`prune` semantics and is left as an open question.

An independently opt-in guest-key rotation command is now implemented as the
next increment: it stages a new guest-owned key, validates an authenticated
CSR against the old public key under the host CAS lock, and activates matching
public and private material. See
[a separate key-rotation plan](aivm-secrets-garrett-guest-key-rotation.md).
This is not vTPM non-exportability or full failure-atomic host/guest migration.

## Operator commands

On the trusted host, with a previously enrolled managed VM:

```bash
cd ~/code/aivm
aivm vm identity_renew --vm=lab \
  --identity_root="$HOME/.config/aivm/secrets/identity"
```

This is explicitly requested; ordinary `aivm ssh` and existing VMs remain
unchanged. The CLI fails if there is no active enrollment, a pinned bootstrap
channel is unavailable, or a concurrent enrollment has replaced the expected
certificate. It does not start, replace, or recreate the VM. The legacy
`identity_enroll --replace` emergency operation remains available; AIVM does
not yet pass the host's optional `--replace` compare-and-swap, so from AIVM it
is **not** CAS-constrained. Routine renewal should use `identity_renew`.

For a manually authenticated CSR (without AIVM's managed-VM association),
`python -I -m aivm_secrets identity renew-client` accepts `--subject`,
`--csr`, `--approve-key-fingerprint`, `--expected-epoch`, and
`--expected-certificate-sha256`. Obtain the epoch and current thumbprint from
an independently trusted `identity status` inspection and verify the CSR
fingerprint outside the guest's control. Supplying values copied solely from
an untrusted guest is not an enrollment approval.

The identity service never issues a new provider credential simply because a
certificate was renewed. A fresh *session* and surrogate JWT must be issued;
running sessions carrying the old epoch fail closed.

To renew the host TLS leaf and its private key, without replacing the CA:

```bash
python -I -m aivm_secrets identity renew-server \
  --root "$HOME/.config/aivm/secrets/identity"
```

Then **restart** the identity bridge/session. Existing TLS contexts keep the
old server certificate in memory. Newly started bridges select one immutable
`server-generations/server-N.{pem,key}` pair through an atomically written
`authority.json` (schema 2), which simultaneously selects the active CA and TLS server generation. Old server public certificates remain available;
there is no automatic deletion. If a crash leaves an unused generation, the
next renewal skips it and never overwrites its files. Missing/malformed
selection fails closed instead of selecting a different trusted pair.

## Proof and parity obligations

- **REN-01 (CAS safety):** renewal cannot overwrite a different epoch or
  thumbprint, including after concurrent replacement or revocation.
- **REN-02 (strict monotonicity):** successful renewal advances the epoch by
  one and makes the previous certificate thumbprint no longer acceptable.
- **REN-03 (no resurrection):** revoked enrollments cannot be renewed;
  initial enrollment remains a separately authorized operation.
- **REN-04 (expiry):** a new certificate's expiry must be strictly later than
  the supplied clock sample; the host CA must remain valid throughout the
  new leaf's lifetime.
- **REN-05 (selection atomicity):** a new TLS server keypair is written and
  durable before the single selection-file commit; failures before that
  commit do not alter the selected pair.
- **REN-06 (effect confinement):** only the host service signs CSRs and
  selects server material. No new guest-visible broker verbs or credentialed
  egress paths are introduced.
- **REN-07 (same-key renewal):** a renewal that is not a rotation certifies
  exactly the public key of the enrolled certificate; any other key is
  `denied`, and a missing or unreadable enrolled certificate fails closed.
  Pure rule `authorize_key_reuse`, pinned by the `reuse` rows of
  `identity-key-rotation-v1.jsonl`; the adapter obligation is that the
  enrolled fingerprint comes from the stored leaf and matches `key_sha256`.
- **REN-08 (key custody):** no transition certifies a key in that subject's
  `retired_keys` (the last 8 replaced, kept only while the row exists), or a
  key certified for a different active subject; no registry with one key on
  two active rows is accepted.
- **REG-01 (fail-safe revocation):** revocation, including revoke-all on CA
  rotation, always leaves the row inactive; the epoch advances unless it is
  at the maximum.
- **REG-02 (safe reuse):** only inactive rows whose certificate has expired
  are forgotten; every other row is preserved unchanged. Forgetting a row
  discards its epoch and its retired keys; only the epoch half is argued
  harmless (above).

`tests/secrets_vectors/identity-renewal-v1.jsonl` pins 48 positive and
negative pure state transitions, evaluated by the same versioned
`aivm_secrets.identity.registry_runner` protocol as earlier enrollment
vectors; the key custody, replace-CAS, fail-safe revocation, revoke-all,
forget and prune rows live in `identity-registry-v1.jsonl`. Registry rows
gained `key_sha256` and `retired_keys` in place (the corpora have not shipped
in a release); every earlier expectation is unchanged except `revoke_epoch_3`,
which now deactivates at the maximum epoch instead of failing. The future Rust backend must implement this contract independently
and pass the exact same corpus. Python tests also cover real certificate
signing, invalidation of old JWTs, on-disk selection recovery and pinned SSH
mock exchanges. These tests provide *evidence*, not Rust proof or Python
formal verification. TLS, RNG, X.509, authenticated CSR acquisition,
filesystem locking, and monotonic persistence remain explicit external
assumptions for future composed theorems.

## Outstanding Garrett work

CA rollover is now implemented as a fail-closed, single-active-root cutover
with mandatory re-enrollment and bridge restart (see
`aivm-secrets-garrett-ca-lifecycle.md`). Multi-root interoperability,
certificate provenance across distinct hosts, host/guest key renewal,
optional vTPM key custody, restoration/cloning semantics, rollback-resistant
state, distributed issuers, live VM/provider tests, and transparent
interoperability with arbitrary existing third-party CLIs remain separate
milestones. Do not promise statelessness: broker budgets, OAuth vault
refresh fencing and local revocation intentionally require state.

Reference: Matthew Garrett, [*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/), 2026-07-02.
