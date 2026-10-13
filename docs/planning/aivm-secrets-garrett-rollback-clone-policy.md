# Garrett identity: rollback and clone policy

**Status (2026-10-13): design only. No rollback or clone detection is
implemented.** This document settles, before any rollback- or
clone-resistance claim is made, which identity state a restore, revert, clone
or disk copy can roll back, what must happen in each case, and which anchors
could detect it. Every statement about current behavior was checked against
the code at this writing. Items are marked **implemented** (true of the code
now), **decided** (policy settled, implementation pending) or **option**
(considered, not scheduled). The open obligations are ROLLBACK-01 and
CLONE-01 in [the assumption ledger](aivm-secrets-assumptions.json).

## The plain limit

**No software witness on a host detects a restore of that whole host.** If a
restore covers the authority directory, the OAuth vault and any anchor file
beside them, everything the software can read agrees with the past.
Detecting such a restore needs state that the restore does not cover: a
counter in the host's hardware TPM, or a remote witness. Until one exists and
is configured, "the host is not restored from an older copy" is an
assumption (ROLLBACK-01), not a property.

## Where identity state lives

| State | Location | Written by |
| --- | --- | --- |
| Trust selection, CA, server and issuer key generations, keyring | `<root>/authority.json`, `ca-generations/`, `server-generations/`, `issuer-keys/`, `issuer-keyring.json`; the default root is `~/.config/aivm/secrets/identity` (mode 0700) | `aivm_secrets` host verbs |
| Enrollment registry: subject to epoch, active, certificate thumbprint, `not_after` | `<root>/enrollments.json` | `aivm_secrets` host verbs |
| Issued client certificates | `<root>/clients/<sha256>.pem` | `aivm_secrets` host verbs |
| OAuth vault | the operator-chosen vault directory | `aivm_secrets` OAuth verbs |
| Guest key, CSR, certificate and CA | `~/.config/aivm/identity/` in the guest user's home (`client.key`, `client.csr`, `client.pem`, `ca.pem`, and `client.rotate.*` during a rotation) | `aivm-guestctl` and AIVM's install script, as the guest user |
| Managed subject inputs | AIVM machine store (VM and principal records) and the live libvirt domain UUID | AIVM, libvirt |
| vTPM state | none: AIVM creates VMs with `virt-install --tpm none` | -- |

Facts the cases below depend on (all **implemented**):

- The managed subject is SHA-256 over the machine-store path's digest, the VM
  name, the live libvirt domain UUID, the principal id, the host UID and the
  guest user (`aivm/secrets_identity_vm.py`). Principal ids are deterministic
  (`stable_principal_id(vm_name, host_user)` in `aivm/scoped_store.py`), and
  the store digest hashes the path's spelling. **The domain UUID is
  therefore the only per-incarnation input.** A domain redefined with an
  earlier incarnation's UUID, name and owner gets that incarnation's subject.
  A domain with a new UUID (`virt-clone`, or re-creation with `virt-install`)
  gets a new subject. Moving the machine store changes every subject.
- The bridge re-reads the registry on every request. It admits only a
  certificate whose thumbprint matches an active row with `now < not_after`
  (`garrett/registry.py: expectation`). A rolled-back *guest* therefore
  fails closed against a current registry. A rolled-back *registry* is
  believed.
- Client certificates last seven days (`CLIENT_DAYS`). A restored registry
  re-admits an already-issued certificate only until its `not_after`, so a
  copy older than seven days re-admits none of the certificates it lists.
  **That bound covers issued certificates, not restored rows.**
  `renew-client` checks a row's active flag, epoch and thumbprint, never its
  `not_after`, so every row the copy holds as active is renewable, whatever
  the copy's age, and each renewal keeps it renewable. A VM
  whose enrollment was revoked after the copy was taken gets a fresh
  certificate at its next renewal. The decided bulk renewal
  (`identity_renew --all` in the
  [operations policy](aivm-secrets-garrett-operations-policy.md)) counts an
  expired active row as due, so it would renew that VM without being asked
  to. A restore can also re-enable a retired issuer key, re-select a
  superseded CA whose private key is still on disk, or restore a locally
  revoked OAuth grant.
- A bound JWT lives at most one hour (`MAX_IDENTITY_LIFETIME`) and is capped
  at the certificate's `not_after`. It wraps an `aivs1` capability that only
  the broker process that minted it can open, because that broker's session
  key exists only in its memory. Restoring a snapshot that contains a JWT
  file cannot revive a session whose broker has exited.
- Nothing deletes private keys. `retire-issuer` only removes the kid from
  the keyring, and superseded CA and server generations stay on disk.
  **Decided:** they are destroyed only by an explicit, locked, audited
  `identity prune-keys --superseded`, which does not exist yet.
- After a whole-directory restore, generation numbers and issuer kid names
  can be reused, because the files of later generations are gone and the
  next free number is taken again. Trust is decided by the CA fingerprint
  and the issuer key, not by the number. A token or certificate from the lost
  generation does not verify against the new one.

## Outcomes

- **Fail closed:** refuse to open the affected state. No enrollment,
  issuance, bridge admission or OAuth lease happens until an explicit,
  audited operator recovery.
- **Re-enroll:** the VM gets a new certificate, through an authenticated CSR,
  for a fresh key, under a strictly greater epoch or as a new subject. When
  the same row is re-enrolled, the key it replaces is retired for that row,
  within the limits of the host key custody rule below. Today a guest gets a
  fresh key in only two ways:
  - `aivm vm identity_rotate_key`, which needs an active enrollment;
  - removing the guest's `~/.config/aivm/identity/` directory, as the guest
    user, before `aivm vm identity_enroll`. The guest helper then generates
    a new key.

  Otherwise `identity_enroll` (with or without `--replace`) and
  `identity_renew` re-present the guest's existing `client.csr` unchanged.
  The guest helper never overwrites a key, and it generates a CSR only
  together with a new key. A key rotation replaces `client.key` but never
  `client.csr`. So after any `identity_rotate_key`, `client.csr` is still the
  CSR of the rotated-away key, and every later renewal or enrollment
  presents that key, not the current `client.key` (**implemented**, a
  defect; see case 3).
- **Advance the epoch:** the registry moves the subject's epoch strictly
  forward. Every certificate and JWT issued before then fails at its next
  presentation.

## Host key custody rule

**Decided** (implementation pending). This is the one definition that cases
3, 5, 6 and 7, CLONE-01, the [vTPM policy](aivm-secrets-garrett-vtpm-policy.md)
and the [issuer API policy](aivm-secrets-garrett-issuer-api.md) rely on.

- **What a row records.** Each registry row records `key_sha256`, the
  fingerprint of the key its current certificate certifies (lowercase hex
  SHA-256, the form `inspect-csr` prints), and `retired_keys`, the
  fingerprints retired for that row. The list holds at most eight entries,
  and the oldest is dropped first. The bound keeps every row within the
  registry's size limit (`MAX_REGISTRY_BYTES`, 128 KiB for at most 128
  rows).
- **What retires a key.** A key is retired for a subject when a later
  `enroll`, `enroll --replace` or `rotate-client-key` puts a different key
  into that subject's row. Nothing else retires a key: not `revoke`,
  `revoke-if-current`, `rotate-ca` (which revokes every row), expiry, or a
  renewal.
- **What is refused.** `enroll` (with or without `--replace`),
  `renew-client` and `rotate-client-key` refuse with `denied`, before
  anything is written (no certificate file, audit record or registry
  change):
  - a key in the subject's own `retired_keys`;
  - a key that is the `key_sha256` of a different **active** subject;
  - for `renew-client`, any key other than the row's own `key_sha256`. A
    renewal keeps the key; changing it is `rotate-client-key`.
- **The guarantee, with its bound.** No key is certified under two active
  subjects at once, a renewal certifies only the enrolled key, and while a
  row exists it never certifies again any of its last eight retired keys.

What the rule does not do:

- **Retirement is per row.** A key retired under one subject is not refused
  under a different one. A managed VM gets a new subject when it is renamed,
  moved to another store root, given to a different principal, or cloned.
  A key rotated away under its old subject can then be certified under the
  new one, for example from a stale `client.csr`. This is open.
- **It forgets.** A key retired more than eight replacements earlier is no
  longer refused. `identity forget` and `identity prune` delete an inactive,
  expired row together with its `retired_keys`. A VM that still exists keeps
  its subject, so after its row is forgotten a rotated-away key can be
  certified for it again. Whether forgetting should keep custody (for
  example, prune skipping rows that hold retired keys, or a bounded custody
  tombstone) awaits a user decision.
- **Revocation keeps the key enrollable.** A revoked VM can re-enroll with
  the key it holds. That is deliberate: `rotate-ca` revokes every row, and
  re-enrolling after it must not require a guest key change. Where the
  required outcome below is a fresh key, the guest has to produce one.
- **It refuses enrollments, not use.** A copied disk or vTPM holds the same
  key. The rule refuses certifying that key a second time. It does not stop
  the copy from presenting a certificate it already holds.

**A fresh key for an inactive or absent row** (**decided**). `aivm vm
identity_enroll` gains an explicit option (name proposed: `--new_key`). It
makes the guest helper stage a new key, as the key-rotation operation does,
and activates that key only after the installed certificate is checked
against it. It needs no active row. Until it exists, remove the guest's
`~/.config/aivm/identity/` directory, as the guest user, before running
`identity_enroll`.

## Threat cases

### 1. Partial restore of the authority directory or the OAuth vault

An operator restores `<root>` (or only `enrollments.json`, or the vault) from
an older copy, and nothing else on the host changes.

- *Today:* not detected. Rows revoked or replaced after the copy was taken
  become active again. Their old certificates are admitted until they
  expire, and the rows stay renewable after that, indefinitely (see the
  facts above). A restored keyring re-enables retired issuer kids. A
  restored manifest re-selects the CA it named. A restored vault reverses
  local OAuth revocation and refresh.
- *Required outcome:* **fail closed** on open, until an explicit operator
  recovery that advances every epoch beyond any value issued before the
  restore.
- *Detected by:* anchors A, C or D below, provided the restore did not also
  cover the anchor.

### 2. Whole-host restore

The host disk (or the host VM, if the host is itself virtual) is restored
from an image, including any anchor kept on it.

- *Today:* not detected.
- *Required outcome:* **fail closed** as in case 1, when a hardware counter
  (C) or a remote witness (D) is configured. Without one, this case is
  outside the guarantee and is stated as the ROLLBACK-01 assumption. No
  software witness can detect it.

### 3. Internal guest snapshot revert

`virsh snapshot-revert` to a qcow2 internal snapshot restores the guest's
disk, and its memory if the snapshot included it. The domain UUID, and hence
the subject, does not change. The host registry does not move.

- *Today:* partly handled. A reverted guest that holds an older certificate
  presents a thumbprint the registry no longer lists, so the bridge refuses
  it (**implemented**, inherent in the per-request check). Re-certifying a
  rotated-away key, however, needs no revert. **Every renewal after a key
  rotation certifies the rotated-away key** (**implemented**, a defect):
  - the rotation's install script replaces `client.key` and deletes the
    staged `client.rotate.*` files, but leaves `client.csr`, the CSR of the
    old key, in place (`aivm/secrets_identity_transport.py`);
  - `identity-csr` returns the existing `client.csr` unchanged when
    `client.key` and `client.csr` both exist (`aivm/rc/guest/guestctl.py`);
  - `renew-client` compares the CSR's key with the enrolled key only for a
    key rotation, so a plain renewal certifies whatever key the CSR carries
    (`aivm_secrets/identity/enrollment.py`);
  - the non-rotation install script moves the new certificate into place
    without comparing its key with `client.key`.

  The next `aivm vm identity_renew`, or `identity_enroll --replace`, after an
  `identity_rotate_key` therefore issues a certificate at a new epoch for the
  rotated-away key, and installs it next to a `client.key` it does not
  match, which also breaks the guest's own mTLS. A guest reverted to a
  snapshot from before the rotation holds the old key in both files and has
  it re-certified too.

  **Workaround until the fixes below land:** before renewing a VM that was
  ever rotated, regenerate its CSR from the current key inside the guest, as
  the guest user: `openssl req -new -key ~/.config/aivm/identity/client.key
  -subj /CN=aivm-guest -out ~/.config/aivm/identity/client.csr`.
  Alternatively, renew such a VM with `identity_rotate_key`, which certifies
  a fresh key each time.
- *Required outcome:* the host registry stays authoritative and stale
  presentations fail closed. **Decided:**
  - on the host, the host key custody rule above: a renewal certifies only
    the enrolled key, and a key among the row's last eight retired ones is
    refused;
  - in the guest, the helper regenerates `client.csr` from the current
    `client.key` before every non-rotation CSR, a rotation moves
    `client.rotate.csr` into place as `client.csr`, and both install scripts
    refuse a certificate whose key is not `client.key`.

  Recovery then depends on the reverted key:
  - If it is still the enrolled key, `aivm vm identity_renew` installs a
    current certificate for it. Until the guest fix lands, apply the
    workaround above first on a VM that was ever rotated.
  - Otherwise the VM must **re-enroll** with a fresh key, which **advances the
    epoch**. While the row is still active, that means
    `aivm vm identity_rotate_key`. It stages a new key in the guest and runs
    under the host's current CAS values. It refuses while staged
    `client.rotate.*` files exist, which a revert can bring back; remove
    them first.
- *Not detected, and not an identity problem:* a revert to a snapshot whose
  identity files equal the current enrollment. The same key and certificate
  are the same identity. Whatever else the revert undid is not identity state.

### 4. External guest snapshot revert

The disk returns to an earlier overlay or backing file. The identity
outcome is the same as case 3. In addition, every overlay and backing file is
a host-side copy of the guest key, so it is also case 6 for anyone who can
read those files.

### 5. virt-clone

The clone gets a new UUID, and therefore a new subject. It also gets copies
of the disk (the guest key and certificate, and the guest SSH host key) and
of the domain XML, including AIVM's `<metadata>` ownership stamp.

- *Today:* the clone is not enrolled. `issue` requires an active row for its
  own subject, so AIVM cannot start a bound session for it. The original's
  bridge socket is forwarded only into the original's SSH session. If the
  clone is enrolled, `identity-csr` re-presents the copied key, and the host
  certifies one key under two subjects.
- *Required outcome:* the clone is a new identity. It must **re-enroll** with
  a fresh key. **Decided:** the host key custody rule refuses a key that is
  the certified key of another active subject, so the copied key is refused
  while the original is enrolled. Once the original's row is revoked, the
  rule no longer refuses it (revocation retires nothing, and retirement is
  per row), so the fresh key must still come from the guest: the decided
  `identity_enroll --new_key`, or today deleting the clone's copied
  `~/.config/aivm/identity/` directory before its first enrollment. Under
  the vTPM policy, a clone gets fresh TPM state.

### 6. Copied qcow2 with a redefined domain

A disk is copied by hand and defined as a domain.

- *New UUID:* same as case 5.
- *Reused UUID, name and owner* (the original was undefined first): this is
  the original's subject by construction, holding the original's key and
  certificate. Nothing can tell the two apart; that is what the UUID input
  means. **Decided:** deleting, renaming or removing access to a VM prompts
  to revoke its enrollment (a guarded `revoke-if-current`; declining aborts
  the operation, and `--keep_identity` skips the step). After a revoke, the
  copy has no active enrollment and must **re-enroll**, which **advances the
  epoch**. Revocation does not retire the copied key, so a plain
  `identity_enroll` would certify that same key again. A fresh key needs
  the decided `identity_enroll --new_key`, or today removing the copy's
  `~/.config/aivm/identity/` directory first. Today AIVM's delete leaves the
  row active. Its certificate stops being admitted when it expires, but the
  row stays renewable, so a later `identity_renew` of the copy, which has
  the same subject, renews it.
- *Another host:* that host's authority has its own CA. A certificate issued
  by this host's CA is not trusted there. Copying the authority directory
  along with the disk is a fork, which the
  [operations policy](aivm-secrets-garrett-operations-policy.md) treats as out
  of scope.

### 7. Copied vTPM state

Not applicable today: no VM has a TPM. If vTPM keys are introduced, copying
the swtpm state copies the TPM-resident key, so two TPMs then hold one key.
TPM2_Certify evidence verifies equally for both copies, and pinning the EK
does not separate them, because a byte copy has the same EK.

- *Required outcome:* AIVM never copies swtpm state, and creates clones with
  reset state and a new subject. The host key custody rule (no key certified
  under two active subjects) refuses the second enrollment while the first
  is active. Nothing prevents the copy from *using* the key if it can reach
  a bridge that admits it. See
  [the vTPM policy](aivm-secrets-garrett-vtpm-policy.md).

### Summary

| Case | Detected today | Required outcome |
| --- | --- | --- |
| 1. Partial authority or vault restore | no; restored rows stay renewable | fail closed; recovery advances every epoch |
| 2. Whole-host restore | no; no software witness can | fail closed with a hardware or remote anchor; otherwise an assumption |
| 3. Internal snapshot revert | stale certificate refused; any renewal after a key rotation re-certifies the rotated-away key, revert or not (defect) | custody rule and guest CSR fix (decided); renew if the key is current, otherwise re-enroll with a fresh key |
| 4. External snapshot revert | as 3 | as 3, and the overlays count as copies |
| 5. virt-clone | new subject, not enrolled; copied key accepted on enrollment | re-enroll with a fresh key; refuse a key active under another subject (decided) |
| 6. Copied disk, redefined domain | new UUID as 5; reused UUID is the same identity, and its row stays renewable | as 5; revoke on delete (decided), then re-enroll with a fresh key |
| 7. Copied vTPM state | n/a (no vTPM) | never copy; reset on clone; no key certified under two active subjects |

## Anchor options

Every anchor below that guards host state (A, C, D) needs the same commit
discipline (**option**). Each durable state file (`authority.json`,
`enrollments.json`, the issuer keyring, each vault record) carries a
sequence number that counts its committed transactions. A transaction runs
these steps in this order, and only this order:

1. append a durable journal record holding the new sequence number and the
   digest of the new state;
2. make the pointer commit (the atomic replacement of the state file);
3. advance the anchor to the new sequence number and digest;
4. report success.

A crash can therefore leave only two non-final states, and open handles
each in exactly one way:

- *The state equals the anchor, and the journal ends in one record beyond
  them.* That transaction never committed and never reported success. Open
  discards the record.
- *The state is exactly one step ahead of the anchor, and the journal's last
  record holds that state's sequence number and digest.* The pointer
  committed, but the anchor did not advance. Open completes the transaction
  by advancing the anchor.

Everything else fails closed, as a rollback or a fork: a state behind the
anchor by any amount, a state at the anchor's sequence number with a
different digest, a state more than one step ahead, and a state one step
ahead without a matching journal record. Because the anchor advances only
after the pointer commit, no crash leaves the state behind the anchor. A
state behind the anchor is always a restore, even one transaction old, and
is never completed or accepted. (An anchor restored to an older value makes
a current state look ahead of it. One step is completed as above. More fails
closed, which is safe but needs the recovery verb.) The pure part of this
(append and check over explicit values) belongs in a new `identity/garrett/`
model under the kernel purity rules, with a frozen JSONL corpus. The anchor
I/O stays in the host adapter.

Recovery is one explicit, audited, operator-only verb (**decided** in
principle; the name `identity accept-restore` is a proposal). For the
registry, it computes `N = max(A, e_max) + 2`, where `A` is the sequence
number the anchor recorded and `e_max` is the highest epoch in the restored
rows. It sets every row inactive at epoch `min(MAX_EPOCH, N)`, and commits
that state with sequence number `N`. No anchor records epochs, and none
needs to:

- a new row starts at epoch 0, and one committed transaction advances any
  row's epoch by at most one (`rotate-ca` advances every row by one in a
  single transaction). So every row's epoch is at most the sequence number
  of the state that holds it, provided the first sequence number is at least
  every epoch already present when the journal is introduced;
- a committed state is at most one step ahead of the anchor, so every epoch
  ever committed is at most `A + 1`, below `N`;
- `e_max` covers a divergent copy whose rows claim more than the anchor.

The verb then rotates the issuer, retires every other kid, and re-anchors at
`N`. Every VM re-enrolls afterwards. For the vault, every grant becomes
reauthorization-required. Restoring an older registry is never a repair.

### A. Software anchor directory outside the authority

The journal head (sequence and digest) is mirrored into an operator-chosen
directory outside `<root>`, recorded in the manifest at `init`. An HMAC keyed
beside the anchor is an optional addition.

- *Detects:* case 1, when the anchor was not restored with the authority.
- *Trust assumptions:* the anchor directory is principal-private and not
  guest-writable (the same `--untrusted-root` rules apply). It is not backed
  up and restored together with `<root>`. Same-UID processes and host
  administrators can rewrite it.
- *Does not detect:* case 2, or a coordinated restore of both directories.
- *Side:* `aivm_secrets`. **Option**, the cheapest useful one.

### B. libvirt domain-metadata incarnation witness

At enrollment, renewal and rotation, AIVM stamps an AIVM `<metadata>` element
on the domain (live and persistent config), as `aivm/domain_authority.py`
already does for store ownership. The stamp holds an incarnation counter, the
domain UUID it was written for, a subject digest and the enrolled thumbprint.
The same values go into the principal-private enrollment record (decided
location: the VM profile's state directory, never the shared machine store).
Before renewal or a bound session, AIVM compares the live stamp with the
record. A lower counter means a revert. A stamp naming a different UUID than
the live one means a copied definition (a clone).

- *Detects:* cases 3 and 5, and case 6 when the domain XML was copied, but
  only if a revert actually restores `<metadata>`. Snapshot XML embeds the
  domain definition, so an internal-snapshot revert is expected to restore
  it. Whether each libvirt version does so for internal and external
  reverts is **unverified**: no libvirt is available where this was written.
- *Trust assumptions:* whoever can redefine the domain can forge the stamp.
  That is libvirt access, which is root-equivalent. This is a guard against
  accidents and unintended reverts, not a security boundary. A rollback done
  inside the guest (file restore, filesystem snapshot) changes no metadata.
  That case is covered by the registry check instead.
- *Side:* AIVM. The verdict reaches `aivm_secrets` only as AIVM refusing to
  call `renew-client` or `issue`. `aivm_secrets` is never told "this is not
  a clone" as authorization.
- *Status:* **option, not scheduled for this release.**

### C. TPM2 NV counter on the host TPM

A monotonic NV counter index (`TPMA_NV_COUNTER`) in the host's hardware TPM
holds the journal sequence. `aivm_secrets` drives it as a child process of
`tpm2-tools` (`tpm2_nvread`, `tpm2_nvincrement`). The child uses fixed
arguments, a program verified with `verify_program`, and a scrubbed
environment. The pure check receives the counter value as an argument.

- *Detects:* cases 1 and 2. A disk restore does not touch the TPM, and the
  counter cannot be decremented. The TPM 2.0 specification initializes a
  newly defined counter to at least the largest value any counter on that
  TPM has held, so deleting and redefining the index does not move it
  backwards. Confirm this on the target TPM before relying on it.
- *Trust assumptions:* the TPM is genuine hardware, not a vTPM on the same
  host. The principal can open `/dev/tpmrm0`, which is a host configuration
  change, and the TPM is shared by every principal. NV space is small: one
  index per authority. Host root can still edit the authority and accept the
  regression; root is trusted, and acceptance goes through the explicit
  recovery verb. Moving an authority to another host reads as a rollback.
- *Side:* `aivm_secrets`, because it protects `aivm_secrets` state. AIVM is
  not involved.
- *Status:* **option**. It needs hardware that is not available here.

### D. Remote witness

An external service stores `(authority id, sequence, head digest)`. It
accepts only compare-and-swap updates authenticated by a key the authority
holds.

- *Detects:* cases 1 and 2, as long as the witness itself is not rolled back.
- *Trust assumptions:* the witness operator and its durability, the network
  path and its authentication, and custody of the update key. Availability is
  part of safety: an open that cannot reach the witness must fail closed,
  because a cached "last seen" value cannot detect a restore that happened
  before it was cached. The witness learns operation counts and timing.
- *Side:* `aivm_secrets`. **Option.** This is also the starting point for the
  cross-host fork detection that the
  [operations policy](aivm-secrets-garrett-operations-policy.md) defers.

## Division of responsibility across the process boundary

AIVM talks to `aivm_secrets` only through `python -I -m aivm_secrets identity
...` children and imports only `aivm_secrets.errors`. This policy keeps that
boundary:

- **`aivm_secrets`** owns its own freshness: registry epochs, key-fingerprint
  custody, the journal, anchors A, C and D, and the recovery verb. It never
  reads libvirt or the machine store, and accepts no "fresh" or "not a
  clone" assertion from its caller.
- **AIVM** owns the VM facts: the domain UUID, anchor B, the machine store,
  principal state, and the decided per-VM enrollment record. It passes only
  values to `aivm_secrets` verbs: the subject, and the expected epoch and
  thumbprint as CAS arguments. It acts on its own findings by refusing to
  proceed, never by asking `aivm_secrets` to trust it.
- Neither layer can see the other's rollback. A VM witness cannot detect a
  restored authority, and an authority anchor cannot detect a reverted
  guest. Each detects its own.

## What to do today

No detection exists, so a known restore must be handled by hand, **whatever
the age of the copy**: rows the copy holds as active stay renewable after
their certificates expire. If `<root>`, the vault or the host was restored,
treat every piece of trust state as possibly stale, and run no
`identity_renew` until these steps are done:

1. `identity rotate-ca --expected-ca-sha256 <sha256 from identity status>`.
   This ends every enrollment by changing the trust root. Old certificates
   no longer chain to a trusted CA, whatever epochs the restored registry
   holds. It revokes every row (each epoch advances by one, saturating)
   rather than emptying the registry, and the required CAS refuses a stale
   second run.
2. Replace the issuer keys, in this order. The `active` kid and the
   `enabled` list are in `<root>/issuer-keyring.json`.
   1. `identity retire-issuer --key-id K` for every enabled kid except the
      active one. This comes first because `rotate-issuer` refuses with
      `exhausted` while eight kids are enabled, which a restored keyring can
      be, and `retire-issuer` refuses the active kid.
   2. `identity rotate-issuer`. It names the new kid
      `local-<next_number>`, taken from the keyring, and never overwrites a
      key file. A restore that brought back an older keyring but left later
      `issuer-keys/` files in place (the keyring restored alone, or an
      overlay restore such as `rsync` without `--delete`) leaves that name
      taken. `rotate-issuer` then fails with `unsafe_file` ("Host file
      ownership, permissions, or type is unsafe") and changes nothing except
      leaving an intent record in the audit directory. In that case, move
      every `issuer-keys/local-N.*` file whose N is at least the keyring's
      `next_number` out of `<root>`, into a private directory that is not
      guest-writable, and run `rotate-issuer` again. Those kids were created
      after the copy, and the restored keyring does not list them. (A
      planned change makes `rotate-issuer` skip names whose files exist,
      which removes this step.)
   3. `identity retire-issuer --key-id K` for the kid that was active before
      step 2.
3. `identity oauth-revoke` for every vault subject, then revoke the grant at
   the provider and log in again.
4. Re-enroll each VM with a fresh key. For each VM, first remove
   `~/.config/aivm/identity/` inside the guest, as the guest user, then run
   `aivm vm identity_enroll`. The guest helper then generates a new key.
   Without the removal, `identity_enroll` re-certifies the key the guest
   already holds, and on a VM that was ever rotated it presents the stale
   `client.csr` of a rotated-away key (case 3). The decided
   `identity_enroll --new_key` will replace the manual removal.

Never copy an older registry back over a newer one to repair a failure.

## Obligations

- **ROLLBACK-01 (open).** Every opened authority and vault state is at least
  as new as the last state the configured anchor recorded. A regression or
  divergence fails closed with no effect, until an audited recovery that
  advances every epoch past any value previously issued. A software anchor
  discharges this only for partial restores. Whole-host restores need anchor C
  or D. Evidence needed: the pure journal model with a frozen corpus and
  mutants, covering both crash points and a restore one transaction old,
  plus a restore test against a real directory copy.
- **CLONE-01 (open).** No key is certified under two active subjects at
  once, a renewal certifies only the subject's enrolled key, and while a row
  exists it never certifies again any of the last eight keys retired for it.
  A VM whose incarnation does not match its enrollment (clone, revert,
  copied definition) is not served under that enrollment. It must re-enroll
  with a fresh key under a strictly greater epoch, or as a new subject. The
  host half is decided as the host key custody rule, and is no stronger than
  that rule: a key retired under a different subject, retired more than
  eight replacements earlier, or retired for a row that was since forgotten
  is outside it. The VM half (anchor B) is an option, and needs real libvirt
  to validate.
