# Garrett identity: pre-deployment trust generations and CA replacement

**Status (2026-10-12): experimental Python reference. No VMs enrolled.** This
increment makes an intentional breaking change to the *undeployed* identity
format. There is no read path or migration tool for the old format, and no
compatibility shim for the former Python identity facades. It does not touch
ordinary AIVM sessions, Git credentials, or guest VM settings.

## Decision: one active CA, one active TLS identity

The authority now has exactly one active trust root and server identity.
`authority.json` schema 2 selects both, atomically:

```json
{
  "schema": 2,
  "issuer": "aivm.local",
  "audience": "aivm-secrets.identity",
  "created_at": 1,
  "ca": {"generation": 1, "sha256": "<SHA-256 hexadecimal>"},
  "server": {"generation": 1, "ca_generation": 1}
}
```

The value above illustrates the schema; the real fingerprint is a canonical
64-digit hexadecimal digest. Files are immutable and principal-private:
`ca-generations/ca-N.{pem,key}`, `server-generations/server-N.{pem,key}`,
`issuer-keys/local-N.{key,pub,aes256}`, plus an explicitly stored issuer
keyring. The initial generation is 1. The mutable `server-selection.json`,
implicit `local-1` key fallback, and flat `ca.pem`/`ca.key` files are **gone**.

**No CA overlap is provided.** For now, replacing a CA deliberately ends the
authority of every existing client enrollment. This is a simpler, stronger
fail-closed transition than keeping two sets of trusted roots indefinitely.
Ending that authority is a *revocation of every row*, not an erasure of the
registry: each active enrollment becomes inactive and its epoch advances
(saturating at the maximum), so every subject's epoch stays monotonic across
the rotation and a re-enrollment under the new root is strictly newer than
anything issued under the old one. The one exception is a row deliberately
forgotten in between (`identity forget`/`prune`, only once it is inactive
and its certificate has expired), which restarts that subject at epoch 0;
see REG-02 in `aivm-secrets-garrett-certificate-lifecycle.md` for why that
is harmless for the epoch and what retired-key custody it discards.
If near-zero-downtime rollover becomes a real requirement after deployment,
it must be specified and implemented as a different, explicitly reviewed
protocol, not slipped in as an implicit compatibility path.

## Operator workflow

Host operations require the isolated trusted installation and correct
`--untrusted-root` declarations. Example for an initialized test authority:

```bash
root="$HOME/.config/aivm/secrets/identity"
python -I -m aivm_secrets identity status --root "$root"   # note ca_sha256
python -I -m aivm_secrets identity rotate-ca --root "$root" \
  --expected-ca-sha256 <ca_sha256 from status>
```

`--expected-ca-sha256` is required. It is a compare-and-swap on the active
root: if the active CA is no longer the one named (a second run of the same
command, or a concurrent rotation), the command is refused with `revoked`
before anything is generated, staged, revoked or audited. Without it, a
repeated rotation would silently revoke the enrollments made under the root
the first run installed.

Stop any existing identity-enabled AIVM sessions, then restart them **only
after** clients have received and validated the replacement CA certificate,
undergone explicit enrollment, and received fresh bound JWTs. The rotate
command does not start a session or enroll a VM. It returns the selected
CA/server generations, the new CA fingerprint, `restart_required=true`, and
`revoked`: the list of `{subject, epoch, certificate_sha256}` enrollments it
revoked (the epoch and thumbprint of each enrollment *as it was*, which is
also what the audit file records, one `identity_revoke_intent` per entry,
before the registry commit). A guest may re-enroll its existing key after
the rotation; revocation does not retire keys. A guest that has run
`identity_rotate_key` is the exception for now: the current helper still
sends the CSR for its original key, which *is* retired, so the operator must
regenerate `client.csr` from `client.key` in the guest first (see
`aivm-secrets-garrett-certificate-lifecycle.md`).
Clients must never silently trust a new public CA delivered over their
untrusted agent channel. Operator-approved host/guest provisioning remains
an independent trust obligation.

Use `identity renew-server` when only the 30-day server leaf needs renewal:
that changes the active server generation under the same CA, without
revoking enrollments. Use client `identity_renew` or `identity_rotate_key`
for per-VM leaf/key changes. Do **not** use CA rotation for routine renewals.

## Persistence and failure ordering

Under one host-private lock:

1. Read and validate the active manifest. A stale instance is denied, and
   so is an active root other than `--expected-ca-sha256`
   (`garrett.authority.require_ca`); either refusal changes nothing.
2. Generate a new P-256 CA key/certificate and new server key/certificate.
   Write each immutable file using exclusive creation; sync the file and its
   directory. Skip partial generations left by interrupted runs; never
   overwrite prior material.
3. Commit the registry with *every* active enrollment revoked (`revoke_all`:
   inactive, epoch advanced, saturating at the maximum) with atomic rename
   and sync. Rows are kept, never erased, so epochs remain monotonic
   (until an operator later forgets a row, REG-02); already inactive rows
   are unchanged, so a retry after a failure in step 4 neither revokes nor
   advances anything twice.
4. Atomically publish the **single** schema-2 manifest selecting both new
   CA and server. Running bridges retain their original TLS context, but
   reload the authority manifest on each request and reject a changed root.

If step 2 fails, old enrollments and the old trust root remain intact. If step 3
succeeds but step 4 fails, the old root remains selected but no client has
an active enrollment: this is a **deliberate fail-closed state**. The retry
names the same (still active) root.
A retry must create fresh, higher-numbered immutable generations. The
operator must never restore the old registry to repair such a failure.
After step 4, the old root is no longer an accepted authority in new
bridges, and old bridges reject further broker dispatch. Neither this
transaction nor the existing enrollment revocation mechanism cancels a
remote provider operation that was already admitted before the cutover;
stop/revoke the original broker when that stronger guarantee is required.

**Host backup rollback is still outside the guarantee.** Replacing the
entire authority directory with an older snapshot can restore an old
manifest, private key and enrollment registry. A future trusted
monotonic/externally anchored state will be needed before claiming
rollback resistance or clone-resistant instance identity.

## Verification boundary and Rust parity

`identity/garrett/authority.py` is a deterministic, side-effect-free model
with `initial`, `validate`, `require_ca`, `activate_server` and
`activate_ca`. It exposes no certificate operations or filesystem handles.
The schema and transitions are pinned in 84 positive/negative JSONL vectors
under `tests/secrets_vectors/identity-trust-generation-v1.jsonl` (including
`require-ca` matches and mismatches, and list or object `action` values,
which must be refusals rather than a crash that ends the reply stream); the
Python runner is `python -m aivm_secrets.identity.authority_runner`. The
registry half (`revoke-all`) is pinned in `identity-registry-v1.jsonl` and
replayed by `aivm_secrets.identity.registry_runner`. A future independent
Rust implementation must agree before parity is claimed.

Proposed implementation-linked lemmas:

- **CA-01:** a successful root activation strictly increases the selected
  CA and server generation and changes the pinned CA fingerprint; the host
  commits it only after every enrollment was revoked (step 3), never after
  erasing the registry.
- **CA-02:** a server-leaf renewal strictly increases only the server
  generation; it cannot modify the CA trust anchor.
- **CA-03:** selection cannot refer to a server issued under a different CA
  generation; malformed and stale transitions fail closed.
- **CA-04 (composition obligation):** every post-cutover broker dispatch must
  have passed a live-root check and a fresh active enrollment. Because the
  cutover revokes every row (inactive, epoch advanced, saturating) instead of
  emptying the registry, no enrollment that was active under the old root is
  active afterwards, and every later enrollment of a subject has a strictly
  greater epoch than any it held before (or the subject is `exhausted`),
  over any transition sequence that does not `forget`/`prune` that subject's
  row in between. A forget restarts the subject at epoch 0; it is allowed
  only for an inactive row whose certificate has expired (REG-02), so the
  composed obligation is that nothing carrying an earlier epoch of a
  forgotten subject is still valid, not that epochs never decrease. The pure
  theorem alone does not establish TLS authenticity, manifest atomicity, or
  the absence of other privileged executor callers.
- **CA-05 (rotation compare-and-swap):** a rotation commits only if the
  active root equals the operator's `--expected-ca-sha256`; otherwise
  nothing is staged, revoked or audited.

The trusted assumptions are X.509 and TLS verification, host RNG, directory
ownership, atomic rename/fsync/locks, certificate provisioning and the
existing broker's complete-mediation property. The Python tests supply
empirical evidence only; no Rust proofs or end-to-end guarantees are claimed.

## Non-goals

No live VM, production OAuth provider or GitHub credential was used. This is
not an implementation of vTPM non-exportable keys, snapshot/clone rollback
protection, multi-host replicated revocation, seamless cross-CA rollover,
transparent third-party CLI proxying, or a verified Rust backend. The
first deployment must start with a newly initialized schema-2 authority,
not a migrated experimental schema-1 directory.

Primary inspiration: Matthew Garrett, [*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
(2026-07-02). The additional operation authorization and single-root
re-enrollment policy are AIVM design choices, not claims about his article.
