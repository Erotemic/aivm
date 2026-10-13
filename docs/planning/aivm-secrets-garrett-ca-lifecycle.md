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
If near-zero-downtime rollover becomes a real requirement after deployment,
it must be specified and implemented as a different, explicitly reviewed
protocol, not slipped in as an implicit compatibility path.

## Operator workflow

Host operations require the isolated trusted installation and correct
`--untrusted-root` declarations. Example for an initialized test authority:

```bash
python -I -m aivm_secrets identity rotate-ca \
  --root "$HOME/.config/aivm/secrets/identity"
```

Stop any existing identity-enabled AIVM sessions, then restart them **only
after** clients have received and validated the replacement CA certificate,
undergone explicit enrollment, and received fresh bound JWTs. The rotate
command does not start a session or enroll a VM. It returns the selected
CA/server generations, the new CA fingerprint, and `restart_required=true`.
Clients must never silently trust a new public CA delivered over their
untrusted agent channel. Operator-approved host/guest provisioning remains
an independent trust obligation.

Use `identity renew-server` when only the 30-day server leaf needs renewal:
that changes the active server generation under the same CA, without
revoking enrollments. Use client `identity_renew` or `identity_rotate_key`
for per-VM leaf/key changes. Do **not** use CA rotation for routine renewals.

## Persistence and failure ordering

Under one host-private lock:

1. Read and validate the active manifest. A stale instance is denied.
2. Generate a new P-256 CA key/certificate and new server key/certificate.
   Write each immutable file using exclusive creation; sync the file and its
   directory. Skip partial generations left by interrupted runs; never
   overwrite prior material.
3. Commit an empty enrollment registry (revocation of *all* clients) with
   atomic rename and sync.
4. Atomically publish the **single** schema-2 manifest selecting both new
   CA and server. Running bridges retain their original TLS context, but
   reload the authority manifest on each request and reject a changed root.

If step 2 fails, old enrollments and the old trust root remain intact. If
step 3 succeeds but step 4 fails, the old root remains selected but no
client has an active enrollment: this is a **deliberate fail-closed state**.
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
with `initial`, `validate`, `activate_server` and `activate_ca`. It exposes
no certificate operations or filesystem handles. The schema and transitions
are frozen in 60 positive/negative JSONL vectors under
`tests/secrets_vectors/identity-trust-generation-v1.jsonl`; the Python
runner is `python -m aivm_secrets.identity.authority_runner`. A future
independent Rust implementation must agree before parity is claimed.

Proposed implementation-linked lemmas:

- **CA-01:** a successful root activation strictly increases the selected
  CA and server generation and changes the pinned CA fingerprint.
- **CA-02:** a server-leaf renewal strictly increases only the server
  generation; it cannot modify the CA trust anchor.
- **CA-03:** selection cannot refer to a server issued under a different CA
  generation; malformed and stale transitions fail closed.
- **CA-04 (composition obligation):** every post-cutover broker dispatch must
  have passed a live-root check and a fresh active enrollment. The pure
  theorem alone does not establish TLS authenticity, manifest atomicity, or
  the absence of other privileged executor callers.

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
