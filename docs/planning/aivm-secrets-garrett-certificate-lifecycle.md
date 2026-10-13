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

The current forced helper **reuses the existing software client key**; that
is adequate for routine certificate renewal but does not recover from guest
key compromise. A later key-rotation protocol must stage a new guest key,
confirm independent provenance, install public material, and revoke the old
identity without falling back to it.

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
`identity_enroll --replace` emergency operation remains available and is **not**
CAS-constrained; routine renewal should use `identity_renew`.

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
`server-selection.json`. Old server keypairs are retained for audit/recovery;
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

`tests/secrets_vectors/identity-renewal-v1.jsonl` freezes 48 positive and
negative pure state transitions, evaluated by the same versioned
`aivm_secrets.identity.registry_runner` protocol as earlier enrollment
vectors. The future Rust backend must implement this contract independently
and pass the exact same corpus. Python tests also cover real certificate
signing, invalidation of old JWTs, on-disk selection recovery and pinned SSH
mock exchanges. These tests provide *evidence*, not Rust proof or Python
formal verification. TLS, RNG, X.509, authenticated CSR acquisition,
filesystem locking, and monotonic persistence remain explicit external
assumptions for future composed theorems.

## Outstanding Garrett work

CA rollover and revocation across multiple roots, host/guest key renewal,
optional vTPM key custody, restoration/cloning semantics, rollback-resistant
state, distributed issuers, live VM/provider tests, and transparent
interoperability with arbitrary existing third-party CLIs remain separate
milestones. Do not promise statelessness: broker budgets, OAuth vault
refresh fencing and local revocation intentionally require state.

Reference: Matthew Garrett, [*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/), 2026-07-02.
