# P4a managed-VM binding and opt-in mTLS-only sessions

Status: **experimental Python reference**, 2026-10-12. This is a **delta** on the
P4a authority/enrollment implementation. No existing VM, policy, agent,
credential, SSH session or ordinary `aivm ssh` behavior is modified merely by
installing the package.

## Trust boundary and mechanism

The trusted AIVM adapter derives the client enrollment subject from a closed
version-1 record, all from **host authority**, not untrusted guest arguments:

- the canonical machine-store path (SHA-256 of its UTF-8 filesystem spelling);
- the managed VM name, validated against an authoritative machine store;
- the *live system libvirt domain UUID* obtained using `virsh -c qemu:///system
  domuuid`, not the guest's reported UUID;
- the current **active**, owner-UID-matching, persisted access principal ID,
  associated host UID and guest username.

The pure `aivm_secrets.identity.vm_model.subject` generates
`vm-` + SHA-256(`aivm-secrets/managed-vm/v1\0` || canonical JSON). Store,
principal, name, UUID or guest username changes therefore change the subject
under the SHA-256 collision-resistance assumption. This is a **derived name**,
not hardware attestation or proof of non-clonability. The pure code is a
closed-input Python reference and has 104 frozen valid/invalid JSONL cases at
`tests/secrets_vectors/identity-managed-vm-v1.jsonl`. A future independently
compiled Rust runner must reproduce them; it is currently **absent**.

### Authenticated CSR enrollment

The explicit `aivm vm identity_enroll` command uses the VM's previously pinned
**forced bootstrap SSH channel**. It refuses missing pinned host keys and does
not use TOFU, an ordinary agent shell, or a user-provided CSR path. It sends a
fresh 128-bit exchange nonce and an **authoritative** guest UID/name to the
fixed guest helper's `identity-csr` operation. Only this operation is added to
`aivm-guestctl --forced` (beside the preexisting access operations).

The forced guest helper checks that its target account's UID matches the host
request, then runs fixed absolute commands as the **unprivileged guest account**
to generate a P-256 software key and PKCS#10 CSR under
`$HOME/.config/aivm/identity/`. The host accepts only a bounded, correct
nonce/UID/username response with a valid proof-of-possession CSR. The host
never trusts the CSR's Common Name as the identity. It performs the CA signing
in a separate `python -I` process with a filtered environment; the guest is
then given **only its public certificate and the public CA certificate** via
its normal, strictly pinned principal SSH account. No host CA/JWT/AEAD keys
are installed in the VM.

Enrollment is requested deliberately and is not an automatic consequence of
VM creation or SSH. Existing VMs that have the **old** forced guest helper
will refuse `identity-csr`. The enrollment command must fail closed; upgrading
an old helper is a separate, explicitly approved guest maintenance action.
We do not silently replace a privileged guest helper from a secrets operation.
A repeated enrollment requires explicit `--replace`, which increments the
registry epoch and invalidates previous client certificates/tokens. Existing
software client key reuse is currently supported; protected key rotation is
still missing.

**Important limit:** The forced channel authenticates which configured VM's
SSH endpoint answered, assuming the prior pinned host key and bootstrap key
remain trusted. It does not prove which *process* generated the CSR. Software
private keys under a guest user are exportable and can be copied to a clone or
to another process. This increment makes **no** hardware or vTPM-backed VM
origin/non-exportability claim. A malicious guest's root can manipulate the
identity request and still use its granted permissions while its key is active.

### Explicit identity-only session

`aivm ssh . --secrets_policy=... --secrets_identity_root=...` selects a distinct
transport. It checks the current managed-VM subject against the enrolled
certificate, starts a separately isolated existing broker, issues an
**encrypted** bound JWT in a separate `python -I` issuer process, and starts
a second isolated mTLS bridge with a finite lifetime. The only reverse SSH
forwarding in this mode is `guest/identity.sock : host/identity.sock`.

**Never forward `broker.sock`** in this mode. The bridge verifies a real TLS
1.3 client certificate, issuer signatures, binding, registry epoch and expiry
on each request. It then unwraps the existing sealed broker capability and
routes through the **unchanged** authorization kernel/executor. A copied JWT
without the matching private key cannot be used on the bridged endpoint.
The guest client is the existing standard-library CLI shim with `mtls-v1`
explicitly selected; it never falls back to plaintext on an unknown mode.
Unrestricted `gh api`, unauthorized writes and token delegation remain denied.

The broker's original socket still exists **on the host** so that the bridge
can consult it, and is not offered to the guest. The identity-only launcher
also disables the separate repository SSH-agent forwarding path, avoiding a
second unbound credential channel. The bridge's stdin is a liveness lease:
closing the foreground SSH session closes the bridge and broker before
best-effort guest client/token cleanup. Access-principal status and libvirt
UUID are rechecked during the session; on change, the broker is stopped.

**This does not revoke all effects already in progress.** Token and cert
revocation are checked before broker dispatch and are not transactional with
provider-side writes. The guest can still perform whatever the original
broker **explicitly** authorized while its session and identity remain valid.
Do not grant a misbehaving agent a capability you do not want it to use.

## Operating sequence (manual and explicitly opt-in)

The host CA must already exist as described in
[`aivm-secrets-p4a-enrollment.md`](aivm-secrets-p4a-enrollment.md). Install
AIVM from a protected Python environment that supports `python -I -m
 aivm_secrets` imports; do not put the package or interpreter inside a
shared workspace. Initialize the authority separately and leave credentials
absent until choosing an explicit policy.

On a managed, already-running VM whose forced helper has been updated through
an operator-approved maintenance process:

```bash
cd "$HOME/code/aivm"

aivm vm identity_enroll \
    --identity_root="$HOME/.config/aivm/secrets/identity" \
    --vm=lab
```

`lab` is an example VM name; select the actual name visible in `aivm vm list`.
No `gh` credential or provider request is involved in this enrollment.

After verifying an enrolled subject and a **separate host-only policy**, the
operator can deliberately start one bound session:

```bash
cd "$HOME/code/aivm"

aivm ssh . \
    --secrets_policy="$HOME/.config/aivm/secrets/lab-readonly.json" \
    --secrets_identity_root="$HOME/.config/aivm/secrets/identity" \
    --secrets_writes=deny
```

No credential-bearing `aivm ssh` session occurs without `--secrets_policy`.
The guest gets only a time-limited, certificate-bound capability; the host
owns the actual provider credential. A read-only policy is strongly preferred
for experiments with untrusted agents. **These commands have not been run
against real libvirt/SSH hardware in this environment.**

## Failures, reset and clone lifecycle

- **Missing or old forced helper:** reject enrollment; no fallback to an
  unverified SSH/shell channel. Explicit maintenance is needed.
- **Guest cannot provision key/cert:** refuse the session. On public
  certificate installation failure, revoke the newly enrolled identity.
- **Domain UUID changes on VM recreation:** derived subject changes; old
  registry entry/token cannot satisfy the new session and must be explicitly
  replaced or revoked. The old registry entry remains until operator review.
- **Clone/rollback preserving UUID, SSH host key and software private key:**
  **not protected**. A privileged host administrator or restored guest that
  preserves all identity state can reproduce the certificate. Future vTPM,
  attestation and clone/restore epoch policy must address this.
- **Changing access principal state:** the session watchdog stops its broker,
  including if the persisted access principal is disabled during the shell.
  Watchdog polling has a delay and is not an atomic revocation fence.
- **Guest logout, crash, SSH loss, broker crash:** the bridge and broker
  processes close on lease end. Guest cleanup is best effort; stale sealed
  material has no live host credential executor when both services have exited.
- **Host CA rotation, restore and rollback:** not supported in this increment.
  A restored host authority can roll back epochs; operator recovery is required.


## Process-only backend boundary

The AIVM orchestrator imports **only** the stable `aivm_secrets.errors`
exception table from the sibling implementation. Host CA, registry, CSR parser,
certificate chain, token issuer and mTLS bridge never run in the ambient AIVM
Python process. Instead, AIVM invokes fixed `python -I -m aivm_secrets identity`
operations (`status`, `inspect-csr`, `enroll`, `public-client`, `revoke`,
`issue`, `bridge`) through its supervised command manager with a filtered
environment. `public-client` produces only the public certificate and CA as
size-bounded base64 JSON; the host wrapper validates this shape and installs
only public material in the guest. Raw token/credential outputs never cross
this process boundary. The server still owns every authorized effect.

This interface is intentionally suitable for a future Rust executable that
implements the same closed JSON command contract. The host's lightweight
version-1 subject digest uses the same canonical encoding as the independent
Python reference (`identity/vm_model.py`), and cross-checks every *valid* case
in the frozen vector corpus. The host adapter's other input validation relies
on its authoritative VM/principal readers; the pure reference rejects arbitrary
malformed values. Do not treat this as proof of equivalence over all inputs.

The existing purity regression test checks that no identity implementation
module is directly imported by AIVM. If a future feature adds such an import,
regard it as a security-boundary review rather than extending the allowlist.

The guest forced helper additionally launches all CSR subprocesses with a
minimal fixed environment to avoid inherited loader/OpenSSL configuration.
Even if the mTLS bridge raises during shutdown, the broker receives a
separate `finally` stop, and best-effort guest file cleanup follows.

## Security assumptions and further work

The machine store, host identity, pinned SSH host key and bootstrap credential,
`virsh` response, Python library installation, `openssl`, guest user-account
database, separate issuer, OS process isolation and TLS/cryptographic libraries
are trusted or externally validated. The current guest key remains software
and exportable; the host CA is per-operator, not yet a multi-tenant service.
Do not claim this code proves VM provenance. No Rust model, Lean proof or
real-VM smoke test has been produced by this increment.

Remaining work: authenticated helper upgrade for existing guests; integration
smokes on a disposable libvirt VM with synthetic service; signed lifecycle
journal/counter for snapshot and restore; true non-exportable vTPM identity
and key policy; separate Rust VM binding runner and proof extraction; OAuth
and provider credential acquisition without exposing ordinary host tokens.

## Planned module extraction (no change to managed-VM authority)

The next design-only increment introduces
[primitive contracts and a pure Garrett protocol model](aivm-secrets-modular-proof-architecture.md).
Keep the managed-VM source of authority here: AIVM's machine store, active
principal, libvirt UUID and pinned bootstrap SSH. These are external facts
provided to the `identity/vm_model.py` reference; a reusable primitive cannot
prove that a guest-generated CSR came from a particular VM merely by
validating its contents. The trust edge from those host facts to the model
must remain explicit when moving to Rust.

Retain the **process-only** AIVM-to-`aivm-secrets` command boundary and the
identity-only forwarded socket. The future `identity/garrett` pure transitions
may reuse binding and epoch lemmas, but cannot launch a VM, read CA keys,
receive guest-origin `VerifiedPeer` values as trusted facts, or bypass the
broker. The installed behavior and opt-in write-denial defaults do not change
as a consequence of the planning document.
