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
  domuuid`, not the guest's reported UUID. Like every other system-libvirt
  probe it runs through sudo when the host user cannot reach
  `qemu:///system` directly (outside the libvirt group, or
  `privilege_mode = "always"`), and that privileged read is announced;
- the current **active**, owner-UID-matching, persisted access principal ID,
  associated host UID and guest username.

The pure `aivm_secrets.identity.garrett.vm.subject` generates
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
under `$HOME/.config/aivm/identity/`: it generates a P-256 software key on
first use (scratch names, then `ln`, so two concurrent requests never pair a
key with the other's CSR) and otherwise re-signs a fresh PKCS#10 CSR with the
installed `client.key`, replying with exactly the CSR it made. The host
accepts only a bounded, correct nonce/UID/username response with a valid
proof-of-possession CSR. The host never trusts the CSR's Common Name as the
identity. It performs the CA signing in a separate `python -I` process with a
filtered environment; the guest is then given **only its public certificate
and the public CA certificate** via its normal principal SSH account. The
guest installs them only after checking that the certificate's public key is
its `client.key`'s. No host CA/JWT/AEAD keys are installed in the VM.

Every principal-account SSH step of enrollment -- the install, and a CSR
refresh that runs first -- uses `-F /dev/null`, `StrictHostKeyChecking=yes`
and the VM's **pinned bootstrap `known_hosts`** as its `UserKnownHostsFile`:
it is the same guest sshd the forced channel already pinned, so ambient
`~/.ssh/known_hosts` entries for a reused address are never consulted, and a
missing or empty pin refuses before any SSH runs. On a *shared* machine store
that file is root's (the bootstrap directory is `root:<group>` `0750`, and the
file is written by `ssh` under sudo with root's umask); when a group member
cannot read it, the principal steps keep `StrictHostKeyChecking=yes` against
the principal's own `known_hosts`, populated when `aivm vm access reconcile`
verified the login. That is not TOFU -- an unknown or changed key still
refuses -- but it is weaker than the pin, and AIVM logs that it happened.
The bound session described below does **not** use the pinned file yet; it
checks the host key strictly against the principal's own `known_hosts`.

The CSR refresh exists for guests that still run an older forced helper,
which replays `client.csr` verbatim: after an `identity_rotate_key` under
the original activation script that file still held the CSR of the retired
key. The fixed refresh step regenerates `client.csr` from `client.key` as
the guest user before every non-rotating enrollment, so renewal and
`--replace` present the active key even with an old helper. See
[guest-key rotation](aivm-secrets-garrett-guest-key-rotation.md).

Enrollment is requested deliberately and is not an automatic consequence of
VM creation or SSH. Existing VMs that have the **old** forced guest helper
will refuse `identity-csr`. The enrollment command must fail closed; upgrading
an old helper is a separate, explicitly approved guest maintenance action.
We do not silently replace a privileged guest helper from a secrets operation.
A repeated enrollment requires explicit `--replace`, which increments the
registry epoch and invalidates previous client certificates/tokens. Renewal
and `--replace` reuse the guest's active software key; replacing that key is
the separate, explicit `aivm vm identity_rotate_key`. Non-exportable
(vTPM-backed) keys are still missing.

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
  unverified SSH/shell channel. Explicit maintenance is needed. The
  `aivm vm identity_*` commands report this, like every expected refusal of
  the identity path, as one error line with its operator detail (for
  example "guest helper upgrade may be required") and exit status 1, not a
  traceback. A declined prompt is not such an error: it aborts the command
  as the user's decision.
- **Guest cannot provision key/cert:** refuse the session. On public
  certificate installation failure (including a certificate whose public
  key is not the guest's `client.key`), revoke the newly enrolled identity
  with the epoch+thumbprint guarded revocation. If that revocation does not
  complete, the error names the exact `python -I -m aivm_secrets identity
  revoke-if-current ...` command to run.
- **Refusal after issuance:** if the user declines or interrupts a step after
  the CA issued the certificate, AIVM runs no further command -- not even the
  revocation, which would continue past that decision -- logs the exact
  guarded revocation command at WARNING, and re-raises the refusal unchanged.
- **Lost issuance reply:** the CA child may time out, crash or fail an audit
  write *after* committing, and its exit status cannot tell that from a
  refusal. Any failure of the issuing child re-reads the registry; if the
  subject now holds an active certificate it did not hold before (compared
  by certificate, since a re-created row restarts at epoch 0), the command
  fails with `outcome_unknown` naming the subject, the epoch, the
  certificate thumbprint and the guarded revocation command, and says it is
  either this attempt's undelivered certificate or another operator's
  concurrent enrollment (a competing renewal also fails this one) -- check
  which before revoking. AIVM never revokes it on its own. An interrupt
  while the issuing child runs gets a WARNING naming the registry read and
  the guarded revocation to fill in; nothing further runs.
- **VM address or host key changed:** the pinned principal and bootstrap
  channels both refuse (ssh exit status 255). The error suggests
  `aivm vm access reconcile`, which pins a *new address*; a changed host key
  at the same address stays refused until the pin is deliberately reset.
- **Domain UUID changes on VM recreation:** derived subject changes; old
  registry entry/token cannot satisfy the new session and must be explicitly
  replaced or revoked. The old registry entry remains until operator review;
  once it is revoked and its certificate has expired, `identity forget` or
  `identity prune` frees its slot (the subject embeds the old domain's UUID,
  so it does not come back once that domain is gone). `prune` also removes
  the revoked, expired row of a VM that still exists; re-enrolling such a VM
  starts without its retired keys, so regenerate its CSR from `client.key`
  first (see `aivm-secrets-garrett-certificate-lifecycle.md`).
- **VM rename or store move:** the derived subject changes while the old
  enrollment may stay active and hold the guest key; if it does, enrolling
  the renamed VM is refused until the old row is revoked by hand (AIVM does
  not yet prompt for it). Keys retired for the old subject are not retired
  for the new one, so a VM that ran `identity_rotate_key` must regenerate its
  stale CSR before enrolling under the new subject (see
  `aivm-secrets-garrett-certificate-lifecycle.md`).
- **Clone/rollback preserving UUID, SSH host key and software private key:**
  **not protected**. A privileged host administrator or restored guest that
  preserves all identity state can reproduce the certificate. Future vTPM,
  attestation and clone/restore epoch policy must address this.
- **Changing access principal state:** the session watchdog stops its broker,
  including if the persisted access principal is disabled during the shell.
  Watchdog polling has a delay and is not an atomic revocation fence.
  It uses noninteractive libvirt UUID reads, preflighted before broker launch.
  On hosts requiring sudo, ``sudo -n virsh domuuid`` must work for the entire
  session (prefer libvirt group access or a narrowly scoped NOPASSWD rule);
  an expired password cache causes fail-closed session shutdown after three
  unsuccessful probes. The background watcher never opens an approval prompt.
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
Python reference (`identity/garrett/vm.py`), and cross-checks every *valid* case
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
provided to the `identity/garrett/vm.py` reference; a reusable primitive cannot
prove that a guest-generated CSR came from a particular VM merely by
validating its contents. The trust edge from those host facts to the model
must remain explicit when moving to Rust.

Retain the **process-only** AIVM-to-`aivm-secrets` command boundary and the
identity-only forwarded socket. The future `identity/garrett` pure transitions
may reuse binding and epoch lemmas, but cannot launch a VM, read CA keys,
receive guest-origin `VerifiedPeer` values as trusted facts, or bypass the
broker. The installed behavior and opt-in write-denial defaults do not change
as a consequence of the planning document.
