# P4a enrollment: host CA, operator issuance, and opt-in Unix mTLS bridge

Status: **historical P4a increment**, 2026-10-12. For the current
single-root schema-2 authority and CLI paths see
[aivm-secrets-garrett-ca-lifecycle.md](aivm-secrets-garrett-ca-lifecycle.md).
Older flat-file examples and lifetime statements below describe the original
prototype and are **not** current operator instructions. The former
`identity/registry_model.py` facade has been deleted; the canonical pure
model is `identity/garrett/registry.py`.

This increment builds on
`docs/planning/aivm-secrets-garrett-identity.md` and the **two parallel
implementations** decision. It does not change VM creation, `aivm ssh`, Git
credentials, or the default secrets transport. Nothing starts automatically.

## What is implemented

1. `aivm-secrets identity init` creates a per-host-principal private authority,
   refusing an existing directory. Host files are owner-only `0600`, the root
   and subdirectories `0700`: a P-256 CA, a short-lived local TLS server
   certificate and key, an Ed25519 JWT signer and public verifier key, a
   256-bit AEAD key, a strict registry, and an exclusive writer lock. CA and
   signer keys never enter the guest. No CA key is registered in the system
   trust store. This local CA expires in 365 days; server certificates in 30
   days. *Renewal and key rotation are not yet implemented.*
2. `identity request` runs in the **guest**, generating an exportable P-256 key
   and a CSR signed with that key; `identity inspect-csr` displays its public
   key fingerprint. A trusted **human operator** retrieves the CSR, verifies
   that the key fingerprint belongs to the intended VM by an independent
   authenticated channel, and passes that fingerprint to `identity enroll`.
   The host never uses the CSR CN or requested extensions as an identity;
   extension-bearing CSRs are refused. Enrollment issues a 7-day client-auth
   certificate with a fresh serial; it binds the DER certificate thumbprint
   to a named identity and an increasing epoch.
3. `identity issue` explicitly wraps an existing **host-only `aivs1` broker
   capability** in the signed/encrypted, certificate-bound JWT. The resulting
   JWT is stored as a new private **host** file, never logged or printed. It
   may be copied to the intended guest through an explicit operation; a broker
   or provider credential is never copied. Its lifetime is at most one hour,
   with a 15-minute default. The original broker can still expire/revoke it.
4. `identity bridge` explicitly opens one restricted **Unix-domain** socket
   (`0600` under a `0700` directory). Each client connection performs a TLS
   1.3 certificate-authenticated handshake, verifies the signed/encrypted JWT,
   rechecks **current** enrollment and epoch, and forwards the resulting
   request to the existing authorized broker over its `broker.sock` only.
   It cannot use `control.sock`, publish a TCP listener, mint child grants, or
   reach the HTTPS executor. It has finite idle and connection limits; the
   foreground operator owns its lifetime. `identity call` is the restricted
   CLI client for a deliberately forwarded Unix socket.
5. `identity revoke` increments the **persisted** epoch and deactivates the
   client certificate; `enroll --replace` similarly rotates its certificate
   and epoch. New TLS calls consult the registry every time. Changes are
   written under an exclusive interprocess file lock and fsync'd with atomic
   replacement. Enrollment, issuance and revocation record a hash-chained
   intent before the action, and an outcome afterwards. The operator should
   retain audit-chain heads externally to detect tail truncation.
6. A **pure** `aivm_secrets.identity.garrett.registry` owns the bounded schema,
   allowed enrollment transitions, revocation and certificate lookup. A
   language-neutral JSONL runner has **69 frozen enrollment vectors**, alongside
   the existing 64 identity-decision vectors and deterministic cryptographic
   fixture. This is the parity contract for an independently built Rust port.

## Trust boundaries and limits

- The CSR cryptographically proves possession of the **software private key**,
  not its VM origin. Merely copying a fingerprint from the same untrusted CSR
  is not independent authentication. A malicious agent with its own key could
  be enrolled if the operator associates it with the wrong VM. AIVM machine
  identity, SSH bootstrap, vTPM/key non-exportability and attestation are
  **future gates**, not claimed here. An enrolled guest process possessing the
  key can exercise **all** operations explicitly granted by the original
  broker. mTLS cannot tell which process inside the guest invoked it.
- The CA root, JWT signer, and registry are controlled by the current trusted
  host account; same-UID host processes and host administrators are trusted.
  `--untrusted-root` must name **every** guest-writable host path before any
  authority or service command runs. A private directory alone does not
  identify all VM-shared mount paths. AIVM does not currently derive those
  exclusions automatically for the standalone identity CLI.
- The issuer is **operator-only**; there is no remote token issuance endpoint.
  `identity issue` accepts a host-selected inner broker capability but does
  not yet independently certify that the source session's `vm` and access
  identity match the enrolled certificate's subject. The underlying broker's
  policy and channel checks still apply; the host operator is responsible for
  selecting the intended broker. A stronger AIVM lifecycle adapter must make
  the mapping automatic and authenticated before unattended enrollment.
- Persistent enrollment revocation rejects the **next** request. It is not an
  atomic transaction with a request that already passed the enrollment check
  and is proceeding through the broker. To revoke an in-flight operation,
  revoke/stop the original broker too. Atomic revocation at the effect
  linearization point and cross-host durable state remain work for P4c.
- Restoring an older copy of the host authority directory can roll back
  enrollment epochs. Host-controlled backup, rollback counters, crash repair,
  issuer rotation, duplicate request handling, multi-host replicas, OAuth
  acquisition and snapshot/clone semantics are not implemented. A copied
  software guest key and client certificate can authenticate a clone until
  revoked. The JWT `jti` is not currently a one-shot replay barrier; the
  underlying broker budget, expiration and audit still apply.
- This bridge is **not** the default `aivm ssh --secrets_policy` transport.
  That existing opt-in mode deliberately forwards the *ordinary* AIVS socket,
  whose operations are host-authorized but not bound to a client certificate.
  Do not forward both the legacy broker socket and the new identity socket
  into a guest if certificate binding is the requirement.
- The CA, PKCS#10 and TLS parser, crypto libraries, Python I/O and kernel
  mediation are trusted dependencies. No Rust backend, Aeneas extraction,
  Lean theorem or Python formal proof is claimed. Tests and differential
  conformance provide evidence only.

## Explicit operator workflow (synthetic identity)

On a **trusted host**, from a securely installed `aivm[secrets]` environment.
**Privileged identity operator commands require `python -I -m aivm_secrets`
from a trusted installation**, not a non-isolated console-script invocation.
This prevents `PYTHONPATH`, the current directory and user-site packages from
replacing the credential-handling code before it can inspect itself:

```bash
install -d -m 700 "$HOME/.config/aivm/secrets"
python -I -m aivm_secrets identity init \
    --root "$HOME/.config/aivm/secrets/identity" \
    --issuer aivm.local --audience aivm-secrets.identity
```

On a **guest**, after explicitly installing the P4a client library (no
automatic provisioning is performed):

```bash
install -d -m 700 "$HOME/.config/aivm/identity"
aivm-secrets identity request \
    --key "$HOME/.config/aivm/identity/client.key" \
    --csr "$HOME/.config/aivm/identity/client.csr"
```

Transfer only the **public CSR** to the trusted host. Compare the SHA-256
public-key fingerprint reported inside the guest over an independently
trusted host-to-VM channel (not a string echoed by a compromised agent). The
host can inspect the received copy with:

```bash
python -I -m aivm_secrets identity inspect-csr \
    --csr "$HOME/Downloads/tauceti-lab.csr"
```

Only after authentication, use `python -I -m aivm_secrets identity enroll`
with `--subject tauceti-lab` and supply the
independently **confirmed** hash using `--approve-key-fingerprint`. The host
prints the issued **public** certificate path. Copy that certificate and the
public `ca.pem` to the guest, never the host's CA key, server key, JWT signer
or AEAD key. The guest private key is not transferred to the host.

If a policy-limited broker is already explicitly running on the host, its
read-only capability file may be wrapped using `python -I -m aivm_secrets identity issue` and a private
host output file. The bridge uses that broker's **host** `broker.sock` and a
new Unix socket chosen by the operator (`python -I -m aivm_secrets identity bridge`). Socket forwarding into the VM is a
**separate, explicit** SSH operation, not something installation or regular
`aivm ssh` does. A guest can then invoke a known operation:

```bash
aivm-secrets identity call \
    --socket "$HOME/.cache/aivm/bound.sock" \
    --ca "$HOME/.config/aivm/identity/ca.pem" \
    --certificate "$HOME/.config/aivm/identity/client.pem" \
    --key "$HOME/.config/aivm/identity/client.key" \
    --jwt-file "$HOME/.config/aivm/identity/bound.jwt" \
    --request '{"operation":"pr.view","arguments":{"repository":"TauCetiProject/TauCeti","pr":13861}}'
```

That request only works if the actual broker permits `pr.view` for that PR.
No real provider credentials are required for unit tests. The integration
suite starts a synthetic broker behind real Unix sockets and real TLS 1.3,
then tests denial, expiration and live revocation, without contacting GitHub.

## Work still needed before a real unattended VM deployment

1. Integrate the enrollment decision with authoritative AIVM VM IDs and
   owner/principal records. Authenticate the CSR channel (e.g. through the
   existing forced bootstrap identity); do not trust a guest-supplied `vm`.
   Associate issuance with the specific broker VM/access-identity metadata.
2. Add an **explicit** foreground launcher option that installs only the
   public CA/client certificate and the sealed token, forwards only the bound
   Unix socket, and does not expose the legacy broker channel. Couple its
   cleanup to the parent/VM identity lifetime and add a guest setup rollback.
3. Add real libvirt/SSH tests (synthetic provider only), including shutdown,
   restore, clone, stale enrollment, expired CA, miswired broker, and missing
   guest crypto dependencies. No live write is needed for this milestone.
4. Implement trust-anchor/server-certificate renewal and CA/key rotation with
   documented overlap, durable rollback resistance, and recovery. Design an
   optional vTPM key and snapshot policy before promising non-exportability.
5. Implement the separate Rust backend with the same registry JSONL
   contract, crypto fixtures and bounded transport parser. Extract and prove
   the Rust policy/enrollment transitions via Aeneas/Lean; list external TLS,
   crypto and storage assumptions rather than declaring the entire system
   verified.
