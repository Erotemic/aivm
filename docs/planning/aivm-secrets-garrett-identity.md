# Garrett-style instance identity: Python P4a increment and Rust boundary

Status: **experimental Python P4a/P4b local functional flow with opt-in managed-VM integration**
(2026-10-12). The host OAuth credential issuer, encrypted vault, refresh,
local revocation and issuer signing-key rotation are now implemented. This
advances P4 independently of P1/P2 Rust formal work; existing VMs gain no
new credential access by default. See
[OAuth acquisition and substitution](aivm-secrets-garrett-oauth-implementation.md)
for the current executable contract and remaining P4c limitations.
No real `gh` or other service credentials are needed for the tests. Consult
[the parallel-implementations decision](aivm-secrets-parallel-implementations.md).

## Policies

Each policy separates what is implemented from what is only decided:

- [Rollback and clone](aivm-secrets-garrett-rollback-clone-policy.md): how
  restores, snapshot reverts, clones and disk copies affect identity state,
  the required outcome for each, and the anchors that could detect them
  (ROLLBACK-01, CLONE-01).
- [vTPM keys](aivm-secrets-garrett-vtpm-policy.md): swtpm state, the key
  template, TPM2_Certify evidence, and exactly what AIVM may claim (VTPM-01).
- [Issuer API authorization](aivm-secrets-garrett-issuer-api.md): which
  identity verbs automation may run, and how AIVM must run operator-only ones
  (ISSUER-API-01).
- [Operations](aivm-secrets-garrett-operations-policy.md): single-host scope,
  `jti` and retried writes, and supported weekly renewal.

## Reference architecture

Garrett's [Securing agentic identity](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
proposes centrally acquiring provider credentials, returning signed surrogate
JWTs with encrypted provider tokens, and authenticating their use by requiring
an instance's client certificate over mTLS. AIVM's additional rule is that
**identity never grants arbitrary provider effects**: the existing broker
must still enforce a named operation, resource, grant, budget and approval.

The first implementation uses the existing per-session `aivs1` broker token
(which itself contains a host-AEAD-encrypted service credential) as the secret
inside a new **Ed25519-signed, AES-256-GCM-encrypted identity-bound JWT**:

```text
Host-only issuer                         Authenticated guest VM (future)
  existing Broker (aivs1 encrypted)                |
    -> new signed JWT with encrypted aivs1         | JWT + API request
                                                  v
  TLS 1.3 bridge: CA-verified client certificate via CERT_REQUIRED
    -> verify Ed25519 signature / issuer / audience / subject / epoch / TTL
    -> compare RFC 8705 SHA256(DER) thumbprint with actual mTLS peer
    -> authenticated AES-GCM decrypt the aivs1 holder
    -> reconstruct only a known v1 broker frame
    -> existing Broker.handle -> admission -> audit -> effect executor
```

The JWT's public claims are `iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `epoch`
and `cnf: {"x5t#S256": base64url(SHA256(DER certificate))}`. Its `enc`
field is a nonce+ciphertext+tag, with the public claims as AEAD associated
data. The header pins `alg=EdDSA`, `typ=aivm-bound+jwt` and an exact trusted
`kid`. The encoding is canonical unpadded base64url over strictly canonical
JSON. The token lifetime cannot exceed one hour. JWT parsing rejects unknown
fields, duplicate keys, noncanonical encodings, alternate algorithms, oversized
input and timestamps outside a bounded window.

The JWT signing key and encryption key are trusted-host private material;
these tests create them in memory. The broker key *still* protects the actual
provider token; the bridge unwraps and forwards only the original opaque
capability to the existing broker. It never returns this inner token to the
guest. The bridge **denies `delegate`**, because an unwrapped child `aivs1`
response would otherwise bypass certificate binding. `request`, `describe`
and `renounce` retain the existing broker's semantics. An authorized guest can
still misuse *its own allowed actions*, and can relay a live authorized client
connection; mTLS does not prevent either.

This is **one restricted token profile**, not complete JWT/OAuth interoperability
or stateless grant authorization: the inner broker still maintains budgets,
epoch and audit state. Initial certificate identity means possession of the
private key accepted by the configured CA, **not** hardware non-exportability,
vTPM enrollment, remote attestation, host identity proof or correct guest-agent
process identity.

## Self-contained Garrett protocol and shared primitives (implemented)

The pure `aivm_secrets.identity.garrett` package now owns closed public
claims, certificate binding, enrollment transitions, managed-VM subject
calculation and pure `prepare_issue`/`present` intent construction. It
has no imports from `kernel`, `host`, TLS, X.509 or the AIVM manager. The
reusable bounded JSON/wire, validity, epoch and binding operations now live
in `aivm_secrets.primitives`; old module names re-export the same functions
and types. See the [refactor implementation record](aivm-secrets-garrett-modular-refactor.md).

This makes **the pure protocol model**, not the cryptographic credential
service, self-contained. The Python issuer still owns filesystem and CA
operations, `identity.token` still uses library-backed Ed25519/AES-GCM and
the mTLS bridge still forwards only into the original broker. It creates
no new privileged API endpoint or authorization bypass. TLS/authenticated
claims, registry snapshots and clock samples are *trusted inputs* to pure
models, not facts proved by calling those models.

## Files and responsibilities

| Path | Boundary / future Rust counterpart |
| --- | --- |
| `aivm_secrets/identity/garrett/claims.py` | Pure typed claims, expectations, explicit time/cert/epoch decision; the old-path facade was removed before deployment |
| `aivm_secrets/identity/garrett_runner.py` | New pure issue/present JSONL runner; original `identity/runner.py` remains for binding vectors |
| `aivm_secrets/identity/token.py` | Host-only Ed25519 JWT and AES-GCM envelope; verify library-backed crypto and document assumptions |
| `aivm_secrets/identity/mtls.py` | One-connection TLS 1.3 CERT_REQUIRED gate; gets real peer DER from SSL before calling the broker |
| `tests/secrets_vectors/identity-v1.jsonl`, `identity-crypto-v1.json` | Independent frozen binding decisions and deterministic, test-only JWT/AEAD byte-level fixture |
| `tests/test_secrets_identity*.py` | Crypto, tamper, mTLS, real existing broker, negative and runner integration tests |

The pure contract consumes explicit inputs. It makes no claim to certificate
chain validation itself; the TLS layer does that before supplying the thumbprint.
Do not allow a guest-supplied JSON `cert`, `thumbprint`, `authenticated` flag or
client-supplied `sub` to stand in for verified transport identity.

## Certificate lifecycle increment (P4c, experimental)

The [certificate lifecycle plan](aivm-secrets-garrett-certificate-lifecycle.md)
adds explicit managed-VM client-certificate renewal with a pure compare-and-swap
epoch transition, plus rotation of the local server TLS leaf/key pair under
the existing CA. Renewal does not rotate software guest keys or the CA, and
running sessions must be replaced after new certificates are installed.
Python/Rust parity is specified by the frozen enrollment-renewal corpus.

## Current deployment boundary and deliberately absent features

The follow-up [P4a enrollment increment](aivm-secrets-p4a-enrollment.md)
provides a principal-owned local CA, a CSR enrollment CLI, persistent per-VM
certificate/epoch records, an optional foreground Unix mTLS bridge, and a
restricted TLS client. This standalone authority does not automatically modify a VM, start a daemon,
expose TCP, or change the default
`aivm ssh --secrets_policy` transport. The separate opt-in managed-VM adapter
now provisions an identity through the authenticated bootstrap path, but live
libvirt and SSH integration remains unvalidated.
A software key can still be copied; CSR signature validity is not VM
attestation. Standalone manual enrollment requires independent operator
authentication of the CSR source.

The signed token's `jti` is informative, not a persisted one-shot replay
guard. The existing broker still governs operations, attempt budgets and
session lifetime. The registry provides new-call epoch revocation, but no
atomic guarantee across an already in-flight request or rollback-resistant
state across host snapshot restoration. Client certificate/key renewal, CA rotation, vTPM, unattended VM enrollment,
and verified Rust remain pending. **Issuer JWT key rotation and retirement are
implemented separately** from CA rotation. OAuth refresh/revocation are local
host-vault operations, with no cross-snapshot rollback resistance.

## P4 milestones, independent of Rust schedule

1. **P4a (started):** pure decision and wire vectors, signed/encrypted token,
   actual certificate-authenticated TLS path, test-only issuer keys, local
   broker mediation. Exit gate: demonstrate a matching cert succeeds and a
   different cert, no cert, expired token, forged token and revoked epoch fail
   *before effect dispatch*. Existing broker scopes remain operative.
2. **P4a deployment hardening (in progress):** host-owned enrollment/key/trust
   files, a manually authenticated CSR workflow, principal-owned Unix socket,
   opt-in CLI, bounded requests, auditable issuance and persistent enrollment
   epochs are implemented. The opt-in managed-VM
   adapter now binds its identity to the machine store, active principal and
   live libvirt UUID, and uses pinned bootstrap SSH. Remaining: controlled
   upgrade of older guest bootstrap helpers, issuer API authentication suitable
   for automation, and real-VM tests with a synthetic provider. Fail-closed
   single-root CA rotation is now available in the Python reference (see
   `aivm-secrets-garrett-ca-lifecycle.md`).
3. **P4b (Python local implementation complete, broad interoperability pending):**
   host-browser authorization-code/PKCE, pinned HTTPS exchange, encrypted host
   credential vault, explicit refresh and revocation, existing restricted
   broker substitution, plus signed/encrypted certificate-bound surrogates.
   This deliberately does not intercept arbitrary existing clients or become
   a cross-host stateless OAuth proxy. The local principal owns its vault.
4. **P4c (partially implemented):** local encrypted-vault revocation,
   refresh-generation fencing and rotating/retirable JWT issuers are in the
   Python implementation. Client renewal and software-key rotation and single-root CA cutover
   are now implemented. Still needed: durable cross-host revocation,
   rollback/clone resistance, vTPM/hardware key custody,
   and recovery/migration tests.
5. **Rust parity:** port model first, then crypto protocol/transport; compare
   canonical on-wire behavior and adversarial traces. Verify Rust pure rules
   through Aeneas/Lean and separately account for Rust TLS and other I/O
   assumptions. Proofs do not apply to Python.

## Threat-model-specific selection

The Python reference may be suitable for experimentation when the operator
trusts host Python and installed dependencies, while the Rust backend aims to
reduce and prove specified core invariants for higher-assurance deployments.
The *actual provider credential* must always remain host-side in both; no
selected backend may turn a rejected operation into a privileged unrestricted
fallback. Neither backend can prevent abuse of operations the operator
explicitly authorized.

## 2026-10-12 — P4a managed AIVM VM adapter

An opt-in Python adapter now maps a managed, active AIVM access principal and
live libvirt UUID to a certificate enrollment subject. The restricted bootstrap
channel returns only a guest-user-owned CSR, and the bridge-only SSH launcher
never forwards the raw broker Unix socket into the guest. Enrollment and
JWT signing execute in isolated host subprocesses. Ordinary VM sessions remain
unchanged. See [`aivm-secrets-p4a-managed-vm.md`](aivm-secrets-p4a-managed-vm.md).
This is transport binding, not hardware attestation, OAuth, or formally verified
isolation; the non-exportability and clone/restore problems remain open.
