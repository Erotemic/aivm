# Garrett-style instance identity: Python P4a increment and Rust boundary

Status: **experimental host-side library** (2026-10-12). This begins P4 in
parallel with P1/P2 Rust formal work; it does **not** enable a new VM feature.
No real `gh` or other service credentials are needed for the tests. Consult
[the parallel-implementations decision](aivm-secrets-parallel-implementations.md).

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

## Files and responsibilities

| Path | Boundary / future Rust counterpart |
| --- | --- |
| `aivm_secrets/identity/model.py` | Pure typed claims, expectations, explicit time/cert/epoch decision; port directly to safe Rust |
| `aivm_secrets/identity/runner.py` | Language-neutral JSONL parity runner, no secret input |
| `aivm_secrets/identity/token.py` | Host-only Ed25519 JWT and AES-GCM envelope; verify library-backed crypto and document assumptions |
| `aivm_secrets/identity/mtls.py` | One-connection TLS 1.3 CERT_REQUIRED gate; gets real peer DER from SSL before calling the broker |
| `tests/secrets_vectors/identity-v1.jsonl`, `identity-crypto-v1.json` | Independent frozen binding decisions and deterministic, test-only JWT/AEAD byte-level fixture |
| `tests/test_secrets_identity*.py` | Crypto, tamper, mTLS, real existing broker, negative and runner integration tests |

The pure contract consumes explicit inputs. It makes no claim to certificate
chain validation itself; the TLS layer does that before supplying the thumbprint.
Do not allow a guest-supplied JSON `cert`, `thumbprint`, `authenticated` flag or
client-supplied `sub` to stand in for verified transport identity.

## Current opt-in boundary and deliberately absent features

The P4a code adds **no** AIVM CLI flag, VM certificate/key provisioning,
network listener, trusted CA initialization, token acquisition endpoint,
credential migration, new SSH forwarding, or daemon. Existing VMs do not gain
any authority simply by installing it. The `IdentityTLSBridge.serve_accepted`
API operates only when trusted host code supplies a socket and explicitly
configures its TLS context; the `server_context` helper requires TLS 1.3,
client CA trust and a client certificate. This is a building block for a
future carefully reviewed host daemon, not an operator-supported service.

Production wiring must first validate every certificate/private-key/CA path
against the existing descriptor-based host file and untrusted-root checks;
limit listeners/connections/rate; isolate private keys from the guest; define
safe enrollment and lifecycle; authenticate issuer requests; rotate keys;
add durable per-instance revocation and auditable control actions; decide
host-only vs remote network trust boundaries. Do not wire an unvetted public
listener to a credentialed broker, and do not auto-fallback to the legacy
socket if certificate authentication fails.

The signed token's `jti` is currently informative, not a persisted one-shot
replay guard. Valid requests remain subject to the **inner broker's** request
and attempt budgets. P4c must specify replay protection, revocation across
restarts, rollback, cloned vTPM state, key compromise and key-rotation overlap.
An mTLS client certificate in guest-readable software storage gives
cryptographic possession, not non-exportability; vTPM support requires a
separate VM lifecycle design (currently AIVM creates VMs without TPM).

## P4 milestones, independent of Rust schedule

1. **P4a (started):** pure decision and wire vectors, signed/encrypted token,
   actual certificate-authenticated TLS path, test-only issuer keys, local
   broker mediation. Exit gate: demonstrate a matching cert succeeds and a
   different cert, no cert, expired token, forged token and revoked epoch fail
   *before effect dispatch*. Existing broker scopes remain operative.
2. **P4a deployment hardening (next):** host-owned enrollment/key/trust files,
   principal-scoped certificate service, lifecycle and socket ownership,
   authenticated issuer API, explicit session opt-in, rate/resource bounds,
   audited issuance, and real VM integration with dummy provider only.
3. **P4b:** host/browser OAuth authorization and refresh, issuer/broker
   separation, interoperable credential substitution and signed encrypted
   surrogate claims; use the user's host principal, never a shared host token.
4. **P4c:** durable revocation/epochs, rotating issuers, renewal, snapshot/
   clone semantics, key custody in vTPM or hardware where available, fail-closed
   backend unavailability, and recovery/migration tests.
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
