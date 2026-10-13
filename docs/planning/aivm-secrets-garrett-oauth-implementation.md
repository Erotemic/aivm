# Garrett credential acquisition and substitution: Python reference

**Status (2026-10-12): experimental, opt-in local-host functionality; synthetic
provider/mTLS integration tested, no live OAuth provider or libvirt VM tested.**
This is the Python P4b/P4c-local implementation. It is not the full remote,
stateless, hardware-bound system described in [Garrett, *Securing agentic
identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/).
See [Garrett identity](aivm-secrets-garrett-identity.md) and the
[parallel Python/Rust agreement](aivm-secrets-parallel-implementations.md).

## End-to-end local architecture

```
Trusted human/browser (host)            Managed VM (untrusted)
       | OAuth authorization            | private software identity key
       v                                | mTLS certificate + surrogate JWT
Operator OAuth issuer                   v
  - pinned HTTPS token endpoint      identity-only Unix socket over SSH
  - exact PKCE callback                |
  - provider manifest                  v
  - host AES-GCM OAuth vault        verified TLS peer / signed+encrypted JWT
  - refresh and revocation              | identity registry + epoch check
       |                                v
       +-- fresh access token --> Broker(aivs1) -- admitted, audited effect -->
                                      fixed HTTPS origin
```

The browser supplies a one-time authorization code to the host-only loopback
listener. The host performs PKCE S256 token exchange, validates bounded
responses and encrypts access/refresh tokens in a principal-owned vault.
A managed, **explicitly selected** bound session selects its OAuth subject from
the authoritative machine-store/live libvirt UUID/principal tuple, not from a
guest field. A host-only broker reads the credential and seals it inside an
`aivs1` capability. The identity issuer signs an outer JWT and AES-GCM seals
the broker capability; the SSH-forwarded socket exposes **only** mTLS. On each
request, the bridge checks CA-validated peer certificate, token signature,
thumbprint, enrollment epoch and active issuer key before calling the original
broker. The broker authorizes the exact operation and resource, records intent,
attaches the decrypted provider token at its fixed HTTPS executor and returns
only the permitted result. No OAuth password, token or refresh token reaches
the guest.

Identity alone grants **zero** API permissions. Host-owned policy limits named
operations and write mode. A running malicious agent can still abuse an
*authorized* operation. This implementation does not authorize arbitrary URLs,
headers, host commands, `gh api`, or GraphQL documents supplied by an agent.

## Separation for proof development

| Component | Interface | Trusted inputs and remaining effects |
| --- | --- | --- |
| `identity/garrett/oauth_contract.py` | `PendingAuthorization`, `accept_callback`, `assess_token_response`, `require_active`, grant parsing | Pure. Authenticated callback/response source, explicit time, allowed scopes supplied by adapters. Rust JSONL corpus `garrett-oauth-v1.jsonl` |
| `identity/oauth_provider.py` | Closed, canonical, host-owned provider profile | File provenance, service behavior, profile pin, public OAuth registration |
| `identity/oauth_transport.py` | PKCE S256, loopback callback, pinned TLS POST, no redirects | Python SSL/HTTP, crypto/hash, browser/operator, external authorization server |
| `identity/oauth_vault.py` | AES-GCM at rest, atomic record changes, revoked/rotated credential leases | Host FS, locks, process and kernel, durable audit, hardware rollback protection not provided |
| `identity/enrollment.py` | `rotate_issuer`, `retire_issuer`, `issue` | Host CA, X.509 crypto, key custody, live per-request issuer checks |
| `host/broker.py` | Optional host-selected credential guard | Enforces existing `machine.admit`/`emit_final` and effect executor; no new API bypass |
| `aivm/secrets_identity_transport.py` | Bound session and isolated broker command arguments | VM store, pinned SSH and libvirt UUID; no import of Python backend into AIVM |

Pure protocol types cannot attest to TLS peer origin; the adapter must
establish the authenticated peer before calling them. Crypto algorithms and
host I/O are not reimplemented as purported proof primitives. The Rust port
will implement the **same data contracts independently**; only the Rust
extracted implementation receives implementation-linked Lean claims.

## Operator workflow

These are **explicitly opt-in commands**. Install `aivm-secrets` in a trusted
virtualenv/system prefix accessible to `python -I`; no guest-writable paths may
contain its code, CA, vault, policy, manifest, or executable. Supply all
host shared mount paths using `--untrusted-root` on standalone host commands.

1. Create an operator-owned OAuth provider profile from
   `docs/examples/aivm-secrets-oauth-synthetic.json`, replacing the example
   domains and OAuth registration with your own host-approved values. The
   example deliberately cannot be used to authenticate to a live provider.
   The `resource_host` MUST equal the restricted policy's HTTPS egress host,
   with Bearer authentication. Use a registered host loopback redirect URI
   `http://127.0.0.1:18765/oauth/callback` (adjust the configured port).
2. Initialize a private host vault, then enroll each exact managed-VM subject
   returned by `aivm vm identity_enroll`. The browser OAuth login occurs on
   the host, **not inside the guest**. The host command does not echo tokens.
3. Establish a managed identity-enabled foreground session, selecting both
   the authority and the OAuth vault/provider profile. The selected subject
   is derived again from the current managed VM identity; mismatches fail.
4. The bridge only exposes the bound identity socket. Revoke the vault account
   or the identity enrollment to end its authority. A completed local vault
   revocation prevents new authorized egress, even from a still-running
   already issued session JWT. Revoking the VM's AIVM principal closes the
   existing broker through the normal watcher.

Example **host** commands (not a credential-issuing script):

```bash
cd ~/code/aivm
install -d -m 700 "$HOME/.config/aivm/secrets"
# The source profile is deliberately synthetic; replace with an operator-owned
# provider registration and check permissions before real authorization.
install -m 600 docs/examples/aivm-secrets-oauth-synthetic.json \
  "$HOME/.config/aivm/secrets/oauth-profile.json"
python -I -m aivm_secrets identity oauth-init \
  --vault "$HOME/.config/aivm/secrets/oauth-vault"
# Use the `subject` printed by aivm vm identity_enroll (actual managed VM).
python -I -m aivm_secrets identity oauth-login \
  --vault "$HOME/.config/aivm/secrets/oauth-vault" \
  --provider-config "$HOME/.config/aivm/secrets/oauth-profile.json" \
  --subject vm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# An enrolled real subject replaces the illustrative synthetic subject above.
```

After operator-enrolled identity and an existing **restricted** service policy:

```bash
aivm ssh ~/code/project \
  --secrets_policy="$HOME/.config/aivm/secrets/readonly-policy.json" \
  --secrets_identity_root="$HOME/.config/aivm/secrets/identity" \
  --secrets_oauth_vault="$HOME/.config/aivm/secrets/oauth-vault" \
  --secrets_oauth_provider_config="$HOME/.config/aivm/secrets/oauth-profile.json" \
  --secrets_writes=deny
```

For manual local `aivm-secrets serve` use explicit `--oauth-vault`,
`--oauth-provider-config` and `--oauth-subject` together. Do **not** add
`--token-file` or `--token-stdin`; mixed credential sources are rejected.
To revoke independently of session lifetime:

```bash
python -I -m aivm_secrets identity oauth-revoke \
  --vault "$HOME/.config/aivm/secrets/oauth-vault" \
  --provider-config "$HOME/.config/aivm/secrets/oauth-profile.json" \
  --subject vm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

For issuer-key retirement (replace ROOT with the trusted authority directory):

```bash
python -I -m aivm_secrets identity rotate-issuer \
  --root "$HOME/.config/aivm/secrets/identity"
# Old keys may be explicitly retired only after new sessions use the active kid.
python -I -m aivm_secrets identity retire-issuer \
  --root "$HOME/.config/aivm/secrets/identity" --key-id local-1
```

`oauth-refresh` explicitly refreshes and replaces the vault access credential.
A running broker with the old access token then **fails closed**; start a new
bound session to use the refreshed token. Session renewal in-place is not
implemented and must not fall back to unrestricted credential resolution.

## Credential and lifecycle semantics

- Public OAuth clients must use the configured rotating refresh-token profile;
  missing/reused rotation is denied. Confidential clients can explicitly
  choose a nonrotating profile. Ambiguous refresh HTTP responses are **not**
  automatically retried; the operator may need to reauthorize.
- A provider response must report a Bearer access token. Reported OAuth scopes
  must be a subset of configured scopes and previously granted scopes. When
  providers omit `scope`, the contract assumes their documented default and
  cannot itself prove upstream permissions. A provider may choose shorter
  expirations; all requests deny expired session credentials.
- AES-GCM vault records bind provider-profile digest and subject in AAD and
  plaintext. A separate host vault key is protected by strict filesystem
  checks. Writes are atomic with fsync; a cross-process `flock` protects
  refresh, revocation and broker effect leasing. In-flight external effects
  can complete before a revocation returns, but once revocation returns,
  old-lease requests cannot dispatch. This assumes a single host/kernel and
  filesystem with working advisory locks.
- Ed25519 JWT signing and AEAD keys may be rotated and old `kid`s retired.
  Bridges consult the active keyring for **every** JWT presentation, not just
  at startup. JWT rotation is separate from client/server TLS leaf renewal,
  both documented in [the certificate lifecycle plan](aivm-secrets-garrett-certificate-lifecycle.md).
  Neither changes the CA or an existing guest's software private key.
- Idempotency and provider-side effects are outside local transactions.
  A dispatched write may have happened even if the provider reports an error;
  use the broker's `outcome_unknown` handling, idempotency keys and service
  reconciliation where available. Broker's default write mode stays `deny`.
- **Trust assumptions:** owning host UID, OS, installed Python and crypto,
  CA, browser/account, OAuth provider, TLS CA roots, process environment,
  clock, audit filesystem, and operator-defined guest-writable roots.
  Same-UID host malware can access the vault. The provider can independently
  revoke or change a grant; the host detects that only through provider replies.
- **Not achieved:** vTPM/hardware non-exportable keys, remote attestation,
  snapshot/clone rollback resistance, CA rotation/renewal, guest key rotation,
  distributed proxy
  replicas, stateless multi-host quotas/revocation, comprehensive OAuth provider
  interoperability, real libvirt/OAuth smoke, formally verified Python, or
  Rust/Lean parity. The local token profile contains an encrypted *broker
  capability*, which itself encloses the provider bearer; it is not a general
  unmodified-CLI HTTPS interception proxy and is not the exact single-layer
  encrypted-provider-token JWT of Garrett's article.

## Validation and future Rust gates

Use `tests/test_secrets_garrett_oauth*.py`,
`tests/test_secrets_garrett_rotation.py`,
`tests/test_secrets_garrett_broker_guard.py`,
`tests/test_secrets_vm_enrollment_transport.py`. The e2e suite uses synthetic
OAuth and an actual local TLS 1.3 client certificate to exercise the existing
restricted broker. The frozen `garrett-oauth-v1.jsonl` contract is an independent
input/output corpus for the future Rust runner, configured with
`AIVM_SECRETS_RUST_OAUTH_RUNNER`; until implemented, its test is an expected skip,
not a parity result.

The P4c certificate renewal increment adds an explicit host-controlled
`identity renew-client` transaction and `aivm vm identity_renew` for managed
VMs, with epoch+thumbprint CAS. A separate `identity renew-server` rotates
the local TLS server leaf/key under the current CA and requires bridge restart.
See [the certificate lifecycle plan](aivm-secrets-garrett-certificate-lifecycle.md).
These operations do not provide guest key renewal or CA rotation.

The first Rust/Lean slice should cover `PendingAuthorization`, grant scope
attenuation, expiration and refresh-generation transitions, issuer binding,
and lease/revocation linearization. The next proof layer must show that only a
valid lease and an authorized effect can cause credentialed egress. Neither
backend is allowed to fall back silently to the other.
