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
| `identity/garrett/oauth_contract.py` | `PendingAuthorization`, `callback_outcome`/`accept_callback`, `assess_token_response`, `require_active`, `classify_refresh_failure`, grant parsing | Pure. Authenticated callback/response source, explicit time, allowed scopes supplied by adapters. Rust JSONL corpus `garrett-oauth-v1.jsonl` |
| `identity/oauth_provider.py` | Closed, canonical, host-owned provider profile | File provenance, service behavior, profile pin, public OAuth registration |
| `identity/oauth_transport.py` | PKCE S256, bounded loopback callback, pinned TLS POST with compiled-in trust roots, no redirects, sent/not-sent reporting | Python SSL/HTTP, crypto/hash, browser/operator, external authorization server |
| `identity/oauth_vault.py` | AES-GCM at rest, durable atomic record replacement, refresh-outcome state, revoked/rotated credential leases | Host FS, locks, process and kernel, durable audit, hardware rollback protection not provided |
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

`oauth-status` prints only nonsecret metadata: `active`, `epoch`,
`refresh_state`, `generation`, `has_refresh`, `expires_at`, `scopes`,
`profile_current` and `previous_digest`. When it reports
`refresh_state: in_doubt` (see below), decide deliberately between:

```bash
# Present the possibly spent refresh token exactly once more.
python -I -m aivm_secrets identity oauth-refresh --retry-in-doubt \
  --vault "$HOME/.config/aivm/secrets/oauth-vault" \
  --provider-config "$HOME/.config/aivm/secrets/oauth-profile.json" \
  --subject vm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# ...or authorize again, which replaces the record.
python -I -m aivm_secrets identity oauth-login --replace ...
# ...or abandon the grant without presenting its token again.
python -I -m aivm_secrets identity oauth-revoke ...
```

`oauth-login --timeout N` (1..600 seconds, default 180) is both how long the
command waits for the browser and the lifetime of the pending authorization.
The login checks that the vault would accept the subject (`--replace` for an
active record) *before* binding the callback port or printing a URL. Once the
code exchange has been sent, two failures can leave a grant at the provider
that nothing stored, and both fail with `grant orphaned upstream` (keeping
their own code): the vault still refuses after the exchange -- another login
for the same subject finished first -- or the exchange ended
`exchange_in_doubt`, which includes a 200 reply the contract refuses (for
example scopes broader than the profile allows, or no Bearer token type) and
a request whose reply was lost. The operator must then revoke the grant at
the provider. An `exchange_rejected` (400 `invalid_grant`: the code was
refused) or `exchange_not_sent` failure issued nothing and is reported
plainly. Automatic upstream revocation is not implemented.

## Credential and lifecycle semantics

- Public OAuth clients must use the configured rotating refresh-token profile;
  missing/reused rotation is denied. Confidential clients can explicitly
  choose a nonrotating profile.
- A refresh token is never presented twice without an operator's decision,
  **across processes and crashes**, not only within one call. Before the
  refresh POST the vault durably records `refresh_state: in_doubt`; the
  successor grant replaces that marker in one atomic replacement. A failure is
  classified by the pure `classify_refresh_failure`: only a failed connection
  or TLS handshake (`refresh_not_sent`) restores the previous state, and only
  a 400 `invalid_grant` (`refresh_rejected`) is definite, moving the record to
  `reauth_required`. Everything else -- a lost or late reply, a 5xx, a
  redirect, an unusable 200, a crash -- leaves `in_doubt`, because the
  provider may already have rotated the token and RFC 9700 reuse detection
  would revoke the whole grant family on a replay. Whether bytes were sent is
  judged conservatively: once the handshake has completed, every failure
  counts as sent. Sessions (`session_snapshot`) and running leases
  (`active_lease`) refuse an `in_doubt` or `reauth_required` record with
  those fixed reasons (`refresh_in_doubt`, `reauth_required`). If the vault
  cannot store a definite outcome -- the successor grant, or the state a
  `refresh_not_sent` / `refresh_rejected` answer allows -- because the disk
  refuses the write, the marker stays and the failure is reported as
  `refresh_in_doubt` too. In the vault's audit log every refresh starts with
  `oauth_refresh_intent` and, while the process is running, ends with
  `oauth_recorded` (success), `oauth_refresh_not_sent`,
  `oauth_refresh_rejected` or `oauth_refresh_in_doubt`; failure records carry
  the closed code `credential_source`, and the event names the outcome. A
  process that is killed or interrupted mid-request records nothing more:
  its intent simply has no outcome event after it, and the record on disk
  still says `in_doubt`. Only `oauth-refresh --retry-in-doubt` (exactly one
  deliberate retry), `oauth-login --replace` or `oauth-revoke` (which
  deactivates the record without presenting the token) leaves `in_doubt`;
  only `oauth-login --replace` or `oauth-revoke` leaves `reauth_required`.
- A grant's refresh generation is bounded at 2^31-1. A record already at the
  maximum is refused with `exhausted` (`refresh_exhausted`) before any
  refresh request is made, since the contract could accept no successor and
  presenting the rotating refresh token would only spend it; reauthorize with
  `oauth-login --replace`.
- A provider response must report a Bearer access token. Reported OAuth scopes
  must be a subset of configured scopes and previously granted scopes. When
  providers omit `scope`, the contract assumes their documented default and
  cannot itself prove upstream permissions. A provider may choose shorter
  expirations; all requests deny expired session credentials.
- AES-GCM vault records (schema 2) bind the account (provider name and
  subject) in AAD, and the provider-profile digest and subject in plaintext.
  A separate host vault key is protected by strict filesystem checks. Each
  record change writes a new file, fsyncs it, renames it over the record and
  fsyncs the directory before returning (`replace_durable`), so the
  `in_doubt` marker is on disk before the request it marks. A cross-process
  `flock` protects refresh, revocation and broker effect leasing. In-flight
  external effects can complete before a revocation returns, but once
  revocation returns, old-lease requests cannot dispatch. This assumes a
  single host/kernel and filesystem with working advisory locks and honest
  `fsync`. Schema-1 records from earlier development builds are refused; no
  migration is provided.
- Using a record for a session requires the *current* provider profile
  digest: an edited profile never silently inherits a grant issued under the
  old one (`profile_changed`). Because the record file is named by provider
  name and subject only, an edited profile still reaches it, so `oauth-status`,
  `oauth-revoke` and `oauth-login --replace` accept a record that the vault key
  authenticates but an earlier profile wrote. Revoke and replace adopt it
  under the new profile, advance its epoch and keep the first 16 hex digits
  of the old digest as `previous_digest`.
- Revocation always deactivates. At the maximum epoch (2^31-1) a record is
  deactivated without advancing; a later enrollment of that subject is then
  refused with `exhausted`.
- The token client trusts either one pinned anchor file (read as a trusted
  host file, as the broker executor does) or the root store compiled into
  OpenSSL. It deliberately does not call `load_default_certs`, which lets
  `SSL_CERT_FILE` / `SSL_CERT_DIR` replace the trust store: the `identity
  oauth-*` commands run in the operator's own shell, not in the scrubbed
  environment AIVM gives the broker.
- The loopback callback is reachable by any local process. Each connection
  has a 5 s per-operation timeout and is cut at an absolute 5 s deadline that
  never extends past the login's own deadline, so an idle or trickling
  client cannot hold the login open. An exact RFC 6749 error response
  (`error`, `state`, optionally `error_description`, `error_uri`, `iss`)
  whose state matches ends the login at once with `authorization_denied`;
  provider text is never echoed. A response carrying another state is
  ignored. A port already in use is `callback_port_unavailable`.
- The contract is language-neutral: reported scopes split on exactly SP and
  `,` (not on "whitespace", which differs between Python and Rust),
  `allowed_scopes` must be a JSON list, `expected_issuer` a string, times
  JSON integers (never booleans), and the PKCE verifier and `state` 43..128
  RFC 3986 unreserved characters. An error callback's `error_description`
  and `error_uri` are bounded as `grammar.text` bounds text: 1..2048 UTF-8
  bytes with no NUL and no lone surrogate (other control characters, such as
  the CR LF some providers put in descriptions, are opaque provider text). A
  classified refresh `error` value is RFC 6749 NQSCHAR, so ASCII; anything
  else is refused rather than measured.
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
  interoperability, real libvirt/OAuth smoke, formally verified Python,
  automatic upstream revocation of an orphaned or replaced grant, or
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
restricted broker. The `garrett-oauth-v1.jsonl` contract is an independent
input/output corpus for the future Rust runner, configured with
`AIVM_SECRETS_RUST_OAUTH_RUNNER`; until implemented, its test is an expected skip,
not a parity result. It has not shipped in a release and is still edited in
place: its callback rows use RFC 7636-length PKCE values, and it covers error
callbacks (a refusal row carries `reason` only for the contract's own fixed
reasons, today `authorization_denied`), the scope separator set, list-typed
`allowed_scopes`, string-typed issuers, integer-typed times, byte-measured
provider error text and a `classify` action for refresh failures. The
in-doubt, profile-edit, callback and trust-store behaviour is tested against
the real vault, loopback listener and a real TLS server on loopback --
including a refresh whose reply is lost or late after the request was read,
and `SSL_CERT_FILE` and a correctly hashed `SSL_CERT_DIR` each naming the
impostor's CA -- with a mutant in `tests/test_secrets_mutation.py` for each
new check (the runner's own copies of the contract's type checks excepted:
deleting one alone changes no output, so it is an equivalent mutant); no
live provider has been exercised.

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
