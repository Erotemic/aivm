# Garrett identity: issuer API authorization

**Status (2026-10-13): the verb classification below is decided.
Enforcement in AIVM is partial (see "Current AIVM call sites"). No socket,
network or multi-tenant issuer exists.** Items are marked
**implemented** (true of the code now), **decided** (settled, implementation
pending) or **option** (not scheduled). The open obligation is ISSUER-API-01
in [the assumption ledger](aivm-secrets-assumptions.json).
`tests/test_secrets_identity_operator.py` checks the table against the real
`identity` argument parser. A verb that exists but is missing here, a row
marked `planned` that has shipped, and a row marked `implemented` that no
longer parses all fail the test.

## How the issuer is reached today

- **Only as a child process** (**implemented**): `python -I -m aivm_secrets
  identity <verb>` with fixed arguments, which prints one JSON object. Every
  host verb that opens an authority or a vault refuses to run unless the
  interpreter is isolated (`-I`), then runs `harden_process` and
  `verify_runtime` before touching that state.
  - **Exception: `inspect-csr`.** It reads no authority, and the CLI handles
    it before the isolation check, so it runs without `-I` enforcement,
    `harden_process` or `verify_runtime`, and takes no `--untrusted-root`.
    It parses an untrusted, guest-supplied CSR. AIVM always runs it with
    `-I` and `broker_environment()`, on a CSR file AIVM wrote inside the
    authority directory. An operator who runs it directly must do the same.
    The guest-side verbs (`request`, `call`) skip the check too; they hold
    no issuer authority.
- **Authorization is the filesystem** (**implemented**). The authority
  directory is owned by the principal and has mode 0700. Every read goes
  through `read_owned` and `private_directory`, which refuse guest-writable
  and foreign-owned paths. Being able to run a verb against an authority
  therefore means running as its owning UID. Processes of the same UID are
  trusted, and the issuer makes no per-verb authorization decision of its own.
- **AIVM never imports the issuer** (**implemented**).
  `aivm/secrets_identity_transport.py` runs verbs through its CommandManager
  with `interpreter_flags()` and `broker_environment()`, and passes one
  `--untrusted-root` for every attachment path in the machine store. AIVM may
  import only `aivm_secrets.errors`.
- **The bridge is not an issuer API** (**implemented**). Apart from the
  bridge's own Unix socket, the only listening socket any identity verb
  opens is `oauth-login`'s temporary loopback listener, which waits for one
  browser redirect. (Outbound connections are separate: `call` connects to a
  bridge socket, the bridge to its broker socket, and `oauth-login` and
  `oauth-refresh` to the provider over HTTPS.) `identity bridge` serves
  the broker verbs `request`, `describe` and `renounce` over TLS 1.3 with a
  client certificate and a bound JWT, and refuses `delegate`. It exposes no
  issuer verb. It is also the only identity endpoint ever forwarded into a
  guest.

## Classes

- **Read-only.** Changes no state. Automation-safe. AIVM must declare these
  `role='read'`, which never prompts.
- **Automation-safe write.** All of these hold:
  1. it acts on a subject the caller resolved from host-authoritative facts
     (for AIVM, `resolve_managed_identity`), never from guest input;
  2. it creates no authority the enrollment did not already carry: no new
     enrollment, no reactivated revocation, no enabled key, no trust-root
     change;
  3. it displaces nobody: either it is guarded by an epoch-and-thumbprint
     CAS, or it writes no registry state;
  4. it consumes no finite generation counter and destroys no key material;
  5. repeating it is harmless: a stale retry fails its CAS, and a verb with
     no CAS writes no registry state.

  `renew-client` and `rotate-client-key` meet criterion 2 only within the
  limits of the decided host key-custody rule. That rule is defined in one
  place, "Host key custody rule" in the
  [rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md).
  Until it exists, every renewal after a key rotation re-certifies the
  rotated-away key (case 3 of that policy).

  "Automation-safe" says when a verb may run unattended inside a workflow
  the user already confirmed. It is not an exemption from confirmation: see
  the ownership rule below.
- **Operator-only.** Everything else: creating or replacing a trust root,
  issuer keys or enrollments; unconditional revocation; deleting rows;
  destroying keys; consuming finite generation counters (64 CA and 2048
  server generations, at most 8 enabled issuer keys).
- **Guest-side.** Runs inside a guest and holds no issuer authority. Listed
  only so the table covers every verb.

**Default:** a verb this document does not classify is operator-only until it
is added here.

## Verb classification

Each row names a verb and the optional flags that select one of its forms.
Flags a verb always requires are not listed. A flag that a row lists as a
form must therefore stay optional: once the parser requires it, the rows
without it name an invocation that no longer parses, and the test fails.

| Command | Class | Status | AIVM caller today | Why |
| --- | --- | --- | --- | --- |
| `init` | operator-only | implemented | none | creates a trust root, its CA and issuer keys |
| `status` | read-only | implemented | `identity_enroll`, `identity_renew`, `identity_rotate_key` (read the CAS values) | changes nothing |
| `verify` | read-only | planned | none | reports findings about the authority's files |
| `inspect-csr` | read-only | implemented | every enrollment path, before signing | parses an untrusted CSR in an isolated child |
| `public-client` | read-only | implemented | certificate delivery; bound-session start | returns only public certificate material |
| `enroll` | operator-only | implemented | `identity_enroll` | creates authority for a subject, or reactivates a revoked one at a new epoch |
| `enroll --replace` | operator-only | implemented | `identity_enroll --replace` | displaces an active enrollment without a CAS |
| `enroll --replace --expected-epoch --expected-certificate-sha256` | operator-only | planned | none | the CAS removes the race, but this still replaces the key a VM is enrolled with |
| `renew-client` | automation-safe | implemented | `identity_renew` | CAS-guarded; same subject; a new seven-day certificate |
| `rotate-client-key` | automation-safe | implemented | `identity_rotate_key` | CAS-guarded; requires a different key |
| `revoke-if-current` | automation-safe | implemented | compensation after a failed certificate delivery | CAS-guarded; never revokes a newer enrollment |
| `revoke` | operator-only | implemented | none | unconditional; can revoke an enrollment another writer just made |
| `forget` | operator-only | planned | none | deletes an inactive row whose certificate has expired |
| `prune` | operator-only | planned | none | deletes every such row |
| `issue` | automation-safe | implemented | bound-session start | a token of at most one hour, capped at the certificate's expiry; no registry write |
| `bridge` | automation-safe | implemented | bound session | serves broker verbs; no state change |
| `renew-server` | operator-only | implemented | none | uses one of 2048 server generations; bridges must restart |
| `rotate-ca` | operator-only | implemented | none | replaces the trust root and ends every enrollment |
| `rotate-ca --expected-ca-sha256` | operator-only | planned | none | the CAS stops a stale second run from revoking later enrollments |
| `rotate-issuer` | operator-only | implemented | none | adds a signing key; at most 8 can be enabled |
| `retire-issuer` | operator-only | implemented | none | every live token signed by that kid fails at its next presentation |
| `prune-keys --superseded` | operator-only | planned | never; AIVM does not wrap it | destroys private keys irreversibly |
| `request` | guest-side | implemented | none; guestctl runs `openssl` itself | makes a key and CSR inside a guest |
| `call` | guest-side | implemented | none; the bound guest client is `aivm_secrets/guest.py` | presents one request to a bridge |
| `oauth-init` | operator-only | implemented | none | creates a vault |
| `oauth-login` | operator-only | implemented | none | authorizes interactively in a host browser and stores a credential |
| `oauth-login --replace` | operator-only | implemented | none | displaces a stored credential |
| `oauth-status` | read-only | implemented | none | changes nothing |
| `oauth-refresh` | operator-only | implemented | none | rotates the refresh token; an ambiguous failure can force reauthorization |
| `oauth-revoke` | operator-only | implemented | none | unconditional |

## How AIVM must run each class

The ownership bar in `docs/source/design.rst` decides how each call is
declared (**decided**). `ownership='tool'` is reserved for state that is
regenerable from the user's config, that the user never authored and would
not miss, and that exists as bookkeeping for work the user asked for. A
registry write meets none of these: it advances an epoch, issues or revokes
the user's credential, ends the VM's live bound sessions, and cannot be
regenerated. **Every verb that writes the registry runs as
`ownership='user'`, whatever its class.**

**Read-only** verbs run as `role='read'`, which never prompts.

**Automation-safe** verbs:

- The registry writes (`renew-client`, `rotate-client-key`,
  `revoke-if-current`) run as `role='modify'`, `ownership='user'`, and only
  inside a workflow the user invoked for that same identity. The workflow
  asks once, before its first write. That confirmation names the VM and the
  identity write, for example "renew the identity certificate of VM X; this
  advances its enrollment epoch and ends its live bound sessions".
  `CommandManager.approved_action` is the existing way to ask once for a
  compound action and suppress the nested prompts. The workflows are:
  - `identity_renew` and `identity_rotate_key`: `status`, `inspect-csr`,
    `renew-client` or `rotate-client-key`, `public-client`;
  - `identity_renew --all` (decided in the
    [operations policy](aivm-secrets-garrett-operations-policy.md)): one such
    confirmation per VM, as with `--vm`;
  - compensating a transaction AIVM itself started: `revoke-if-current` with
    that transaction's CAS values, covered by that transaction's
    confirmation.
- `issue` and `bridge` write no registry state. `issue` writes a token valid
  for at most one hour into the broker's private session directory, plus an
  audit record. `bridge` serves one session and exits with it. Both are
  regenerable bookkeeping for the bound session the user started, so they
  meet the bar and run as `ownership='tool'`. `public-client` and `status`
  are reads.

When an automation-safe write runs as a side effect of a different user
operation, it gets a confirmation of its own. **Decided** for VM delete,
rename and access removal: a guarded `revoke-if-current` with its own prompt,
under the same confirmation rule as an operator-only verb (below). A decline
aborts the operation, and `--keep_identity` skips the step.

**Operator-only** verbs run only as `ownership='user'` commands, never
`'tool'`. That alone is not enough:

- AIVM runs one only as the direct object of an explicit user command, as
  `role='modify'`, `ownership='user'`.
- **Its confirmation names the verb, and only `--yes` on that command line
  skips it** (**decided**). No CommandManager path behaves that way today.
  For a non-sudo `ownership='user'` write, `_command_needs_approval` also
  skips the confirmation when any of these holds:
  - the process runs as root (effective UID 0). Then no write is confirmed
    at all.
  - `yes_sudo` is set. It comes from `--yes_sudo`, whose help says it
    approves sudo prompts only, from `--yes`, and from the persisted
    `behavior.yes_sudo` setting.
  - an earlier `[a]ll` answer, to any plan, sudo or write prompt in the same
    process, set the approve-all flag.
  - the command runs inside an `approved_action` scope, which sets that flag
    for its duration. The scope's own prompt ignores `yes_sudo`, but an
    earlier `[a]ll` or an enclosing scope still skips it.

  The increment that adds operator-verb wrappers must therefore add a
  confirmation that consults only `--yes`: not the effective UID, not
  `yes_sudo` (flag or setting), not an earlier `[a]ll`, and not an enclosing
  scope. In `identity_enroll`, that confirmation, naming `enroll` or
  `enroll --replace`, is the workflow's one confirmation. ISSUER-API-01
  records this dependency. Separately, `yes_sudo` approving every
  confirmable write, not only sudo, contradicts the flag's own help text and
  affects every `ownership='user'` write in AIVM, VM delete included. That
  is a CommandManager deviation, recorded here and not fixed here.
- A decline raises `CommandControlError`, which propagates unchanged. No
  handler converts it into a failure or continues past it.
- One confirmation covers one operator-only verb. A wrapper never chains a
  second operator-only verb after the first under the same approval.
- A wrapper uses the same isolation as AIVM's automation calls:
  `interpreter_flags()`, `broker_environment()`, and `--untrusted-root` for
  every path in `guest_writable_roots(store)`.
- `prune-keys --superseded` is **never** wrapped. Destroying private keys is
  reserved for the operator invoking the verb directly.
  `tests/test_secrets_purity.py` checks that no AIVM source names it.
- The other operator-only verbs that AIVM has no wrapper for (`init`,
  `renew-server`, `rotate-ca`, `rotate-issuer`, `retire-issuer`, `revoke`,
  `oauth-*`) are run directly as `python -I -m aivm_secrets identity ...`. The
  operator must pass `--untrusted-root` for every guest-writable host path,
  because nothing derives those paths for standalone use.

## Current AIVM call sites

At this writing, `_identity_action` declares `role='modify'` and
`ownership='tool'` for every verb it runs. Consequences:

- Read-only verbs are logged as writes. That causes no prompt, so it is
  inaccurate rather than unsafe.
- `enroll` and `enroll --replace` are operator-only but run without their
  own confirmation. The one prompt a user sees in `aivm vm identity_enroll`
  belongs to the earlier forced-bootstrap SSH step (`role='modify'`, default
  ownership `'user'`). That prompt names the CSR retrieval, not the
  enrollment, and every bypass listed above skips it. **This contradicts the
  rule above, and correction is pending.**
- `renew-client`, `rotate-client-key` and the compensating
  `revoke-if-current` write the registry as `'tool'`. The same
  forced-bootstrap prompt precedes them in their workflows, but it does not
  name them. **This contradicts the ownership rule above, and correction is
  pending.**
- `issue` and `bridge` run as `'tool'`, which matches the rule.
- Three guest writes over login SSH are also declared `'tool'`:
  - installing the public certificate and CA in `~/.config/aivm/identity/`
    after an enrollment, renewal or rotation, which for a rotation also
    activates the staged key;
  - installing a bound session's capability and guest client in its
    per-session directory under `/tmp` (`run_bound_secrets_ssh`);
  - removing that directory when the session ends.

  The ownership bar in `docs/source/design.rst` says installing into the
  guest is not bookkeeping. The first call replaces the guest's persistent
  identity, so it is a user-owned write. The other two follow the choice
  that `aivm ssh --secrets_policy` already makes, and justifies in a
  comment, for its own per-session guest directory
  (`aivm/secrets_transport.py`). The correction must decide both session
  paths together, not identity alone. These calls are outside the verb
  classification and are listed so the correction covers them.

## Future: an SO_PEERCRED-gated multi-tenant issuer (option, out of scope)

One host service could hold the authority for several principals, reached
over a local Unix socket, instead of one authority directory per principal.
Requirements for such a design:

1. **Same verbs, same JSON.** A request carries what the argv carries today,
   and the reply is today's stdout object. AIVM's adapter swaps a child
   process for one socket connection. AIVM still imports only
   `aivm_secrets.errors`, and still talks to a separate process, so a Rust
   implementation of the same verbs remains a drop-in replacement.
2. **A service account owns the state.** Principals no longer own an
   authority directory. The service is its only reader and writer.
3. **Authentication is the kernel's peer credential and nothing else.** The
   service reads the credentials the kernel captured when the client called
   `connect()`: the effective UID and effective GID from `SO_PEERCRED`, and
   the supplementary groups from `SO_PEERGROUPS` (Linux 4.13 and later). No
   request field naming a principal, UID or subject is authority. The PID is
   not used, because it can be reused. One connection carries one request,
   so a descriptor passed to another process does not become a session.
4. **Ownership comes from the service's own records.** The operator-only
   `enroll` that creates an enrollment also records the principal UID it is
   for. A peer UID may use automation-safe verbs only on subjects recorded
   for that UID. The service reads neither the machine store nor libvirt, so
   the process boundary in the
   [rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md)
   holds unchanged: AIVM still derives the subject from host facts and
   passes it as a value, and the service checks it against its own record,
   never against AIVM's. Operator-only verbs need membership of a separate
   operator group, taken only from the connect-time credential: the
   effective GID or an `SO_PEERGROUPS` entry. Where `SO_PEERGROUPS` is
   unavailable, the service refuses operator-only verbs. It never consults
   the account database (`/etc/group`, NSS), which would grant a group that
   the process deliberately dropped and apply membership changes the process
   never received. The private-group check (GROUP-01) answers a different
   question, whether a group belongs to the caller alone, and is not used
   here.
5. **UID 0 names no principal.** Principal-scoped verbs refuse a root peer,
   rather than guess whose VM it means. Root can still administer the service
   through its files, which is a trust assumption, not an API.
6. **Never forwarded.** For a forwarded socket, the peer SO_PEERCRED reports
   is the host's own `ssh` process, which runs as the principal (CHAN-02).
   Forwarding the issuer socket would therefore hand a guest the principal's
   entire issuer authority. The bridge remains the only identity endpoint a
   guest can reach.

**Composition with "sudo is not a substitute for group membership."** The
machine-store rule is that a principal either belongs to the trusted group
and uses the shared store with its own descriptors and locks, or gets a
private store. It never escalates into the shared one. A shared issuer
follows the same rule:

- A principal reaches it only from its own UID, through a socket its group
  may open. Using the machine store's trusted group means "may use shared
  VMs" and "may use the shared issuer" are one decision.
- `sudo` is never the way in. An escalated connection reports UID 0, which
  erases the very principal the service authorizes. A root-run child would
  also write state the principal cannot read back: the same locking,
  read-back and atomic-replacement problems the machine store documents.
- A host that declines membership keeps today's per-principal authority. That
  gives two roots and one implementation, as with the machine store.
- A shared issuer that exists always wins and never silently forks. AIVM must
  not fall back from an unreachable shared issuer to a private authority,
  because two authorities would then claim the same domains.
