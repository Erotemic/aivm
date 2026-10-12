# AIVM Secrets: provider-neutral integrations and CLI compatibility

Status: **implemented experimental Python schema 2 with planned verified Rust
kernel** (updated 2026-10-10). This refines [the main architecture](aivm-secrets-design.md) and
[the assurance plan](aivm-secrets-formal-assurance.md); the implemented state
machine is specified in [the kernel specification](aivm-secrets-kernel-spec.md).
The original GitHub PR schema 1 remains a compatibility integration, **not the
core architecture**.

## 1. Architectural decision

**An authentication tool, a target service, and an interactive CLI are three
independent concerns.** The service must not infer any authority from the CLI
name or from possession of a token-resolving tool. The host policy selects a
specific service and a finite set of effects. The broker authorizes each effect
before a credential crosses its trust boundary. A guest can replace its CLI
entirely without increasing authority.

```text
             HOST-ONLY CONFIGURATION / OWNERSHIP
  +----------------------+      +--------------------------+
  | Credential resolver  |      | Service integration      |
  | command / file /     |      | fixed destination, auth  |
  | later OAuth/PKCS#11  |      | method, bounded effects, |
  |                      |      | typed input and results  |
  +-----------+----------+      +------------+-------------+
              |                              |
         Real credential               Host-owned policy
              |                              |
        +-----v------------------------------v---------------------+
        | Trusted secret-use broker                                 |
        | identity + grant + operation + budget + epoch + audit    |
        |              + constrained effect compiler              |
        | [target] small safe-Rust kernel + typed effect executor  |
        +---------------------------------+-------------------------+
                                          |
                                 fixed authenticated egress
                                          |
                                     Remote service

    UNTRUSTED GUEST
  stock CLI (future, via proxy)     CLI adapter / script
                  \               /
                generic `aivm-secrets invoke`
                         |
                  sealed capability
                         |
               SSH/Unix-socket channel
                         |
                    broker above
```

This adopts Matthew Garrett's separation of original credential from a sealed
identity-bound placeholder, and adds authorization of the **meaning of each
operation**, rather than replacing any `Authorization` header on any request.
See [Garrett's July 2, 2026 design][G], and his references to RFC 8705 and
Fly.io's earlier tokenization architecture. It is distinct from Docker
Sandboxes' host-token command resolvers and HTTP proxy credential injection:
those are relevant compatibility precedents, but token substitution alone
cannot impose object/operation restrictions. See [Docker's CLI-auth docs][D].

[G]: https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/
[D]: https://docs.docker.com/ai/sandboxes/workflows/authentication/

## 2. Pluggability contracts

| Contract | Inputs | Output | What must not be exposed |
| --- | --- | --- | --- |
| `CredentialSource` | **host-only** fixed resolver spec and host operator identity | credential in broker memory | source invocation, raw stdout, diagnostic stderr to guest |
| `ServicePolicy` | host-owned schema, service ID, origin, allowed operations, scope | canonical digest / typed rules | guest control over destination, headers, credential or effects |
| `ServiceAdapter` | typed request plus authoritative policy (and optional trusted preflight facts) | effect intent: method, fixed relative path, projected JSON body | direct network I/O, arbitrary shell, caller-provided headers |
| `EffectExecutor` | previously validated effect, host-held credential | bounded response or unknown outcome | redirects, fallback origins, unbounded responses, credentials in results |
| `GuestCLIAdapter` | CLI args or a high-level agent request | structured operation and typed arguments | policy mutation, credential retrieval, custom HTTP request URLs |

**Production source and service adapters are host-trusted dependencies.** An
agent is not allowed to import Python modules by name, select arbitrary host
executables, or register an adapter through the guest protocol. An installed
third-party adapter would require explicit operator approval, version pinning,
and a security/conformance review. The current runtime deliberately has a
finite built-in registry instead of indiscriminately loading entry points.

Generic integrations SHOULD use declarative schema 2 rather than trusted Python
plugins. Most read/write REST APIs can be represented by a finite list of
allowlisted path templates, literal permitted path parameters, an explicit
request-body schema, and fixed host and authentication header. Non-HTTP
protocols (Git operations, signing, AWS SigV4, Kubernetes client certificates,
opaque interactive CLIs) require dedicated executors and threat models; do not
silently map them onto bearer-token HTTP.

### 2.1 Credential sources: host operation, never guest operation

Schema 2 supports:

```json
{"kind": "file", "path": "/home/operator/.config/service/token"}
```

and:

```json
{
  "kind": "command",
  "argv": ["op", "read", "op://Work/GitLab/personal-token"],
  "inherit_env": ["XDG_CONFIG_HOME"]
}
```

The second example refers to an **operator-owned 1Password entry**; it is an
illustration, not a requirement or an assumption that the entry exists. The
resolver runs on the host, with literal `argv`, `shell=False`, stdin closed,
stderr discarded, bounded stdout, a timeout, and a restricted inherited
environment (`HOME` and `PATH`, plus explicit allowed variable names). The
result is a single printable-ASCII opaque token. Credentials containing JSON,
refresh tokens, multiple headers, X.509 identities, or interactive sessions
need a future typed resolver profile; treating them as opaque bearer tokens
would be incorrect. Because a resolver executes host code under the owning
operator UID, **the policy and the executable are trusted code/configuration**,
not something the agent may edit. A command itself can invoke a shell if a
trusted operator deliberately configures it; the broker does not implicitly
interpret a command string as shell syntax.

Long term, support resolvers with a `resolve -> Lease` interface:

```text
Lease {
    credential_handle: opaque host-local ID,
    identity: issuer / account / audience,
    expires_at: verified host time,
    refresh_capability: host-local,
}
```

Include explicit account/audience checks, refresh and zeroization contracts.
Never let the guest request a different resolver at invocation time. Where
possible, avoid even carrying an encrypted long-lived provider token inside a
guest-visible JWT: short-lived, server-side keyed handles can be preferable for
local revocation and rotation. The Garrett-style sealed envelope remains an
important target for distributed systems, with real instance-backed mTLS.

### 2.2 Service integration, not arbitrary API relay

The declarative adapter uses **policy schema 2**, with keys:

* `service`: stable descriptive identifier, chosen by the operator;
* `adapter`: currently `https`;
* `host`: one canonical public DNS hostname; always the name TLS authenticates;
* `authentication`: `bearer` or `x-api-key` (no custom/header injection);
* `credential_source`: host-only typed source object;
* `operations`: finite, distinct names, each with a required `effect`
  (`read` or `write`), `GET`/`POST`/`PATCH`, a validated relative path
  template, optional `query` entries that are fixed values or
  `{placeholder}` references, `parameters` giving every placeholder its
  permitted values (a finite list of integers or strings, or an integer
  range `{"min", "max"}`), optional bounded JSON string body fields (each
  optionally `optional`), a `json`/`text` response and an optional `accept`
  media type. Optional `defaults`, `fold` and `page` normalize requests and
  annotate list answers;
* `checks` (optional): named fact checks. An operation that `requires` one
  first performs the check's `GET`; every `require` entry -- a value reached
  by object keys must equal a literal or a request parameter, by exact type,
  optionally ASCII-case-folded -- must hold before anything else is
  constructed. `bind` names a fact for use in a later path after validating
  its `format` (`hex`, `integer`, `segment`). `"returns": "check"` makes the
  verified answer the result;
* `cli` (optional): command tables for the guest client, per tool name; see
  section 2.3;
* `egress` (optional): operator pins for a private deployment -- `port`, an
  `address` to connect to, and a `ca_file` that replaces the system roots for
  this service. TLS still authenticates `host`;
* `headers` (optional): static headers such as an API version. Names the
  executor owns (authentication, `Host`, cookie, content, proxy) are refused;
* `lifetime_seconds`, `max_requests`, `max_body_bytes`: bounded session limits.

A request is only:

```json
{"operation": "issue.view", "arguments": {"issue": 23}}
```

It cannot supply an HTTP method, URL, token, `Host` header, proxy, body schema,
or executable path. Every placeholder, in the path or the query, must have an
explicit allowlist: finite integer or segment-string values, or a bounded
integer range. Permitted values contain only RFC 3986 unreserved characters,
so the request target is constructed without escaping. No arbitrary query strings, arbitrary HTTP bodies, binary streaming, redirects
or retries are available in schema 2. Schema 2 admits a host-pinned, named
GraphQL **query** as a typed read: the document and destination come from
the reviewed manifest, and only declared scalar variables come from requests.
The query parser is intentionally not a general GraphQL parser, and its
nonmutation is a provider assumption (SPEC-02).

**What counts as a write is declared, not inferred.** `effect` is required on
every operation. An ordinary body-carrying method must be `write`; a named, fixed
GraphQL query is the only currently admitted read-body exception. A `GET` may
be either, and one that changes provider state must be declared `write`. The
declaration decides everything downstream: a write requires a host write
mode of `allow`, or `approve` plus a one-shot approval of the exact request;
its authorization is marked as a write for the executor; and its failure is
`outcome_unknown` whatever the status, because a service may apply a request
and then answer 4xx. That an operation declared `read` really is read-only
is the operator's statement about the provider (assumption SPEC-02). The trusted HTTP executor rechecks the
constructed route and only connects to the policy's fixed TLS host. Reflection
checks are a backstop, **not** a general noninterference guarantee.

Reference manifests ship in `docs/examples/`: GitLab merge-request review
(`aivm-secrets-gitlab-merge-request.json`), GitHub issues through schema 2
(`aivm-secrets-github-issues.json`), a non-Git service
(`aivm-secrets-huggingface-readonly.json`), a private-CA deployment
(`aivm-secrets-selfhosted-pinned.json`) and the built-in GitHub pull-request
manifest written out in full (`aivm-secrets-github-pr.json`), which uses
`checks`, bound facts and a `cli` table. They are examples to copy and edit:
none has been run against the live service by this project.
See [the GitLab example](../examples/aivm-secrets-gitlab-readonly.json) for
the smallest complete non-GitHub service configured without a Python plugin. The example
uses `gitlab.com` and its documented Bearer authorization for access tokens,
resolving one operator-owned token using 1Password's `op read`. Check the
underlying credential scopes before actual use.

### 2.3 Guest CLI integration

The **generic**, stdlib-only client supports:

```bash
"$AIVM_SECRETS_CLIENT" invoke account.read
"$AIVM_SECRETS_CLIENT" invoke issue.view --arguments '{"issue":23}'
"$AIVM_SECRETS_CLIENT" invoke issue.comment --arguments-file comment.json
"$AIVM_SECRETS_CLIENT" operations
"$AIVM_SECRETS_CLIENT" delegate --scope '{"operations":{"issue.view":{"issue":[23]}}}' --output helper.cap
"$AIVM_SECRETS_CLIENT" renounce
```

`operations` reports what the presented capability permits. `delegate` mints a
strictly smaller capability (ATTEN-01); `renounce` gives one up. These are the
whole guest protocol: there is no verb for approval, revocation of another
grant, or anything on the host control plane.

A human-friendly command line is an **untrusted argument translator**: it
constructs this limited request shape and nothing more. It is not privileged,
even if malicious, because the broker validates the result against the
selected operation. The translator is data, not code. A manifest's `cli`
section maps a tool name to rows of

```json
{"command": ["pr", "view"], "operation": "pr.view",
 "positional": ["pr"],
 "options": {"--repo": "repository", "-R": "repository"},
 "output": "reply"}
```

and the one guest client interprets them: the longest matching `command`
selects a row, positionals and options become typed arguments (`@name` reads
a body field from a file or stdin), and the request is sent as usual. The
client is linked under each tool name in the session's directory, and
`aivm-secrets as NAME ...` is the explicit spelling. The tables are served by
`describe` and carry no authority; the kernel only checks that a row names an
operation and arguments that exist.

`gh` support is exactly this: the built-in GitHub manifest carries a `gh`
table. There is no `gh`-specific branch in the client or the broker, and a
`glab`-shaped or in-house command line is added the same way. It is not the
stock tool -- a command, flag or form the table does not list is a usage
error, never a fallback -- and a table may not take the client's own verbs or
the names the client is started through (`env`, `python3`, `sh`). Don't rely
on PATH shadowing for security: the guest can execute any executable anyway.

**Supporting unmodified stock tools** is a separate P3 workstream:

* HTTP(S) clients that honor proxy configuration can use a constrained proxy
  if it authenticates the guest session, pins the intended endpoint, and
  validates **full API semantics** before substituting credentials.
* HTTPS CONNECT tunnels do not expose encrypted request methods, paths, or
  bodies; credential/policy substitution requires an explicit client-aware
  mechanism, trusted TLS interception, or an endpoint adapter.
* Tools using non-HTTP protocols or multiple authentication exchanges require
  custom profiles. E.g., `kubectl` may use bearer, OIDC exec plugins, client
  certificates, or cloud auth; `aws` often signs requests using SigV4. Merely
  providing a token is not protocol support.
* Never offer a generic `host.run({argv: guest_controlled})` endpoint.
  Arbitrary host CLI execution grants host authority and defeats confinement.

## 3. Pure service-neutral kernel and effects

The Python implementation keeps the common model, scope algebra and state
machine in the pure package `aivm_secrets/kernel/`. Authorization
(`machine.admit`) takes the authenticated claims and binding, a canonical
request, and an explicit clock sample; it knows operations only as entries of
a `Scope` -- names, typed parameter allowlists and field size caps. It has **no
GitHub operation names, PR identifiers, credentials, sockets or
subprocesses**.

There is one service mechanism, `HTTPSpec` (`aivm_secrets/kernel/https.py`),
and `kernel/service.py` maps a policy onto it:

* schema 2 is a manifest: validated declarative REST operations, optional
  fact `checks`, a declared `effect` per operation, and optional `cli`
  command tables for the guest client;
* schema 1 is *shorthand*. `kernel/presets.py` expands it into the schema-2
  manifest for GitHub pull requests -- author/head/base facts as a `check`,
  the head commit as a bound fact, a `gh` command table -- and that manifest
  is parsed by the same code. The two have one digest;
* the form is selected by the policy's explicit schema number, never by a
  guest field. One executor (`host/egress.py`) serves every manifest.

Built-in support for a provider or a tool is therefore a reviewed *data*
change. `gh pr view 7` works in a guest because a table in the manifest maps
those words to the operation `pr.view`; the guest client contains no command
of any tool, and a command the table does not list is a usage error.

The broker uniformly parses a request, authenticates/decrypts a capability,
reserves a budget slot, writes an audit admission, optionally performs a
read-only preflight, builds an effect, rechecks session/policy/time, writes an
audit dispatch, and executes the service-provided fixed-route request. Failed
write outcomes are not automatically retried. The trusted executor is pinned
by the service policy, and cannot be chosen from a URI returned by the remote
service.

The Python implementation already has this shape: `admit` leaves an open
`Ticket` in kernel state, `emit_preflight`/`emit_final` compute the effect
from the spec and the admitted request and are the only constructors of
`AuthorizedEffect`, and the executor accepts nothing else. For the Rust
refactor, keep it: the service spec must **not have arbitrary egress
capability**, and the pipeline stays

```text
ParsedGrant  -> authorize/reserve -> ReservedTicket
ReservedTicket + validated service facts -> emit -> AuthorizedEffect
AuthorizedEffect + secret-handle -> execute at pinned transport
```

The Rust kernel owns the ticket constructor; the Rust executor consumes it.
Python plugins may propose typed intentions but may not mint tickets, issue
raw effects or receive credential bytes. A scriptable Python plugin that
receives a provider token would return the design to a broad trusted-code
boundary; that is **not** a formally verified extension.

## 4. Concrete proof obligations for a plugin architecture

In addition to the current [assurance inventory](aivm-secrets-formal-assurance.md):

* **PLUGIN-01:** all service effects arise from a pinned, operator-selected
  integration, never from untrusted guest fields or dynamic imports;
* **RESOLVER-01:** credentials are passed only to the selected, pinned egress
  adapter, and the resolver is never callable by the guest;
* **ROUTE-01:** the effect's destination, method, resource key and body
  projection are exactly those induced by policy and validated arguments;
* **COMP-01:** a typed intent/permission checked by the verified Rust kernel is
  the same one the executor serializes and sends;
* **EXT-01:** extending the service registry does not alter the common
  authorization and revocation/budget invariants;
* **REFINE-01:** every service-specific parameter parser and builder either
  belongs to the verified Rust program or has an explicit refinement/assumption
  ledger. Theorem statements must quantify over **all registered adapters**
  under their admission/serialization contracts.

Aeneas currently targets primarily a **safe, sequential Rust subset**, with
limitations around concurrency, closures and dynamic dispatch. Prefer an
inductive `ServiceSpec` algebra and a single interpreter whose operations are
closed data. A dynamic Rust `Box<dyn Plugin>` abstraction may be a productive
runtime interface, but is not automatically suitable for Charon/Aeneas or
for cross-plugin theorem composition. Keep parsing, template evaluation,
route construction and transitions extractable; leave actual TLS/socket I/O
in a small trusted interpreter with an explicit refinement argument.

### Verification strategy

1. Model service specs as finite enums/lists of pinned endpoints, methods,
   finite argument sets and bounded payload transformations.
2. Prove the parser yields a canonical `ServiceSpec` or an error, including
   rejection of invalid names, header injection, path escapes and duplicate
   operation identifiers.
3. Prove an `admit` transition cannot produce an effect unless the operation
   belongs to the service spec and its typed resource arguments are permitted.
4. Prove each executor effect has exactly one matching reservation and an audit
   acknowledgment, with explicit treatment of read-only preflights.
5. Generate Lean from the *actual* Rust authorization and effect-builder code
   with Charon/Aeneas, pin toolchain versions, prohibit `sorryAx` and unreviewed
   security axioms, and include positive witnesses to avoid vacuous proofs.
6. Test cross-service conformance with the same vectors in Python, compiled
   Rust and extracted Lean. Repeat for each service manifest; don't claim
   that a proof over GitHub examples covers arbitrary custom integrations.
7. Establish executor refinement: a validated effect with service ID `s`
   cannot emit a network request to an origin outside `s`, even with hostile
   upstream responses, redirects, proxy variables or malformed arguments.

The current Python tests and design do **not** establish these proofs. They
do provide the executable counterpart of steps 1-4 and 6: a closed
`ServiceSpec`, policy acceptance vectors, admission and effect traces, and a
conformance corpus (`tests/secrets_vectors/`) the Rust and Lean
implementations must reproduce.

## 5. Deployment roadmap

* **P0 (delivered):** schema 2 host-only command/file resolution, strict
  HTTPS service manifests, service-neutral session kernel and broker,
  `invoke` guest client, cross-service tests, and schema 1 compatibility.
  No live credential smoke test or Lean proof is claimed.
* **P1 (partly delivered):** reference manifests for GitLab, GitHub and one
  non-Git service ship as examples; the typed effect IR (`Effect`) and its
  grammar are implemented and pinned by vectors. Still open: declaring the
  manifest schema frozen, optional CLI wrappers outside the TCB, and explicit
  identity semantics and auth-scope introspection per service.
* **P2:** safe-Rust implementation of common policy, typed manifest compiler,
  reservation and effect-ticket construction, with Aeneas/Lean proof artifacts.
  Keep Python/libvirt orchestration outside the verified crate.
* **P3:** credential-owning Rust service with constrained egress/serialization,
  tamper-resistant policy source, audited plugin install/approval, safe rotation
  and secret-provider refresh. Evaluate stock CLI HTTP(S) proxy modes with real
  protocol tests; do not claim universal CLI compatibility.
* **P4:** remotely bound identity with mTLS, external issuer, certificate
  binding and carefully specified non-exportable keys / snapshot semantics.
  Improve revocation and multi-session quota sharing.
* **P5:** approved third-party adapter ecosystem, signed/versioned manifests,
  conformance corpus, hardening and security review. Publication claims name
  exactly which adapter version and proof obligations have been checked.

## 6. Security and compatibility notes

* The guest does not receive the plaintext credential, but the guest **can use
  its permitted effects** while the host session exists. A leaked sealed token
  alone is insufficient to access a different host broker, but session relay
  by an active malicious guest remains possible without stronger nonexportable
  identity assumptions.
* Host policy files and credential files must remain outside shared workspaces.
  Host command resolvers run with owning host user authority; never accept
  an executable path or argv from the guest request.
* Broad API bearer tokens still exist upstream. The grant reduces what AIVM
  sends, not what an independently stolen or reused upstream token could do.
* `allow_writes` governs direct protocol methods only. A permitted GET can have
  side effects at the remote service, and a permitted POST can trigger bots;
  manifest correctness requires service-specific review.
* The HTTPS policy uses a single fixed hostname. It supports allowlisted query
  parameters, operator-pinned static headers, and operator-pinned port,
  address and trust anchor. It does not support redirects, arbitrary GraphQL documents from the guest,
  streaming, request bodies beyond flat string fields or fixed typed GraphQL
  query variables, client
  certificates, OAuth refresh or SigV4.
* `aivm-secrets` is an independent Python module in the existing `aivm` wheel.
  It can be split into its own distribution later with the same policy/wire
  contracts, after protocol stability and a compatibility period.

### Executable provenance caveat

The broker rejects a resolver executable that lies inside a declared untrusted
root (for AIVM, the shared workspace), following symlinks hop by hop, and
rejects literal path arguments resolving inside one. It also requires every
directory on the way to the executable to be controlled only by root or the
caller. This prevents executing a guest-writable script and closes the window
between checking a path and running it, but is **not a proof of dependency
provenance**. A host CLI may import modules or load
plugins/configuration from other mutable paths, and command arguments may use
other indirections. The operator must pin and audit trusted resolver programs
and all their executable dependencies, then move resolution into a dedicated
least-privilege service for production. `aivm-secrets serve` standalone has no
workspace of its own to distrust; pass `--untrusted-root DIR` to give it one.
