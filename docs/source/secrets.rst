Secret-use sessions
===================

``aivm-secrets`` lets a guest *use* a service credential without ever *holding*
it. The credential stays on the host. The guest receives a short-lived,
encrypted capability and may ask a host-side broker to perform a fixed list of
named operations on its behalf. Every request is checked on the host against a
policy you wrote, counted against a budget, and recorded in an audit file.

It is an experimental Python implementation, tested but not formally verified.
The architecture, the plan for a verified Rust kernel and the precise claims
are in ``docs/planning/``:

* ``aivm-secrets-design.md`` -- architecture and threat model;
* ``aivm-secrets-repository-boundary.md`` -- temporary branch policy,
  optional AIVM integration and the future separate-repository gate;
* ``aivm-secrets-agnostic-integrations.md`` -- the service manifest contract;
* ``aivm-secrets-kernel-spec.md`` -- the state machine, as specified for the
  Rust port;
* ``aivm-secrets-formal-assurance.md`` -- what is to be proved, and what is
  only tested today;
* ``aivm-secrets-validation.md`` -- what was actually run;
* ``aivm-secrets-parallel-implementations.md`` -- Python/Rust parity decision;
* ``aivm-secrets-garrett-identity.md`` -- experimental P4a signed, encrypted
  certificate-bound identity protocol and remaining deployment work.

The Python reference implementation remains supported while a separate Rust
implementation is developed for implementation-linked proofs. The Rust
backend does **not** exist in this release; Python/Rust behavioral parity is
not yet demonstrated. P4a/P4b identity and OAuth facilities are explicit opt-in host services,
with an enrolled-VM launcher. They add no listener, certificate, credential
access or session flag activation by default. No real-VM or provider smoke
validation has been completed.

This is separate from repository SSH deploy keys. Existing guest-key and
dedicated ssh-agent workflows are unchanged, and ``git push`` is not added by
this feature. Only foreground ``aivm ssh`` is integrated; VS Code and detached
sessions are not.

Opt-in Garrett OAuth-backed identity sessions
---------------------------------------------

The Python reference now supports a host-only OAuth authorization-code + PKCE
acquisition and refresh workflow with an encrypted credential vault. Its
certificate-bound identity bridge forwards only restricted operations to the
existing broker. This functionality is **never enabled automatically** by
installing or updating AIVM. It is not a generic transparent proxy for every
third-party CLI.

See ``docs/planning/aivm-secrets-garrett-oauth-implementation.md`` for the
provider profile, host login, vault, revocation and key-rotation commands,
including the synthetic-only example. The explicit managed-VM session adds
these options to the existing enrolled identity mode::

    aivm ssh ~/code/project \
      --secrets_policy="$HOME/.config/aivm/secrets/readonly-policy.json" \
      --secrets_identity_root="$HOME/.config/aivm/secrets/identity" \
      --secrets_oauth_vault="$HOME/.config/aivm/secrets/oauth-vault" \
      --secrets_oauth_provider_config="$HOME/.config/aivm/secrets/oauth-profile.json" \
      --secrets_writes=deny

The OAuth account subject is derived from the managed-VM identity. Selecting
OAuth and a token file together is refused. A completed local vault revocation
or refresh prevents the old session broker from dispatching subsequent
authorized effects. Refreshing an account requires a new bound session to use
the newly issued access token. Real provider and libvirt validation is still
pending; no Rust/Lean proof is claimed.

Quick start
-----------

Install the experimental ``aivm-secrets`` distribution explicitly from a
trusted host checkout **the guest cannot modify**. Ordinary ``pip install aivm``
installs neither this package nor its cryptographic dependencies. Until the
separate repository/distribution is published, use the sibling project::

    python -m pip install ./aivm_secrets
    install -d -m 700 "$HOME/.config/aivm/secrets"
    install -m 600 docs/examples/aivm-secrets-gitlab-merge-request.json \
        "$HOME/.config/aivm/secrets/gitlab.json"
    aivm-secrets policy-check "$HOME/.config/aivm/secrets/gitlab.json"

Edit the copy: set the project, the merge requests and the credential source
that are yours. Then open a session::

    aivm ssh "$HOME/code/project" \
        --secrets_policy "$HOME/.config/aivm/secrets/gitlab.json"

Inside the guest, ``aivm-secrets`` is on ``PATH`` (its explicit path is
``$AIVM_SECRETS_CLIENT``)::

    aivm-secrets operations
    aivm-secrets invoke mr.view --arguments '{"project":278964,"mr":101}'
    aivm-secrets invoke mr.notes --arguments '{"project":278964,"mr":101,"page":1}'

Closing the SSH session ends the broker and revokes the capability.

What the guest can and cannot do
--------------------------------

A request is an operation name and typed arguments -- nothing else::

    {"operation": "mr.view", "arguments": {"project": 278964, "mr": 101}}

It cannot supply a URL, host, HTTP method, header, credential, query string or
body shape. Those come only from the policy. The guest client is a
convenience: a guest may replace or bypass it and gains nothing, because every
check is made on the host. There is no ``host.exec``, no raw API passthrough
and no fallback to an unrestricted tool.

The guest holds three things: the path of a forwarded socket, a file of
ciphertext, and the client script. The session's encryption key and the
service credential never leave the host.

Writing a policy
----------------

A policy is a host-owned JSON file. It must not be writable by other users and
must not be reachable through the workspace you share with the guest: the
session refuses to start if the path, any symbolic link on the way, or the
place it finally leads lies inside that folder. Unknown fields, duplicate
keys, wildcards and URLs are rejected.

::

    {
      "schema": 2,
      "adapter": "https",
      "service": "gitlab-mr-review",
      "host": "gitlab.com",
      "authentication": "bearer",
      "credential_source": {
        "kind": "command",
        "argv": ["op", "read", "op://Work/GitLab/personal-token"],
        "inherit_env": ["XDG_CONFIG_HOME"]
      },
      "operations": [
        {
          "name": "mr.notes",
          "effect": "read",
          "method": "GET",
          "path": "/api/v4/projects/{project}/merge_requests/{mr}/notes",
          "query": {"per_page": "100", "page": "{page}"},
          "parameters": {
            "project": [278964],
            "mr": [101, 102],
            "page": {"min": 1, "max": 20}
          }
        },
        {
          "name": "mr.note",
          "effect": "write",
          "method": "POST",
          "path": "/api/v4/projects/{project}/merge_requests/{mr}/notes",
          "parameters": {"project": [278964], "mr": [101]},
          "body_fields": {"body": 4096}
        }
      ],
      "lifetime_seconds": 1800,
      "max_requests": 100,
      "max_body_bytes": 4096
    }

``host``
    One lowercase public DNS name. It is always the name TLS authenticates.
    Addresses, ports in the name, ``localhost`` and ``.local`` are refused.

``authentication``
    ``bearer`` (``Authorization: Bearer ...``) or ``x-api-key``.

``credential_source``
    Where the *host* obtains the credential. ``{"kind": "file", "path": ...}``
    reads a private file (owner-only, no hard links). ``{"kind": "command",
    "argv": [...]}`` runs a program with no shell, a closed stdin, a discarded
    stderr, and an environment of ``HOME`` and ``PATH`` plus the variables
    named in ``inherit_env``. The program is trusted host code: it must be
    owned by you or root, on a path no other user can modify, and outside the
    shared workspace. It is located and checked once, and the checked file
    itself is what runs -- a link re-pointed afterwards changes nothing.

``operations``
    Up to 64 named operations. Each states its ``effect`` -- ``read`` or
    ``write`` -- a ``method`` (``GET``, ``POST`` or ``PATCH``) and a ``path``
    template. Every ``{placeholder}`` in the path or in ``query`` must be
    declared in ``parameters`` with the exact values a request may use: a
    list of integers, a list of strings, or an integer range ``{"min": a,
    "max": b}``. ``query`` maps a name to a fixed value or to a
    ``{placeholder}``. ``POST`` and ``PATCH`` operations declare
    ``body_fields``: the names of string fields and the most bytes each may
    carry (``{"max_bytes": n, "optional": true}`` for a field that may be
    left out). ``response`` is ``json`` (default) or ``text``; ``accept``
    overrides the ``Accept`` header.

    ``effect`` is required and is never guessed from the method. Ordinary
    ``POST`` and ``PATCH`` must be ``write``. A fixed GraphQL query is the
    only body-carrying ``read`` exception. A ``GET`` is usually ``read``; if the service
    changes state on one, declare it ``write`` and it is treated as a write
    everywhere: refused under ``--secrets_writes deny``, held for approval,
    and reported as ``outcome_unknown`` if it fails. Declaring a
    state-changing request ``read`` is the one mistake the broker cannot
    catch for you.

``egress`` (optional)
    For a private deployment: ``port``, an ``address`` to connect to (TLS still
    authenticates ``host``), and a ``ca_file`` that *replaces* the system trust
    roots for this service. See
    ``docs/examples/aivm-secrets-selfhosted-pinned.json``.

``headers`` (optional)
    Static headers to pin, such as an API version. Authentication, ``Host``,
    cookie, content and proxy headers cannot be set this way.

``lifetime_seconds``, ``max_requests``, ``max_body_bytes``
    Session limits: at most one hour, 1,000 requests and 16,384 body bytes.

Path and query values are restricted to letters, digits and ``-._~``, so a
request target is built without escaping and cannot be steered by an argument.
A string parameter used only in the path may list values with several such
segments (``"my-org/my-repo"``). There are no arbitrary query strings,
redirects, retries, streaming or arbitrary request bodies. A ``graphql``
block may declare **one fixed named query**, an operation name and a bounded
map of allowlisted scalar variables. Its operation must be ``POST``, with
``effect: read``; the query document is taken from the host policy, **never**
from the guest. GraphQL resolvers being non-mutating is a provider contract,
not a guarantee obtained by inspecting the query text.

File and directory permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The policy, a credential file, a trust anchor, a resolver program and every
directory leading to them must be owned by you or root and writable by nobody
else. World-writable is refused unless the directory is sticky (``/tmp``).

Group-writable is accepted only when the group is provably yours alone: it is
your primary group, it lists no other member, no other account has it as
*its* primary group, and the host's accounts are all local (``passwd: files``
or ``files systemd`` in ``/etc/nsswitch.conf``) so that every account can be
seen. That is the stock Ubuntu arrangement of a per-user group and ``umask
0002``. On a host with a directory service (``sss``, ``ldap``, ...) other
accounts cannot be enumerated, so group-writable paths are refused; run
``chmod g-w`` on the files and directories the error names.

Conditions on live data: ``checks``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An allowlist of identifiers is sometimes not enough: "merge request 101" says
nothing about who opened it. A manifest can state facts that must hold *right
now*, fetched from the service before anything else happens::

    "checks": {
      "pull": {
        "path": "/repos/{repository}/pulls/{pr}",
        "require": [
          {"at": ["number"], "equals_parameter": "pr"},
          {"at": ["user", "login"], "equals": "octocat", "fold": true}
        ],
        "bind": {"head_sha": {"at": ["head", "sha"], "format": "hex"}}
      }
    },
    "operations": [
      {"name": "pr.view", "effect": "read", "requires": "pull",
       "returns": "check",
       "parameters": {"repository": ["my-org/my-repo"], "pr": [7]}},
      {"name": "pr.checks", "effect": "read", "requires": "pull",
       "method": "GET",
       "path": "/repos/{repository}/commits/{head_sha}/check-runs",
       "parameters": {"repository": ["my-org/my-repo"], "pr": [7]}}
    ]

An operation that ``requires`` a check first performs that ``GET``. Each
``require`` entry names a value in the JSON answer by its object keys (``at``)
and what it must equal: a literal (``equals``) or one of the request's own
parameters (``equals_parameter``). Types must match exactly; ``"fold": true``
compares strings without regard to ASCII case. If any fact does not hold, the
request ends with ``resource_mismatch`` and nothing further is sent.

``bind`` gives a value from the answer a name that later paths may use as a
``{placeholder}``. It must have the stated ``format`` -- ``hex`` (a 40- or
64-digit hash), ``integer`` or ``segment`` -- or the request is refused; a
service cannot steer a request by what it returns.

``"returns": "check"`` makes the verified answer itself the result: such an
operation has no method or path of its own and must be a read.

Three smaller conveniences live on an operation:

``defaults``
    Values for parameters a request may omit, e.g. ``{"page": 1}``.

``fold``
    String parameters to lowercase before they are compared, for services
    whose names are case-insensitive. The allowlist itself must be lowercase.

``page``
    ``{"size": 100, "parameter": "page", "at": ["items"]}`` marks a list
    answer as one page. The reply then carries ``pagination`` with
    ``possibly_more``, so one page is never mistaken for the whole list.

Shipped examples (under ``docs/examples/``):

==========================================  ===================================
``aivm-secrets-gitlab-merge-request.json``  GitLab merge-request review
``aivm-secrets-github-issues.json``         GitHub issues through schema 2
``aivm-secrets-github-pr.json``             the built-in GitHub PR manifest,
                                            written out in full
``aivm-secrets-huggingface-readonly.json``  a non-Git service
``aivm-secrets-selfhosted-pinned.json``     private CA, pinned address and port
``aivm-secrets-gitlab-readonly.json``       the smallest possible manifest
``aivm-secrets-tauceti-readonly.json``      the GitHub PR shorthand (schema 1)
==========================================  ===================================

Writes
------

Listing an operation whose ``effect`` is ``write`` is not enough. The host
chooses, per session, how writes are treated::

    aivm ssh . --secrets_policy POLICY --secrets_writes MODE

``deny`` (default)
    Reads only. Every write is refused before anything is sent.

``approve``
    Each write waits for you. The guest's request is refused with
    ``approval_required`` and held, exactly as sent, on the host. From another
    host terminal::

        aivm-secrets pending
        aivm-secrets approve DIGEST

    ``pending`` shows the operation and its complete arguments; ``approve``
    shows them again and asks for confirmation (``--yes`` to skip the prompt).
    The guest then repeats the identical request, which is sent once. An
    approval covers one request with exactly those bytes, expires after five
    minutes by default (``--ttl``), and is used up even if the write then
    fails. ``aivm-secrets deny DIGEST`` discards a pending write.

``allow``
    Policy-listed writes proceed without a prompt. The whole permitted body is
    delegated to the guest, up to the size limit.

A permitted write can have effects you did not list: a comment can trigger a
repository bot. Denying a "merge" operation is not proof that nothing can
cause a merge.

If a write fails, the error says what is known -- and only two things can be:

``unreachable``
    No connection was made. Nothing was sent.

``outcome_unknown``
    The request was sent and did not come back as a success. **Any** other
    answer means this, including a 4xx status (shown as ``outcome_unknown
    (HTTP 409)``): a service may apply a write and then report a conflict or
    a validation error, so no status proves that nothing happened. Inspect
    the service before retrying; nothing is retried automatically.

A failed *read* is different, because there is nothing to have applied:
``upstream_rejected`` means the service answered 4xx.

The same rule holds on the way back to the guest. When the identity bridge
has handed a request to the broker and gets no well-formed answer in time
(or the broker hangs up), the guest is told ``outcome_unknown``, whether or
not it was a write, because the bridge cannot tell whether the broker acted.
The guest client says the same when its own wait runs out after sending; a
reply it cannot read is a client or transport failure (exit ``2``), which is
not retried either. Each hop waits longer than the one behind it (the
broker's worst case for one request is two provider calls of at most 45 s
each; the bridge waits 120 s for it, the guest client 150 s), so the hop
nearest the broker is normally the one that answers.

``outcome_unknown`` does not mean the request is over. The broker runs one
request at a time and never abandons a request it has read, and those 120 s
count only a request's own work, not the time it waited behind others (or
behind another session holding an OAuth vault). So a request answered
``outcome_unknown`` -- typically one of several sent at once to a slow
service -- may still be carried out *after* that answer. A check made
straight away that finds nothing applied is not proof that nothing will be;
look again once the session's other requests have finished.

Delegating to a helper
----------------------

A guest process can mint a strictly smaller capability, for example to hand a
sub-agent access to one item for a few requests::

    aivm-secrets delegate --output helper.cap --scope '{
        "operations": {"mr.view": {"mr": [101]}},
        "max_requests": 5,
        "lifetime_seconds": 300
    }'
    aivm-secrets --capability-file helper.cap invoke mr.view \
        --arguments '{"project":278964,"mr":101}'

A child can name only operations and values its parent has, can only shorten
its lifetime, and spends its parent's request budget rather than a budget of
its own. Revoking a capability revokes everything delegated from it.
``aivm-secrets renounce`` gives a capability up.

Managing sessions from the host
-------------------------------

::

    aivm-secrets sessions                 # live sessions, usage, time left
    aivm-secrets revoke SESSION           # by the id shown in ``sessions``
    aivm-secrets revoke --vm NAME         # or by VM / access identity
    aivm-secrets revoke --all
    aivm-secrets audit-verify FILE...

A session ends, and its capability stops working, when any of these happens:

* the foreground ``aivm ssh`` process exits or is killed -- the broker is a
  child process bound to it and cannot outlive it;
* its lifetime elapses (the shell stays open; requests answer ``expired``);
* you run ``aivm-secrets revoke``;
* the AIVM access identity it was opened for is disabled or removed
  (``aivm vm access disable``), by you or by an administrator, from any
  terminal -- noticed within a few seconds;
* writing an audit record fails.

Each session starts with a fresh encryption key that is never written to
disk, so a capability from one session is rejected by every other session.

Auditing
--------

``aivm ssh`` prints the audit file's path; it lives under the profile's
``secrets-audit`` directory. Each line records an event, a fixed outcome code,
the operation, its allowlisted resource identifiers and digests. It never
contains a credential, a capability, a request body or provider text.

Records are chained: each carries the hash of the one before, and a record is
written and flushed to disk *before* the action it announces.
``aivm-secrets audit-verify`` detects a record that was removed, reordered or
edited. It cannot detect that the end of a file was cut off unless you kept
the head digest printed when the session closed. A local file is not
tamper-proof against the host user or root.

Built-in: GitHub pull requests (schema 1)
-----------------------------------------

GitHub pull-request review is supported out of the box, and it is **not a
special case**. ``schema: 1`` is shorthand for a manifest in exactly the
format above::

    {
      "schema": 1,
      "gh_compat": 2,
      "repository": "TauCetiProject/TauCeti",
      "pr_numbers": [13861],
      "operations": ["pr.view", "pr.diff", "pr.comments", "pr.reviews",
                     "pr.review-comments", "pr.checks", "pr.summary",
                     "pr.review-threads"],
      "author": "Erotemic",
      "head_repository": "Erotemic/TauCeti",
      "lifetime_seconds": 1800,
      "max_requests": 200,
      "max_body_bytes": 8192
    }

``aivm-secrets policy-check`` prints what it stands for: a schema-2 manifest
for ``api.github.com`` whose ``pull`` check requires the PR's number, base
repository, author and head repository to match before anything else is read
or written, and which binds the head commit for ``pr.checks``. The shorthand
and that manifest are the same policy, with the same digest. Copy the output
(or ``docs/examples/aivm-secrets-github-pr.json``) to change anything the
shorthand does not offer.

``gh_compat: 2`` enables the richer command-table syntax. Leaving it out
preserves the original schema-1 command table and canonical policy digest,
including the old requirement to specify ``-R`` explicitly. See
``docs/examples/aivm-secrets-tauceti-gh2.json`` for a read-only example.

The credential comes from the owning host user's ``gh auth token``, or from
``--secrets_token_file``. ``pr.comment`` and ``pr.edit`` (title and body
only) are writes. ``pr.checks`` returns check runs for the validated head
commit, not workflow logs. The optional ``pr.summary`` and
``pr.review-threads`` operations are **fixed**, reviewed GraphQL reads.
A schema-1 policy must explicitly grant them. REST lists return at most
100 records and say ``pagination.possibly_more``; the JSON compatibility
client refuses to output an incomplete check run list or truncated review
list as though it were complete.

Answering to another tool's name: ``cli``
-----------------------------------------

Agents already know command lines like ``gh pr view 7``. A manifest can teach
the guest client to accept them::

    "cli": {
      "gh": [
        {"command": ["pr", "view"], "operation": "pr.view",
         "positional": ["pr"],
         "options": {"--repo": "repository", "-R": "repository"}},
        {"command": ["pr", "comment"], "operation": "pr.comment",
         "positional": ["pr"],
         "options": {"--repo": "repository", "--body": "body",
                     "--body-file": "@body"}},
        {"command": ["pr", "diff"], "operation": "pr.diff",
         "positional": ["pr"], "options": {"--repo": "repository"},
         "output": "result"}
      ]
    }

For every name under ``cli``, the client is also installed in the guest under
that name. Each row maps the words of one command to an operation:
``positional`` names the arguments that follow, ``options`` maps flags to
arguments (``@name`` reads the value from a file, or ``-`` for standard
input), and ``"output": "result"`` prints just the result, raw if it is text.
The built-in GitHub manifest ships such a table; the extension enabled by
``gh_compat: 2`` adds bounded JSON rendering and repository inference::

    gh pr view 13861 --repo TauCetiProject/TauCeti
    gh pr reviews 13861 --repo TauCetiProject/TauCeti --page 1
    gh pr diff 13861 -R TauCetiProject/TauCeti
    gh pr comment 13861 --repo TauCetiProject/TauCeti --body-file notes.md

``aivm-secrets as gh pr view ...`` is the same thing spelled out. The table is
a translation aid for the guest and grants nothing: the result is an ordinary
request, checked on the host like any other.

This is **not the real tool**. With ``gh_compat: 2``, the command table supports a
bounded subset of ``--json``, with locally rendered fields and explicit
repository inference from ``GH_REPO`` or Git remotes. Missing fields are
not fabricated. The optional ``pr.summary`` operation enables fields such as
``reviews`` and ``reviewDecision`` through a separately authorized fixed
GraphQL read. For example::

    gh pr view 13861 -R TauCetiProject/TauCeti --json title,body,number
    gh pr checks 13861 -R TauCetiProject/TauCeti --json name,state,link
    gh pr view 13861 -R TauCetiProject/TauCeti --json title,reviews,reviewDecision

The third command requires ``pr.summary`` explicitly in the policy.
``gh api``, arbitrary GraphQL, workflow logs, ``--jq``, ``--template``,
implicit PR selection and unsupported flags still fail closed with exit
status 2. A ``gh`` wrapper provides a **subset**, not drop-in stock CLI
compatibility. Host policy remains authoritative regardless of what the
guest infers as a repository.

Error codes
-----------

The client prints one fixed code and exits ``3`` (refused), ``4`` (approval
needed) or ``2`` (client or transport failure).

======================  ====================================================
``denied``              outside the operations, values or sizes granted
``invalid_request``     not a well-formed request for that operation
``approval_required``   a host operator must approve this exact write
``expired``             the grant's lifetime has passed
``revoked``             the session, or this capability, was revoked
``exhausted``           the request budget is spent
``invalid_capability``  not a capability of this session
``resource_mismatch``   a ``checks`` fact fetched from the service does not
                        hold
``unreachable``         no connection; nothing was sent
``upstream_rejected``   the service refused a read (4xx)
``upstream_error``      the service failed or redirected; not retried
``upstream_response``   the response was unusable, oversized, or echoed the
                        credential
``outcome_unknown``     a write was sent and did not succeed, or a request
                        was sent and no answer came back in time; either
                        way it may have been applied
======================  ====================================================

Running the broker without AIVM
-------------------------------

The package does not depend on AIVM or libvirt::

    python -I -m aivm_secrets serve --policy POLICY [--writes MODE] \
        [--token-file FILE]

Start it with ``python -I`` as shown, and from an environment without
``PYTHONPATH``, ``LD_PRELOAD`` and the like: those variables decide what code
the broker *is*. ``aivm ssh`` does both for you.

It prints the two environment variables a client needs
(``AIVM_SECRETS_SOCKET`` and ``AIVM_SECRETS_CAPABILITY_FILE``) and stays in
the foreground until its lifetime ends or Ctrl-C. Its sockets live in a
private directory under ``$XDG_RUNTIME_DIR/aivm-secrets``; audit files default
to ``$XDG_STATE_HOME/aivm-secrets/audit``. The listener is local to your UID:
do not publish or mount it elsewhere as a substitute for an authenticated
channel. ``--untrusted-root DIR`` declares a directory another party can
write. The broker then refuses to start if the policy, the credential, the
resolver or a trust anchor is reachable through it, or if its own
interpreter, module search path or any loaded module comes from it.

Optional P4a certificate-bound identity (experimental)
------------------------------------------------------

The separate ``aivm-secrets identity`` command family implements **manual**
certificate enrollment and a bounded TLS 1.3 bridge that ultimately invokes
the existing broker, not a second privileged executor. Privileged host
commands require ``python -I -m aivm_secrets identity`` from a trusted install. See
``docs/planning/aivm-secrets-p4a-enrollment.md`` for the complete operational
sequence, security assumptions and remaining VM integration work.

On the trusted host, initialize an owner-only local authority explicitly::

    install -d -m 700 "$HOME/.config/aivm/secrets"
    python -I -m aivm_secrets identity init --root "$HOME/.config/aivm/secrets/identity"

Inside a guest that separately has the secrets package installed, create a
software private key and CSR (no VM is modified automatically)::

    install -d -m 700 "$HOME/.config/aivm/identity"
    aivm-secrets identity request \
        --key "$HOME/.config/aivm/identity/client.key" \
        --csr "$HOME/.config/aivm/identity/client.csr"

**Enrollment requires independent host verification of the CSR key
fingerprint and the VM it belongs to.** The signature on a CSR authenticates
the software key, not the VM. The host explicitly enrolls with isolated Python using
``python -I -m aivm_secrets identity enroll --subject ... --csr ... --approve-key-fingerprint ...``;
that operator-approved mapping is not yet integrated with the AIVM machine
store. The issued public certificate and host CA certificate may be copied
into the guest. The host CA private key, JWT signer and AEAD key may **not**.

For an existing separately started and scoped AIVS broker, ``identity issue``
wraps its host-only capability in a signed, encrypted, certificate-bound JWT.
``python -I -m aivm_secrets identity bridge`` starts a foreground **Unix** listener.
It serves up to 16 connections at once, so a slow provider call no longer
holds up other callers' TLS handshakes or the answers the bridge gives by
itself (a refused delegation, a wrong binding, a revoked certificate). The
broker behind it still runs requests one at a time: a call that needs the
broker -- every ``describe`` and ``request`` -- waits behind the one in
progress, and that wait counts against the caller's deadline. It has no
connection cap by default: it ends when its operator stops it, when the
parent holding ``--exit-on-stdin-eof`` closes its stdin, or after
``--idle-seconds`` with nothing in flight (``--max-connections N`` is still
accepted, for a deliberately short-lived bridge). When the lease closes it
stops listening and removes its socket at once, and gives a call still in
flight a few seconds to be answered, not the full provider wait. ``--subject NAME`` pins it to one enrolled subject: a certificate the
same CA enrolled for anyone else is refused (``wrong_binding``) before
anything reaches the broker. It forwards only to a socket named
``broker.sock``, and checks that socket's type, owner and mode again on every
request. ``identity call`` speaks verified TLS over an explicitly forwarded socket.
A revoked or replaced certificate is denied on its next request, and the
broker still checks the operation, resource, budget and approval. Host-only
OAuth/PKCE acquisition is described earlier in this guide, but the local
bridge does not create a public TCP endpoint, vTPM identity, or Rust proof.

**This is not enabled by ordinary ``aivm ssh`` or by installing the package.**
Even ``aivm ssh --secrets_policy`` continues to forward its existing unbound
broker socket; use an explicitly forwarded P4a identity socket *instead* if
certificate binding is the desired property. Do not forward both.

What this does not protect against
----------------------------------

* A guest can use every operation its capability permits for as long as the
  session lives, and can relay that ability to anything it talks to.
* The upstream credential is as broad as you created it. The policy limits
  what AIVM sends, not what a separately stolen token could do.
* Root and your own other host processes are trusted. Do not share your home
  directory, credential store, or the broker's installation with a guest.
  A broker installed in editable mode from the very folder you attach, or
  running from a virtualenv inside it, is refused.
* ``aivm ssh`` starts the broker isolated from ``PYTHONPATH`` and similar
  variables, but AIVM itself is an ordinary program: if your own shell loads
  Python code from a folder the guest can write, the guest already runs code
  as you, and no broker can help.
* A provider that receives the credential can misuse it; so can a wrong
  manifest -- in particular one that declares a state-changing request a
  ``read``. Review manifests like code.
* Timing, response sizes and the content of permitted responses are visible
  to the guest by design.

Validation
----------

::

    python -m pytest -o addopts='' -q tests/test_secrets_*.py
    AIVM_E2E=1 python -m pytest -o addopts='' -s tests/e2e/test_secrets.py

The first runs offline, against in-process fakes and a real TLS server on
loopback. The second creates a real KVM guest and drives real interactive
sessions through it; it needs libvirt/KVM and passwordless sudo, and uses a
throwaway certificate authority and a made-up token, so it contacts no third
party. Neither is a live test against a real provider: before relying on a
policy, run one read-only session against the real service and confirm that
an operation outside the policy is refused.

Managed-VM certificate enrollment (experimental)
------------------------------------------------

The experimental Python P4a VM adapter is **opt-in**. For an already managed
VM that has the updated forced bootstrap helper, first initialize an identity
authority as described above, then explicitly enroll the current host principal::

    aivm vm identity_enroll --vm=lab --identity_root="$HOME/.config/aivm/secrets/identity"

Every principal-account SSH step of enrollment checks the guest's host key
strictly against the VM's pinned bootstrap ``known_hosts`` -- or, on a shared
machine store where that file is root-only, against your own
``known_hosts`` -- never trusting a key on first use. The live libvirt UUID
read runs through sudo, announced, on hosts where ``virsh`` needs it. A
certificate-bound session also needs **unattended read access** to
``qemu:///system`` for its running identity watchdog: the foreground launcher
checks this before issuing a session capability, and the watchdog uses only
``sudo -n``, never a password prompt. Use direct libvirt group access or a
narrowly scoped ``NOPASSWD`` permission for ``virsh domuuid``. A cached sudo
password may expire mid-session, in which case the broker fails closed after
three unsuccessful polls. Ordinary ``aivm ssh`` needs none of this. An
expected failure (an old forced helper, an unpinned host key, a renewal
conflict, a changed domain UUID) prints one ``Identity operation failed:``
line with its operator detail and exits with status 1; a declined prompt
aborts the command as your decision.

Enrollment does not grant provider access. After separately creating a host-only
policy, choose the mTLS-only launcher::

    aivm ssh . --secrets_policy="$HOME/.config/aivm/secrets/lab-readonly.json" --secrets_identity_root="$HOME/.config/aivm/secrets/identity" --secrets_writes=deny

An explicitly enrolled managed VM can renew its seven-day public certificate
and revoke the old epoch using the same pinned forced-bootstrap channel::

    aivm vm identity_renew --vm=lab --identity_root="$HOME/.config/aivm/secrets/identity"

This reuses the guest's *active* software key and does not rotate the CA:
the guest first re-signs its CSR with ``client.key`` (even with an older
forced helper, through a fixed host-delivered step), so a renewal after a key
rotation certifies the rotated key. Every install checks that the issued
certificate's public key is the guest key it will be used with before
replacing anything.
To explicitly replace the guest-owned software key and its client certificate
with epoch fencing, run (on a managed VM with the updated forced helper)::

    aivm vm identity_rotate_key --vm=lab --identity_root="$HOME/.config/aivm/secrets/identity"

A key-rotation attempt is never automatic. A failed activation revokes the
new enrollment with an epoch+thumbprint guarded revocation; when that cannot
complete, or when you decline or interrupt a step after the certificate was
issued, AIVM prints the exact
``python -I -m aivm_secrets identity revoke-if-current ...`` command to run
instead of continuing. If the certificate authority's reply is lost after it
may have committed, the command fails with ``outcome_unknown`` and names the
certificate the registry now holds; that may instead be another operator's
concurrent enrollment, so check before revoking it. An interrupt while the
authority is issuing logs the registry read and the guarded revocation to
fill in, and runs nothing more. See
``docs/planning/aivm-secrets-garrett-guest-key-rotation.md``.
A stale epoch or certificate thumbprint fails closed. It requires a fresh
certificate-bound session token afterward. The separate host-only command
``python -I -m aivm_secrets identity renew-server --root ...`` renews the
30-day local TLS server leaf and key beneath the current CA; **restart**
the identity bridge for that keypair to take effect. For an explicit,
fail-closed CA replacement with **no dual-root grace period**, use the
host-only ``identity rotate-ca --root ... --expected-ca-sha256 SHA`` command,
where ``SHA`` is the ``ca_sha256`` that ``identity status`` prints. The
expected root is required: a stale or repeated run is refused before anything
changes, so it cannot revoke enrollments made under the new root. CA rotation
revokes every enrollment (each row becomes inactive and its epoch advances,
so a re-enrollment is newer unless the row was forgotten in between, see
below), prints and audits the revoked ``{subject, epoch, certificate_sha256}``
list, and requires bridge restart,
distribution of the NEW public CA, explicit re-enrollment (a VM that has run
``identity_rotate_key`` first needs the CSR step described below) and new
bound session tokens. Do not run it to renew a server leaf. See
``docs/planning/aivm-secrets-garrett-ca-lifecycle.md`` and
``docs/planning/aivm-secrets-garrett-certificate-lifecycle.md``.

The host enforces key custody on every enrollment change. ``identity_renew``
(``identity renew-client``) re-certifies only the enrolled key; a CSR for any
other key is refused. A key replaced by ``identity_rotate_key`` or
``identity enroll --replace`` is retired for the VM's identity subject
(below). It is refused for that subject while it is among the last 8 keys
retired for it, and only until that subject's enrollment is forgotten (see
``identity forget`` below); retirement does not follow the VM to a new
subject. A key enrolled for one active subject is refused for any other, so a
cloned guest's copied key cannot gain a second identity while the original
enrollment is active. AIVM reports either refusal only as "identity service
refused the operation"; the host-only ``aivm-secrets identity`` command says
which rule refused.

A VM's identity subject is derived from its name, its machine store, the
owning principal and its libvirt domain UUID. Renaming a VM, moving it to
another store or changing its owning principal gives it a new subject, with
no retired keys, while the old enrollment may still be active and hold the
guest's key. If it does, ``identity_enroll`` for the renamed VM is refused,
because another active subject holds the key. Until AIVM offers to revoke the
old enrollment on rename, revoke it by hand first. Inside the guest, this
prints the key's fingerprint::

    openssl pkey -in ~/.config/aivm/identity/client.key -pubout -outform DER | sha256sum

Find the row with that ``key_sha256`` in ``identity status``, and run
``identity revoke --root ... --subject OLD`` with that row's subject. If the
VM has ever run ``identity_rotate_key``, regenerate its CSR first (below):
its stale CSR carries the original key, which nothing refuses under the new
subject.

**Guests rotated before the CSR fix.** The original activation script left
the original key's CSR in ``client.csr``. The host refuses that stale CSR
instead of re-certifying the rotated-away key, so AIVM regenerates
``client.csr`` from ``client.key`` over the pinned principal channel before
every ``identity_enroll`` and ``identity_renew``, and the updated forced
helper signs a fresh CSR with ``client.key`` on every request. Managed
renewals therefore present the active key even when the guest's helper
predates the fix. Only a standalone enrollment from an operator-supplied CSR
still needs the manual step, run inside the guest as the guest user::

    cd ~/.config/aivm/identity && umask 077 &&
      openssl req -new -key client.key -out client.csr -subj /CN=aivm-guest

If ``identity_rotate_key`` fails while activating the new key, AIVM revokes
the new enrollment. The guest is left on its old key, which is now retired,
so re-enrolling it is refused. Reset the guest identity instead: inside the
guest, remove ``client.key``, ``client.csr``, ``client.rotate.key`` and
``client.rotate.csr`` from ``~/.config/aivm/identity``, then run
``identity_enroll``, which generates a fresh key.

``identity enroll --replace`` accepts an optional compare-and-swap,
``--expected-epoch N --expected-certificate-sha256 T`` (both together), which
refuses the replacement if the enrollment changed since it was inspected.

The registry holds at most 128 enrollments, revoked ones included. Two
locked, audited host-only verbs free slots::

    python -I -m aivm_secrets identity forget --root ... --subject SUBJECT
    python -I -m aivm_secrets identity prune --root ...

Both remove only enrollments that are revoked **and** whose certificate has
expired, and print the removed ``{subject, epoch, certificate_sha256}`` list.
A forgotten subject would restart at epoch 0, which is harmless: its
certificate has expired and every token bound to it expired no later.
Managed-VM subjects embed the libvirt domain UUID, so a recreated VM is a new
subject anyway. A VM that still exists keeps its subject, though, through
revocation and ``rotate-ca``, and ``prune`` also removes its row once it is
revoked and its last certificate (valid for 7 days) has expired. Forgetting a
row discards the keys retired for it, so the next enrollment of that VM
certifies whatever key its CSR carries, including a key it rotated away from.
Before enrolling such a VM again, make sure its ``client.csr`` was made from
its current ``client.key`` (regenerate it as above), or reset its guest
identity.

This mode forwards **only** the bound mTLS bridge socket, not the unbound broker
socket or repository agent. Ordinary ``aivm ssh`` is unchanged. Existing guest
helpers must be upgraded explicitly; there is no silent bootstrap upgrade.
This is not vTPM/non-exportable-key attestation and has not yet been smoke-tested
against a live libvirt VM. See ``docs/planning/aivm-secrets-p4a-managed-vm.md``
for the trust model, cleanup semantics, and known clone/restore limitations.
