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
* ``aivm-secrets-agnostic-integrations.md`` -- the service manifest contract;
* ``aivm-secrets-kernel-spec.md`` -- the state machine, as specified for the
  Rust port;
* ``aivm-secrets-formal-assurance.md`` -- what is to be proved, and what is
  only tested today;
* ``aivm-secrets-validation.md`` -- what was actually run.

This is separate from repository SSH deploy keys. Existing guest-key and
dedicated ssh-agent workflows are unchanged, and ``git push`` is not added by
this feature. Only foreground ``aivm ssh`` is integrated; VS Code and detached
sessions are not.

Quick start
-----------

Install the optional dependency from a host checkout **the guest cannot
modify**, write a policy, and validate it::

    python -m pip install '.[secrets]'
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
must not live inside the workspace you share with the guest (the session
refuses to start if it does). Unknown fields, duplicate keys, wildcards and
URLs are rejected.

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
    shared workspace.

``operations``
    Up to 64 named operations. Each has a ``method`` (``GET``, ``POST`` or
    ``PATCH``) and a ``path`` template. Every ``{placeholder}`` in the path or
    in ``query`` must be declared in ``parameters`` with the exact values a
    request may use: a list of integers, a list of strings, or an integer
    range ``{"min": a, "max": b}``. ``query`` maps a name to a fixed value or
    to a ``{placeholder}``. ``POST`` and ``PATCH`` operations declare
    ``body_fields``: the names of string fields and the most bytes each may
    carry. ``response`` is ``json`` (default) or ``text``; ``accept`` overrides
    the ``Accept`` header.

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
There are no arbitrary query strings, redirects, retries, GraphQL, streaming
or request bodies beyond the declared string fields.

Shipped examples (under ``docs/examples/``):

==========================================  ===================================
``aivm-secrets-gitlab-merge-request.json``  GitLab merge-request review
``aivm-secrets-github-issues.json``         GitHub issues through schema 2
``aivm-secrets-huggingface-readonly.json``  a non-Git service
``aivm-secrets-selfhosted-pinned.json``     private CA, pinned address and port
``aivm-secrets-gitlab-readonly.json``       the smallest possible manifest
``aivm-secrets-tauceti-readonly.json``      the GitHub PR service (schema 1)
==========================================  ===================================

Writes
------

Listing a ``POST`` or ``PATCH`` operation in the policy is not enough. The
host chooses, per session, how writes are treated::

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

If a write fails, the error says what is known:

``unreachable``
    No connection was made. Nothing was sent.

``upstream_rejected``
    The service answered with a 4xx status. It did not apply the request.

``outcome_unknown``
    The request was sent and no definite answer came back. Inspect the
    service before retrying; nothing is retried automatically.

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

The GitHub pull-request service (schema 1)
------------------------------------------

The original integration remains available as a second policy schema. It
differs from a declarative manifest in one way: every operation first fetches
the selected pull request and requires its number, base repository, author and
head repository to match the policy before anything else is read or written.

::

    {
      "schema": 1,
      "repository": "TauCetiProject/TauCeti",
      "pr_numbers": [13861],
      "operations": ["pr.view", "pr.diff", "pr.comments", "pr.reviews",
                     "pr.review-comments", "pr.checks"],
      "author": "Erotemic",
      "head_repository": "Erotemic/TauCeti",
      "lifetime_seconds": 1800,
      "max_requests": 200,
      "max_body_bytes": 8192
    }

The credential comes from the owning host user's ``gh auth token``, or from
``--secrets_token_file``. In the guest the client is also installed under the
name ``gh``, so these work::

    gh pr view 13861 --repo TauCetiProject/TauCeti
    gh pr reviews 13861 --repo TauCetiProject/TauCeti --page 1
    gh pr diff 13861 --repo TauCetiProject/TauCeti

This is **not stock gh**. Results are broker JSON; ``--json``, ``gh api`` and
every other subcommand are usage errors, never a fallback. ``pr.comment`` and
``pr.edit`` (title and body only) are writes. ``pr checks`` returns check runs
for the validated head commit, not workflow logs. List operations return at
most 100 records and say ``pagination.possibly_more``.

Error codes
-----------

The client prints one fixed code and exits ``3`` (refused), ``4`` (approval
needed) or ``2`` (client or transport failure).

=====================  ====================================================
``denied``             outside the operations, values or sizes granted
``invalid_request``    not a well-formed request for that operation
``approval_required``  a host operator must approve this exact write
``expired``            the grant's lifetime has passed
``revoked``            the session, or this capability, was revoked
``exhausted``          the request budget is spent
``invalid_capability`` not a capability of this session
``resource_mismatch``  provider metadata does not match the grant (schema 1)
``unreachable``        no connection; nothing was sent
``upstream_rejected``  the service refused the request (4xx)
``upstream_error``     the service failed or redirected; not retried
``upstream_response``  the response was unusable, oversized, or echoed the
                       credential
``outcome_unknown``    a write was sent and its result is not known
=====================  ====================================================

Running the broker without AIVM
-------------------------------

The package does not depend on AIVM or libvirt::

    aivm-secrets serve --policy POLICY [--writes MODE] [--token-file FILE]

It prints the two environment variables a client needs
(``AIVM_SECRETS_SOCKET`` and ``AIVM_SECRETS_CAPABILITY_FILE``) and stays in
the foreground until its lifetime ends or Ctrl-C. Its sockets live in a
private directory under ``$XDG_RUNTIME_DIR/aivm-secrets``; audit files default
to ``$XDG_STATE_HOME/aivm-secrets/audit``. The listener is local to your UID:
do not publish or mount it elsewhere as a substitute for an authenticated
channel. ``--untrusted-root DIR`` declares a directory another party can
write; the broker then refuses to start if its own code, the policy, the
credential or the resolver lies inside it.

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
* A provider that receives the credential can misuse it; so can a wrong
  manifest. Review manifests like code.
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
