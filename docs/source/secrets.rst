Experimental secret-use sessions
===============================

``aivm-secrets`` keeps a GitHub credential on the host and gives a guest a
short-lived encrypted capability for selected pull-request operations. It is an
experimental Python implementation, not formally verified software. The
architecture and proof roadmap live in ``docs/planning/aivm-secrets-design.md``
and ``docs/planning/aivm-secrets-formal-assurance.md``.

This is separate from repository SSH deploy keys. Existing guest-key and
dedicated ssh-agent workflows are unchanged. Git push is not added by this
feature. Only foreground ``aivm ssh`` is integrated; VS Code is not yet wired.

Host setup
----------

Install from a trusted host checkout which the guest cannot modify::

    cd "$HOME/code/aivm"
    python -m pip install -e '.[secrets]'
    install -d -m 700 "$HOME/.config/aivm/secrets"
    install -m 600 docs/examples/aivm-secrets-tauceti-readonly.json \
        "$HOME/.config/aivm/secrets/tauceti.json"
    aivm-secrets policy-check "$HOME/.config/aivm/secrets/tauceti.json"

The example grants only PR 13861. It is an example identifier from the campaign,
not a claim about the PR's current existence or ownership. Review the policy
and change its PR list to the exact approved campaign PRs before use. Both the
PR author and head repository are checked against fresh provider metadata.

The default credential source is the **owning host user's** existing ``gh``
login. Check it on the host, never in the guest::

    gh auth status --hostname github.com
    aivm ssh "$HOME/code/TauCeti" \
        --secrets_policy "$HOME/.config/aivm/secrets/tauceti.json"

The explicit VM SSH identity, existing access-identity checks and repository
agent options remain in effect. This command requires the already-established
VM host key and streamlocal forwarding support in the guest sshd. A forwarding
failure stops the session rather than changing sshd policy automatically.

Alternatively, supply a private host token file with
``--secrets_token_file "$HOME/.config/aivm/secrets/github.token"``. Its final
path must be a regular file owned by the current UID, with no group/other
permissions and no additional hard links. Do not place it in the shared
workspace, pass its value as an argument, or export it in the guest environment.
No provider token or encryption key is written into the guest by this feature.

The policy must also be host-owned and not group/other writable. Keeping it
mode 0600 is recommended even though it is not the provider credential. The
adapter rejects policy/token paths under the current workspace, but does not
prove that no previous attachment exposes them. Do not share your host home,
credential store, broker source installation, runtime or audit directories.

Guest commands
--------------

The session installs a restricted, standard-library-only client named ``gh``
in its private temporary directory. It prepends that directory to ``PATH``.
A login shell profile can change ``PATH`` again, so the stable explicit form is::

    "$AIVM_SECRETS_CLIENT" pr view 13861 --repo TauCetiProject/TauCeti
    "$AIVM_SECRETS_CLIENT" pr reviews 13861 --repo TauCetiProject/TauCeti
    "$AIVM_SECRETS_CLIENT" pr review-comments 13861 --repo TauCetiProject/TauCeti
    "$AIVM_SECRETS_CLIENT" pr comments 13861 --repo TauCetiProject/TauCeti --page 1
    "$AIVM_SECRETS_CLIENT" pr checks 13861 --repo TauCetiProject/TauCeti
    "$AIVM_SECRETS_CLIENT" pr diff 13861 --repo TauCetiProject/TauCeti

When that directory remains first on ``PATH``, the same calls work as ``gh pr
view ...`` and so on. This is **not stock gh**: results are broker-native JSON,
``--json`` and ``gh api`` are unsupported, and unsupported commands never fall
back to an unrestricted client. A custom caller may send the documented
version-1 JSON request over the socket; the host still enforces every check.

``pr checks`` returns check runs for the validated head SHA, not workflow logs
or combined commit status contexts. ``pr review-comments`` returns REST review
comments, not GraphQL unresolved-thread state. List operations return at most
100 records and include ``pagination.possibly_more``. Request subsequent pages
explicitly; each call consumes one admission. Large diffs/responses fail closed.
The existing campaign polling script may require a separate adapter.

Policy schema
-------------

The shipped example is::

    {
      "schema": 1,
      "repository": "TauCetiProject/TauCeti",
      "pr_numbers": [13861],
      "operations": [
        "pr.view", "pr.diff", "pr.comments", "pr.reviews",
        "pr.review-comments", "pr.checks"
      ],
      "author": "Erotemic",
      "head_repository": "Erotemic/TauCeti",
      "lifetime_seconds": 1800,
      "max_requests": 200,
      "max_body_bytes": 8192
    }

Unknown fields, duplicate entries/JSON keys, wildcards, URLs and invalid types
are rejected. Repositories/logins normalize to lowercase. Maximums are one
hour, 1,000 admissions, 512 PR numbers, and 16,384 body bytes. A failed metadata
preflight consumes its reserved admission. Invalid attempts have a separate
finite limit. A policy is read once at session start; editing its file does not
change an existing session. Exit and re-enter to apply a new policy.

Writes and their limitations
---------------------------

Add ``pr.comment`` and/or ``pr.edit`` to the policy only after review. Then
explicitly opt in on the host::

    aivm ssh "$HOME/code/TauCeti" \
        --secrets_policy "$HOME/.config/aivm/secrets/tauceti.json" \
        --secrets_allow_writes=true

Neither switch nor policy alone enables writes. In that session::

    "$AIVM_SECRETS_CLIENT" pr comment 13861 \
        --repo TauCetiProject/TauCeti --body-file review-reply.md
    "$AIVM_SECRETS_CLIENT" pr edit 13861 \
        --repo TauCetiProject/TauCeti --body-file pr-description.md

There is no per-message approval prompt or automatic retry. The whole allowed
body is delegated to the guest, up to the size limit. A comment can invoke a
repository bot, so denying the merge endpoint is not proof against indirect
merge effects. Keep write grants disabled until that external behavior is
understood. The broker cannot give the host account permissions it lacks.

``pr edit`` changes only title/body. Merge, close/reopen, branch management,
labels, reviewer requests, workflow dispatch, secrets/settings and arbitrary
GraphQL/REST calls are not supported.

Lifecycle, auditing, and errors
------------------------------

The foreground SSH process owns the capability lifetime. Closing the session
revokes the host broker before best-effort guest cleanup. A fresh session uses
a fresh encryption key, so old ciphertext is not accepted by a new process.
At expiry the shell can remain open, but the broker refuses requests.
Disabling an AIVM access identity in another command does not yet revoke an
already-running broker automatically: terminate its foreground host session.
Policy files and access-identity records are not continuously watched. A guest
that can use the live channel can relay its permitted operations; this is not
non-exportable hardware identity or protection from active delegated misuse.

The host prints the audit path under the owning AIVM profile's
``secrets-audit`` directory. Audit records exclude credentials, sealed tokens,
comment bodies, titles and arbitrary provider error text. A required audit
failure stops further authority. Local audit files are not tamper-proof.

``denied`` means the operation/resource/bounds are outside the grant.
``resource_mismatch`` means provider PR metadata did not match the required
author/head/base repository. ``expired``, ``revoked`` and ``exhausted`` require
an explicit host decision before starting a new grant. ``outcome_unknown``
means a dispatched write may already have succeeded: inspect the selected PR
before retrying. A client timeout on a write has the same reconciliation need.

The provider uses a direct TLS connection to ``api.github.com``. It ignores
HTTP proxy environment variables, follows no redirects and retries no requests.
Networks requiring an enterprise egress proxy are not supported by this first
adapter. Host system TLS roots remain trusted. There is no generic TCP listener.

Standalone local mode
---------------------

The package can run without AIVM or libvirt for development. Choose a new, short
runtime directory; existing paths are deliberately refused::

    SECRETS_RUNTIME="/tmp/aivm-secrets-${UID}-${RANDOM}"
    aivm-secrets serve \
        --policy "$HOME/.config/aivm/secrets/tauceti.json" \
        --runtime-dir "$SECRETS_RUNTIME" \
        --credential-source gh

The command stays in the foreground until its policy lifetime ends or Ctrl-C.
A second terminal may use ``aivm-secrets gh --socket`` and
``--capability-file`` with the printed runtime path, followed by a supported
``pr`` command. This listener is local to the host UID; do not publish or mount
it into another environment as a substitute for an authenticated channel.
Standalone mode leaves its private audit/ciphertext files behind for inspection;
the key is not persisted. Remove that directory after the session ends when
its audit is no longer needed.

Validation before deployment
----------------------------

Run the isolated tests without contacting GitHub::

    python -m pytest -o addopts='' -q tests/test_secrets_*.py
    python dev/devcheck/architecture_docs.py check

Before use with real credentials, review the host policy and account, confirm
no secret-bearing host paths are guest-visible, and run one real read-only
session. Verify that a selected PR can be read, a nonselected PR is denied,
a write is denied, and the same client cannot use the expired/closed session.
Run a second session to test cross-session ciphertext rejection. Keep any
write smoke test to a separately approved disposable repository.

The shipped tests cover real local sockets, strict parsing, encryption tamper,
resource checks, audit failures and mocked AIVM/provider transport. They do
not constitute a live libvirt integration run, a GitHub permission audit, a
cryptographic proof, or formal verification of the host service.
