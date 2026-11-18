.. _aivm-repository-credentials:

Repository credentials
======================

AIVM can grant one VM access to one GitHub or GitLab repository with a
dedicated deploy key. ``--access`` selects ``read`` (the default) or ``write``;
``ro`` and ``rw`` are accepted as aliases. ``write`` means read *and* write,
because deploy keys have no write-only mode. A credential's access is fixed
once granted, so switching requires ``creds revoke`` followed by a new
``creds add``. Provider-management credentials remain on the host and are
never copied into the guest; the VM receives only its repository-scoped SSH
private key.

On a shared machine, credentials are owned by the selected VM principal rather
than by the VM as a whole. Alice and Bob may therefore grant the same VM access
to the same repository using independent deploy keys and provider accounts.
Ordinary commands see only the caller's records. ``creds list
--all_principals`` and ``creds status --all_principals`` expose machine-wide
non-secret metadata, but they never read another user's host key, provider
authentication, or guest home. Revoke and abandon must be run by the owning
host user.

.. code-block:: bash

   # Install/check host tools and authenticate GitHub CLI.
   aivm vm creds setup

   # Diagnostic-only readiness checks. Naming a repository also verifies
   # deploy-key administration for that repository.
   aivm vm creds setup --check
   aivm vm creds setup Kitware/kwimage --check

   # Infer the repository from the current checkout and the VM from AIVM
   # context. Without --access this grants read-only access.
   aivm vm creds add .
   aivm vm creds add . --access write

   # Or name both explicitly.
   aivm vm creds add Kitware/kwimage --vm aivm-2404-workstation --access write

   # For a checkout with many initialized submodules, generate one editable
   # plan instead of granting every repository by hand.
   aivm vm creds plan . --access rw > /tmp/aivm-creds.yaml
   ${EDITOR:-vi} /tmp/aivm-creds.yaml
   aivm vm creds apply /tmp/aivm-creds.yaml --dry_run
   aivm vm creds apply /tmp/aivm-creds.yaml

   # GitLab.com is inferred from its canonical URL. A host-only GITLAB_TOKEN
   # enables automatic publication, but it is optional: without one AIVM
   # prints the public key for a project administrator to add.
   export GITLAB_TOKEN='glpat-...'
   aivm vm creds add \
       git@gitlab.com:group/subgroup/project.git \
       --vm aivm-2404-workstation --access write

   # Self-managed GitLab is selected explicitly.
   aivm vm creds add \
       git@gitlab.example.com:group/project.git \
       --provider gitlab --access write

   # Current principal's records and full machine metadata.
   aivm vm creds list --vm aivm-2404-workstation
   aivm vm creds list --vm aivm-2404-workstation --all_principals

   aivm vm creds status Kitware/kwimage --vm aivm-2404-workstation
   aivm vm creds status <credential-id> \
       --vm aivm-2404-workstation --all_principals

   # Secret-bearing changes must run as the owning host user.
   aivm vm creds revoke Kitware/kwimage --vm aivm-2404-workstation

``creds plan`` crawls the selected checkout and every initialized nested Git
submodule. The result is a real YAML document whose active repository list
items are grants. Each row contains its own ``access`` (``ro`` or ``rw``), Git
``remote``, and ``provider`` value, so the reviewed file has no hidden access
defaults. A repository with one remote gets one active row. When several remote
names point at the exact same URL, ``origin`` is active when available and the
aliases are shown as commented alternatives. When remotes point at distinct
destinations, every choice is commented and annotated with its URL; uncomment
exactly one choice, or leave them all commented to skip that checkout.

``creds apply`` parses the YAML, resolves every selected remote again from the
checkout recorded by ``root``, rejects duplicate choices or duplicate repository
identities, and completes that validation before creating any credential. Use
``--dry_run`` to review the resolved grants before applying them.

``creds setup`` installs a missing GitHub CLI or OpenSSH client using the
host's package backend (apt, dnf, zypper, pacman, or apk), then starts
``gh auth login`` when necessary. ``--dry_run`` previews those actions without
changing the host.

The GitHub CLI must be **2.5.0 or newer**, which is when ``gh repo deploy-key``
was added; without it no deploy key can be created. Several distributions ship
much older builds -- Ubuntu 22.04 packages gh 2.4.0 -- so on apt, dnf, and
zypper hosts AIVM installs gh from GitHub's own repository following the
`official instructions
<https://github.com/cli/cli/blob/trunk/docs/install_linux.md>`_. That adds a
third-party package repository to the host, so it appears in the approval
prompt like any other privileged step. Arch and Alpine track upstream closely
enough that their own packages are used. ``creds setup --check`` reports the
installed version and refuses hosts whose gh is too old.

Where gh is 2.48.0 or newer, the browser login passes ``--skip-ssh-key`` so it
never offers to upload the user's ordinary SSH key; AIVM creates
repository-scoped deploy keys separately. On older builds that flag does not
exist, so setup warns instead -- decline the upload if the login offers it.

GitLab uses direct v4 REST calls and does not require ``glab``. Set
``GITLAB_TOKEN`` on the AIVM host to automate publication and revocation; for a
self-managed instance whose API is not at ``https://HOST/api/v4``, also set
``GITLAB_API_URL``. ``aivm vm creds setup --provider gitlab --check`` reports
token and project API readiness, but a failed readiness check does not prevent
``creds add`` from generating an administrator handoff.

A GitLab token is only valid on the server that issued it, so a host-scoped
``GITLAB_TOKEN_<HOST>`` -- for example ``GITLAB_TOKEN_GITLAB_EXAMPLE_COM`` --
takes precedence over the generic variable. Use it when you deal with more
than one instance; otherwise naming a host is enough to send it a token minted
somewhere else. The token travels in a request header on every call, so AIVM
refuses a non-loopback ``GITLAB_API_URL`` that is not ``https``.

Hosts named ``gitlab.<domain>`` are treated as GitLab without ``--provider``,
since the provider decides which API is called and is recorded permanently in
the credential's ``kind``. Any other self-managed hostname needs
``--provider gitlab``.

Managing deploy keys requires **admin** permission on the repository; write
access is not enough, so a contributor who can push may still be unable to add
a key. On a private repository GitHub reports that denial as ``404 Not Found``
rather than ``403`` so responses do not reveal what exists, so AIVM checks
whether the repository is visible to the signed-in account before deciding
whether a 404 means "not an admin" or "no such repository".

Provider publication is best effort rather than a prerequisite. If AIVM lacks
a suitable client, login, token, repository permission, or organization
approval -- or the provider refuses the automated request -- AIVM still does
everything local and hands off the one bureaucratic step it cannot take: the
keypair is generated, the private half is installed in the VM, Git is
configured to use it, and the public half is printed for a repository admin to
add. Nothing further needs to be run; access begins working as soon as the
provider accepts the public key. Such a credential is listed as
``unregistered``; ``aivm vm creds status <id>`` reprints the key to send an
admin, and ``aivm vm creds abandon <id>`` discards it.

Installing the key before it is registered is deliberate and safe: an SSH
private key confers nothing on its own, so the copy in the VM authenticates
against nothing until the provider holds its public half. AIVM will not
``revoke`` such a credential, because it never registered the key and will not
claim a provider-side deletion it cannot perform; an admin deletes the key and
``creds abandon`` removes the local and guest copies.

If the repository provider can no longer be inspected or administered, an explicit recovery
command can remove local copies without claiming that provider-side revocation
was successful::

   aivm vm creds abandon Kitware/kwimage \
       --vm aivm-2404-workstation --provider_unverified

This writes a non-secret audit tombstone and warns that any copied private key
may remain usable until the deploy key is removed at the provider.

Each grant has a unique SSH keypair. The provider scopes the key to the selected
repository; branch protections and rulesets remain repository settings and are
not managed by AIVM. Managed Git routing recognizes canonical clone URLs ending
in ``.git`` (the form shown by GitHub); restricting rewrites to that form avoids
Git's prefix-based URL rewriting from capturing similarly named sibling
repositories. If a selected checkout's remote omits the suffix, ``creds add``
refuses the grant instead of reporting success for a remote it cannot route;
normalize that remote to its canonical ``.git`` URL first. A VM cannot be
deleted while it still owns active credential records, preventing a deploy key
from being silently orphaned. Status and retry paths validate both halves of
the host keypair, ownership, file type, and private-key permissions before the
key can be reused or copied into a guest. Explicit transport URLs are accepted
only when Git can prove that they resolve through the credential-specific SSH
alias before network access is attempted.

Credential directories and key files must remain owned by the current user,
must be real directories and regular files rather than symlinks, and private
key files must stay inaccessible to group or other users. Those checks always
fail closed. Only the *directory mode* findings follow
``behavior.credential_directory_permission_policy``, so a group-writable AIVM
data root, VM directory, credential parent, or credential leaf is reported as a
warning rather than blocking credential creation; tighten it with
``chmod 700 ~/.local/share/aivm`` when the broader permissions are not
intentional.

Credential backends
-------------------

``aivm vm creds`` is the single repository-credential frontend. It dispatches
to two independently owned backends:

``guest-key``
   Generates a repository deploy key and installs the private half into the
   selected guest principal. This remains the stable fallback backend today.

``ssh-agent``
   Generates a fresh repository deploy key whose private half remains host-only,
   loads it into a dedicated ``(VM, principal)`` ``ssh-agent``, and exposes only
   that signing capability through managed SSH / VS Code Remote-SSH sessions.

New grants default to ``--backend auto``. An explicit ``--backend guest-key``
or ``--backend ssh-agent`` bypasses preferences. Otherwise ``auto`` resolves the
selected VM's ``vm.credential_backend`` preference, then the caller profile's
``credential_backend`` preference, then AIVM's package fallback. The fallback
is currently ``guest-key``; a future release may change the fallback to
``ssh-agent`` after that backend has accumulated equivalent operational history.

Inspect the preference hierarchy, set a VM-specific preference, or set a
user-wide preference with the schema-aware credential frontend::

   aivm vm creds preference
   aivm vm creds preference ssh-agent
   aivm vm creds preference guest-key --scope user

Use ``auto`` to clear either preference::

   aivm vm creds preference auto
   aivm vm creds preference auto --scope user

A VM-specific preference wins over the user-wide preference. The values are
persisted as ``vm.credential_backend`` in machine state and
``credential_backend`` in the caller profile respectively.

The normal commands operate over the union of both backend stores::

   # Uses VM/user preference, then the current guest-key fallback.
   aivm vm creds add Kitware/kwimage --access rw

   # Explicit backend selection bypasses preferences.
   aivm vm creds add Kitware/kwimage --backend ssh-agent --access rw
   aivm vm creds add Kitware/kwimage --backend guest-key --access rw

   aivm vm creds list
   aivm vm creds status <credential-id>
   aivm vm creds revoke <credential-id>
   aivm vm creds revoke Kitware/kwimage --all
   aivm vm creds revoke --all
   aivm vm creds doctor
   aivm vm creds doctor --fix

``revoke <repository> --all`` revokes every credential for that repository
owned by the current principal on the selected VM, including both backends by
default. Bare ``revoke --all`` revokes every credential in that same
principal/VM scope. Add ``--backend guest-key`` or ``--backend ssh-agent`` to
narrow either bulk form. Each credential still follows its own provider-first
revocation lifecycle; successful revocations remain complete if a different
credential reports a retryable failure.

Bulk plans carry a per-row ``backend`` field. ``backend: auto`` resolves through
the same VM/user/fallback hierarchy when the plan is applied, while
``guest-key`` and ``ssh-agent`` pin a row to one backend.

The two backend stores remain independent. ``ssh-agent`` never adopts or loads a
private key from ``guest-key`` records, and a key that may have crossed into a
guest is never relabeled as host-only. This allows a migration window in which
the same repository has one credential in each backend: create and verify the
fresh ``ssh-agent`` grant, then revoke the old ``guest-key`` grant. Repository
selectors that match both backends are deliberately ambiguous; use an exact
credential id or ``--backend`` rather than letting AIVM guess.

For the ``ssh-agent`` backend, the dedicated agent never inherits the caller's
ordinary ``SSH_AUTH_SOCK``. Managed ``aivm ssh`` and VS Code Remote-SSH sessions
forward the explicitly selected AIVM agent socket and install only public key
selectors plus repository-specific SSH/Git routing in the guest. ``IdentityFile``
points at a public selector with ``IdentitiesOnly yes`` so OpenSSH asks the
forwarded agent for the matching private-key operation without copying private
material into the VM. Session preparation verifies the forwarded fingerprints
before handing control to the shell/editor. When ``creds add`` creates an
``ssh-agent`` grant, it also opportunistically performs that same guest-routing
and forwarding preflight if the VM is running and SSH-ready. A stopped or
still-booting VM does not block the grant; activation is deferred to the next
managed session. If the final read-only repository probe cannot reach the
provider because the guest network path is unavailable, the grant remains
active and ``creds add`` reports a warning instead of treating the credential
as failed; forwarding or authentication failures still return an error.

The forwarding channel is connection-scoped. After adding an ``ssh-agent``
credential, AIVM points the operator at a fresh ``aivm vm ssh`` or
``aivm vm code`` session as the reliable way to use it. A host reboot or dead agent is
repaired lazily by the next managed SSH/Remote-SSH entry. Detached
``code --tunnel`` processes do not retain an SSH forwarding channel after their
bootstrap connection exits, so Remote-SSH is the credential-bearing editor path.

A VM cannot be deleted while either backend still owns repository authority.
``creds doctor --fix`` repairs only derived ``ssh-agent`` runtime state; provider
grants, revocations, and key replacement remain explicit lifecycle operations.
