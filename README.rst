The aivm Module
===============


.. warning::

   This project was written starting with GPT-5.3 Codex, but then with
     significant updates from later models such as Fable 5 and GPT 5.6.
   Its development has been human supervised, but not extensively audited for
     correctness and safety, as such it is only recommended for experimental
     use.
   See the `Security Model <docs/source/security.rst>`_ for the threat model and
     security posture.


|Pypi| |PypiDownloads| |ReadTheDocs| |GithubActions| |Codecov|



+---------------+-----------------------------------------+
| Read the Docs | https://aivm.readthedocs.io/en/latest/  |
+---------------+-----------------------------------------+
| Pypi          | https://pypi.org/project/aivm           |
+---------------+-----------------------------------------+

A small Python CLI to **create and manage a local libvirt/KVM Ubuntu 24.04 VM**
designed for running coding agents with a stronger boundary than containers.

Current state
-------------

``aivm`` is experimental and best understood as a local, long-lived
libvirt/KVM development VM manager for agent workflows. The actively maintained
daily path is:

.. code-block:: bash

   aivm code .
   aivm ssh .
   aivm attach .
   aivm status

The current attachment model is centered on explicit host-folder registration:

* ``persistent`` is the default for new attachments. It uses a dedicated
  ``persistent-root`` virtiofs export, persisted attachment declarations, and
  replay helpers so attachment intent survives VM reboot/reconcile cycles.
* ``shared-root`` is the legacy single-export path. It still uses one VM-level
  virtiofs export plus host/guest bind mounts, but new attachments no longer
  choose it unless ``--mode shared-root`` is explicit or a saved attachment
  already uses that mode.
* ``shared`` is the older direct per-folder virtiofs mode and is mostly useful
  for simple/small attachment sets.
* ``git`` bootstraps a guest-local Git repo and host remote plumbing. It is not
  a live filesystem sync engine.

The old settings-sync story has been removed for now. It was too flaky to keep
as a supported workflow. Project handoff should use explicit attachments,
manual Git operations, or a future redesigned synchronization feature.

What it provides
----------------

* Dedicated libvirt NAT network per ``aivm`` configuration
* Optional host firewall isolation via nftables
* Ubuntu cloud-image VM provisioning via cloud-init
* SSH + VS Code Remote-SSH workflows
* Optional virtiofs folder sharing (explicit trust extension)
* A single config store for defaults, VMs, networks, and attachments

.. note::

   Opt-in end-to-end tests live in ``tests/e2e/``. They carry the ``e2e``
   marker and are deselected by default; to run them locally set
   ``AIVM_E2E=1`` and invoke pytest manually. The VM lifecycle suites need a
   host with KVM, passwordless ``sudo``, and optionally a cached Ubuntu image
   under ``~/.cache/aivm/e2e``. Storage-adoption tests additionally require
   ``setfacl`` and exercise real bind mounts under a scratch tree.

   An additional opt-in bootstrap-context e2e test is available in
   ``tests/e2e/test_bootstrap_context.py``. It creates a fresh outer VM and
   runs the host-context e2e suite inside that VM. Enable it with
   ``AIVM_E2E_BOOTSTRAP=1`` when running ``./run_e2e_tests.sh``.

Install
-------

.. code-block:: bash

   uv pip install .

Fast Start
----------

Recommended for new repos:

No explicit setup is required first: if VM context is missing, ``aivm code .``
offers to run the ``aivm config init`` / ``aivm vm create`` bootstrap for you
(run them yourself for the explicit, reproducible path).

.. code-block:: bash

   aivm code .
   aivm status
   aivm status --sudo   # optional deeper privileged checks

``aivm code .`` auto-selects/bootstraps VM context from the global config store
(``~/.config/aivm/config.toml``), attaches the current folder if needed, and
opens VS Code.

During setup and reconcile flows, subprocess logging is now organized around
user-meaningful steps instead of isolated commands. ``aivm`` shows the current
step, why it exists, a semantic summary for each planned command, and the exact
command line that will run before it executes the step. Full raw commands still
appear at higher verbosity.

If you prefer an explicit flow, ``aivm config init`` is required before
``aivm vm create``.

Interactive ``aivm config init`` shows the detected defaults once, then lets
you accept them, edit the generated TOML in ``$EDITOR``/``$VISUAL`` (falling
back to ``nano`` or ``micro``), or use a prompt-by-prompt editor.  Subsequent
confirmation steps show only changed values instead of repeating the full
defaults table.

See also:

* `Design Contract <docs/source/design.rst>`_
* `Quickstart <docs/source/quickstart.rst>`_
* `Workflows <docs/source/workflows.rst>`_
* `Running under WSL2 <docs/source/wsl.rst>`_

Status and sudo behavior
------------------------

By default, ``aivm status`` avoids privileged probes. Use ``--sudo`` for
network/firewall/libvirt/image checks.

Privilege modes (``behavior.privilege_mode``):

Both answer one question -- *when does aivm invoke sudo?*

* ``as-needed`` (default) probes what already works without sudo --
  unprivileged ``qemu:///system`` access via the ``libvirt`` group,
  user-writable VM storage -- and uses sudo only where required.
* ``always`` escalates every privileged-capable host operation through sudo
  (the classic behavior).

An unrecognized value is an error, not a silent fallback. A global
no-sudo mode is not exposed because managed nftables and new host bind mounts
still require root on the supported runtime.

Credential directory mode checks default to ``warn`` so trusted and personal
workstations are not blocked by inherited ``0775`` directories. Set
``behavior.credential_directory_permission_policy`` to ``error`` for strict
enforcement or ``ignore`` to suppress these mode warnings. Ownership, symlink,
file-type, and key-file permission failures remain errors in every mode.

Run ``aivm host permissions check`` to inspect the permissions used by
routine VM operations, and ``aivm host permissions setup`` to establish the
host-side prerequisites. Normal setup may use sudo to add you to the
``libvirt`` group; ``--adopt`` additionally runs one privileged metadata pass
for each existing storage tree. Setup never changes your config: establishing a capability and
choosing a policy are different acts, so ``privilege_mode`` and
``firewall.enabled`` stay yours to set. State-changing
hypervisor commands keep their approval prompt even when they no longer need
sudo, so destructive operations never become promptless just because
escalation stopped being necessary.

Command manager defaults:

* subprocess execution is centralized through a command manager
* logs are grouped into step/plan previews with nested context
* read-only sudo probes (inspect/query/status) are auto-approved by default
* state-changing sudo steps still prompt unless ``--yes``/``--yes-sudo`` is set
* approval usually happens once per grouped step, not once per command

Grouped approval does **not** widen privilege beyond the commands shown in the
step preview. The preview is the approval boundary.

Use:

* ``--yes`` to auto-approve all prompts
* ``--yes-sudo`` to auto-approve only sudo prompts

When running interactively, expect step previews such as:

* current context / breadcrumb
* current step title
* why the step exists
* semantic summaries plus exact commands for the current step
* a single approval prompt for the whole step when required

Interactive approval semantics:

* ``y`` approves the current step only
* ``a`` approves the current step and all later steps
* ``s`` shows the full exact commands for the current step, then reprompts

For example, the default ``persistent`` path used by ``aivm ssh .`` /
``aivm code .`` groups attachment reconciliation into named steps such as
inspecting host bind state, preparing host bind targets, ensuring the VM
virtiofs mapping, syncing the persisted manifest, and mounting/verifying the
bind inside the guest.

Readable previews may abbreviate long shell payloads, but the full exact
commands are still available on demand in the approval prompt and are always
logged when they actually run.

Config defaults:

New configs use a host-qualified default VM name derived from ``$HOSTNAME``.
For example, on a host named ``workstation``, the generated VM name, guest hostname,
and primary SSH alias are all ``aivm-2404-workstation``. Existing explicit config
values are not migrated; configs that relied on an omitted implicit name now
receive the new host-qualified default.

.. code-block:: toml

   [behavior]
   yes_sudo = false
   auto_approve_readonly_sudo = true  # set false for strict "prompt every sudo" mode
   privilege_mode = "as-needed"       # "never" | "as-needed" | "always"
   credential_directory_permission_policy = "warn"  # "warn" | "error" | "ignore"

Common Workflows
----------------

VS Code and SSH

.. code-block:: bash

   aivm vm ssh_config

.. code-block:: bash

   aivm code .
   aivm vm code --host_src .
   aivm vm code .
   aivm vm ssh .

Folder attachment

.. code-block:: bash

   aivm attach .
   aivm detach .
   aivm vm attach --vm aivm-2404-$HOSTNAME --host_src .
   aivm attach . --mode git

Attachment modes:

* ``persistent`` (default for new attachments): the preferred persistent-
  attachment path. It uses a dedicated VM-level virtiofs export at
  ``/var/lib/libvirt/aivm/<vm>/persistent-root`` plus stable staged host binds,
  writes a persisted attachment manifest, installs a guest systemd replay
  helper at VM bootstrap, and lets boot / ``aivm code .`` / ``aivm ssh .``
  repair guest-visible bind mounts from that manifest instead of rebuilding
  every attachment from scratch.
* ``shared-root``: legacy single-export behavior. One VM-level virtiofs mapping
  exports ``/var/lib/libvirt/aivm/<vm>/shared-root``; each attached folder is
  bind-mounted under that root on host and then bind-mounted to ``guest_dst`` in
  guest. Existing saved ``shared-root`` attachments continue to use this mode,
  and new attachments can still request it with ``--mode shared-root``.
* ``shared``: direct per-folder virtiofs mapping from host source to guest. This
  is simpler but consumes one VM virtiofs device slot per folder.
* ``git``: guest-local Git repo bootstrap plus host/guest remote plumbing. It
  does not automatically synchronize worktree contents.

In ``shared``, ``shared-root``, ``persistent``, and ``git`` modes, attached folders
mount to the same absolute path inside the guest by default unless
``--guest_dst`` overrides it. Running VMs are
live-attached when possible.
``aivm code`` and ``aivm ssh`` remount the selected folder and best-effort
restore other folders already saved for that VM after guest startup.

For ``persistent`` attachments, explicit detach updates the stored declaration
and refreshes the replay manifest instead of depending on interactive teardown
of the stable host-side staged bind mount.
If the guest can mount the persistent-root export but the host manifest is
missing, replay now fails closed instead of silently reusing stale cached guest
state.

Major limitation: shared-mode folder count
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each ``shared`` folder uses a dedicated virtiofs device mapping in the VM
definition. Attaching many folders can hit VM device-slot limits (for example
PCI/PCIe capacity), which surfaces from libvirt as errors like
``No more available PCI slots`` during attach/restore.

``shared-root`` and ``persistent`` reduce this pressure by using one persistent
virtiofs mapping per VM and per-attachment host/guest bind mounts.
Their host-side preparation is also designed to avoid mutating the ownership or
permissions of the user's source tree; ``aivm`` prepares only its own internal
directories and does not recursively rewrite a bind-mounted project path.

Workarounds today:

* detach unused shared folders
* prefer ``--mode git`` for folders that do not need live writable host sharing
* split large folder sets across multiple VMs

Use ``--mode git`` to keep a normal Git repo on guest disk instead of exposing
a writable virtiofs share. In that mode, ``aivm`` configures the guest repo to
accept host pushes via ``receive.denyCurrentBranch=updateInstead`` and
registers a host-side remote pointing at the guest repo over the VM SSH alias.
That remote is plumbing for explicit Git handoff; ``aivm`` no longer tries to
push or pull project contents automatically for git-mode attachments.

``aivm code --mode git .`` behavior:

* New folder (no saved attachment): creates/uses a git-mode attachment and
  defaults the guest destination to the exact host path.
* Folder previously attached in any non-``git`` mode, including ``shared``,
  ``shared-root``, or ``persistent``: returns an error (mode mismatch). Detach +
  reattach is required to switch modes.
* ``aivm code .`` without ``--mode``: reuses saved mode if present; otherwise
  creates a new ``persistent`` attachment.

Migration note:

* ``persistent`` has become the default path for new attachments. Existing
  ``shared-root`` attachments keep working unchanged. Reattach a folder with
  ``aivm detach .`` then ``aivm attach . --mode persistent`` when you want an
  older saved attachment to move to the persisted replay behavior.

Mode selection behavior:

* New folder (no saved attachment record): defaults to ``persistent`` unless
  ``--mode`` is explicitly set.
* Existing folder attachment: omitting ``--mode`` reuses the saved mode for that
  ``(host folder, VM)`` pair.
* Existing folder attachment + explicit different ``--mode``: this now errors.
  You must explicitly detach then reattach to change mode:

.. code-block:: bash

   aivm detach .
   aivm attach . --mode git

Known issue: long-lived virtiofs FD growth (now auto-mitigated)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Host-side ``virtiofsd`` keeps one open descriptor per inode the guest caches,
and guests never evict those caches on their own, so long-lived virtiofs
attachments historically saturated the daemon's fd ceiling (~1M) and ordinary
traversal failed with ``OSError: [Errno 24] Too many open files`` even though
``ulimit -n`` looked fine. The dominant trigger turned out to be the guest OS
itself: Ubuntu's stock nightly ``updatedb`` sweep walks virtiofs mounts
(``virtiofs`` is missing from the default ``PRUNEFS``), touching every shared
inode every day.

aivm now installs a guest-side *virtiofs guard* (systemd timer) that prunes
``updatedb`` and flushes guest dentry/inode caches when the cached-inode
count crosses a watermark, releasing the host descriptors before the ceiling
is reached. The guard is config-driven (``[virtiofs] fd_guard = true``, the
default): new VMs get it via cloud-init, and ``aivm vm update`` reconciles
existing running VMs — installing, refreshing after config/version changes,
or uninstalling when disabled — so no manual setup or host-side
``aivm vm flush_caches`` cron jobs are needed. ``aivm vm fdguard`` (default
action ``status``) shows the live state and offers direct
install/uninstall.

Remaining guidance:

* prefer fewer, narrower shared folders; detach stale attachments
* use ``--mode git`` for repos that do not need live writable host sharing
* ``aivm vm flush_caches`` remains as a manual recovery command
* see ``docs/source/virtiofs.rst`` for the full mechanism, tuning knobs
  (``[virtiofs] fd_guard*``), and the incident runbook

Inventory and visibility
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   aivm list
   aivm vm list
   aivm list --section vms
   aivm list --section networks
   aivm list --section folders
   aivm status --detail

Config-store lifecycle (explicit flow)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   aivm config init
   aivm vm create
   aivm vm update
   aivm vm edit
   aivm config discover
   aivm config show
   aivm config edit
   aivm config lint
   aivm config format
   aivm config paths
   aivm help plan
   aivm help tree
   aivm help completion
   aivm host doctor

Alternatives and related projects
---------------------------------

Depending on the threat model and workflow, these projects may be a better fit:

* `Matchlock <https://github.com/jingkaihe/matchlock>`_ runs AI-agent workloads
  in ephemeral microVMs with network allowlisting and host-side secret
  injection.
* `JAI <https://github.com/stanford-scs/jai>`_ is a lightweight Linux jail for
  AI CLIs, giving the current directory direct access while keeping the rest of
  home copy-on-write or more restricted depending on mode.

``aivm`` is different: it favors a persistent libvirt/KVM Ubuntu VM that can be
re-entered for local development with VS Code/SSH and explicit folder
attachments.

VM repository credentials
-------------------------

AIVM can grant one VM access to one GitHub or GitLab repository with a
dedicated deploy key. ``--access`` selects ``read`` (the default) or ``write``;
``ro`` and ``rw`` are accepted as aliases. ``write`` means read *and* write,
because deploy keys have no write-only mode. A credential's access is fixed
once granted, so switching requires ``creds revoke`` followed by a new
``creds add``. Provider-management credentials remain on the host and are
never copied into the guest; the VM receives only its repository-scoped SSH
private key.

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

   aivm vm creds list --vm aivm-2404-workstation
   aivm vm creds status Kitware/kwimage --vm aivm-2404-workstation
   aivm vm creds revoke Kitware/kwimage --vm aivm-2404-workstation

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

Command Groups
--------------

.. code-block:: bash

   aivm config --help
   aivm host --help
   aivm host image_fetch --help
   aivm help --help
   aivm host net --help
   aivm host fw --help
   aivm vm --help
   aivm vm creds --help

Safety Notes
------------

* This tool assumes **Linux + libvirt**. It focuses on Debian/Ubuntu hosts for dependency installation.
* Security model and threat model details: the `Security Model <docs/source/security.rst>`_.
* NAT alone does not prevent VM -> LAN. Enable firewall isolation if you want "internet-only" access.
* To allow specific VM->host or VM->blocked-LAN service ports while firewall isolation is enabled, set ``[firewall].allow_tcp_ports`` / ``allow_udp_ports`` in config (for example ``allow_tcp_ports = [22, 5432]``).
* virtiofs sharing is optional; it's powerful, but it intentionally exposes that host directory to the VM.
* ``aivm vm code`` requires VS Code's ``code`` CLI and the Remote - SSH extension.


.. |Pypi| image:: https://img.shields.io/pypi/v/aivm.svg
    :target: https://pypi.python.org/pypi/aivm

.. |PypiDownloads| image:: https://img.shields.io/pypi/dm/aivm.svg
    :target: https://pypistats.org/packages/aivm

.. |ReadTheDocs| image:: https://readthedocs.org/projects/aivm/badge/?version=latest
    :target: https://aivm.readthedocs.io/en/latest/

.. |GithubActions| image:: https://github.com/Erotemic/aivm/actions/workflows/tests.yml/badge.svg
    :target: https://github.com/Erotemic/aivm/actions?query=branch%3Amain

.. |Codecov| image:: https://codecov.io/github/Erotemic/aivm/badge.svg?branch=main&service=github
    :target: https://codecov.io/github/Erotemic/aivm?branch=main
