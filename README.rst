AIVM
====

|Pypi| |ReadTheDocs| |GithubActions| |Codecov|

**A persistent Ubuntu development VM for coding agents, managed from your
Linux workstation.** AIVM creates and maintains an Ubuntu 24.04 guest using
KVM/libvirt, gives you SSH and editor access, and shares only the host projects
you explicitly attach.

The everyday workflow is deliberately short:

.. code-block:: bash

   cd ~/code/my-project
   aivm code .             # open this project in the VM using VS Code
   aivm ssh .              # or start a guest shell in this project

Unlike an ephemeral command runner, AIVM keeps a development environment you
can return to: installed tools, guest-local files, and declared project
attachments survive across sessions. The guest is intended to be a place where
an agent can install packages and use guest sudo without having the same access
to the host.

**Project status.** AIVM has received substantial use and iterative hardening
in real development workflows, including long-lived guests, attachment
recovery, and shared-workstation operation. That experience comes from a
**small number of users**, not broad deployment. It has an extensive automated
test suite and optional live-VM tests, but it has **not undergone an independent
security audit**. Development has involved human review and AI coding
assistants; neither replaces a security audit. Expect rough edges around
host-specific virtualization and permissions. See the
`security model <docs/source/security.rst>`_ before using it to run code you do
not trust.

What it does
------------

* **Persistent VM lifecycle.** Create, start, stop, update, provision, and
  remove managed Ubuntu guests with cloud-init, libvirt, and a dedicated NAT
  network.
* **Project-first entry.** ``aivm code .`` opens VS Code Remote-SSH and
  ``aivm ssh .`` opens a shell at the selected guest directory. Both check VM
  readiness and the requested attachment before entering.
* **Explicit folder sharing.** Choose a persistent replayed virtiofs share,
  an independent virtiofs device, a legacy shared-root export, or a Git-based
  handoff without a live host share. Read-only shares are supported by the
  virtiofs modes.
* **Multi-user workstations.** A shared machine store tracks separate
  host-to-guest **access identities**, principal-owned attachments, and
  repository credentials. Administrators can provision a coworker without
  asking them to initialize a profile.
* **Network controls.** An optional nftables policy limits guest access to
  private networks while keeping internet access; NAT alone is not isolation.
* **Repository-specific credentials.** GitHub and GitLab deploy-key workflows
  can use guest-local keys or an SSH-agent backend that keeps private keys on
  the host.
* **Observable operations.** Grouped steps show the concrete host/guest
  commands, privilege changes, and approval boundaries before modifying state.

For the overall design, see the `design contract <docs/source/design.rst>`_
and `workflows guide <docs/source/workflows.rst>`_.

Requirements and installation
-----------------------------

* A **Linux host** with KVM, QEMU/libvirt, and systemd available. Debian and
  Ubuntu have the supported host dependency installer. WSL2 has additional
  requirements; see the `WSL2 guide <docs/source/wsl.rst>`_.
* **Python 3.11 or newer** for the AIVM CLI. The guest image is Ubuntu 24.04.
* SSH client access. VS Code's ``code`` CLI and the Remote - SSH extension
  are needed only for the editor workflow.
* Host administrator privileges for initial host setup and for operations
  such as managed firewall changes and new host bind mounts. Routine libvirt
  operations can be configured to work without repeated sudo prompts.

Install the published CLI into your Python environment:

.. code-block:: bash

   python -m pip install aivm

Or, when working from a source checkout (including unreleased changes):

.. code-block:: bash

   uv pip install -e .

The examples below describe the current source tree; features not yet in the
published package require an installation from this checkout.

Check the host and, on Debian/Ubuntu, install missing system dependencies if
needed. The installer may request host sudo:

.. code-block:: bash

   aivm host doctor
   aivm host install_deps       # Debian/Ubuntu only; if needed
   aivm host permissions check
   aivm host permissions setup # prepare routine libvirt/storage access

Group membership changes may require a new login session. AIVM's normal
privilege mode is ``as-needed``: it uses the current user's capabilities and
escalates only operations that actually require it. See
`privilege modes <docs/source/privilege-modes.rst>`_.

Quickstart: one developer
-------------------------

The simplest entry point bootstraps missing configuration and VM context
interactively, attaches the selected directory, and opens the editor:

.. code-block:: bash

   aivm code .

For an explicit first-time setup:

.. code-block:: bash

   aivm config init
   aivm vm create
   aivm ssh .

Inspect what AIVM manages and whether the guest is ready:

.. code-block:: bash

   aivm status
   aivm status --detail
   aivm status --sudo             # additional privileged host checks
   aivm vm list
   aivm list --section folders

The generated VM name normally includes the host name (for example,
``aivm-2404-workstation``). On a shared host, machine-wide desired state lives
under ``/var/lib/aivm/machine``; otherwise AIVM uses a user-owned machine
store. Each user keeps private settings and SSH identity paths in an XDG
profile. AIVM does not silently adopt an unrelated libvirt domain with the
same name.

Projects, SSH, and attachments
------------------------------

.. code-block:: bash

   aivm code ~/code/my-project   # VS Code Remote-SSH
   aivm ssh ~/code/my-project    # interactive SSH shell
   aivm attach ~/code/my-project
   aivm detach ~/code/my-project

**Attachment modes** (use ``--mode`` when creating an attachment):

``persistent`` (default)
   A single VM virtiofs export with staged host bind mounts, a persisted
   manifest, and guest replay after startup or reconciliation. Designed for
   long-lived workspaces and multiple project directories. Creating a new host
   bind requires sudo; reusing an already-established bind generally does not.

``direct-virtiofs``
   A separate virtiofs device per folder, avoiding host bind mounts. Useful
   for users without host sudo, but **each folder consumes a guest PCIe slot**.
   Many folders can exhaust the VM's device capacity.

``shared-root``
   The older single-export mechanism with host and guest bind mounts. Existing
   saved attachments remain supported; new attachments normally use
   ``persistent`` instead.

``git``
   A guest-local Git checkout and host/guest remote plumbing. There is **no
   automatic worktree synchronization**: push, fetch, or pull intentionally.
   This mode does not expose a live writable host folder.

Examples:

.. code-block:: bash

   aivm attach . --mode direct-virtiofs
   aivm attach . --mode persistent --access ro
   aivm code . --mode git

The selected host directory **must exist** before attachment. New attachments
inherit their host absolute path inside the guest unless a guest destination
is specified. Existing attachments retain their saved mode; switching modes
requires an explicit detach and reattach. Read-only sharing is available in
``persistent``, ``shared-root``, and ``direct-virtiofs`` modes.

Entering a running guest checks the selected workspace without tearing down
other live mounts. Explicit lifecycle and repair commands handle disruptive
reconciliation. Settings synchronization was removed; use explicit shares or
Git for project handoff.

See the `attachment workflows <docs/source/workflows.rst>`_ and
`virtiofs notes <docs/source/virtiofs.rst>`_ for replay, mirroring,
file-descriptor growth, and recovery.

Shared hosts: enroll users without host sudo
--------------------------------------------

A shared AIVM VM has one machine-wide definition but **separate access
identities** for host users. Each identity has its own guest login and SSH
credential. Attachment declarations and repository credentials are owned by
an identity; normal path resolution does not adopt another user's records.

An administrator can prepare a trusted coworker's shared-store/libvirt access,
then enroll them **without requiring that person to run commands**:

.. code-block:: bash

   # Administrator, using their own installed AIVM CLI:
   aivm host permissions grant alice --admin_override

   # Replace the example VM name with the one from `aivm vm list`.
   aivm vm access onboard alice --vm aivm-2404-workstation \
       --admin_override --dry_run
   aivm vm access onboard alice --vm aivm-2404-workstation \
       --admin_override --yes

   aivm vm access list --vm aivm-2404-workstation

Onboarding initializes the coworker's private profile and SSH identity under
*their* host UID, provisions their guest login, and verifies guest SSH access
before marking the access identity ``active``. It does **not** give them host
sudo, install AIVM in their Python environment, or create project directories.
A shared executable that they can actually run is still required before their
first session. If the guest rejects its bootstrap SSH key, the administrator
may explicitly retry with ``--repair_bootstrap``, which uses the
administrator's already-active guest SSH/sudo access to restore the restricted
bootstrap account.

``host permissions grant`` is a **powerful authorization step**: it grants
libvirt management access (usually through the ``libvirt`` group), which is
potentially root-equivalent even though it does not add the user to sudoers.
Only grant it to trusted host accounts, and allow a new login session to pick
up group membership.

A coworker can alternatively join using ``aivm config init``. For a pending
identity, an administrator runs ``aivm vm access prepare USER --vm VM
--admin_override`` and the owner runs ``aivm vm access verify --vm VM``.

An administrator can attach an **existing** host directory on another user's
behalf with ``aivm vm attach ... --owner_principal ID --admin_override``. A
user without host sudo may create their own ``direct-virtiofs`` attachments.
Guest destinations are VM-global: different owners cannot reserve the same
path. Account-level group/store access, ownership rules, and guest account
isolation are not a substitute for isolation from a malicious host user.

For access disable/remove, migration, and administrative recovery, see
`the operational lifecycle reference
<docs/reference/operational-lifecycle.md>`_ and
`the shared-host quickstart <docs/source/quickstart.rst>`_.

Repository access
-----------------

AIVM can grant guest code access to a selected GitHub or GitLab repository with
a dedicated deploy key. The provider manages the repository access scope;
AIVM tracks the grant under the current user's VM access identity.

.. code-block:: bash

   aivm vm creds setup --check
   aivm vm creds add .                     # read-only by default
   aivm vm creds add . --access write      # request read/write
   aivm vm creds list
   aivm vm creds status <credential-id>
   aivm vm creds revoke <credential-id>

``guest-key`` installs the repository-specific private key in the guest;
``ssh-agent`` keeps it on the host and forwards signing access for managed SSH
and VS Code Remote-SSH sessions. ``--backend auto`` resolves preferences and
currently falls back to ``guest-key``. The SSH-agent backend does not turn a
previously guest-exposed key into a host-only key. GitLab projects can be
specified with canonical URLs; provider administration may require a manual
public-key handoff if the caller lacks repository-admin privileges.

For backend preferences, submodule grant plans, provider requirements,
revocation/abandonment, and the SSH-forwarding trust boundary, see the
`repository credentials reference <docs/source/credentials.rst>`_. The
separately developed ``aivm-secrets`` broker is **experimental and optional**;
it is not part of the ordinary AIVM installation.

Host networking and the security boundary
-----------------------------------------

The VM is meant to contain agent execution, **not** to make code safe. The
guest user can have root inside the guest; the host, libvirt daemon, and
explicitly mounted host paths form the trusted side of the boundary.

* **NAT is not a LAN firewall.** Configure managed nftables isolation if the
  guest should have internet access without reaching host/private networks.
  Inspect/apply with ``aivm host fw status`` and ``aivm host fw apply``.
  Rules live in the kernel and must be restored after host reboot.
* **File shares are a deliberate trust extension.** A guest that can write a
  host project can change code and build inputs the host might later execute.
  Share the smallest necessary directory; do not attach your whole home or
  secrets directories to an untrusted agent.
* **Privilege is explicit, not absent.** ``libvirt`` membership can convey
  host-administrator-level power. Creating new persistent binds and changing
  nftables rules still require root. An ordinary user may be unable to verify
  firewall state; AIVM distinguishes **unverified** from **missing** rather
  than silently rewriting rules.
* **VM escape is in scope as a risk.** KVM, QEMU, virtiofsd, and the kernel
  remain part of the security boundary. AIVM is not independently audited and
  should not be treated as a high-assurance hostile multi-tenant sandbox.

See the `security model <docs/source/security.rst>`_ for assumptions,
attack surfaces, and limitations, including firewall exceptions.

Maintenance and troubleshooting
-------------------------------

.. code-block:: bash

   aivm vm up
   aivm vm down
   aivm vm restart
   aivm vm update                  # reconcile VM/guest state
   aivm vm provision docker rust  # install selected guest tools
   aivm vm fdguard                 # inspect guest virtiofs guard
   aivm vm flush_caches           # manual virtiofs recovery
   aivm host doctor               # host prerequisites
   aivm config lint
   aivm help tree

A guest-side virtiofs guard is enabled by default for new VMs. It mitigates
long-lived host ``virtiofsd`` descriptor growth by excluding shared trees from
``updatedb`` indexing and flushing reclaimable guest metadata caches at
watermarks. It reduces a known failure mode; it is **not a guarantee** that
file-descriptor exhaustion cannot happen. Existing guests can reconcile the
guard through ``aivm vm update`` or ``aivm vm fdguard --action install``.

Legacy per-user config stores are **not** silently migrated to the 0.6
machine/profile model. Use ``aivm config migrate plan`` before any explicit
``apply``, and consult the `migration plan and recovery reference
<docs/planning/released-store-migration-plan.md>`_. VM removal uses a
recoverable cleanup journal; credential ownership must be resolved before
removing a VM.

AIVM logs concrete commands and groups related operations into approval
steps. State-changing host operations prompt unless you explicitly approve
them (for example, with ``--yes``). **In the current implementation,
``--yes-sudo`` can also approve non-sudo state-changing steps**; do not
assume its approval scope is limited to sudo. Large generated payloads may be
abbreviated at ordinary verbosity while remaining inspectable at higher
verbosity. Private keys and
tokens are not intended for logging. See the
`auditability contract <docs/source/design.rst>`_.

Documentation and contributing
------------------------------

* `Full documentation <https://aivm.readthedocs.io/en/latest/>`_
* `Quickstart <docs/source/quickstart.rst>`_
* `Workflows <docs/source/workflows.rst>`_
* `Privilege modes <docs/source/privilege-modes.rst>`_
* `Virtiofs behavior and incident guide <docs/source/virtiofs.rst>`_
* `Repository credentials <docs/source/credentials.rst>`_
* `Security model <docs/source/security.rst>`_
* `Development and test guidance <AGENTS.md>`_

For development, run the ordinary non-E2E checks:

.. code-block:: bash

   python -m pytest -q -m 'not e2e'
   mypy aivm tests
   ty check aivm tests/

Live libvirt/KVM E2E tests are opt-in (``AIVM_E2E=1``). Passing unit tests
and experience on a small number of machines do not replace review of the
security boundary or testing on a new host configuration.

.. |Pypi| image:: https://img.shields.io/pypi/v/aivm.svg
   :target: https://pypi.org/project/aivm/

.. |ReadTheDocs| image:: https://readthedocs.org/projects/aivm/badge/?version=latest
   :target: https://aivm.readthedocs.io/en/latest/

.. |GithubActions| image:: https://github.com/Erotemic/aivm/actions/workflows/tests.yml/badge.svg
   :target: https://github.com/Erotemic/aivm/actions?query=branch%3Amain

.. |Codecov| image:: https://codecov.io/github/Erotemic/aivm/badge.svg?branch=main&service=github
   :target: https://codecov.io/github/Erotemic/aivm?branch=main
