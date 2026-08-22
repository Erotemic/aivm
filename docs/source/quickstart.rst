Quickstart
==========

Choose one of these startup paths.

Path A: One-command project entry (recommended)
-----------------------------------------------

.. code-block:: bash

   aivm code .

Behavior:

* Uses the shared machine store under ``/var/lib/aivm/machine`` and the
  caller's private XDG profile.
* If VM context is missing, ``aivm`` can bootstrap required config/VM steps.
* Attaches current folder and opens VS Code.
* Major setup/reconcile logs are grouped into step previews so you can see what
  the current step is doing before the commands run.
* For default ``persistent`` attachments, those steps usually include host
  bind inspection/repair, persistent-root VM mapping checks, manifest sync, and
  guest mount verification.

Use this path when you want minimal setup friction.

Path B: Explicit config-store setup
-----------------------------------

.. code-block:: bash

   aivm config init
   aivm vm create

For the first host user, this path is explicit and reproducible:
``aivm config init`` establishes machine defaults and the private SSH profile,
and ``aivm vm create`` provisions the VM. During interactive creator init,
choose the editor path for direct TOML editing or the prompt-by-prompt path for
a terminal-only walkthrough.

A later host user runs only:

.. code-block:: bash

   aivm config init

If the hostname-qualified name exactly matches a managed VM, AIVM creates that
user's profile and enrolls a separate guest account through the restricted
bootstrap channel. It never rewrites the VM definition during a join and never
silently adopts an unmanaged same-name libvirt domain. A stopped VM may leave a
recoverable pending principal; retry with ``aivm vm access reconcile``.

Shared workstation: what the administrator does once
-----------------------------------------------------

Two host privileges are separate, and on a shared workstation only one of
them is usually handed out. Membership in the ``libvirt`` and ``aivm`` groups
lets an ordinary user drive libvirt and the shared machine store directly.
Sudo is a different grant, and a few operations need root on *every*
invocation no matter how the host is prepared:

* managed nftables rules --- installing them, and reading them back;
* establishing a *new* host bind mount, which the ``persistent`` and
  ``shared-root`` attachment modes use to stage a folder under the VM's
  export root.

So an administrator prepares the host once:

.. code-block:: bash

   # For each user who will share the VM.
   sudo aivm host permissions setup --user alice

   # Install the sandbox rules. They live in the live kernel ruleset, so
   # this is needed again after every host reboot.
   sudo aivm firewall apply

Users log out and back in (or ``newgrp libvirt``) for the group change, then
run ``aivm config init`` to join, and work normally from there.

What a user without sudo can and cannot do
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

They can create, start, stop, restart, update and delete VMs, attach folders
in ``direct-virtiofs`` and ``git`` modes, manage credentials, and open
sessions. Their already-established ``persistent`` attachments keep working:
AIVM re-asserts those binds only when they have actually drifted, so an
ordinary start needs no privileges.

They cannot install or read the nftables rules, and cannot create a *new*
``persistent`` or ``shared-root`` attachment. Two ways around the second:

.. code-block:: bash

   # No host privileges needed; maps the folder straight into the guest.
   # Costs one guest PCIe slot per folder, so keep the set small.
   aivm vm attach ~/proj --mode direct-virtiofs

   # Or an administrator declares it on the user's behalf, so the record is
   # owned by that user rather than by the admin.
   sudo aivm vm attach /home/alice/proj \
       --owner_principal <alice-access-identity> --admin_override

Run ``aivm host permissions check`` to see which of these apply to your
account; it reports what is unavailable to *you* rather than what a
privileged account could do.

Because ``nft`` has no unprivileged read, a user without sudo cannot verify
the firewall. AIVM says so rather than guessing: a session or VM start whose
firewall cannot be checked continues with a clear "rules UNVERIFIED" warning
instead of assuming the table is missing and trying to reinstall it. It
never silently treats an unreadable firewall as an absent one, and never
blocks a user over a check they are not allowed to perform.

After either path
-----------------

.. code-block:: bash

   aivm status
   aivm status --sudo
   aivm vm update

Optional: routine operation without sudo
----------------------------------------

The default posture assumes an administrator: system libvirt plus sudo
prompts, with no setup ceremony. :doc:`privilege-modes` compares the
postures side by side.

If you prefer ``aivm`` to never invoke ``sudo``:

.. code-block:: bash

   aivm host permissions check    # report what is missing
   aivm host permissions setup    # establish routine host access

Normal setup may use sudo to add you to the ``libvirt`` group, then prepares
a user-owned VM storage directory with ``setfacl`` traversal grants for
``libvirt-qemu``. It changes nothing in your config -- it prints the one line
(``defaults.paths.base_dir``) that the storage grant depends on, or writes it
for you with ``--persist``. Log out and back in (or ``newgrp libvirt``) after
the group change, then re-run the check.

That host work is all the default ``as-needed`` mode needs: it then stops
invoking sudo for whatever already works without it. Root is still required for
managed nftables and for establishing new host bind mounts, so a global
no-sudo mode is intentionally not exposed.

Notes
-----

* ``status --sudo`` enables privileged checks (libvirt/network/firewall/image).
* ``behavior.privilege_mode`` controls escalation: ``as-needed`` (default,
  sudo only where needed) or ``always`` (classic).
* ``status --detail`` includes raw diagnostics (virsh/nft/ssh probe outputs).
* Privileged operations prompt unless ``--yes`` or ``--yes-sudo`` is used.
* Approvals normally happen once per grouped step, not once per command.
* Step previews show both semantic summaries and the exact commands to be run.
* ``s`` shows the full exact commands for the current step, then reprompts.
* ``y`` approves the current step only; ``a`` approves the current and all
  later steps.
* Full executed commands are always logged; raw commands are also still visible
  at higher verbosity levels.
* Persistent and shared-root setup are designed to avoid changing ownership/perms
  of your host source tree.
* ``persistent`` is the default attachment mode for new folders. It preserves
  attachment intent with replay helpers. ``shared-root`` remains available with
  ``aivm attach . --mode shared-root`` for the legacy single-export path, and
  both modes still rely on virtiofs.
* On shared-machine installs, attachments are globally visible but owned by the
  principal that declared them. Ordinary code/SSH restoration uses only the
  caller's records. Mutating another owner's declaration requires both
  ``--owner_principal`` and ``--admin_override``; guest destinations must be
  unique across the VM.
* Settings sync has been removed for now because it was too flaky. Use explicit
  attachments or manual Git operations until a replacement is designed.

Known virtiofs limitation
-------------------------

Long-lived VMs with virtiofs-backed attachments accumulate host-side
``virtiofsd`` file descriptors (one per guest-cached inode) and historically
hit the daemon's fd ceiling, failing with ``Too many open files`` /
``OSError: [Errno 24]`` even when user limits look high. The dominant
trigger was the guest's nightly ``updatedb`` indexing sweep over the shares.

aivm now handles this automatically: new VMs get a guest-side *virtiofs
guard* (a systemd timer that prunes updatedb and flushes guest
dentry/inode caches at a watermark, releasing the host descriptors).
Retrofit existing VMs once with ``aivm vm fdguard --action install`` and
retire any periodic host-side ``aivm vm flush_caches`` jobs. See
:doc:`virtiofs` for the full mechanism, tuning knobs, and incident
runbook. Prefer narrow attachments, detach stale folders, and use
``--mode git`` when live writable host sharing is not required.
