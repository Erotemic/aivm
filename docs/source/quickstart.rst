Quickstart
==========

Choose one of these startup paths.

Path A: One-command project entry (recommended)
-----------------------------------------------

.. code-block:: bash

   aivm code .

Behavior:

* Uses global config store at ``~/.config/aivm/config.toml``.
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

This path is explicit and reproducible. ``aivm config init`` establishes VM
defaults and SSH identity configuration; ``aivm vm create`` provisions the VM.
During interactive init, choose the editor path for direct TOML editing or the
prompt-by-prompt path for a terminal-only walkthrough.  The detected defaults
table is shown once; later confirmations summarize only values that changed.

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
   aivm host permissions setup    # establish it (sudo used at most once)

Setup adds you to the ``libvirt`` group (the one privileged step) and prepares
a user-owned VM storage directory with ``setfacl`` traversal grants for
``libvirt-qemu``. It changes nothing in your config -- it prints the one line
(``defaults.paths.base_dir``) that the storage grant depends on, or writes it
for you with ``--persist``. Log out and back in (or ``newgrp libvirt``) after
the group change, then re-run the check.

That host work is all the default ``as-needed`` mode needs: it then stops invoking
sudo for whatever already works without it. Setting
``behavior.privilege_mode = "never"`` on top is a separate, stricter
choice -- aivm will then refuse rather than escalate, which means no nftables
firewall and no *new* ``persistent``/``shared-root`` attachments, since
``mount --bind`` requires root.

Notes
-----

* ``status --sudo`` enables privileged checks (libvirt/network/firewall/image).
  Under ``privilege_mode = "never"``, ``--sudo`` is ignored with a notice.
* ``behavior.privilege_mode`` controls escalation: ``as-needed`` (default,
  sudo only where needed), ``always`` (classic), ``never`` (refuse rather
  than escalate; see above). ``--never_sudo`` forces ``never`` for one
  invocation.
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
