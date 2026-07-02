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

After either path
-----------------

.. code-block:: bash

   aivm status
   aivm status --sudo
   aivm vm update

Optional: sudoless operation
----------------------------

If you prefer ``aivm`` to never invoke ``sudo``:

.. code-block:: bash

   aivm host sudoless check    # report what is missing
   aivm host sudoless setup    # establish it (sudo used at most once)

Setup adds you to the ``libvirt`` group (the one privileged step), moves the
default VM storage to a user-owned directory with ``setfacl`` traversal grants
for ``libvirt-qemu``, disables the managed nftables firewall (it requires
root; keep it with ``--keep_firewall``), and persists
``behavior.privilege_mode = "sudoless"``. Log out and back in (or ``newgrp
libvirt``) after the group change, then re-run the check.

In sudoless mode new attachments default to ``--mode shared`` (direct
virtiofs); the ``persistent`` and ``shared-root`` modes rely on host bind
mounts, which require root. The default ``auto`` mode needs no setup ceremony:
it simply stops using sudo for whatever already works without it.

Notes
-----

* ``status --sudo`` enables privileged checks (libvirt/network/firewall/image).
  In sudoless mode ``--sudo`` is ignored with a notice.
* ``behavior.privilege_mode`` controls escalation: ``auto`` (default, sudo
  only where needed), ``sudo`` (classic), ``sudoless`` (never; see above).
  ``--never_sudo`` forces sudoless for one invocation.
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

Long-lived VMs with virtiofs-backed attachments can accumulate host-side
``virtiofsd`` file descriptors after heavy traversal of shared folders. The
symptom is usually ``Too many open files`` / ``OSError: [Errno 24]`` from
ordinary filesystem tools even when user limits look high.

``persistent`` mode mitigates attachment replay and mount churn, but it has not
solved this underlying virtiofs behavior. Restarting the VM usually clears the
bad runtime state. Prefer narrow attachments, detach stale folders, and use
``--mode git`` when live writable host sharing is not required.
