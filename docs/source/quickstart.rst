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

Notes
-----

* ``status --sudo`` enables privileged checks (libvirt/network/firewall/image).
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
