Workflows
=========

Common daily workflows.

Open project in VM
------------------

.. code-block:: bash

   aivm code .
   aivm vm code .

These shortcut flows now report progress as grouped steps. Expect a current
step title, a short explanation of why that step is happening, semantic command
summaries, and the exact commands that will run. Privileged host changes prompt
once for the whole step when approval is required.

For the default ``shared-root`` attachment path, the current implementation
usually breaks reconciliation into:

* inspect shared-root host bind state
* prepare host bind targets
* inspect/ensure the VM virtiofs mapping
* mount and verify the bind inside the guest

SSH into mapped directory
-------------------------

.. code-block:: bash

   aivm vm ssh .
   aivm vm ssh_config

Attach folders
--------------

.. code-block:: bash

   aivm attach .
   aivm detach .
   aivm vm attach --vm aivm-2404 --host_src . --guest_dst /workspace/project
   aivm attach . --mode git

``aivm code`` / ``aivm ssh`` restore the requested folder and attempt to
remount the VM's other saved folder attachments after reboot.

Attachment modes:

* ``shared-root`` (default for new attachments): one persistent VM virtiofs
  mapping and per-folder host/guest bind mounts.
* ``persistent``: a dedicated ``persistent-root`` virtiofs export plus a persisted
  attachment manifest and guest systemd replay helper. This keeps host-side
  staged binds stable and restores guest-visible bind mounts at boot or during
  reconcile.
* ``shared``: direct per-folder virtiofs mapping.
* ``git``: guest-local Git repo bootstrap plus host/guest remote plumbing.
  It does not automatically synchronize worktree contents.

``--mode git`` switches the attachment to a normal guest-local repo. That
avoids a writable host share and adds a host-side Git remote pointing at the
guest repo. ``aivm`` configures the guest side with
``receive.denyCurrentBranch=updateInstead`` so the host can push committed
branch state into the checked-out guest repo and fetch guest commits later.
Git-mode default guest paths match the exact host path unless ``--guest_dst``
overrides them.

Major limitation: shared folder count
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each ``shared`` folder consumes a dedicated virtiofs device mapping. Large
attachment sets can exhaust VM device-slot capacity (for example PCI/PCIe
slots), causing attach/restore failures such as
``No more available PCI slots``.

``shared-root`` and ``persistent`` reduce this pressure by using a single
persistent virtiofs mapping per VM.

If this happens, prefer ``--mode git`` for some folders, detach unused shared
folders, or split the workload across multiple VMs.

Major limitation: long-lived virtiofs FD growth
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Long-lived ``shared-root`` and ``persistent`` VMs can still run into a
virtiofs/submount file-descriptor problem. The visible error is often
``Too many open files`` or ``OSError: [Errno 24]`` from normal traversal tools
inside the guest or from host tools walking the attached tree.

Current investigation points at host-side ``virtiofsd`` workers retaining many
path-backed file descriptors across exported token trees after heavy traversal.
The ``persistent`` backend reduces repeated mount teardown/rebuild churn, but
it does not remove the shared virtiofs export design and therefore should be
treated as a mitigation rather than a fix.

Operational guidance:

* keep attachments narrow and remove stale attachment records when possible
* prefer ``--mode git`` for repositories that can tolerate explicit Git
  handoff instead of live host sharing
* restart the VM when the failure appears; this usually resets the hot
  ``virtiofsd`` state
* use ``dev/devcheck/debug-harness.sh`` to collect comparable host/guest
  evidence when debugging the issue

Attachment mode rules:

* New folder defaults to ``shared-root`` when ``--mode`` is omitted.
* Existing folder reuses its saved mode when ``--mode`` is omitted.
* Changing mode for an existing folder requires explicit detach + reattach.
  Passing a different ``--mode`` directly now returns an error.
* ``persistent`` is opt-in for now and is the preferred migration target for
  users who want attachment replay instead of repeated host-side mount churn.
* The persistent replay helper is installed as part of VM bootstrap, so stopped-VM
  attaches can still replay on the next boot once the persistent-root mapping and
  manifest are in place.

``aivm code --mode git .`` specifics:

* New folder: attaches in ``git`` mode, with default guest path matching the
  exact host path.
* Previously attached ``shared``/``shared-root`` folder: errors until you detach
  and reattach in ``git`` mode.
* No explicit mode (``aivm code .``): use saved mode when present, else create a
  new ``shared-root`` attachment.

.. code-block:: bash

   aivm detach .
   aivm attach . --mode git

Attachment access modes:

* ``rw`` (default): read-write access to the shared folder.
* ``ro``: read-only access; supported for ``shared``, ``shared-root``, and
  ``persistent`` modes.

Specify access with ``--access``:

.. code-block:: bash

   aivm attach . --access ro

Inspect and list resources
--------------------------

.. code-block:: bash

   aivm status
   aivm status --detail
   aivm list
   aivm list --section vms
   aivm list --section networks
   aivm list --section folders

Manage config store
-------------------

.. code-block:: bash

   aivm config show
   aivm config edit
   aivm config discover

Reconcile VM drift
------------------

.. code-block:: bash

   aivm vm update

Workflow logging model
----------------------

``aivm`` command execution is organized around:

* nested intent context, which keeps the larger goal visible
* step/plan previews, which describe what the current sequence of commands is
  about to do and show the exact commands that will run
* raw commands, which remain visible for deeper inspection at higher verbosity

This is meant to make multi-command workflows easier to follow and safer to
approve than a stream of isolated sudo command prompts. All command execution
now flows through ``CommandManager`` with explicit intent/plan structure.

Interactive approval semantics:

* ``y`` approves the current block only
* ``a`` approves the current block and all later blocks
* ``s`` shows the full exact commands for the current block, then reprompts

Normal previews are intentionally readable and may abbreviate long shell blobs,
but the full exact commands can be shown before approval and are always logged
when they execute. For ``shared-root`` attachments, host-side preparation is
designed to avoid mutating ownership or permissions in the user's source tree.

Get command tree
----------------

.. code-block:: bash

   aivm help tree
   aivm help plan
   aivm help raw
   aivm help completion

Related projects
----------------

* `Matchlock <https://github.com/jingkaihe/matchlock>`_: ephemeral microVMs for
  AI-agent workloads with network allowlisting and host-side secret injection.
* `JAI <https://github.com/stanford-scs/jai>`_: lightweight Linux jail for AI
  CLIs with current-directory access and copy-on-write or stricter home
  handling.

These tools make different tradeoffs than ``aivm``. ``aivm`` emphasizes a
persistent libvirt/KVM Ubuntu VM with explicit folder attachments and
VS Code/SSH-oriented local development workflows.
