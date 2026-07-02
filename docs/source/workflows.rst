Workflows
=========

Common daily workflows.

New configs derive the default VM name from the host's own ``$HOSTNAME``. On a
host named ``workstation``, the canonical VM name, guest hostname, and SSH alias are
all ``aivm-2404-workstation``. Existing explicit config values are left alone; omitted
implicit names use the new host-qualified default.

Open project in VM
------------------

.. code-block:: bash

   aivm code .
   aivm vm code .

These shortcut flows now report progress as grouped steps. Expect a current
step title, a short explanation of why that step is happening, semantic command
summaries, and the exact commands that will run. Privileged host changes prompt
once for the whole step when approval is required.

For the default ``persistent`` attachment path, the current implementation
usually breaks reconciliation into:

* inspect persistent host bind state
* prepare persistent-root bind targets
* inspect/ensure the VM persistent-root virtiofs mapping
* sync the persisted attachment manifest
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
   aivm vm attach --vm aivm-2404-$HOSTNAME --host_src . --guest_dst /workspace/project
   aivm attach . --mode git

``aivm code`` / ``aivm ssh`` restore the requested folder and attempt to
remount the VM's other saved folder attachments after reboot.

Attachment modes:

* ``persistent`` (default for new attachments): a dedicated ``persistent-root``
  virtiofs export plus a persisted attachment manifest and guest systemd replay
  helper. This keeps host-side staged binds stable and restores guest-visible
  bind mounts at boot or during reconcile.
* ``shared-root``: the legacy single-export backend with one VM virtiofs mapping
  and per-folder host/guest bind mounts. Existing saved ``shared-root``
  attachments continue to use it; new attachments can request it explicitly
  with ``--mode shared-root``.
* ``shared``: direct per-folder virtiofs mapping.
* ``git``: guest-local Git repo bootstrap plus host/guest remote plumbing.
  It does not automatically synchronize worktree contents.

In sudoless mode (``behavior.privilege_mode = "sudoless"``) new attachments
default to ``shared`` instead of ``persistent``: the ``persistent`` and
``shared-root`` backends stage host bind mounts, which require root.
Requesting them explicitly in sudoless mode fails with detach/reattach
guidance rather than escalating.

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

Long-lived virtiofs-backed VMs historically hit a file-descriptor failure:
host-side ``virtiofsd`` keeps one descriptor per guest-cached inode, the
guest never evicts on its own, and the guest's stock nightly ``updatedb``
sweep walked every attached inode — so the daemon marched to its fd ceiling
and normal traversal failed with ``Too many open files`` /
``OSError: [Errno 24]``.

This is now prevented automatically by the guest-side virtiofs guard: new
VMs install it via cloud-init, and ``aivm vm update`` reconciles existing
running VMs against the ``virtiofs.fd_guard*`` config (install, refresh
after config/version changes, or uninstall when disabled). The guard prunes
``updatedb`` and flushes guest dentry/inode caches when the cached-inode
watermark is crossed. See :doc:`virtiofs` for the full analysis and tuning.

Operational guidance:

* verify the guard with ``aivm vm fdguard`` (status is the default action)
  and retire any periodic host-side ``aivm vm flush_caches`` jobs
* keep attachments narrow and remove stale attachment records when possible
* prefer ``--mode git`` for repositories that can tolerate explicit Git
  handoff instead of live host sharing
* ``aivm vm flush_caches`` remains available as a manual recovery command;
  restart the VM only if flushing is not enough
* use ``dev/devcheck/debug-harness.sh`` or
  ``dev/devcheck/virtiofsd_fd_postmortem.py`` to collect host/guest
  evidence when debugging

Attachment mode rules:

* New folder defaults to ``persistent`` when ``--mode`` is omitted.
* Existing folder reuses its saved mode when ``--mode`` is omitted.
* Changing mode for an existing folder requires explicit detach + reattach.
  Passing a different ``--mode`` directly now returns an error.
* ``shared-root`` is still supported explicitly and for existing saved
  attachments, but ``persistent`` is the default migration target for attachment
  replay instead of repeated host-side mount churn.
* The persistent replay helper is installed as part of VM bootstrap, so stopped-VM
  attaches can still replay on the next boot once the persistent-root mapping and
  manifest are in place.

``aivm code --mode git .`` specifics:

* New folder: attaches in ``git`` mode, with default guest path matching the
  exact host path.
* Previously attached non-``git`` folder, including ``shared``, ``shared-root``,
  or ``persistent``: errors until you detach and reattach in ``git`` mode.
* No explicit mode (``aivm code .``): use saved mode when present, else create a
  new ``persistent`` attachment.

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
   aivm config lint      # flag unknown/unused keys and sections
   aivm config format    # rewrite into the canonical split-file layout
   aivm config paths     # show config, data, and libvirt-related paths

Reconcile VM drift
------------------

.. code-block:: bash

   aivm vm edit     # change the saved VM config fragment in $EDITOR
   aivm vm update   # reconcile the live libvirt domain against saved config

Run without sudo
----------------

.. code-block:: bash

   aivm host sudoless check
   aivm host sudoless setup
   aivm status            # header shows the active privilege mode
   aivm vm up --never_sudo  # force sudoless for one invocation

The default ``auto`` mode already prefers unprivileged execution and only
escalates where required, so most hosts need no ceremony: joining the
``libvirt`` group removes sudo from every ``virsh``/``virt-install`` call, and
a user-owned ``paths.base_dir`` removes it from image/disk/cloud-init file
work. ``sudoless setup`` performs those two changes (using sudo at most once,
for ``usermod``) and persists ``behavior.privilege_mode = "sudoless"``, after
which ``aivm`` refuses to invoke sudo at all: the managed nftables firewall is
skipped with a warning, and bind-mount attachment modes fail with guidance.

State-changing hypervisor commands keep the same interactive approval prompts
they had under sudo, so unprivileged operation does not make destructive
operations promptless.

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
when they execute. For ``persistent`` and ``shared-root`` attachments, host-side
preparation is designed to avoid mutating ownership or permissions in the
user's source tree.

Get command tree
----------------

.. code-block:: bash

   aivm help tree
   aivm help plan
   aivm help raw
   aivm help completion

Related projects
----------------

See :doc:`alternatives` for related tools (Matchlock, JAI) and how their
tradeoffs compare with ``aivm``'s persistent-VM, attachment-first approach.
