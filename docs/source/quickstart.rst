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

Optional: rootless session runtime
----------------------------------

Sudoless still uses the root *system* libvirt daemon (the ``libvirt`` group
is effectively root-equivalent). For truly rootless VMs on the per-user
``qemu:///session`` daemon:

.. code-block:: bash

   aivm host rootless check    # /dev/kvm access, session libvirt, passt, storage
   aivm host rootless setup    # kvm group (sudo used at most once) + defaults
   aivm vm create              # new VMs land on qemu:///session
   aivm ssh .

Setup adds you to the ``kvm`` group (the one privileged step; log out and
back in afterwards), points default VM storage at a user-owned tree
(``~/.local/share/aivm``), persists ``runtime.mode = "session"`` in the
defaults, and forces sudoless. Session VMs use passt user-mode networking:
guest SSH is forwarded to a persisted localhost port (shown by
``aivm status``), there is no managed network or nftables firewall, and
folder attachments currently support ``--mode git`` only.

.. note::

   Ubuntu 24.04's stock AppArmor profile for passt breaks libvirt-launched
   passt (mmap of its own binary and the pid file under ``/run/user`` are
   denied). If ``aivm vm create`` reports a passt failure, add
   ``/usr/bin/passt{,.avx2} mr,`` and
   ``owner /run/user/[0-9]*/libvirt/qemu/run/passt/* rw,`` to the profile in
   ``/etc/apparmor.d/usr.bin.passt`` and reload it with
   ``sudo apparmor_parser -r /etc/apparmor.d/usr.bin.passt``.

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
