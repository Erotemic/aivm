Runtimes and privilege modes
============================

``aivm`` has two independent configuration axes that are easy to conflate.
This page separates them and describes the three practical operating
postures they combine into.

The two axes
------------

**Runtime** (``runtime.mode``, per-VM) — *which hypervisor daemon owns the
VM*:

* ``system`` (default): the root system libvirt daemon
  (``qemu:///system``). VMs get a managed NAT network, storage under
  ``/var/lib/libvirt/aivm``, and optional nftables firewall isolation.
* ``session``: the per-user libvirt daemon (``qemu:///session``). QEMU
  runs as you. No root daemon is involved at any point.

**Privilege mode** (``behavior.privilege_mode``, global) — *how host
commands acquire privileges*:

* ``auto`` (default): probe what already works without sudo and escalate
  through sudo only where required.
* ``sudo``: always escalate privileged host operations through sudo (the
  classic behavior).
* ``sudoless``: never invoke sudo; features that genuinely require root
  fail with guidance instead of escalating.

The axes answer different questions: runtime is *whose daemon and
resources*, privilege mode is *whether the CLI may run sudo*. One
coupling exists: activating a session-runtime VM structurally forces
``sudoless``, because a rootless flow that silently escalated would be a
contradiction.

The three postures
------------------

.. list-table::
   :header-rows: 1
   :widths: 22 26 26 26

   * -
     - Classic (admin-assuming)
     - Sudoless
     - Rootless (session)
   * - Configuration
     - ``runtime.mode = "system"`` + ``privilege_mode = "auto"`` or
       ``"sudo"`` (all defaults — nothing to set)
     - ``runtime.mode = "system"`` + ``privilege_mode = "sudoless"``
     - ``runtime.mode = "session"`` (forces sudoless)
   * - Libvirt daemon
     - root system daemon (``qemu:///system``)
     - root system daemon (``qemu:///system``)
     - per-user daemon (``qemu:///session``)
   * - Host privilege needed
     - sudo (prompted per grouped step)
     - ``libvirt`` group membership — **effectively root-equivalent**,
       but ``aivm`` itself never runs sudo
     - ``kvm`` group membership only (not root-equivalent)
   * - VM storage
     - ``/var/lib/libvirt/aivm`` (root-owned)
     - user-owned tree + ``setfacl`` traversal for ``libvirt-qemu``
     - user-owned tree (``~/.local/share/aivm``), plain directories
   * - Networking
     - managed NAT network (bridge + DHCP)
     - managed NAT network
     - user-mode passt; guest SSH forwarded to a persisted localhost port
   * - nftables firewall
     - available
     - skipped (needs root); warns
     - not applicable (no managed network to filter)
   * - Attachment modes
     - all (``persistent`` default)
     - ``shared`` default; bind-mount modes rejected
     - ``git`` only (virtiofs needs the system daemon for now)
   * - Setup
     - none
     - ``aivm host sudoless setup``
     - ``aivm host rootless setup``
   * - Preflight report
     - ``aivm host doctor``
     - ``aivm host sudoless check``
     - ``aivm host rootless check``
   * - E2E proof suite
     - ``test_e2e_nested.py`` / ``test_e2e_full.py``
     - ``test_e2e_sudoless.py``
     - ``test_e2e_session.py``

Choosing a posture
------------------

* **Classic** is the simplest and most capable: full attachment support,
  managed network, optional firewall isolation. Choose it when you are
  the machine's administrator and interactive sudo prompts are
  acceptable. It requires no setup ceremony and remains the default —
  nothing about the newer modes changes it.
* **Sudoless** keeps every system-runtime feature that does not
  fundamentally require root, and guarantees ``aivm`` never invokes
  sudo. Understand the trade: ``libvirt`` group membership grants
  control of the root daemon, which is root-equivalent on the host. It
  is a *no-sudo-invocation* guarantee, not a reduced-privilege one.
* **Rootless** is the strongest host-privilege posture: no root daemon,
  user-owned everything, one forwarded localhost port. Choose it on
  hosts where you cannot or do not want to hold root-equivalent grants.
  The trades are feature-level: git-only attachments and no
  managed-network/nftables egress isolation (the guest gets whatever
  passt NAT provides). See :doc:`security` for the full analysis.

Coexistence and switching
-------------------------

The runtime is a per-VM property. One config store can hold a session VM
and a system VM side by side; each command resolves its VM's runtime and
targets the right daemon, storage, and connectivity records with no
cross-talk.

Changing ``runtime.mode`` on an existing VM is **not** a migration: the
domain, disk, and network identity live with the original daemon.
Recreate the VM instead (``aivm vm delete`` + ``aivm vm create``).

The setup tools only change *defaults for new VMs* (plus the global
privilege mode); they never touch existing VM records. Existing VMs keep
working exactly as created, whichever posture they were born under.
