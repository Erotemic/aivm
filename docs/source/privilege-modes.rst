Privilege modes
===============

``aivm`` runs its VMs on the root system libvirt daemon
(``qemu:///system``). What varies is *how host commands acquire the
privileges they need*, controlled by ``behavior.privilege_mode``.

The modes
---------

All three answer the same question --- *when does aivm invoke sudo?* ---
so they read as an ordered scale rather than three unrelated words:

* ``never``: refuse rather than escalate. Operations that genuinely
  require root fail with guidance.
* ``as-needed`` (default): probe what already works without sudo and
  escalate only where required.
* ``always``: escalate for every privileged-capable operation (the
  classic behavior).

An unrecognized value is an error, not a fallback. Every fallback would
have to guess, and guessing wrong on a privilege setting means either
escalating when you forbade it or refusing work you expected to succeed.

The mode is enforced at a single chokepoint ---
``CommandManager._reject_sudo_if_forbidden`` sees every subprocess --- so
enforcement keys on the command actually being run, never on the feature
requesting it. A feature that *can* need root (a ``persistent``
attachment needs ``mount --bind`` only when the bind is missing) is not
refused up front; the command that needs root is.

The two postures
----------------

.. list-table::
   :header-rows: 1
   :widths: 26 37 37

   * -
     - Classic (admin-assuming)
     - Sudoless
   * - Configuration
     - ``privilege_mode = "as-needed"`` or ``"always"`` (default --
       nothing to set)
     - ``privilege_mode = "never"``
   * - Host privilege needed
     - sudo (prompted per grouped step)
     - ``libvirt`` group membership -- **effectively root-equivalent**,
       but ``aivm`` itself never runs sudo
   * - VM storage
     - ``/var/lib/libvirt/aivm`` (root-owned)
     - user-owned tree + ``setfacl`` traversal for ``libvirt-qemu``
   * - nftables firewall
     - available
     - unavailable (``nft`` requires root, with no unprivileged
       equivalent)
   * - Attachment modes
     - all (``persistent`` default)
     - all, except that establishing a *new* bind mount
       (``persistent`` / ``shared-root``) needs one ``mount --bind``.
       ``shared`` needs no bind mount at all.
   * - Setup
     - none
     - ``aivm host sudoless setup``
   * - Preflight report
     - ``aivm host doctor``
     - ``aivm host sudoless check``
   * - E2E proof suite
     - ``test_e2e_nested.py`` / ``test_e2e_full.py``
     - ``test_e2e_sudoless.py``

Choosing a mode
---------------

* **Classic** (``as-needed``) is the default and the right answer for
  almost everyone. After ``aivm host sudoless setup`` has put you in the
  ``libvirt`` group and pointed VM storage at a user-owned tree,
  ``as-needed`` stops invoking sudo for libvirt and image operations on its own. Sudo
  remains for the operations that genuinely require it: the nftables
  firewall, ``apt-get``, and establishing a *new* host bind mount.
  Reconciling an already-established attachment -- the ``aivm code .``
  hot path -- issues no privileged command at all.
* **Sudoless** (``never``) is a hard guarantee rather than a preference:
  aivm raises instead of escalating. It suits CI and audit contexts. Note
  that it cannot establish a new ``persistent`` or ``shared-root`` attachment,
  because ``mount --bind`` has no unprivileged implementation, and it
  cannot manage the firewall.

Understand the trade in either case: ``libvirt`` group membership grants
control of the root daemon, which is root-equivalent on the host.
``never`` is a *no-sudo-invocation* guarantee, not a reduced-privilege
one. See :doc:`security` for the full analysis.

A per-user ``qemu:///session`` runtime was prototyped and removed before
release; see ``docs/planning/deferred/session-runtime.md``.
