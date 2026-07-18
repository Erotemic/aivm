Privilege modes
===============

``aivm`` runs VMs on the root system libvirt daemon
(``qemu:///system``). ``behavior.privilege_mode`` controls when host commands
use sudo.

Supported modes
---------------

* ``as-needed`` (default): probe what already works without sudo and escalate
  only where required.
* ``always``: escalate for every privileged-capable operation.

Unknown values are errors. In particular, the former experimental ``never``
value is not supported or advertised. The current runtime still needs root for
managed nftables and for establishing new host bind mounts. Pretending those
operations have an unprivileged implementation would either weaken isolation or
make ordinary workflows fail unpredictably.

Reducing sudo use
-----------------

``aivm host permissions check`` reports where the host still needs escalation.
``aivm host permissions setup`` can add the invoking user to the ``libvirt``
group and prepare user-manageable storage. After that work, ``as-needed``
usually avoids sudo for libvirt and image operations while retaining it for
operations that really require root.

Existing VMs do not need to be recreated. ``aivm host permissions setup
--adopt`` stops running VMs, changes access metadata on their existing storage
in place, and restarts them. It does not move storage, rewrite disk bytes, or
replace domain definitions. The recursive pass prunes descendant mounts and
symlinks so attachment bind mounts cannot carry the metadata change into the
user's source tree.

``libvirt`` group membership grants control of the root daemon and is therefore
effectively root-equivalent. Reducing sudo prompts is not the same as reducing
the account's host authority. See :doc:`security` for the full analysis.
