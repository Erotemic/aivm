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

When escalation is not available at all
----------------------------------------

Host permissions and sudo are separate grants: on a shared workstation an
administrator commonly gives users the ``libvirt`` and ``aivm`` groups and no
sudoers entry. ``aivm host permissions check`` reports what that means for
*your* account rather than for a privileged one, and the operations that still
need root fail with a message naming what wanted it and what to ask an
administrator for --- not a bare ``sudo -v`` error. Once an escalation attempt
has failed, later steps in the same run degrade immediately instead of
re-prompting an account that has already been shown to have no usable sudo.

The firewall is the case worth understanding, because ``nft`` has no
unprivileged read. Three states are kept distinct:

* **present** --- nothing to do;
* **missing** --- installed, or reported as missing-and-not-installable;
* **unverifiable** --- reported as unverified, and *nothing is changed*.

Conflating the last two is what makes an unprivileged account unusable: an
administrator's correctly-installed table is invisible to an ordinary user, and
treating that silence as "absent" schedules a repair they cannot perform. AIVM
warns and continues instead. A firewall that cannot be checked is never allowed
to be the thing that stops someone from working.

The rules themselves are verified before a guest can use the bridge --- on
``vm up`` and ``vm restart`` as well as at creation --- because the managed
table lives only in the live kernel ruleset and a host reboot removes it while
the VM definition survives. Pass ``--no-ensure_firewall`` to skip the check.

What appears in the log
-----------------------

You are made aware of anything with the potential to perform an unbounded
privileged sudo op, even when the program being called is known. Merely
invoking ``sudo`` on the command line is strong enough of a thing that it needs
to be called out, so every escalated command is printed at default verbosity
regardless of whether it only reads. ``sudo qemu-img info`` inspects a disk and
changes nothing, and it is still announced.

State-changing commands are likewise always printed. What is held back for
``--verbose 2`` is the remainder: reads that escalate nothing, such as ``virsh
dominfo`` on a host where ``libvirt`` group membership has already removed the
need for sudo. Nothing is discarded -- raising verbosity shows every command,
along with the literal text of any payload the log abbreviated.
