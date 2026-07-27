Design Contract
===============

Purpose
-------

This document defines the long-lived engineering contract for ``aivm``.
It is the reference for product intent, safety boundaries, reliability
expectations, and coding conventions.

The journal captures implementation history. This document captures stable
intent.


Product Intent
--------------

``aivm`` is a local libvirt/KVM VM manager optimized for agent workflows.

Primary user outcomes:

* run common workflows with minimal commands (for example ``aivm code .`` and
  ``aivm ssh .``)
* keep usage low-friction for non-VM experts
* make day-to-day development feel close to host-native workflows by default
  (attach needed folders, then run ``code`` / ``ssh`` from the working folder)
* keep a clear host/guest boundary with explicit trust expansion points
* support both interactive use and automation-friendly non-interactive flows


System Model
------------

Single source of truth
~~~~~~~~~~~~~~~~~~~~~~

* Use the config store as the canonical declared state for managed VMs,
  networks, and attachments.
* Treat runtime state (libvirt, network, firewall, guest reachability) as
  observed state that may drift from declared state.

Reconciliation model
~~~~~~~~~~~~~~~~~~~~

* Commands should reconcile toward declared intent when safe.
* Re-running the same operation should converge (idempotent behavior), not
  compound side effects.
* Runtime-sensitive operations should prefer live inspection over stale
  assumptions.
* Shared-root evolution should favor stable host-side staging plus persisted
  guest-visible attachment declarations over repeated teardown/rebuild churn.


Safety and Trust Boundaries
---------------------------

1. Visibility and consent are separate guarantees

   *Visible* and *confirmable* are two axes, and the automatic-approval flags
   apply to only one of them. ``--yes`` / ``--yes-sudo`` waive **confirmation**.
   They never waive **visibility**.

   Every write, on the host or in the guest, is logged at ``INFO`` regardless of
   sudo status, and so is every command that invokes sudo on the host even when
   it only reads. Nothing a run changed may be absent from that run's default
   output. See :ref:`command-visibility-and-approval` for the case table.

2. No silent trust broadening

   Actions that broaden VM access to host resources (filesystem sharing,
   firewall relaxations, network exposure, external file edits) must be
   explicit and diagnosable.

3. Verified image sources

   Base image usage must remain integrity-checked. Local caches and mirrors are
   acceptable only when they preserve verification guarantees.

4. Fail with actionable diagnostics

   Errors should explain what failed, why, and what the operator can do next.
   Favor clear failure over ambiguous partial success in safety-critical paths.

5. Shared-folder trust is a mode, not an assumption

   Read/write host-folder sharing is the practical default today, but
   isolation-oriented modes should remain first-class. Git-backed attachment is
   now one supported alternative for explicit repo handoff, not automatic
   worktree synchronization. Read-only attachment support should continue to
   support secret-sensitive host repos and cleaner guest environments.

   Current implementation limitations:

   * direct ``shared`` attaches use one VM virtiofs device mapping per folder
     and can exhaust device-slot capacity (for example PCI/PCIe slots) when
     many folders are attached to one VM
   * ``shared-root`` and ``persistent`` reduce device-slot pressure by using a
     single export, but long-lived exports can still trigger virtiofsd
     file-descriptor retention/growth and downstream ``Too many open files``
     failures


Reliability Principles
----------------------

Idempotency
~~~~~~~~~~~

* Lifecycle operations (network create/destroy, VM create/start/delete,
  attachment reconcile) should tolerate retries and partially completed prior
  runs.
* Persistent attachment replay is a mitigation for mount churn and stale
  declaration handling. It is not proof that the underlying virtiofs/submount
  file-descriptor issue has been solved.
* Settings-copy helpers are optional convenience behavior and must not become a
  hidden project synchronization contract.

Atomic operations
~~~~~~~~~~~~~~~~~

* Multi-step file operations (downloads, generated artifacts, state writes)
  should use atomic patterns whenever practical:

  * write to temporary target
  * validate integrity/shape
  * replace into final location atomically when possible
  * clean up invalid intermediates

Integrity-verified and content-addressable data access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* All network/downloaded artifacts must be hash-verified before they are
  trusted.
* Favor content-addressable lookup paths (by digest) as a fallback for data
  access, so mutable names/URLs are not the only resolution path.
* Cached artifacts should remain re-verifiable, not implicitly trusted forever
  by pathname alone.

Preflight and readiness checks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Validate hard prerequisites as early as practical.
* Ensure readiness checks match the actual execution context (including
  privilege context).

Observability
~~~~~~~~~~~~~

* Long-running and mutating operations should expose progress and command intent
  clearly.
* The preferred unit of explanation is a user-meaningful step/plan, not an
  isolated subprocess. Logs should help operators understand what a sequence of
  commands is accomplishing.
* When writing a file to the host system, emit a note describing the write.
  If reconciliation determines there is nothing to write, skip both the write
  and the normal note; an optional debug-level message may explain the no-op.
* Normal output should be concise; deeper diagnostics should be available with
  verbosity/detail flags.


CLI and Code Architecture
-------------------------

CLI framework conventions
~~~~~~~~~~~~~~~~~~~~~~~~~

* Use ``kwconf`` for command structure and argument definitions.
* Keep command modules thin: parse/dispatch/orchestrate in CLI modules, place
  operational logic in domain modules.
* Prefer explicit command return codes and stable CLI behavior for scripting.

Operational command execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Route external command execution through a centralized command manager for
  consistent sudo policy, plan rendering, logging, and error semantics.
* Keep privilege handling explicit and auditable.
* Privilege acquisition is a policy, not a property of call sites:
  ``behavior.privilege_mode`` selects ``as-needed`` (probe unprivileged
  capability -- libvirt group access, user-writable storage trees -- and
  escalate only where required) or ``always`` (escalate every
  privileged-capable operation). ``aivm.privilege`` owns the capability
  probes and per-family decisions (``virsh_needs_sudo``,
  ``path_needs_sudo``). A global no-sudo mode is not exposed while managed
  nftables and new host bind mounts still require root.
* Because all ``virsh``/``virt-install`` commands can now run unprivileged,
  they pin ``-c qemu:///system`` explicitly (bare unprivileged ``virsh``
  would silently target ``qemu:///session``), and state-changing hypervisor
  commands require interactive approval regardless of whether sudo is used,
  preserving the consent contract of principle 1. Hypervisor control is one of
  three things that require approval; see
  :ref:`command-visibility-and-approval` for the full case table.
* Preserve ``--dry_run`` as a true non-destructive preview path.
* Automatic/background reconciliation must avoid disruptive host operations
  against existing mounts (for example, forced/lazy unmount of busy targets).
  If repair might break active guest workflows, skip with a warning and require
  an explicit user-invoked reconcile command.

Command orchestration subsystem
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Decision Title:
  Object-oriented command orchestration
Context:
  ``aivm`` runs many multi-command host steps (dependency install, network
  setup, storage preparation, cloud-init generation). Logging and sudo approval
  at one-command granularity creates repetition, weakens operator understanding,
  and encourages approval fatigue.
Decision:
  Centralize subprocess execution in an object-oriented command subsystem built
  around:

  * ``CommandManager`` as the execution authority for command submission,
    approval, logging, and result handling
  * ``IntentScope`` for nested narrative context (high-level goal plus current
    sub-step)
  * ``PlanScope`` for grouped user-visible steps that preview command
    summaries plus exact commands and usually approve once per step
  * ``CommandHandle`` for deferred but deterministic execution

  The manager should show the current step title, breadcrumb/context, why the
  step exists, and both the semantic meaning and exact command for each planned
  action in the step preview. Full raw command lines remain available in
  debug/trace output, and the full executed command is always logged for
  auditability.
Consequences:
  Sudo approval now normally happens at the plan/step boundary rather than for
  each command in a multi-command workflow. This reduces prompt fatigue while
  preserving explicit visibility into the exact commands included in the
  approved step.
Follow-ups:
  All command execution now goes through ``CommandManager``. The legacy
  ``util.run_cmd`` helper and ambient sudo-intent mechanism have been removed.
  New code should use explicit plans/intents for all subprocess work.

Intent stack semantics
~~~~~~~~~~~~~~~~~~~~~~

* Intent scopes describe nested context such as ``Create VM`` -> ``Prepare VM
  storage`` -> ``Write cloud-init files``.
* Breadcrumbs should help operators understand how the current step relates to
  the larger workflow.
* Command role (read vs modify) should be attached to the command itself when
  practical; broad parent intent must not incorrectly turn read probes into
  mutating actions.

Plan and approval semantics
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* A plan is the normal approval/logging unit for one user-meaningful step.
* Plans should preview command summaries before execution.
* Grouped approval does not widen privileges beyond the commands listed in the
  approved plan preview.
* Read-only sudo plans may still auto-approve by policy; mutating sudo plans
  should require approval unless ``--yes`` / ``--yes-sudo`` applies.
* Interactive approval semantics are:

  * ``y`` approves the current plan/block only
  * ``a`` approves the current plan/block and all later plans/blocks too
  * ``s`` shows the full exact commands for the current plan/block, then
    reprompts
* Once a plan is approved, legacy per-command sudo prompting must not fire for
  commands inside that approved plan.

.. _command-visibility-and-approval:

Command visibility and approval
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two independent questions are asked of every command, and they must not be
collapsed into one:

**Is it visible?**
  Does the command appear at ``INFO``, the default verbosity, or only under
  ``--verbose 2``?

**Is it confirmable?**
  Must the user interactively approve it before it runs?

``--yes`` / ``--yes-sudo`` answer the second question only. No flag, mode, or
setting suppresses the first.

What "sudo" means here
^^^^^^^^^^^^^^^^^^^^^^

Throughout this policy, **sudo means sudo on the host**: a ``sudo`` token that
this process places on a command line it executes, escalating the privilege of
the user running ``aivm``.

A ``sudo`` appearing *inside* a payload sent to the guest -- for example
``ssh agent@vm 'sudo -n install ...'`` -- is **not** host sudo and does not make
the command a privileged host operation. Guest root is not a meaningful
boundary: the guest credentials are known to the tool, so escalating inside the
VM costs nothing and proves nothing. Such a command is still a **write**, and is
classified by its effect, never by the presence of that inner token.

The visibility axis
^^^^^^^^^^^^^^^^^^^

A command is visible at ``INFO`` if **either**:

* it writes -- changes state on the host or in the guest; or
* it invokes sudo on the host, even if it only reads.

The second clause is deliberate and is not redundant with the first. The user is
made aware of anything with the potential to perform an unbounded privileged
sudo op, even if we know what the program being called is. Merely invoking sudo
on the command line is strong enough of a thing that it needs to be called out.
Do not reduce this rule to effect alone.

Only a read that escalates no host privilege is held back for ``--verbose 2``.
Nothing is ever discarded: raising verbosity reveals every command, plus the
literal text of any payload the log abbreviated.

Classification axes
^^^^^^^^^^^^^^^^^^^

Four properties decide both tables. They are independent questions and must be
answered separately; collapsing any two of them is how a case goes unclassified.

Effect
  ``read`` or ``write``. A command writes if it changes state anywhere, on the
  host or inside the guest.

Authority
  What the command spends: ``none``, ``host sudo`` (a ``sudo`` token this
  process places on a command line), or ``hypervisor control`` (a
  state-changing ``virsh`` / ``virt-install`` command, which spends
  root-equivalent ``libvirt`` group membership whether or not sudo was needed).

Ownership
  Whose state a write touches: ``tool`` -- state ``aivm`` created and manages
  for itself, such as export roots, caches, and generated cloud-init -- or
  ``user`` -- anything else, including the user's source tree, host system
  configuration, and the guest.

Inspectability
  Whether the log can render the command in full, or a payload is too large to
  print and is omitted (see the ``Elided`` marker in ``aivm/commands.py``).

Ownership is a real axis rather than a footnote on authority. An unprivileged
write to a directory ``aivm`` created for itself is implied by invoking the
command at all; the same write into the user's tree or the guest is not.

Policy table: visibility
^^^^^^^^^^^^^^^^^^^^^^^^

Rows are evaluated in order; the first match decides. No flag or setting
changes this table.

.. list-table::
   :header-rows: 1
   :widths: 30 22 18 30

   * - Effect
     - Host sudo
     - Level
     - Why
   * - write (host or guest)
     - any
     - ``INFO``
     - the run changed something; the record of it is not optional
   * - read
     - yes
     - ``INFO``
     - escalation is called out on its own merits, not for what it read
   * - read
     - no
     - ``--verbose 2``
     - changes nothing and crosses no boundary; plumbing

Policy table: approval
^^^^^^^^^^^^^^^^^^^^^^

Rows are evaluated in order; the first match decides. ``--yes`` /
``--yes-sudo`` waive every prompt below, and nothing else does.

.. list-table::
   :header-rows: 1
   :widths: 12 24 16 20 16

   * - Effect
     - Authority
     - Ownership
     - Inspectability
     - Confirm
   * - read
     - none
     - --
     - --
     - no
   * - read
     - host sudo
     - --
     - --
     - by policy [#robypolicy]_
   * - write
     - host sudo
     - any
     - any
     - yes
   * - write
     - hypervisor control
     - any
     - any
     - yes
   * - write
     - none
     - tool
     - any
     - no
   * - write
     - none
     - user
     - payload omitted
     - yes
   * - write
     - none
     - user
     - fully logged
     - **unsettled** [#unsettled]_

.. [#robypolicy] Auto-approves under ``auto_approve_readonly_sudo``, else
   prompts. Visible either way.
.. [#unsettled] Today these run without a prompt: an unprivileged, fully
   printable write into the user's tree or the guest matches no approval
   trigger. Whether that is correct is an open question this table exists to
   expose rather than hide. Resolving it decides, for example, whether
   ``ssh vm 'mkdir -p ...'`` should prompt.

Rationale for the non-obvious rows. A write with ``hypervisor control``
confirms even unprivileged, because ``libvirt`` group membership is
root-equivalent, so the authority is spent whether or not sudo appeared. A
write to ``tool`` ownership does not confirm, because it is already implied by
invoking the command, and prompting for it is the approval fatigue principle 1
exists to avoid. A ``user`` write with an omitted payload confirms on
inspectability rather than privilege: approval is the only moment at which the
user could read what is about to run, which is precisely what an unreadable
23KB installer script otherwise denies them.

Worked examples
^^^^^^^^^^^^^^^

Each row is classified on the four axes, then read off the tables above.

.. list-table::
   :header-rows: 1
   :widths: 26 10 18 12 16 10 10

   * - Command
     - Effect
     - Authority
     - Ownership
     - Inspectability
     - Visible
     - Confirm
   * - ``virsh dominfo``
     - read
     - none
     - --
     - fully logged
     - ``-vv``
     - no
   * - ``sudo qemu-img info``
     - read
     - host sudo
     - --
     - fully logged
     - ``INFO``
     - by policy
   * - ``qemu-img info`` as root
     - read
     - none [#root]_
     - --
     - fully logged
     - ``-vv``
     - no
   * - ``ssh vm true``
     - read
     - none
     - --
     - fully logged
     - ``-vv``
     - no
   * - ``virsh setvcpus``
     - write
     - hypervisor control
     - user
     - fully logged
     - ``INFO``
     - yes
   * - ``sudo nft ...``
     - write
     - host sudo
     - user
     - fully logged
     - ``INFO``
     - yes
   * - ``mkdir -p`` on an export root
     - write
     - none
     - tool
     - fully logged
     - ``INFO``
     - no
   * - ``ssh vm 'sudo -n install ...'``
     - write
     - none [#guest]_
     - user
     - payload omitted
     - ``INFO``
     - yes
   * - ``ssh vm 'mkdir -p ...'``
     - write
     - none
     - user
     - fully logged
     - ``INFO``
     - unsettled [#unsettled]_

.. [#root] Already root, so no ``sudo`` token reaches the command line. There
   is no escalation to call out.
.. [#guest] The ``sudo -n`` runs in the guest and is not host sudo, so the row
   is decided by the write and by the payload being unprintable, never by that
   token.

Loose commands are a defect, not a mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A command submitted outside ``mgr.step(...)`` is queued loose and gets a
reduced prompt that cannot show its full text. This is not a second supported
approval path; it is a call site that was never wrapped. ``submit`` already
appends to the open plan when there is one, so wrapping a call site is
sufficient to give it the full ``y`` / ``a`` / ``s`` semantics above.

The "not grouped into an explicit step" warning enumerates the remaining work.
The target state is that ``_confirm_loose_command`` has no callers and the
reduced prompt is deleted, rather than that it grows features to match the plan
prompt.

Design constraints
~~~~~~~~~~~~~~~~~~

* All workflow code should submit commands through ``CommandManager`` and use
  explicit ``IntentScope`` / ``PlanScope`` blocks.
* Shared-root host preparation must preserve the ownership and permissions of
  the user's source tree; qemu/libvirt-access preparation should be limited to
  aivm-managed internal directories rather than applied recursively through
  bind-mounted exports.
* New attachment backends should prefer a single VM-level export model, like
  ``persistent-root`` / ``shared-root``, when they only need different replay /
  reconcile semantics.
* New non-virtiofs backends should be considered if they materially reduce the
  long-lived virtiofsd FD-retention risk.

State management
~~~~~~~~~~~~~~~~

* Keep state transitions explicit.
* Avoid hidden coupling between config mutation and runtime mutation.
* When behavior depends on inferred state, provide diagnostics that make the
  inference visible.

Provisioning scope
~~~~~~~~~~~~~~~~~~

* Provide basic provisioning primitives and sensible defaults.
* Keep provisioning policy user-directed rather than overly prescriptive.
* Prefer extensibility over hardcoding opinionated full-environment setup.


Testing Contract
----------------

* Unit tests should cover success paths and failure messaging for new behavior.
* Integration/E2E flows should include explicit prerequisite checks and clear
  failure reasons.
* Cleanup paths should run in ``finally`` blocks for lifecycle tests.
* Tests should protect idempotency and atomicity assumptions when those are part
  of command guarantees.


Design Change Process
---------------------

When a change modifies behavior at a design level (safety boundary, trust model,
state model, CLI contract, compatibility policy), update this document in the
same change.

Keep updates concise and structured using this template:

.. code-block:: text

   Decision Title:
   Context:
   Decision:
   Consequences:
   Follow-ups:

Guidelines:

* This document should remain evergreen and principle-focused.
* Journal entries may reference time-specific incidents; this document should
  not rely on those references.
* If implementation and this contract diverge, either align implementation or
  update this contract explicitly.

Roadmap
-------

Major forward-looking efforts are designed in ``dev/design/future/``; see
``dev/design/future/README.md`` for the index, statuses, and recommended
sequencing (externally-managed virtiofsd, egress allowlist networking,
snapshots/ephemeral clones, e2e in CI). A per-user ``qemu:///session``
runtime was prototyped and removed; see
``docs/planning/deferred/session-runtime.md``.

Implementation TODO Notes
-------------------------

To fully realize the integrity/content-addressable principle, current code
should be evolved in these areas:

* ``aivm/vm/images.py``:
  add digest-keyed cache lookup fallback before URL fetch. (Pre-existing
  cached base images are now revalidated by checksum before reuse; the
  digest-keyed lookup remains open.)
* ``aivm/config.py``:
  move image cache identity toward digest-first semantics (``cache_name`` is
  currently name-oriented).
* ``aivm/status.py``:
  status reporting should eventually reflect both named-path cache and any
  content-addressable fallback resolution.
* E2E/shared cache helpers in ``tests/e2e/_helpers.py``:
  keep local cache path/version conventions aligned with digest-addressable
  behavior once implemented in runtime code.
* Folder sharing backend flexibility:
  evaluate alternatives that scale beyond per-folder virtiofs device-slot
  limits (see ``dev/design/future/flexible-folder-sharing.md``).
* Long-lived virtiofs FD growth:
  continue investigating ``virtiofsd`` FD retention/growth on ``shared-root``
  and ``persistent`` exports. ``dev/devcheck/debug-harness.sh`` is the current
  evidence-gathering tool, but the root cause is not solved.


Non-goals
---------

* cloud orchestration
* broad hypervisor abstraction beyond the current local libvirt focus
* opaque "magic" recovery that hides security-sensitive state changes
* forcing one fixed provisioning stack for all users/workflows
