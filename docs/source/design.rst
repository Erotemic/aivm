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

1. Explicit consent for privileged host changes

   Privileged operations must be visible and confirmable unless the user has
   explicitly opted into automatic approval (``--yes`` / ``--yes-sudo``).

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
  ``behavior.privilege_mode`` selects ``auto`` (probe unprivileged
  capability -- libvirt group access, user-writable storage trees -- and
  escalate only where required), ``sudo`` (always escalate), or ``sudoless``
  (never invoke sudo). ``aivm.privilege`` owns the capability probes and
  per-family decisions (``virsh_needs_sudo``, ``path_needs_sudo``); the
  ``CommandManager`` enforces the sudoless guarantee structurally by
  rejecting any sudo command before execution or approval side effects, so a
  call site that forgets to consult the policy fails loudly instead of
  escalating.
* Because all ``virsh``/``virt-install`` commands can now run unprivileged,
  they pin ``-c qemu:///system`` explicitly (bare unprivileged ``virsh``
  would silently target ``qemu:///session``), and state-changing hypervisor
  commands require interactive approval regardless of whether sudo is used,
  preserving the consent contract of principle 1.
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
* E2E/shared cache helpers in ``tests/test_e2e_nested.py``:
  keep local cache path/version conventions aligned with digest-addressable
  behavior once implemented in runtime code.
* Folder sharing backend flexibility:
  evaluate alternatives that scale beyond per-folder virtiofs device-slot
  limits (see ``dev/design/future/flexible-folder-sharing.md``).
* Long-lived virtiofs FD growth:
  continue investigating ``virtiofsd`` FD retention/growth on ``shared-root``
  and ``persistent`` exports. ``dev/devcheck/debug-harness.sh`` is the current
  evidence-gathering tool, but the root cause is not solved.
* Settings sync:
  the previous ``aivm vm sync_settings`` feature has been removed. Reconsider
  synchronization later only with an explicit design for reliability,
  conflict behavior, and user intent.


Non-goals
---------

* cloud orchestration
* broad hypervisor abstraction beyond the current local libvirt focus
* opaque "magic" recovery that hides security-sensitive state changes
* forcing one fixed provisioning stack for all users/workflows
