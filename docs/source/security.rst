Security Model
==============

Scope
-----

This document describes the security model for ``aivm`` under its intended use:
running potentially untrusted agent code inside a local libvirt/KVM VM while
preserving host safety and operator usability.

Threat Model
------------

Primary attacker:

* Malicious code running inside the guest VM as the configured guest user
  (which may have sudo inside the VM).

In-scope goals:

* Prevent guest code from reading/modifying host data outside explicitly shared
  host folders.
* Limit guest lateral movement into host-local/private network ranges by
  default.
* Keep privileged host operations explicit and user-approved.

Out-of-scope assumptions:

* The host user is trusted.
* The host OS and hypervisor stack are maintained and patched by the operator.
* Physical/firmware attacks and compromise of the host kernel/hypervisor are
  out of scope for ``aivm`` itself.

Trust Boundaries
----------------

Host boundary (trusted):

* Host user account and local filesystem.
* ``sudo`` on host when user approves ``aivm`` privileged operations.

Guest boundary (untrusted):

* All code running in the VM.
* VM user account, even when it has sudo inside guest.

Shared boundary (explicitly trusted by user decision):

* virtiofs-mounted host directories attached to the VM.
* Anything written there by guest code is considered guest-controlled.

Network boundary:

* Guest gets outbound WAN access by design.
* Firewall mode is intended to block guest access to common private/LAN ranges
  unless explicitly allowed.

Use of SSH Keys
---------------

``aivm`` uses the configured SSH identity path to authenticate from host to VM.

What ``aivm`` does:

* Reads configured key file paths to run local ``ssh/scp`` commands.
* Injects the configured *public* key into cloud-init for guest access.
* Stores identity/public key *paths* in config, not private key contents.

What ``aivm`` does not do:

* Copy private key material into the VM.
* Intentionally persist private key contents in the config store.

Risk implication:

* A malicious guest can attempt to phish/relay SSH sessions but should not gain
  host private key material unless the host is separately compromised.

Host Package Installation
-------------------------

``aivm host install_deps`` may install host packages (for example libvirt,
qemu, nftables, SSH client tools).

Risk introduced:

* Expanded host attack surface from additional privileged services/binaries.
* Supply-chain and package trust risk inherited from host package repositories.

Why this is accepted:

* ``aivm`` requires these components for VM lifecycle, networking, and
  isolation controls.

Operational expectation:

* Users should treat host package management hygiene as part of deployment
  security (trusted repos, patch cadence, standard host hardening).

Design Decisions and Tradeoffs
------------------------------

The table below explains why key choices exist and the consequence of tightening
them.

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - Design choice
     - Security effect
     - If tightened
     - UX consequence
   * - Guest has sudo in VM
     - Guest compromise becomes full guest compromise.
     - Remove/restrict sudo in guest.
     - Breaks common agent setup/provisioning workflows that need package/system changes.
   * - WAN egress enabled
     - Malicious guest can exfiltrate to internet.
     - Block or heavily restrict egress.
     - Breaks LLM/API access and many development workflows.
   * - Optional virtiofs host folder sharing
     - Shared host paths become readable/writable by guest.
     - Disable shares or enforce read-only.
     - No-share breaks in-place repo editing; read-only breaks normal code-write workflows.
   * - Host installs VM/network tooling
     - Increases host binary/service footprint.
     - Avoid host installs.
     - ``aivm`` cannot create/manage VMs or enforce firewall/network policy.
   * - Sudo-confirmed host operations
     - Reduces accidental privileged changes.
     - Require manual command execution only.
     - Higher friction; one-step workflows degrade.

What This Model Protects
------------------------

Under this threat model, ``aivm`` aims to ensure:

* Guest code does not get host root via normal operation.
* Guest code cannot access arbitrary host files unless they are explicitly
  shared.
* Guest-to-private-network access is constrained when firewall isolation is
  enabled and applied.

What This Model Does Not Eliminate
----------------------------------

* Hypervisor/virtiofs/kernel escape vulnerabilities in underlying stack.
* Data exfiltration from host directories that the user explicitly shared.
* Malicious outbound internet traffic from the guest.

Security Improvements With Minimal UX Cost
------------------------------------------

The following improvements can increase security without materially harming the
core UX:

* Make firewall isolation fail-closed for ``code``/``ssh`` flows (warn+abort if
  expected firewall rules are missing).
* Add an optional egress allowlist mode (preserve WAN but restrict destinations
  by policy for high-risk scenarios).
* Improve attachment guardrails:
  - Warn on sharing high-risk paths (``~``, ``/``, SSH dirs, secrets dirs).
  - Optionally require extra confirmation for sensitive host paths.
* Offer read-only share mode as an explicit opt-in per attachment (useful for
  audit/review sessions).
* Emit a clear runtime banner when a session includes writable host shares.
* Continue tightening command construction and secret-redaction in host-side
  logs.

Operator Guidance
-----------------

For strongest practical isolation while preserving productivity:

* Share only the minimum project subtree needed.
* Keep firewall isolation enabled.
* Keep host and virtualization packages updated.
* Treat guest VM as untrusted and disposable.
* Keep sensitive host secrets outside shared trees.
