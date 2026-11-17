# ADR-0001: Unrestricted agent administration inside the guest VM

- **Status:** Accepted
- **Date:** 2026-10-26
- **Decision maker:** Project maintainer
- **Scope:** AIVM-managed agent execution environments, including shared
  persistent guest VMs

## Context

AIVM is intended to run autonomous software agents for long periods with
minimal operator intervention. They must be able to repair their environment,
install arbitrary software and dependencies, use system services, build and
execute code, and continue working when the operator is absent. Denying guest
administration or requiring interactive confirmation for routine guest
privileged operations would interfere with that goal. In particular,
`sudo apt install` must be an ordinary, unattended operation.

The guest is a sandbox *from the physical host's perspective*, not a
restricted user session inside the guest. The security model already treats
potentially malicious guest root as in scope. Security protections that an
agent with guest root can disable are not meaningful containment guarantees.

## Decision

**The agent has unrestricted administrator/root capability inside its own
AIVM guest environment.** This is a product requirement, not a temporary
bootstrap convenience.

1. AIVM-provisioned agent principals must be able to run arbitrary commands
   with guest-root privileges without an interactive password or human
   approval. Guest `sudo` must permit arbitrary package installation,
   executables, services, configuration changes and repair activities.
2. Do not rely on guest user permissions, guest sudo policy, guest nftables,
   guest environment variables, or agent cooperation to enforce sandbox
   isolation from the host or external resources.
3. Security boundaries that must withstand a hostile guest root belong
   **outside the agent-controlled guest privilege domain**: for example,
   hypervisor/host controls on network egress, explicitly exported host paths,
   and host-enforced resource limits. The particular network mechanism is not
   selected by this ADR.
4. Guest-root authority does **not** imply host sudo, authority to change
   host firewall policy, access to unrelated host directories, or permission
   to mutate the host's libvirt machine configuration. These are separate
   host-side authority decisions.
5. Network policies, host attachment permissions and resource limits may
   constrain what the guest can reach or consume; these constraints must be
   externally enforced and disclosed. "Unrestricted environment" means
   unrestricted guest administration, *not* unrestricted host or network
   access or unbounded physical resources.
6. Preserve the existing managed shared-VM model: multiple enrolled host
   users can have independent guest accounts, SSH identities, homes and
   attachment attribution. **These are not security boundaries between
   mutually adversarial users when all have guest root.** Agents that must be
   isolated from one another require a different isolation boundary (for
   example separate VMs); the exact product workflow is not decided here.

The requirement covers the autonomous agent's usable guest environment.
Future optional execution modes may expose additional containment, but
must not silently replace the full-administrator AIVM environment with a
restricted container/user that fails unattended installation and repair.

## Consequences

- A legitimate agent can install arbitrary guest packages and run services,
  but malicious guest software can also take complete control of that guest.
  Guest secrets and data within its reach must be treated accordingly.
- An agent with guest root can affect other guest users and may read or modify
  resources exported into the same shared VM, subject to the actual mount
  model and permissions. Principal-level attribution is not a confidentiality
  guarantee against such an agent.
- Guest-admin usability and host security are not competing requirements;
  the architecture should provide both by keeping enforcement outside the
  guest's authority.
- Privileged *host* operations still require explicit authorization or a
  separately approved delegation mechanism; this decision does not approve
  a host broker or broaden host sudo privileges.
- Automated tests should verify unattended guest sudo, arbitrary package
  manager invocation and service-management capability. Tests for network or
  filesystem containment must assume guest root is adversarial.

## Alternatives rejected

- **Restrict guest sudo to a package allowlist:** arbitrary agent work and
  environment recovery would become dependent on operator intervention.
- **Enforce network restrictions solely in the guest:** guest root can undo
  them; such rules may be convenient for configuration but are not the
  sandbox security boundary.
- **Treat separate guest Unix accounts as mutually untrusted sandboxes:**
  inconsistent with unrestricted guest-root authority in one VM.

## Explicit non-decisions

This ADR does **not** approve or select:

- a root-owned AIVM systemd daemon or generic privileged host broker;
- libvirt `nwfilter`, host nftables boot services, a policy proxy, or any
  other specific host networking implementation;
- a mandatory strict egress allowlist, its default, or a fail-open/fail-closed
  migration policy for existing installs;
- a change to the separate virtiofs attachment server (out of scope).

These remain subjects of the
[firewall lifecycle and delegation investigation](../firewall-lifecycle-and-delegation-2026-10.md),
the [host-operations broker proposal](../privileged-operations-broker-proposal-2026-10.md),
and the [egress allowlist design](../../../dev/design/future/egress-allowlist.md).
