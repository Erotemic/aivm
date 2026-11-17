# Firewall lifecycle and non-sudo operation on shared AIVM hosts

- **Status:** Investigation / proposal; **NOT APPROVED**
- **Date:** 2026-10-26
- **Scope:** Host-side AIVM networking, firewall readiness, observability,
  boot and runtime policy administration for trusted multi-user libvirt hosts
- **Excluded:** Changes to the separate virtiofs attachment server; an
  assumption that guest root will comply with in-guest firewall rules

## Related accepted requirement

[ADR-0001](adr/0001-unrestricted-agent-environment.md) requires the agent to
retain full unattended guest sudo. This document investigates how AIVM can
support externally enforced network policy **without requiring every host
user to have sudo**. That requirement is accepted; this design is not.

A distinct [privileged host-operations broker proposal](privileged-operations-broker-proposal-2026-10.md)
remains **unapproved**. None of the alternatives below authorizes building
that daemon yet.

## Observed failure mode and code-grounded current behavior

In the shared-host workflow, a user may be in `libvirt` and able to start a
managed VM through `qemu:///system`, while lacking permission to run host
`sudo` or `nft`. `aivm firewall status` and the firewall probes use
privileged nftables reads. `aivm firewall apply` similarly requires privileged
host mutation. The current `aivm.firewall.ensure_firewall_ready()`:

1. attempts to inspect the AIVM-managed `inet` table;
2. if the table is known missing, attempts repair;
3. if inspection or repair cannot be authorized, logs that the firewall is
   **unverified** or **missing** and permits the guest to run.

This was a deliberate usability choice, but it means a non-sudo user cannot
establish that the host firewall exists just by successfully starting a VM.
It is *not* correct to call this a guaranteed isolation state. An in-guest
connection test is not a substitute for a trusted host-side policy probe:
failed connections could have unrelated causes, and a successful probe of
one destination says nothing about the whole rule set.

`nft` rules installed only into the kernel are not automatically retained
after reboot. Consequently, a host reboot followed by libvirt VM startup
may expose a period with the managed policy absent. AIVM must not report
``ready`` or ``protected`` solely because the desired configuration exists
in the machine store. The current firewall protects private/LAN destinations
when installed, while permitting WAN by design; a future strict egress mode
is a separate feature.

**Important distinction:** nftables changes are executed with host-wide
privilege, but AIVM's `effective_firewall_table()` uses a network-derived
name. The managed policy can be network-scoped; it need not be identical for
every VM. Sharing one libvirt network means sharing its rules, and a common
bridge/global packet path still needs careful isolation from unrelated
networks and host services. Per-principal policies within one shared guest
would need additional trustworthy workload isolation/identification.

## Requirements for an acceptable solution

1. **Guest-root-resistant:** the agent may change anything inside its guest,
   including its guest firewall; external isolation must still hold.
2. **Boot-safe:** applying/realizing policy must be coupled to VM/network
   readiness. A VM launched via libvirt directly, by autostart, or by a
   different user cannot silently bypass a claimed mandatory policy.
3. **Non-sudo diagnosis:** ordinary authorized AIVM users can distinguish
   `verified-current`, `missing`, `drifted`, `not-configured`, and `unknown`
   without a host sudo prompt. Never translate `unknown` into `present`.
4. **Authorized changes:** policy inspection, policy requests, privileged
   installation and destructive removal are separate capabilities. Define
   whether and how non-sudo users request changes; do not let an ordinary
   guest change its own outer policy by editing guest-controlled files.
5. **Scoped state:** keep desired policy with the authoritative shared
   machine/network store; detect and report realized state separately.
   Multiple networks/VMs and concurrent user requests must not overwrite
   unrelated rules. Include policy revision and drift in diagnostics.
6. **Explicit failure policy:** for a *mandatory* isolation mode, verify the
   actual enforcement before guest traffic is possible or prevent traffic
   until verification succeeds. Existing best-effort behavior must be
   described accurately, and migration to stricter defaults requires a
   separate reviewed decision.
7. **No hidden prompt dependency:** unattended start/restart after reboot must
   not depend on someone authenticating to sudo interactively.
8. **Host-user threat model:** existing `libvirt` membership is already
   broad, effectively host-root-equivalent authority. Better UX for trusted
   coworkers is not protection against a malicious host libvirt admin.

## Candidate mechanisms, not selected

### A. Libvirt `nwfilter` as the baseline enforcement mechanism

Libvirt supports host-enforced filters attached to individual guest NICs.
Its documented lifecycle installs the filter when the VM starts, supports
runtime changes, and can apply different policies to different interfaces.
An authorized `qemu:///system` client can manage libvirt objects through the
libvirt API, potentially avoiding direct invocation of host `nft` for the
baseline policy. The filter is still enforced on the host, outside guest
root's authority.

**Potential advantage:** policy realization follows VM interface activation
rather than depending on a separate first-user-sudo invocation after reboot.
Inspection and updates might be possible through the existing libvirt access
route. This is the leading *experiment*, not an architectural selection.

**Must verify:** exact AIVM NAT-bridge/interface XML compatibility; whether
libvirt filters can faithfully express the existing blocked CIDRs, TCP/UDP
exceptions and IPv6 posture; distro backend interactions with nftables,
iptables and firewalld; application to already-running interfaces; failure
if filter creation fails; libvirt autostart ordering; how to observe *live*
enforcement instead of only XML desired state; and no accidental expansion
of an unprivileged user's host authority. `virsh nwfilter-dumpxml` showing a
filter definition is **not** proof that packets are currently filtered.

Sources: [libvirt network filters](https://libvirt.org/formatnwfilter.html),
[libvirt firewall and network filtering](https://libvirt.org/firewall.html).

### B. Root-installed systemd restoration / readiness service

An administrator installs a root-owned boot service once to load/reconcile
AIVM's host nftables policy, with explicit ordering relative to the libvirt
network, domain autostart and packet forwarding. That would let non-sudo users
start VMs later without personally reapplying the firewall.

A non-sudo status interface could use a narrowly scoped read-only system
service, a root-owned observation published with boot ID, policy fingerprint,
and check time, or a separately authorized read-only command. A cached file
is only a *last-verified observation*, not a continuously valid proof; state
must be marked stale or unknown after a restart, timeout or drift opportunity.
If strong live attestation is needed, it requires an actual authorized probe.

**Must verify:** boot ordering and direct libvirt autostart; reboot/restart
recovery; coexistence with system nftables/firewalld rules; failure behavior
if the service fails; rapid policy updates; and no unprotected window.
Merely starting the service *eventually* after boot is not a fail-closed
architecture.

### C. Narrow read-only sudoers / polkit delegation

An administrator can allow exact read-only `nft list ...` commands to
specified users or groups without allowing arbitrary rule changes. This can
solve the observability problem without a resident daemon, though users still
invoke a narrowly authorized privileged action. It does not solve reboot
restoration or authorized updates. Never expose unrestricted `nft -f -` in
NOPASSWD sudoers: argv validation cannot constrain its arbitrary stdin
ruleset. See [prior analysis](candidate_ideas/nft-nopasswd-sudoers.md).

### D. Privileged policy service / broker

An explicitly approved root-owned host process could answer read-only live
checks and accept narrowly authorized policy updates through a typed API
with kernel-authenticated peer identity. A policy broker might be useful
for richer dynamic egress rules, but it is a larger privileged attack surface
and is **not approved** by this plan. A generic daemon granting arbitrary
`nft` execution is not acceptable. The earlier host-operations broker proposal
is related but independently undecided.

### Not an enforcement candidate: an in-guest firewall

The autonomous agent has full guest sudo under ADR-0001 and can remove or
replace guest rules. Those rules can be useful operationally but cannot
provide the security boundary that AIVM promises against guest root.

## Evaluation sequence / decision gates

1. **Inventory the existing firewall contract:** current table/chains,
   IPv4/IPv6 filtering, libvirt bridge/route, blocked CIDRs, exceptions,
   drift fingerprinting, existing boot persistence or hooks. Identify exactly
   what must remain effective on a cold boot and under direct `virsh start`.
2. **Prototype `nwfilter` separately:** test actual traffic after cold boot,
   direct libvirt start and guest `sudo`; check parity with existing policies
   and policy update behavior. Do not replace current nftables enforcement
   until parity is demonstrated.
3. **Prototype persistent nftables restoration if needed:** compare its
   operational and security properties with the `nwfilter` approach. Include
   root-owned read-only status pathways and an explicit policy-change path.
4. **Choose failure semantics by policy mode:** preserve and clearly label
   today's best-effort mode unless a separately approved default changes it;
   mandatory policy must gate *traffic*, including paths that bypass the
   AIVM CLI, when enforcement is unavailable.
5. **Approval required:** record a separate architecture decision for the
   selected firewall backend, startup dependency, status attestation method,
   delegation model, and migration strategy before implementation.

## Regression scenarios for a future implementation

- Boot host from cold power state; allow libvirt autostart before any human
  login; confirm rules or deliberate traffic denial before first guest egress.
- Non-sudo user starts a VM after reboot; readable status distinguishes
  policy configured, last verified, current observation and drift.
- Non-sudo user with no `sudo` policy can request a change, but cannot install
  arbitrary host firewall rules through the delegation mechanism.
- Non-sudo user cannot infer that a firewall is active solely from a failing
  `curl` or `ping` inside the guest.
- Guest with `sudo`/root changes its in-guest routing, firewall, DNS and proxy
  environment; the host-enforced restriction remains effective.
- Two VMs on separate networks retain independent enforcement; if on one
  network, document shared policy explicitly.
- Stop the enforcement service/delete an AIVM table while the guest is
  running; report `missing` or `unknown`, and test the mandatory-policy
  fail-closed behavior rather than only the next CLI invocation.
- Change policy during active traffic; validate confinement during update,
  rollback and concurrent administrative requests.
- Inspect real host policy after a new boot to detect a stale root-owned
  status export with the previous boot ID.

## References

- [ADR-0001: unrestricted guest environment](adr/0001-unrestricted-agent-environment.md)
- [Existing egress allowlist design](../../dev/design/future/egress-allowlist.md)
- [Shared-machine architecture](shared-machine-architecture.md)
- [Earlier onboarding diagnostics](multi-user-onboarding-preflight-2026-10.md)
- [Unapproved host broker proposal](privileged-operations-broker-proposal-2026-10.md)
