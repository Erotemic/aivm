# Related work: Docker `sbx`, NVIDIA OpenShell, and AIVM (2026-10-26)

> **Status: research notes; not a product decision or implementation approval.**
> Sources are upstream documentation and repositories inspected on
> 2026-10-26, not local benchmarks or a completed security audit. Specific
> findings may change between releases. The separate virtiofs attachment
> server is **out of scope** for the proposed AIVM work.

## What we are comparing

AIVM manages persistent libvirt/KVM VMs and project-directory attachments for
local development, including **several trusted host users sharing one VM**,
with distinct enrolled guest users, personal SSH keys and attachment owners.
The recent non-sudo onboarding case exposed control-plane friction, not a
failure of the successful final SSH session. See
[shared-machine architecture](shared-machine-architecture.md) and
[onboarding review](multi-user-onboarding-preflight-2026-10.md).

Docker **Sandboxes (`sbx`)** targets coding agents in their own isolated local
microVMs or Docker-managed cloud sandboxes [D1, D2]. NVIDIA **OpenShell** is an
agent runtime and policy gateway with pluggable backends: Docker, rootless
Podman, Kubernetes, or an opt-in microVM driver [O1, O2]. Their security and
user models are not equivalent to AIVM's shared multi-principal VM. The
comparison below identifies product fit and mechanisms to learn from, not a
universal winner.

## Side-by-side capability inventory

| Dimension | AIVM (current 0.6 shared-host mode) | Docker `sbx` | NVIDIA OpenShell |
| --- | --- | --- | --- |
| Primary unit | Persistent VM and enrolled host-to-guest principals | Per-agent sandbox microVM; local or Docker-managed cloud | Per-agent sandbox supervised by gateway; compute driver chooses container/VM/Kubernetes |
| Linux isolation | libvirt/KVM VM; users can share one guest and trust boundary | Separate microVM kernel per sandbox; agent has sudo *inside* its VM [D3] | Docker driver: container; Podman: rootless container; optional KVM/libkrun microVM on Linux, QEMU for the VM GPU case [O2] |
| Host workspace | Explicit globally recorded, principal-owned attachments; host source may be in a private home | Direct read-write host workspace; read-only source + private clone; or mountless; paths preserved for direct mounts [D3, D4] | Driver-owned workspace; Docker/Podman bind mounts require explicit enablement and weaken isolation; named volumes/K8s PVCs supported [O2] |
| Ordinary multi-user shared guest | Yes: separate guest logins in the same machine-store VM, but trusted-host mode is not a security boundary | Not the documented product unit; per-sandbox agent VMs rather than users jointly enrolling in one guest | Not the documented product unit; gateway-managed individual sandboxes, not the same shared libvirt guest |
| Host privilege/setup on Linux | Shared machine store + `libvirt` membership; an admin may perform privileged guest enrollment and cross-user persistent attach | Local KVM group required; `sbx` install/setup and Docker account sign-in; host Docker Engine not required for `sbx` CLI [D2] | Docker/Podman/K8s/host virtualization according to backend; rootless Podman option; no common privilege assertion across all drivers [O2, O4] |
| Network policy | No analogous comprehensive agent egress policy claimed for AIVM core in this comparison | Proxy-mediated egress with policy allow rules; some common sites allowed by default, inspect the actual active policy [D3, D5] | Supervisor/gateway egress controls; deny-by-default policy; operator approvals can dynamically add rules [O1, O5] |
| Credential handling | Per-principal SSH/credential ownership; separately installed `aivm-secrets` is experimental and opt-in | Host proxy substitutes provider credentials into approved outbound requests [D3] | Gateway/supervisor-mediated endpoint-bound credentials and inference routing [O1, O5] |
| Formal policy checking | No general sandbox policy prover claimed as part of AIVM core; `aivm-secrets` proof effort is separate | No comparable formally checked policy-containment contract established in this survey | OpenShell's SMT-based prover checks policy boundary containment and risky proposed rules for **modeled features**; not a proof of implementation isolation [O3] |
| GPU | Must test AIVM's actual VM/device setup on target hardware; no comparative measurement here | Experimental Linux x86_64 *exclusive* VFIO NVIDIA GPU passthrough; needs unused device and matching guest driver bundle [D6] | GPU requests supported by Docker/Podman CDI and Kubernetes; opt-in VM driver has separate device-selection constraints [O2] |
| Local lifecycle | Persistent libvirt VM, explicit machine store and attachments | Per-sandbox persistent filesystem, packages and private Docker Engine until sandbox deletion [D3, D4] | Stop/start retains driver-owned workspace/overlay; delete removes driver-owned state; gateway reconciles driver intent [O2] |
| License/commercial | Package metadata declares Apache-2.0 [A1] | Docker labels `sbx` **proprietary**; local CLI/compute free for commercial use, cloud pay-as-you-go; paid organization governance [D1, D7] | Apache-2.0 source license [O6] |
| External account | No vendor login in ordinary AIVM VM creation/SSH path | Docker login is required, including for local setup [D2, D7] | Local quickstart docs do not state a mandatory NVIDIA login; validate actual dependencies/offline operation in hands-on tests [O4] |
| Operational diagnostics | Rich transparent command logs; onboarding/status needs a request-first preflight | `sbx diagnose`, inspect/run/exec commands, interactive dashboard [D8] | Gateway status, policy revisions, operator review and supervisor logs [O1, O5] |

**Important limitations of the table:** "Not documented" is not "impossible".
Docker organization policy, Docker per-sandbox policy, and OpenShell driver
isolation have different scopes. A user with host root or broad libvirt access
is outside AIVM's current principal-ownership enforcement boundary. A
read-write host mount can still let an agent edit the mounted worktree even
if that agent is otherwise sandboxed.

## Docker Sandboxes (`sbx`)

**Strengths relevant to AIVM.** An integrated local agent experience:
`sbx run`, `sbx exec`, `sbx diagnose`, automatic workspace sharing, persistent
sandboxes, isolated guest Docker engines, transparent host-path mapping,
clone-mode separation, network controls and a proxy-mediated credential flow
[D3, D4, D8]. It has a useful precedent for **mountless entry**: workspaces
are optional for `sbx create` starting with 0.42.0 [D4]. AIVM's
attachment-free shell request is analogous in usability, not architecture.

**Tradeoffs.** `sbx` is distributed in a proprietary release repository
[D7]. Docker's FAQ nevertheless says the CLI and *local sandbox compute* are
free, including commercial use. Docker login is required, and centralized
organization policy/audit capabilities are separately paid [D1, D2, D7].
These are distinct claims: *free of charge* is not *open-source licensing*,
and a paid governance feature does not mean local sandboxes require payment.
AIVM's no-vendor-login, source-modifiable, persistent shared-VM workflow
remains a different product fit.

**GPU caveat.** `sbx`'s documented local NVIDIA path is experimental VFIO
passthrough requiring a GPU unused by the host. It is not the same as
sharing an actively used host GPU with multiple sandboxed workloads [D6].
This is important for a shared GPU development server and must be tested,
not inferred from the existence of a `--gpu` flag.

## NVIDIA OpenShell

**Strengths relevant to AIVM.** OpenShell has the sort of control-plane/
execution-plane separation proposed for AIVM: a gateway owns sandbox state,
policy revisions, authorization and credential mapping, while a supervisor
applies controls in the runtime [O1]. Its driver interface supports Docker,
rootless Podman, Kubernetes, and an explicit microVM driver [O2]. Access
policies address filesystem, process, egress and providers; dynamic network
policy decisions can be brokered outside the agent [O5]. These ideas are
more developed than the proposed standalone AIVM host-operations broker.

**Isolation must be qualified by driver.** A default OpenShell installation
using Docker sandboxes is not equivalent to a KVM virtual machine. The VM
driver is opt-in and uses libkrun/KVM on Linux, or QEMU for GPU-backed VMs
[O2]. A design comparison should always name the selected driver, host
kernel protection, user identity, workspace strategy and exact policy.
Docker/Podman host bind mounts are disabled unless explicitly enabled and
OpenShell warns that they can undermine filesystem isolation [O2]. That is
particularly relevant when considering AIVM-like live host workspaces.

**Formal-methods nuance.** The standalone `openshell-prover` models supported
policy features with an SMT solver. It can check that a candidate policy is
contained within a boundary and analyze risky access changes. It has explicit
`unsupported` and `inconclusive` outcomes and does not establish that the
running sandbox faithfully enforces every checked rule [O3]. This is related
work for AIVM's future policy design, but is not evidence of an end-to-end
verified sandbox; do not conflate it with the separate `aivm-secrets` Lean
formalizations.

**Potential integration, not a decision.** OpenShell supports extension
compute drivers through its driver protocol [O2]. Investigate whether an
AIVM adapter could use that boundary *without* weakening AIVM's shared guest
semantics or OpenShell's per-sandbox isolation promises. The answer is unknown
until a prototype. In particular, starting a supervisor for one OpenShell
sandbox inside an existing shared AIVM VM is not automatically equivalent to
one sandbox per guest or a defensible isolation boundary.

## What is actually differentiated, and what is not

**Currently evidenced fit for AIVM:** a durable, locally controlled,
source-modifiable libvirt VM; several coworkers sharing a single guest with
separate accounts and SSH identities; machine-global attachment inventory
with per-principal ownership; familiar `aivm ssh .`/`aivm code .` sessions;
and no mandatory Docker/NVIDIA account. The last onboarding case demonstrates
that the current host-side privilege ergonomics need work. None of these
properties demonstrates stronger agent containment than `sbx` or OpenShell.

**Areas where related work has stronger documented functionality:** Docker
provides cohesive agent workspace modes and network/credential mediation;
OpenShell provides extensible supervised runtimes and richer policy-as-code
and policy checking [D3, D4, O1, O3]. AIVM should not try to replicate these
features simply to claim parity if its smaller shared-VM use case does not
need them.

**Open questions:** source-to-guest file performance; startup and idle memory;
VM guest GPU access vs usable concurrent GPUs; SSH/editor experience;
machine-wide multi-user delegation without host admin powers; self-hosted
operation during account/network outages; policy correctness under root and
mount bypasses; unattended recovery; real deployment costs. No benchmarks or
independent security tests were run for this survey.

## Proposed hands-on evaluation (requires separate approval)

Use the same Ubuntu/KVM development host and one disposable project/VM. For
each product, record exact release, driver, config and hardware. Do not use a
production coworker's home or existing live VM as an experiment.

1. **Workspace:** create a direct read-write workspace, then a no-host-mount
   workspace; inspect edit visibility, permissions, symlinks, persistence and
   source path semantics. Try an unprivileged user's private-home path only
   when explicitly authorized, with no blanket new host group grants.
2. **Onboarding:** enroll a second user with no host sudo and no access to
   other homes. Record every admin action and whether the product actually
   supports a shared guest or provides a per-user sandbox instead.
3. **Isolation:** inspect the actual kernel boundary and whether default
   egress, filesystem restrictions and credential proxy are in force; test
   denied access and revocation. Do not equate marketing policy names with
   measured enforcement.
4. **GPU:** compare supported GPU allocation modes and whether the host GPU
   can remain usable concurrently; record required driver/IOMMU/CDI steps.
5. **Reliability/ergonomics:** measure first-use time, warm-start time, memory
   and disk costs, common repo operations and `ssh`/editor launch; test
   reboot, killed daemon, stale guest mounts and lost network access.
6. **Licensing/dependency:** archive the terms/license at the tested version;
   verify what fails without vendor login, paid governance, account access,
   or Docker Engine on the host.

Suggested decision outcomes: **keep AIVM's current scope and improve UX**;
**add a small narrowly authorized host helper**; **investigate an OpenShell
backend/integration**; or **change the core product direction**. None is
approved by this survey. The candidate broker is separately documented in
[delegated host operations](privileged-operations-broker-proposal-2026-10.md).

## Sources (primary, accessed 2026-10-26)

- **[A1] AIVM package and trust model:** [`pyproject.toml`](../../pyproject.toml),
  [shared-machine architecture](shared-machine-architecture.md),
  [secrets boundary](aivm-secrets-repository-boundary.md).
- **[D1]** [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/).
- **[D2]** [Docker Sandboxes installation and login](https://docs.docker.com/ai/sandboxes/install/).
- **[D3]** [Docker Sandboxes security model](https://docs.docker.com/ai/sandboxes/security/).
- **[D4]** [Docker Sandboxes architecture](https://docs.docker.com/ai/sandboxes/architecture/).
- **[D5]** [Docker Sandboxes default security posture](https://docs.docker.com/ai/sandboxes/security/defaults/).
- **[D6]** [Docker Sandboxes GPU passthrough](https://docs.docker.com/ai/sandboxes/configuration/gpu-passthrough/).
- **[D7]** [Docker FAQ: pricing/sign-in](https://docs.docker.com/ai/sandboxes/faq/),
  [docker/sbx-releases README and license](https://github.com/docker/sbx-releases).
- **[D8]** [Docker `sbx` command reference](https://docs.docker.com/reference/cli/sbx/).
- **[O1]** [OpenShell architecture](https://docs.nvidia.com/openshell/latest/about/how-it-works).
- **[O2]** [OpenShell compute drivers](https://docs.nvidia.com/openshell/latest/reference/sandbox-compute-drivers).
- **[O3]** [OpenShell policy prover (coverage and limitations)](https://docs.nvidia.com/openshell/latest/how-it-works/policies/prover).
- **[O4]** [NVIDIA/OpenShell source, setup and Apache-2.0 license](https://github.com/NVIDIA/OpenShell).
- **[O5]** [OpenShell security best practices](https://docs.nvidia.com/openshell/latest/security/best-practices).
- **[O6]** [NVIDIA/OpenShell `LICENSE`](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE).
