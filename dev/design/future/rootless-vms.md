# Rootless VM Support Goal

Written: **2026-05-12 14:09:36 America/New_York**

Baseline commit: **525a96e8bafbfa539e3db27ed4c9a128a4665ea6**

Status: **design goal / implementation planning note**

## Purpose

This document records the goal for making `aivm` work with rootless VMs after a
user or group has already been granted the basic host permission required to run
VMs. The intended target is true unprivileged libvirt/QEMU operation via
`qemu:///session`, not only non-root access to the privileged system libvirt
daemon.

The result should let an approved user create, start, stop, inspect, SSH into,
and use an `aivm` VM without host `sudo` during ordinary `aivm` operation.

## Definitions

### Existing system runtime

The current implementation is primarily a system-libvirt workflow:

- libvirt URI: `qemu:///system`
- VM storage: `/var/lib/libvirt/aivm/...`
- network: managed libvirt network plus host firewall rules
- host privilege: many operations may use `sudo`

This mode should remain supported.

### Rootless/session runtime

The rootless target is a per-user libvirt/QEMU workflow:

- libvirt URI: `qemu:///session`
- VM storage: user-owned paths, for example `~/.local/share/aivm/...`
- network: user-mode networking, preferably `passt`, with explicit forwarded
  host ports for inbound access such as SSH
- host privilege: no host `sudo` in normal VM create/start/stop/status/ssh/code
  paths

### Not considered rootless for this goal

The following are useful configurations, but they are not the target of this
rootless design:

- adding the user to a group or policy that permits use of `qemu:///system`
- passwordless `sudo` wrappers around existing host-root operations
- systemd services or host bind-mount helpers that run as root
- a system libvirt network that happens to be usable by a non-root caller

## Current baseline observations

As of the baseline commit, several implementation details assume a privileged
system-libvirt model:

- `aivm/runtime.py` hard-codes `qemu:///system`.
- `aivm/config.py` defaults `paths.base_dir` to `/var/lib/libvirt/aivm`.
- `aivm/vm/lifecycle.py` explicitly states that most functions assume
  `qemu:///system` with host `sudo`.
- `virt-install` is constructed in the lifecycle path without a runtime-level
  `--connect` abstraction.
- status and lifecycle flows use managed-network inspection such as
  `net-dhcp-leases`.
- firewall behavior is based on host `nftables` management.
- `shared-root` and `persistent` attachment modes rely on host-side bind mounts
  and replay helpers that are fundamentally host-root operations.

These are not just permission prompts. They are runtime model assumptions and
need to be split by backend.

## Goal

Add an explicit runtime model so `aivm` can support both:

1. the existing privileged system runtime; and
2. a new rootless session runtime.

The session runtime should be a first-class mode with clear behavior, clear
unsupported-feature errors, and tests that prevent accidental reintroduction of
host-root assumptions.

A practical first milestone is:

```bash
aivm init --runtime session
aivm start
aivm status
aivm ssh .
aivm code .
aivm attach . --mode git
# and, if reliable on supported hosts:
aivm attach . --mode shared
```

No command in that basic path should require host `sudo` after the user has the
normal ability to run KVM/session libvirt.

## Non-goals for the first milestone

- Migrating an existing `qemu:///system` VM into `qemu:///session`.
- Preserving the current managed-network IP-address model.
- Supporting the existing host-bind-mount implementations of `shared-root` or
  `persistent` in rootless mode.
- Solving every virtiofs UID/GID mapping edge case before exposing any rootless
  workflow.
- Proving stronger guest isolation than the existing VM boundary provides.

Rootless mode reduces host-privileged control-plane operations. It does not make
VM escape bugs impossible, and it does not make shared host folders safe to
trust after a malicious guest has modified them.

## Required implementation changes

### 1. Add explicit runtime configuration

Introduce a runtime section or equivalent config fields:

```toml
[runtime]
mode = "system"      # system | session
libvirt_uri = "qemu:///system"
host_privilege = "sudo"  # sudo | none

[network]
mode = "managed"     # managed | user-passt
ssh_host = "127.0.0.1"
ssh_port = 22042
```

In session mode, the defaults should become:

```toml
[runtime]
mode = "session"
libvirt_uri = "qemu:///session"
host_privilege = "none"

[paths]
base_dir = "~/.local/share/aivm"

[network]
mode = "user-passt"
ssh_host = "127.0.0.1"
```

Exact field names can change, but runtime mode must become explicit and visible
in config, diagnostics, and logs.

### 2. Centralize libvirt command construction

All `virsh`, `virt-install`, and related libvirt commands should be built through
a runtime-aware helper.

Requirements:

- `virsh` commands use `-c <runtime.libvirt_uri>`.
- `virt-install` commands use `--connect <runtime.libvirt_uri>`.
- session mode never implicitly falls back to `qemu:///system`.
- tests can assert that every generated command targets the requested URI.

This should replace one-off command construction and any hard-coded
`qemu:///system` call sites.

### 3. Split host privilege policy from command intent

Session mode should have a hard guardrail: host commands in the normal VM path
must not set `sudo=True` or otherwise shell through `sudo`.

System mode can keep the current privilege-confirmation policy.

The command layer should make this distinction explicit enough that tests can
verify it. A useful invariant is:

- `runtime.mode == "session"` implies `host_privilege == "none"` for normal VM
  create/start/stop/status/ssh/code/attach-git paths.

### 4. Move storage to user-owned paths in session mode

Session-mode storage should be fully user-owned. It should not rely on:

- `/var/lib/libvirt/aivm`
- `root:libvirt-qemu` ownership
- privileged `chown`
- privileged image creation or seed ISO generation

Expected session-mode layout:

```text
~/.local/share/aivm/<vm-name>/images/<vm-name>.qcow2
~/.local/share/aivm/<vm-name>/cloud-init/seed.iso
~/.local/share/aivm/<vm-name>/state/...
```

The implementation should skip system-mode helpers such as qemu-user ownership
fixups when `runtime.mode == "session"`.

### 5. Replace managed libvirt networking with user-mode networking

Session mode should not create or inspect a system libvirt network. It should
not depend on:

- `virsh net-define`
- `virsh net-start`
- `virsh net-dhcp-leases`
- host bridge names
- host `nftables` mutation

The rootless network model should use user-mode networking, preferably `passt`,
and expose guest SSH through an explicit forwarded localhost port.

Implementation consequences:

- Persist the chosen SSH forwarded port in `aivm` state or config.
- `aivm ssh`, `aivm code`, provisioning, and guest probes connect to
  `127.0.0.1:<ssh_port>` instead of a DHCP-provided guest IP.
- `aivm status` reports that networking is user-mode and shows forwarded ports
  instead of managed bridge/DHCP state.
- The firewall module is disabled or marked not applicable in session mode.

### 6. Make attachment modes runtime-aware

For the first rootless milestone, support only attachment modes that can work
without host root.

Likely first supported modes:

- `git`, because it avoids live host filesystem sharing.
- direct `shared` virtiofs, if host support and UID/GID semantics are reliable
  enough.

Initially unsupported in session mode:

- `shared-root`, because it depends on host bind mounts under a managed export
  root.
- `persistent`, because it depends on host-side bind replay and system service
  machinery.

Unsupported modes should fail early with a message like:

```text
shared-root attachments are not supported in runtime.mode=session because they
require host bind mounts. Use --mode git, or use runtime.mode=system.
```

### 7. Add rootless preflight diagnostics

`aivm doctor` or the session-mode startup path should check for:

- `virsh -c qemu:///session capabilities` works.
- the user can access `/dev/kvm`.
- `virt-install`, `qemu-img`, and `cloud-localds` are present.
- `passt` is present when `network.mode == "user-passt"`.
- `virtiofsd` is present when `shared` is requested.
- the session-mode `paths.base_dir` is writable.
- any required subordinate UID/GID mapping exists before enabling rootless
  virtiofs features that depend on it.

Failures should be actionable and should distinguish missing VM permission from
missing optional attachment/network capabilities.

### 8. Preserve system-mode compatibility

The current system runtime should continue to work. The rootless work should not
remove support for:

- managed libvirt networks
- nftables isolation in system mode
- `/var/lib/libvirt/aivm` storage
- `shared-root` and `persistent` attachment modes in system mode
- existing confirmation behavior for privileged operations

The implementation should prefer backend-specific branching over weakening the
existing safety model.

## Acceptance criteria

A rootless/session implementation should be considered minimally working when
all of the following are true:

1. A fresh user-owned VM can be created with `runtime.mode=session` and appears
   under `virsh -c qemu:///session list --all`.
2. The same VM does not require `sudo virsh` or `qemu:///system` for normal
   lifecycle/status/ssh operations.
3. VM disk and generated cloud-init files are created under a user-owned AIVM
   directory.
4. SSH access works through a persisted localhost forwarded port.
5. `aivm status` works without querying a managed libvirt network or nftables.
6. `aivm code .` and `aivm ssh .` work against the session VM.
7. `aivm attach . --mode git` works in session mode.
8. unsupported attachment modes fail early with clear rootless-specific errors.
9. automated tests assert that session-mode command plans contain no host
   `sudo`, no `qemu:///system`, no `virsh net-*`, and no nftables operations in
   the normal rootless path.

## Suggested implementation order

1. Add runtime config fields and default derivation.
2. Centralize `virsh` and `virt-install` command construction.
3. Add session-mode storage layout and remove sudo from image/cloud-init setup
   in that path.
4. Add user-mode networking with persisted SSH port forwarding.
5. Teach status, SSH, code, and provisioning paths to use forwarded localhost
   ports for session VMs.
6. Gate attachment modes by runtime and enable `git` first.
7. Evaluate direct rootless virtiofs for `shared` mode.
8. Add preflight diagnostics.
9. Add command-plan and end-to-end tests.

## Open questions

- Should `aivm init --runtime session` be a separate profile, or should runtime
  mode be inferred from `paths.base_dir` and `libvirt_uri`?
- How should ports be allocated and reserved to avoid collisions between many
  session VMs?
- Should direct `shared` rootless virtiofs require matching host/guest UID/GID,
  or should it require a newer libvirt/virtiofs ID-mapping capability?
- Should rootless mode eventually grow a replacement for `shared-root`, such as
  guest-initiated SSHFS/SFTP or an explicit sync backend?
- Should a host with permission to use `qemu:///system` but no `sudo` be modeled
  as a third runtime variant, or as system mode with a different host privilege
  policy?

## Summary

Rootless VM support should be implemented as a first-class session-libvirt
runtime, not as a collection of ad hoc `sudo` removals. The important design
shift is from a privileged host-managed VM/network/filesystem model to a
user-owned VM with explicit user-mode networking and rootless-compatible
attachments.

## Status update and implementation handoff (2026-07-02)

Everything above remains the design of record. This section reconciles it
with the `dev/sudoless` branch, which landed after the original writeup and
completed several "Required implementation changes" ahead of schedule. An
implementing agent should start here.

### What is already done (verified anchors)

* **Change 2 (centralize libvirt command construction): DONE.**
  All `virsh` argv construction goes through
  `aivm/runtime.py::virsh_system_cmd` (currently pinning
  `LIBVIRT_URI = 'qemu:///system'`), and `virt-install` passes
  `--connect qemu:///system` (`aivm/vm/create.py`). Bare `virsh` no longer
  exists in the package. Making the URI runtime-dependent is now a
  one-module change plus test updates (unit tests normalize/assert the
  pinned URI; grep tests for `qemu:///system`).
* **Change 3 (privilege policy split from command intent): DONE**, with a
  different spelling than proposed. `behavior.privilege_mode`
  (`auto`/`sudo`/`sudoless`) lives on `CommandManager`
  (`aivm/commands.py`), which structurally rejects sudo in `sudoless`
  mode before execution or approval side effects
  (`_reject_sudo_if_sudoless`). The invariant the doc asks for
  ("session implies no sudo") is expressible as: session runtime forces
  `privilege_mode='sudoless'`. Note the approval contract survives:
  `_command_needs_approval` prompts for `virsh`/`virt-install`
  role=modify commands even when unprivileged; keep that in session mode.
* **Change 4 (user-owned storage): LARGELY DONE.** File operations decide
  privilege via `aivm/privilege.py::path_needs_sudo`;
  `aivm/vm/host_access.py::_ensure_qemu_access_unprivileged` prepares
  user-owned trees. One session-mode delta remains: the unprivileged path
  grants `setfacl u:libvirt-qemu:x` traversal because **system** libvirt
  runs qemu as `libvirt-qemu`. In **session** mode qemu runs as the
  invoking user, so those ACLs are unnecessary — gate the ACL step on the
  runtime, don't remove it.
* **Change 6 (runtime-gated attachment modes): PATTERN EXISTS.**
  `aivm/attachments/resolve.py::_resolve_attachment` already rejects
  `shared-root`/`persistent` and flips the default mode to `shared` when
  sudo is forbidden, with detach/reattach guidance. Session mode extends
  the same guard (and initially also rejects `shared` until rootless
  virtiofs lands — see `external-virtiofsd.md`).
* **Partial change 7 (preflight diagnostics):** `aivm host sudoless
  check`/`setup` (`aivm/cli/host_sudoless.py`) established the readiness
  report + one-time setup pattern and the `status_line` rendering to
  reuse for `aivm host rootless check`.
* **Test harness pattern:** `tests/test_e2e_sudoless.py` runs the full
  lifecycle under the never-sudo guarantee and is the direct template for
  `tests/test_e2e_session.py`. Its trick generalizes: configure the
  restrictive mode in the store, run the real CLI, and let structural
  enforcement turn any violation into a hard failure.

### What remains (the actual rootless work)

In the doc's numbering: change 1 (runtime config axis), the session half
of 2 (URI selection), 5 (user-mode networking — the hard one), the
connectivity model, 7 (rootless preflights), and 8 (regression protection
for system mode).

Suggested first-session milestones, smallest-shippable first:

1. **Runtime axis.** Add `runtime.mode: 'system' | 'session'` (a new
   `RuntimeConfig` dataclass in `aivm/config.py`, rendered/parsed like
   `BehaviorConfig`; store-level like `privilege_mode`, resolved in
   `aivm/cli/_common.py::_BaseCommand.cli`). Thread it to where commands
   are built: replace the `LIBVIRT_URI` constant with a
   `current_libvirt_uri()` accessor (context-var or CommandManager
   attribute, mirroring `privilege_mode`). Session mode forces
   `privilege_mode='sudoless'` at manager construction and never falls
   back to `qemu:///system`.
2. **Session storage + domain lifecycle.** With the URI switched and a
   user-owned `paths.base_dir`, `vm create`/`up`/`down`/`delete` should
   mostly work already (all file ops are unprivileged-capable; skip the
   libvirt-qemu ACL step in session mode). Expect two snags: (a)
   `virt-install --connect qemu:///session` requires user networking
   flags (`--network user` or passt, see milestone 3) instead of
   `network=<managed>`; (b) UEFI/nvram paths differ per-user — reuse the
   existing missing-UEFI fallback in `create.py`.
3. **Networking: passt + forwarded SSH port.** This is the core new code.
   Decisions already made in this doc: passt preferred, explicit
   localhost port forward for SSH, port persisted in state. Concretes:
   `virt-install --network passt,portForward0.proto=tcp,portForward0.range=2222:22`
   style config (libvirt >= 9.2 supports `<interface type='user'>
   <backend type='passt'>` with `<portForward>`); allocate the host port
   deterministically from the VM name with collision probing; persist in
   the VM state dir (`aivm/vm/paths.py`) next to the cached IP.
   `aivm/vm/connectivity.py` grows a runtime split: session mode skips
   `net-dhcp-leases`/`domifaddr` entirely and returns
   (`127.0.0.1`, port) for SSH endpoints. Audit every consumer of
   `get_ip_cached`/`wait_for_ip` (ssh, code, provisioning, attachments'
   `_resolve_ip_for_ssh_ops`, status) to carry host+port rather than bare
   IP — this is the widest-touch part; do it as a preparatory
   behavior-preserving refactor (introduce an `SshEndpoint` value object
   defaulting to port 22) before flipping session mode on.
4. **Gate the rest.** Firewall: session mode behaves like sudoless
   (skip + warn; `probe_firewall` reports not-applicable). Networks CLI:
   `host net create/destroy` error in session mode with guidance.
   Status: report runtime mode and forwarded ports instead of
   bridge/DHCP state.
5. **Preflights + docs + e2e.** `aivm host rootless check` (KVM access,
   `virsh -c qemu:///session capabilities`, passt presence, base_dir
   writability); README/quickstart/security sections mirroring the
   sudoless docs; `tests/test_e2e_session.py` cloned from the sudoless
   module (requirements: `/dev/kvm` access and passt, *not* libvirt
   group). CI note: the session runtime is the most CI-friendly of all
   modes — see `ci-e2e.md`.

### Additional acceptance criteria (beyond the list above)

10. `aivm status` on a session VM shows runtime mode and the forwarded
    SSH endpoint, and does not execute `net-*` or `nft` commands.
11. System-mode e2e suites still pass unchanged (criterion for change 8).
12. A session VM and a system VM can coexist in one config store without
    cross-talk (distinct URIs, storage, and connectivity records).

### Known open question resolved since the original writeup

The last open question ("should system-without-sudo be a third runtime
variant?") is now answered: that is exactly `privilege_mode` on the
existing system runtime, orthogonal to `runtime.mode`. The two axes stay
separate: runtime = which hypervisor/daemon identity, privilege_mode = how
host commands escalate.
