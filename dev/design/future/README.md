# AIVM Roadmap (design-doc index)

Updated: 2026-07-02 (post session-runtime implementation)

This directory holds forward-looking design documents. This file is the
index: what each doc covers, its current status, and the recommended
sequencing for the major efforts. Each "major" doc below is written to be
executable by an implementing agent without additional context: problem,
current-state anchors (file/function pointers verified against this
commit), decided design, step-by-step plan, tests, and acceptance criteria.

## Major efforts (recommended order)

| # | Effort | Doc | Status |
|---|--------|-----|--------|
| 1 | Rootless VMs (`qemu:///session` runtime) | [rootless-vms.md](rootless-vms.md) | **Implemented, then removed before release** — deferred behind effort 2. See [session-runtime.md](../../../docs/planning/deferred/session-runtime.md) |
| 2 | Externally-managed virtiofsd backend | [external-virtiofsd.md](external-virtiofsd.md) | Designed here; not started |
| 3 | Egress allowlist networking | [egress-allowlist.md](egress-allowlist.md) | Designed here; not started |
| 4 | Snapshots, rollback, ephemeral clones | [snapshots-and-clones.md](snapshots-and-clones.md) | Designed here; not started |
| 5 | E2E suites in CI | [ci-e2e.md](ci-e2e.md) | Designed here; not started |

Sequencing rationale:

- **1 before 2 is not required** — they touch different layers (runtime
  identity vs share transport) and can proceed in parallel, but 2 is a
  *prerequisite for rootless `shared` attachments* (session-mode virtiofs
  needs an unprivileged externally-launched virtiofsd), so finishing 2
  first makes milestone 7 of the rootless plan much smaller.
- **5 (CI e2e) should land alongside whichever of 1/2 starts first**: both
  efforts are exactly the kind of change the e2e suites keep catching bugs
  in, and the sudoless e2e suite is already CI-compatible (no passwordless
  sudo needed).
- **3 and 4 are independent** of everything else and of each other.

## Prerequisite work already landed (do not redo)

The `dev/sudoless` branch (commit `02dbdf6` and follow-ups) delivered a
large share of what these designs assumed would be future work:

- **Privilege policy layer**: `aivm/privilege.py` (capability probes
  `libvirt_unprivileged_ok()`, `virsh_needs_sudo()`, `path_needs_sudo()`,
  `qemu_traversal_blockers()`); `behavior.privilege_mode` config knob
  (`auto`/`sudo`/`sudoless`); structural never-sudo enforcement in
  `CommandManager._reject_sudo_if_sudoless` (`aivm/commands.py`).
- **URI discipline**: every libvirt client command is built via
  `aivm/runtime.py::virsh_system_cmd` (pins `-c qemu:///system`);
  `virt-install` passes `--connect qemu:///system` (`aivm/vm/create.py`).
  There is exactly one place to make the URI runtime-dependent.
- **User-owned storage path**: `path_needs_sudo()` decisions across
  images/disk/cloudinit; `_ensure_qemu_access_unprivileged` in
  `aivm/vm/host_access.py` (mkdir + `setfacl u:libvirt-qemu:x` instead of
  chown); `aivm host sudoless setup` provisions a user-owned base dir.
- **Approval contract decoupled from sudo**:
  `CommandManager._command_needs_approval` prompts for state-changing
  hypervisor commands (`virsh`/`virt-install`, role=modify) even when they
  run unprivileged.
- **Runtime-gated attachment modes**: the pattern for "this mode is
  unsupported in this mode, fail early with guidance" exists in
  `aivm/attachments/resolve.py::_resolve_attachment` (sudoless guard).
- **E2E proof harness**: `tests/test_e2e_sudoless.py` runs a full lifecycle
  under the never-sudo guarantee; it is the template for a session-runtime
  e2e module.
- **virtiofs EMFILE root cause + guest-side mitigation**: `aivm vm fdguard`
  (`aivm/cli/vm_guard.py`, `virtiofs.fd_guard*` knobs in `aivm/config.py`,
  `docs/source/virtiofs.rst`). The *host-side* fix is effort 2.

## Other design docs in this directory

- [flexible-folder-sharing.md](flexible-folder-sharing.md) — background for
  effort 2 (virtiofs device-slot limits; single-export strategies).
  Partially implemented (`shared-root`, `persistent`).
- [virtiofsd-inode-file-handles.md](virtiofsd-inode-file-handles.md) —
  background for effort 2 (why `--inode-file-handles` cannot be passed
  today; why generated host-side wrappers were rejected).
- [refactor-before-rootless.md](refactor-before-rootless.md) — historical
  record of the lifecycle/CLI/config splits that prepared effort 1. Mostly
  complete; its "runtime context object" checkpoint is absorbed into the
  rootless plan.
- [cli-refactor.md](cli-refactor.md), [vm-update-refactor.md](vm-update-refactor.md),
  [vm-attach-ops-refactor.md](vm-attach-ops-refactor.md),
  [config-layout.md](config-layout.md), [config-refactor-plan.md](config-refactor-plan.md)
  — completed or largely-completed structural refactors; keep for history.
- [brainstorm.md](brainstorm.md) — unstructured idea capture.

## Smaller tracked improvements (no dedicated doc)

These are real but do not need a full design doc. Suitable as standalone
tasks; listed with enough context to start.

1. **Two-axis command role model** (`aivm/commands.py` top-of-file TODO).
   Today `role` collapses privilege and mutation into `read`/`modify`; the
   sudoless work bolted a third distinction on via
   `_is_system_libvirt_mutation`. The TODO sketches the axes (privilege
   boundary x mutation x host/guest target). The comment says "don't
   execute on this, needs more thought" — treat as needs-design, not
   needs-code. Entry point: replace the `role: str` on `CommandSpec` with a
   small dataclass while keeping the `role=` kwarg as sugar.
2. **Digest-addressed image cache** (`TODO(design)` in `aivm/config.py`;
   half-done note in `docs/source/design.rst` Implementation TODOs).
   Cache identity is name-based (`ImageConfig.cache_name`); checksum
   *verification* of cached images already exists
   (`aivm/vm/images.py::fetch_image`). Remaining: look up
   `SUPPORTED_IMAGE_SHA256[url]` and check a digest-keyed cache path before
   fetching by URL; store new downloads under both names (hardlink).
3. **qemu-guest-agent channel** for probes. SSH-based guest probes require
   networking to already work, which makes "networking is broken" hard to
   diagnose. Adding the guest agent (`<channel>` device at create time +
   `virsh -c ... qemu-agent-command` / `guestinfo`) gives IP discovery,
   exec, and file probes that work pre-network. Touch points:
   `aivm/vm/create.py` (device), `aivm/vm/connectivity.py::wait_for_ip`
   (prefer agent query, fall back to leases/domifaddr), provisioning
   (install `qemu-guest-agent` via cloud-init packages).
   This also removes the last reason `wait_ip` can hang on healthy VMs.
4. **Flip `allow_password_login` default to False** (`aivm/config.py::VMConfig`).
   `docs/source/security.rst` now discloses the `agent`/`agent` default;
   the safer default is key-only with password login as an explicit opt-in.
   Breaking change for console recovery workflows — needs a CHANGELOG entry
   and a release-notes callout, not code cleverness.
5. **`aivm host doctor` should absorb the sudoless preflights** so there is
   one diagnostic entry point (today: doctor, sudoless check, and status
   each probe different things). This once read "sudoless/rootless
   preflights", but the rootless `qemu:///session` runtime was removed in
   `190ed83` (see `docs/planning/deferred/session-runtime.md`) and has no
   preflights to absorb. If it returns, its checks belong here too.
6. **conf.py intersphinx** points at `kwconf.readthedocs.io` which 404s;
   remove or fix once kwconf docs publish. No longer fails `./run_docs.sh` —
   inventory-fetch failures are filtered in `docs/source/conf.py`, since
   reachability is a property of the network, not of the docs.
