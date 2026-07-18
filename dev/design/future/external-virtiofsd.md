# Externally-managed virtiofsd backend

Written: 2026-07-02
Status: design ready for implementation; not started

## Problem

libvirt currently owns the virtiofsd invocation for every `<filesystem
type='mount'>` device aivm attaches. That single fact causes three
independent limitations:

1. **The EMFILE root cause cannot be fixed at the source.** Host virtiofsd
   holds one `O_PATH` fd per guest-cached inode and releases it only on
   guest inode eviction (see
   `dev/devcheck/virtiofsd_emfile_case_report_2026_05_17.md`). The real
   fix is virtiofsd's `--inode-file-handles=prefer` (file-handle-backed
   inodes, no persistent fd), but libvirt's `<filesystem>` XML exposes no
   way to pass it, and generated host-side wrapper scripts were tried and
   explicitly rejected on host-trust grounds. The shipped
   `aivm vm fdguard` guest timer (`aivm/cli/vm_guard.py`,
   `virtiofs.fd_guard*` in `aivm/config.py`, `docs/source/virtiofs.rst`)
   is a mitigation that prunes guest caches; it does not remove the
   underlying design problem.
2. **A wedged virtiofsd cannot be restarted without a VM restart.**
   libvirt supervises the daemon; aivm has no per-share lifecycle control.

## Decided direction

Run virtiofsd **outside** libvirt, owned by aivm as a per-share user
systemd service, and connect it to the guest with libvirt's first-class
external-socket form:

```xml
<filesystem type='mount'>
  <driver type='virtiofs' queue='1024'/>
  <source socket='/run/user/1000/aivm/<vm>/<tag>.sock'/>
  <target dir='<tag>'/>
</filesystem>
```

This is *not* a generated wrapper script: the executed binary is the
system `virtiofsd`, launched by a unit file aivm writes under the user's
`~/.config/systemd/user/` (guest-side helper generation of this kind is
already accepted practice — the persistent replay unit and fdguard do it
in the guest; this extends the pattern to *user-owned host services*,
which does not place generated executables in a privileged host startup
path).

Requirements background:

* libvirt supports `<source socket=.../>` for vhost-user-fs when the
  daemon is externally managed (the same mechanism virtiofs docs describe
  for custom deployments). The VM must use shared memory
  (`<memoryBacking><source type='memfd'/><access mode='shared'/>`), which
  aivm already configures for virtiofs-bearing VMs — verify at
  implementation time via `aivm/vm/share.py::vm_has_virtiofs_shared_memory`.
* Rust virtiofsd supports `--inode-file-handles=prefer` (needs
  `CAP_DAC_READ_SEARCH`; degrades gracefully without it), `--sandbox
  namespace|chroot|none`, and unprivileged operation. For **system**
  runtime the service can run as the invoking user with
  `--sandbox=none --inode-file-handles=prefer` (file handles need the
  capability: grant via the unit's `AmbientCapabilities=` when the user
  service manager permits, else fall back to O_PATH mode and log it).

## Design

### Config

```toml
[virtiofs]
backend = "libvirt"    # "libvirt" (current) | "external"
inode_file_handles = "prefer"   # only honored by the external backend
```

`backend` defaults to `"libvirt"` initially; flip the default only after
an e2e bake period. The long-dormant `virtiofs.inode_file_handles` knob
(`aivm/config.py::VirtiofsConfig`, currently documented as ignored)
finally gets a lawful consumer.

### Components

1. **Socket/unit manager** — new module `aivm/vm/virtiofsd_service.py`:
   * unit name: `aivm-virtiofsd-<vm>-<tag>.service`; socket path under
     `$XDG_RUNTIME_DIR/aivm/<vm>/` (fall back to the state dir when no
     XDG runtime dir).
   * `ensure_share_service(cfg, tag, source_dir)` writes/updates the unit
     (ExecStart with `--socket-path`, `--shared-dir`, flag set derived
     from config), `systemctl --user daemon-reload`, `enable --now`.
     Content-hash the unit file to make this idempotent (same pattern as
     the guest replay helpers in `aivm/attachments/persistent/transport.py`).
   * `remove_share_service(...)`, `restart_share_service(...)`,
     `share_service_status(...)`.
   * All through `CommandManager` (`systemctl --user` is unprivileged;
     works in every privilege mode including ``privilege_mode="never"``).
2. **Attach/detach integration** — `aivm/vm/share.py::attach_vm_share`
   and `detach_vm_share` branch on the backend: external backend first
   ensures the service, then attach-device with the `<source socket=>`
   XML; detach reverses (detach device, then stop/remove unit). The
   shared-root/persistent flows reuse the same two functions, so they
   inherit the backend switch for their single export.
3. **Drift/update integration** — `aivm/vm/drift.py` mapping comparison
   must treat a socket-source filesystem with tag T as equivalent to the
   mount-source form for "is this attachment mapped" purposes;
   `aivm vm update` learns to migrate a share between backends
   (detach mount-form device, ensure service, attach socket-form) when
   config and live XML disagree. Follow the existing fd-guard
   reconciliation shape in `aivm/vm/update/` (probe, plan, apply).
4. **Boot ordering** — a socket-form device requires the daemon to be
   listening before the VM starts. `create_or_start_vm`
   (`aivm/vm/create.py`) and `vm up`/restart paths must call
   `ensure_share_service` for every configured share *before*
   `virsh start`. On host reboot, `enable`d user units restart with the
   user session; the persistent-replay host systemd service pattern
   (`aivm vm install_persistent_host_replay_service`) shows how to make
   that robust when the user session is not a login session (lingering).
   Document `loginctl enable-linger` as a requirement for VMs that
   auto-start.
5. **Recovery UX** — `aivm vm flush_caches` gains a host-side sibling:
   `aivm vm restart_share --tag <tag>` (or extend fdguard docs) that
   bounces one wedged daemon; guest remounts via the existing replay
   machinery. This is the payoff item 2 above.

### Failure modes to handle explicitly

* virtiofsd binary missing or too old for a requested flag: probe
  `virtiofsd --version`/`--help` once per manager (cache in
  `mgr.probe_cache`, like `libvirt_without_sudo_ok`), degrade flags with
  a warning rather than failing the attach.
* Stale socket file with no live daemon: `ensure_share_service` removes
  the socket before start (virtiofsd refuses to bind otherwise).
* `attach-device` while daemon dead: surfaces as vhost handshake error —
  precheck `share_service_status` and error with
  "run aivm vm restart_share".
* Unit-file drift after aivm upgrade: hash comparison already covers it.

## Implementation plan (ordered, each step testable)

1. `virtiofsd_service.py` with unit render + ensure/remove/status + unit
   tests (mock CommandManager subprocess like `tests/test_commands.py`).
2. Capability probe for virtiofsd flags + unit tests.
3. `attach_vm_share`/`detach_vm_share` backend branch + socket-form XML
   render + unit tests asserting the generated XML and command sequence.
4. Boot-ordering hooks in `create.py` / lifecycle start paths.
5. Drift equivalence + `vm update` backend migration.
6. `restart_share` CLI + docs (`docs/source/virtiofs.rst` new section;
   README FD-growth mitigation list).
7. E2E: extend `tests/test_e2e_full.py` or add `test_e2e_external_virtiofsd.py`
   — attach with `backend=external`, write/read through the share, kill
   the daemon, `restart_share`, read again, then `vm update` migration
   from libvirt-backend to external on a live VM.
8. Bake, then consider flipping the default and closing the fdguard
   threshold down (file-handle mode should keep `fuse_inode` slab growth
   from mattering on the host side).

## Acceptance criteria

1. A `backend=external` share attaches, mounts in-guest, and survives
   guest reboot and VM restart without manual daemon management.
2. `--inode-file-handles=prefer` is passed when supported; `aivm status
   --detail` (or `vm fdguard --action status`) shows which mode each
   share's daemon runs in.
3. Killing a share's virtiofsd and running the restart command restores
   the share without VM restart.
4. `aivm vm update` converges a VM from libvirt-backend shares to
   external-backend shares (and back) per config.
5. E2E suites pass with both backend values; the privilege-never E2E suite passes with
   `backend=external` when the selected attachment path requires no host
   bind mount.
6. The EMFILE reproduction from
   `dev/devcheck/virtiofsd_emfile_case_report_2026_05_17.md` (updatedb
   sweep over a large attached tree) does not grow host fd count when
   file-handle mode is active.
