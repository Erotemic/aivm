# Snapshots, rollback, and ephemeral clones

Written: 2026-07-02
Status: design ready for implementation; not started

## Problem

aivm's model is one long-lived VM per host. For agent workflows two
capabilities are missing:

1. **Undo**: snapshot before letting an agent run, roll back when it
   damages the guest (broken toolchain, polluted home dir, rogue
   installs). Today the only recovery is `vm delete` + recreate +
   re-provision.
2. **Disposable clones**: cheap per-task VMs sharing the provisioned base
   (agent gets a fresh guest in seconds, discarded afterwards), instead
   of reusing one increasingly-stateful VM.

## The design-critical caveat: attachments are outside the boundary

Snapshots capture the VM disk (and optionally RAM). They do **not**
capture attached host folders — which is where the user's actual work
lives. That is a feature (rollback doesn't eat your repo) but must be
explicit in UX and docs: *rollback restores the guest system, not shared
folder contents.* The persistent-attachment manifest
(`aivm/attachments/persistent/`) is the bridge: it is a declarative
record of what should be mounted, so post-rollback reconcile
(`aivm code .` / replay service) restores attachment *state* even when
the guest filesystem predates the attachment. The snapshot design should
lean on that instead of trying to version shared data.

## Snapshot mechanics (decided)

Use **external qcow2 snapshots via libvirt** (`virsh snapshot-create-as
--disk-only` for running VMs, or internal snapshots for shut-off VMs).
Constraints that shape this:

* Internal qcow2 snapshots (`virsh snapshot-create-as` on a shut-off VM)
  are the simplest and support RAM-less revert cleanly; they are slow on
  large disks but aivm disks are modest (40G sparse default,
  `aivm/config.py::VMConfig.disk_gb`).
* Running-VM snapshots with RAM (`--memspec`) interact poorly with
  virtiofs (vhost-user devices are generally not migratable/savable);
  **decide**: v1 supports snapshots of *shut-off* VMs only (internal
  snapshots), with `--live` explicitly rejected while virtiofs devices
  are attached. This dodges the whole memory/vhost problem and matches
  the use case ("checkpoint before an agent session" tolerates a
  shutdown; `shutdown_vm` already exists in `aivm/vm/domain.py`).
* UEFI/nvram: `virsh snapshot-*` handles nvram poorly across versions;
  test explicitly, and snapshot/restore the nvram file alongside if
  needed (it lives in the domain XML; the delete path already passes
  `--nvram`).

### CLI

```bash
aivm vm snapshot [--name pre-agent-2026-07-02] [--note "..."]
aivm vm snapshots           # list, with creation time + note + current marker
aivm vm rollback --name X   # shut down if running (prompt), revert, restart
aivm vm snapshot_delete --name X
```

Implementation home: new `aivm/cli/vm_snapshot.py` +
`aivm/vm/snapshot.py`, registered in `VMModalCLI` (`aivm/cli/vm.py`).
All virsh commands via `virsh_system_cmd` with `sudo=virsh_needs_sudo()`
and `role='modify'` for mutations (the approval contract applies:
rollback is destructive to the guest). Snapshot metadata is libvirt's
(`snapshot-list --name`, `snapshot-info`); aivm stores only optional
notes in the VM state dir.

### Rollback flow

1. Confirm (destructive; `--yes` honored).
2. `shutdown_vm` if running (existing graceful path + timeout).
3. Detach transient virtiofs devices if any linger in config XML
   (snapshot was taken without them; reattach happens via reconcile).
4. `virsh snapshot-revert <vm> <name>`.
5. Start VM; run attachment reconcile (the same code path
   `aivm code .` uses) so manifest-declared mounts return.
6. Report what was reverted and remind that shared folders were not.

## Ephemeral clones (second milestone)

Layered qcow2: create `clone.qcow2` with `backing_file=<base vm disk>`
(`qemu-img create -f qcow2 -F qcow2 -b ...` — the exact pattern
`aivm/vm/disk.py::_ensure_disk` already uses against the cached cloud
image), plus a fresh cloud-init seed with a new instance-id/hostname so
the clone re-runs per-instance cloud-init.

```bash
aivm vm clone --from aivm-2404-host [--name task-123] [--ephemeral]
aivm vm reap             # destroy ephemeral clones + storage
```

Design decisions:

* **The base must be quiesced**: writing to a backing file corrupts
  overlays. Options: (a) require base shut off while clones exist —
  simple, restrictive; (b) clone from a *snapshot* of the base instead of
  its live disk (`qemu-img create -b` against the snapshot layer). Start
  with (a) + a hard guard (refuse `vm up` of the base while ephemeral
  clones exist; record clone ancestry in the config store), and note (b)
  as the follow-up. The guard belongs in `create_or_start_vm`.
* Clone identity: reuse the multi-VM support that already exists in the
  config store (`VMEntry` records, `--vm` flags everywhere). A clone is a
  normal VM record flagged `ephemeral = true` with `parent = <base>`, so
  status/list/ssh/attach all work unchanged.
* Networking: same managed network; DHCP hands the clone its own lease
  (MAC is generated per-domain by virt-install). Nothing new needed.
* Attachments: **not inherited**. A fresh clone starts with no
  attachments; `aivm code .` in a project attaches as usual. Inheriting
  the parent's writable shares would silently multiply write access to
  host folders — make it explicit per-clone.
* Provisioning: the point of cloning is to skip re-provisioning; the
  base's provisioned state is in the disk. cloud-init per-instance
  re-runs only identity bits (hostname, ssh keys, user) — verify the
  existing user-data is idempotent for that split (it targets NoCloud
  per-instance semantics already; test).

## Implementation plan

1. `aivm/vm/snapshot.py`: list/create/revert/delete wrappers + unit
   tests (mock subprocess; assert virsh argv and role/sudo policy).
2. CLI commands + confirmation flow + docs (workflows.rst "Checkpoint
   and roll back" section; README feature bullet; security.rst note that
   rollback does not revert shared folders).
3. Rollback e2e in `test_e2e_full.py`: create VM, touch marker file in
   guest, snapshot, remove marker + add junk, rollback, assert marker
   restored and junk gone, attachment still mounts after reconcile.
4. Clone milestone: store schema additions (`ephemeral`, `parent`),
   `vm clone`/`vm reap`, base-quiesce guard, e2e (clone boots, has own
   IP, parent guarded; reap removes domain + storage + records).

## Acceptance criteria

1. snapshot → damage guest → rollback restores guest system state;
   attached folders untouched; reconcile restores mounts.
2. Live snapshot attempts with virtiofs attached are rejected with a
   clear message (shut down first).
3. Clone boots in seconds (no image copy), has independent identity
   (hostname/IP/ssh alias), and `vm reap` fully removes it.
4. Base VM cannot be started while ephemeral clones exist (guard fires),
   and the error names the clones.
5. All snapshot/rollback/clone mutations show the standard approval
   prompts (unprivileged-libvirt approval contract applies).
