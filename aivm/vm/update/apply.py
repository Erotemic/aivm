"""Apply VM update drift to libvirt and disk state."""

from __future__ import annotations

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...runtime import virsh_system_cmd
from .models import RestartKind, VMUpdateDrift, _escalate
from .util import _bytes_to_gib
from .virtiofs import _apply_virtiofs_binary_drift


def _apply_vm_update(
    cfg: AgentVMConfig, drift: VMUpdateDrift, *, dry_run: bool
) -> tuple[bool, RestartKind]:
    """Apply each drift type and report the most invasive restart needed.

    See ``RestartKind`` for which drift types need which kind of restart
    and why. Returns ``(changed, restart_kind)``.
    """
    changed = False
    restart = RestartKind.NONE

    # TODO: Should we check for network config drift here too?
    if drift.cpus is not None:
        _, want = drift.cpus
        cmd = virsh_system_cmd('setvcpus', cfg.vm.name, str(want), '--config')
        if dry_run:
            print(f'DRYRUN: {" ".join(cmd)}')
        else:
            CommandManager.current().run(
                cmd, sudo=True, check=True, capture=True
            )
            print(f'Updated CPU count to {want}.')
        changed = True
        # --config writes the persistent XML only; live qemu keeps the old
        # vCPU count. Picked up on next qemu start, so a guest reboot
        # would NOT see it: we need a full power cycle.
        restart = _escalate(restart, RestartKind.HARD)
    if drift.ram_mb is not None:
        _, want = drift.ram_mb
        kib = int(want) * 1024
        max_cmd = virsh_system_cmd(
            'setmaxmem', cfg.vm.name, str(kib), '--config'
        )
        mem_cmd = virsh_system_cmd('setmem', cfg.vm.name, str(kib), '--config')
        if dry_run:
            print(f'DRYRUN: {" ".join(max_cmd)}')
            print(f'DRYRUN: {" ".join(mem_cmd)}')
        else:
            mgr = CommandManager.current()
            mgr.run(max_cmd, sudo=True, check=True, capture=True)
            mgr.run(mem_cmd, sudo=True, check=True, capture=True)
            print(f'Updated RAM to {want} MiB.')
        changed = True
        # Same reasoning as CPU: setmem --config is persistent-only.
        restart = _escalate(restart, RestartKind.HARD)
    if drift.disk_bytes is not None:
        cur, want = drift.disk_bytes
        if want < cur:
            raise RuntimeError(
                f'Disk shrink is not supported safely (live={_bytes_to_gib(cur):.2f} GiB, config={_bytes_to_gib(want):.2f} GiB).'
            )
        if want > cur:
            cmd = ['qemu-img', 'resize', drift.disk_path, f'{cfg.vm.disk_gb}G']
            if dry_run:
                print(f'DRYRUN: {" ".join(cmd)}')
            else:
                CommandManager.current().run(
                    cmd, sudo=True, check=True, capture=True
                )
                print(
                    f'Expanded disk to {_bytes_to_gib(want):.2f} GiB at {drift.disk_path}.'
                )
            changed = True
            # qemu-img resize on the backing file is honoured live; the
            # guest may want to rescan its partition table, but no
            # power cycle is required at the qemu layer.
    if drift.virtiofs_binary:
        if _apply_virtiofs_binary_drift(cfg, drift, dry_run=dry_run):
            changed = True
            # vhost-user-fs <binary path> changes only take effect when
            # libvirt spawns a fresh virtiofsd, which requires a full
            # qemu power cycle. virsh reboot would NOT swap the binary.
            restart = _escalate(restart, RestartKind.HARD)
    return changed, restart
