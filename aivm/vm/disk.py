"""VM disk creation, recreation, and resize helpers."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..privilege import path_needs_sudo
from .host_access import _sudo_path_exists, _undetermined_existence_error
from .paths import _paths

log = logger

def _ensure_disk(
    cfg: AgentVMConfig,
    base_img: Path,
    *,
    dry_run: bool = False,
    recreate: bool = False,
) -> Path:
    p = _paths(cfg, dry_run=dry_run)
    vm_disk = p['img_dir'] / f'{cfg.vm.name}.qcow2'
    mgr = CommandManager.current()
    use_sudo = path_needs_sudo(p['img_dir'])
    disk_exists = _sudo_path_exists(vm_disk)
    if disk_exists is None:
        raise _undetermined_existence_error(vm_disk, 'VM disk')
    if disk_exists and recreate:
        if dry_run:
            log.info('DRYRUN: rm -f {}', vm_disk)
        else:
            mgr.run(
                ['rm', '-f', str(vm_disk)], sudo=use_sudo, check=True, capture=True
            )
            disk_exists = False
    if disk_exists:
        log.info('VM disk exists: {}', vm_disk)
        return vm_disk
    if dry_run:
        log.info(
            'DRYRUN: qemu-img create -f qcow2 -F qcow2 -b {} {} {}G',
            base_img,
            vm_disk,
            cfg.vm.disk_gb,
        )
        return vm_disk
    mgr.run(
        [
            'qemu-img',
            'create',
            '-f',
            'qcow2',
            '-F',
            'qcow2',
            '-b',
            str(base_img),
            str(vm_disk),
            f'{cfg.vm.disk_gb}G',
        ],
        sudo=use_sudo,
        check=True,
        capture=True,
    )
    return vm_disk
