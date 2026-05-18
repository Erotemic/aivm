"""VM update drift detection."""

from __future__ import annotations

from pathlib import Path

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...runtime import virsh_system_cmd
from ..drift import parse_dominfo_hardware as _parse_dominfo_hardware
from .models import VMUpdateDrift
from .util import (
    _parse_domblkinfo_capacity,
    _parse_qemu_img_virtual_size,
    _parse_vm_disk_path_from_dumpxml,
    _parse_vm_network_from_dumpxml,
)
from .virtiofs import _virtiofs_binary_drift


def _resolve_vm_disk_path(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[Path, tuple[str, ...]]:
    notes: list[str] = []
    expected = (
        Path(cfg.paths.base_dir)
        / cfg.vm.name
        / 'images'
        / f'{cfg.vm.name}.qcow2'
    )
    res = CommandManager.current().run(
        virsh_system_cmd('dumpxml', cfg.vm.name),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if res.code != 0:
        notes.append(
            'Could not read domain XML; falling back to expected aivm disk path.'
        )
        return expected, tuple(notes)
    xml_path = _parse_vm_disk_path_from_dumpxml(res.stdout)
    if not xml_path:
        notes.append(
            'Domain XML has no file-backed disk entry; falling back to expected aivm disk path.'
        )
        return expected, tuple(notes)
    return Path(xml_path), tuple(notes)


def _qemu_img_virtual_size_bytes(
    path: Path, *, use_sudo: bool
) -> tuple[int | None, str]:
    res = CommandManager.current().run(
        ['qemu-img', 'info', '--output=json', str(path)],
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if res.code != 0:
        err = (res.stderr or res.stdout or '').strip()
        return None, err
    return _parse_qemu_img_virtual_size(res.stdout), ''


def _virsh_domblk_capacity_bytes(
    cfg: AgentVMConfig, path_or_target: str, *, use_sudo: bool
) -> int | None:
    res = CommandManager.current().run(
        virsh_system_cmd('domblkinfo', cfg.vm.name, path_or_target),
        sudo=use_sudo,
        check=False,
        capture=True,
    )
    if res.code != 0:
        return None
    return _parse_domblkinfo_capacity(res.stdout)


def _vm_update_drift(
    cfg: AgentVMConfig, *, yes: bool
) -> tuple[VMUpdateDrift, bool]:
    """Compute editable drift between config and live libvirt VM state.

    The update flow is intentionally conservative:
    * prefer non-sudo probes first,
    * escalate to sudo only when required,
    * gather diagnostics in ``notes`` instead of failing hard when a probe is
      inconclusive (for example qemu-img lock contention on running VMs).
    """
    del yes
    notes: list[str] = []
    mgr = CommandManager.current()
    dominfo = mgr.run(
        virsh_system_cmd('dominfo', cfg.vm.name),
        sudo=False,
        check=False,
        capture=True,
        summary=f'Inspect VM definition {cfg.vm.name} for update planning',
    )
    if dominfo.code != 0:
        dominfo = mgr.run(
            virsh_system_cmd('dominfo', cfg.vm.name),
            sudo=True,
            check=False,
            capture=True,
            summary=f'Inspect VM definition {cfg.vm.name} with sudo for update planning',
        )
    if dominfo.code != 0:
        raise RuntimeError(
            f"VM '{cfg.vm.name}' is not defined (or inaccessible via sudo)."
        )

    cur_cpus, cur_mem_mib = _parse_dominfo_hardware(dominfo.stdout)
    cpus = (
        (cur_cpus, int(cfg.vm.cpus))
        if cur_cpus is not None and cur_cpus != int(cfg.vm.cpus)
        else None
    )
    ram_mb = (
        (cur_mem_mib, int(cfg.vm.ram_mb))
        if cur_mem_mib is not None and cur_mem_mib != int(cfg.vm.ram_mb)
        else None
    )

    state_res = mgr.run(
        virsh_system_cmd('domstate', cfg.vm.name),
        sudo=False,
        check=False,
        capture=True,
    )
    if state_res.code != 0:
        state_res = mgr.run(
            virsh_system_cmd('domstate', cfg.vm.name),
            sudo=True,
            check=False,
            capture=True,
        )
    vm_running = (
        state_res.code == 0
        and 'running' in (state_res.stdout or '').strip().lower()
    )

    sudo_confirmed = False

    disk_path, disk_notes = _resolve_vm_disk_path(cfg, use_sudo=False)
    if (
        any('Could not read domain XML' in note for note in disk_notes)
        and not sudo_confirmed
    ):
        sudo_confirmed = True
        disk_path, disk_notes = _resolve_vm_disk_path(cfg, use_sudo=True)
    notes.extend(disk_notes)
    cur_disk, qemu_img_err = _qemu_img_virtual_size_bytes(
        disk_path, use_sudo=False
    )
    if cur_disk is None:
        sudo_confirmed = True
        cur_disk, qemu_img_err = _qemu_img_virtual_size_bytes(
            disk_path, use_sudo=True
        )
    if cur_disk is None:
        if (
            qemu_img_err
            and 'failed to get shared "write" lock' in qemu_img_err.lower()
        ):
            notes.append(
                'qemu-img could not inspect disk while VM was running (shared write lock); falling back to virsh domblkinfo.'
            )
        domblk = _virsh_domblk_capacity_bytes(
            cfg, str(disk_path), use_sudo=bool(sudo_confirmed)
        )
        if domblk is None and not sudo_confirmed:
            sudo_confirmed = True
            domblk = _virsh_domblk_capacity_bytes(
                cfg, str(disk_path), use_sudo=True
            )
        cur_disk = domblk
    desired_disk = int(cfg.vm.disk_gb) * (1024**3)
    disk_bytes = (
        (cur_disk, desired_disk)
        if cur_disk is not None and cur_disk != desired_disk
        else None
    )
    if cur_disk is None:
        notes.append(f'Could not determine disk size from {disk_path}.')

    xml = mgr.run(
        virsh_system_cmd('dumpxml', cfg.vm.name),
        sudo=False,
        check=False,
        capture=True,
        summary=f'Inspect VM XML for {cfg.vm.name} network details',
    )
    if xml.code != 0:
        sudo_confirmed = True
        xml = mgr.run(
            virsh_system_cmd('dumpxml', cfg.vm.name),
            sudo=True,
            check=False,
            capture=True,
            summary=f'Inspect VM XML for {cfg.vm.name} network details with sudo',
        )
    if xml.code == 0:
        live_network = _parse_vm_network_from_dumpxml(xml.stdout)
        want_network = (cfg.network.name or '').strip()
        if live_network and want_network and live_network != want_network:
            notes.append(
                f'Network drift detected (live={live_network}, config={want_network}); auto-update is not implemented for network rebinding.'
            )

    virtiofsd_mode, virtiofs_binary = _virtiofs_binary_drift(
        cfg, xml.stdout if xml.code == 0 else ''
    )
    requested_inode_mode = str(
        getattr(cfg.virtiofs, 'inode_file_handles', '') or ''
    ).strip()
    if requested_inode_mode:
        notes.append(
            'virtiofs.inode_file_handles is currently ignored in managed-libvirt mode; '
            'AIVM no longer installs generated host-side virtiofsd wrappers. '
            'Existing AIVM wrapper paths will be removed from domain XML.'
        )

    return (
        VMUpdateDrift(
            cpus=cpus,
            ram_mb=ram_mb,
            disk_bytes=disk_bytes,
            disk_path=str(disk_path),
            virtiofs_binary=virtiofs_binary,
            virtiofsd_mode=virtiofsd_mode,
            notes=tuple(notes),
        ),
        vm_running,
    )
