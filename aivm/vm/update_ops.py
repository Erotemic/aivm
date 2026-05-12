"""VM update helpers: drift detection, planning, and application."""

from __future__ import annotations

import json
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..runtime import virsh_system_cmd
from ..vm import virtiofsd_wrapper
from ..vm.drift import parse_dominfo_hardware as _parse_dominfo_hardware


class RestartKind(StrEnum):
    """How invasive a post-update restart needs to be.

    NONE  - no restart required (e.g. disk grow via qemu-img is live)
    SOFT  - guest-OS reboot only; qemu process persists
            (``virsh reboot``). Right for changes the guest reads on its
            own boot.
    HARD  - full power cycle; kill qemu and respawn it
            (``virsh shutdown`` + ``virsh start``). Required when the
            change is at the qemu/virtiofsd layer rather than inside the
            guest: CPU and RAM are configured with ``--config`` only and
            so are picked up on next qemu start, not on guest reboot;
            virtiofsd's ``<binary path>`` likewise can only change when
            qemu spawns a fresh virtiofsd.
    """

    NONE = 'none'
    SOFT = 'soft'
    HARD = 'hard'


def _escalate(current: RestartKind, candidate: RestartKind) -> RestartKind:
    """Return whichever of the two is "more invasive"."""
    order = {RestartKind.NONE: 0, RestartKind.SOFT: 1, RestartKind.HARD: 2}
    return current if order[current] >= order[candidate] else candidate


@dataclass(frozen=True)
class VirtiofsBinaryDrift:
    """A single ``<filesystem>`` device whose ``<binary path>`` is wrong.

    ``tag`` is the virtiofs target dir (the libvirt-side identifier);
    ``current`` is what the XML currently has (empty string if the
    ``<binary>`` element is absent); ``desired`` is the path we want
    libvirt to launch.
    """

    tag: str
    current: str
    desired: str


@dataclass(frozen=True)
class VMUpdateDrift:
    cpus: tuple[int, int] | None = None
    ram_mb: tuple[int, int] | None = None
    disk_bytes: tuple[int, int] | None = None
    disk_path: str = ''
    virtiofs_binary: tuple[VirtiofsBinaryDrift, ...] = ()
    virtiofsd_mode: str = ''
    notes: tuple[str, ...] = ()

    def has_changes(self) -> bool:
        return any(
            (self.cpus, self.ram_mb, self.disk_bytes, self.virtiofs_binary)
        )


def _bytes_to_gib(size_bytes: int) -> float:
    return float(size_bytes) / float(1024**3)


def _parse_qemu_img_virtual_size(info_json: str) -> int | None:
    try:
        raw = json.loads(info_json or '{}')
    except Exception:
        return None
    size = raw.get('virtual-size')
    if isinstance(size, int) and size > 0:
        return size
    return None


def _parse_vm_disk_path_from_dumpxml(dumpxml_text: str) -> str | None:
    try:
        root = ET.fromstring(dumpxml_text)
    except ET.ParseError:
        return None
    devices = root.find('devices')
    if devices is None:
        return None
    for disk in devices.findall('disk'):
        if disk.get('device') != 'disk':
            continue
        source = disk.find('source')
        if source is None:
            continue
        source_file = (source.get('file') or '').strip()
        if source_file:
            return source_file
    return None


def _parse_vm_network_from_dumpxml(dumpxml_text: str) -> str | None:
    try:
        root = ET.fromstring(dumpxml_text)
    except ET.ParseError:
        return None
    devices = root.find('devices')
    if devices is None:
        return None
    for iface in devices.findall('interface'):
        if (iface.get('type') or '').strip() != 'network':
            continue
        source = iface.find('source')
        if source is None:
            continue
        network_name = (source.get('network') or '').strip()
        if network_name:
            return network_name
    return None


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


def _parse_domblkinfo_capacity(domblkinfo_text: str) -> int | None:
    for line in (domblkinfo_text or '').splitlines():
        if ':' not in line:
            continue
        key, val = [x.strip() for x in line.split(':', 1)]
        if key.lower() == 'capacity':
            m = re.search(r'(\d+)', val)
            if m:
                return int(m.group(1))
    return None


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

    virtiofsd_mode, virtiofs_binary = _virtiofs_binary_drift(cfg, xml.stdout if xml.code == 0 else '')

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


def _virtiofs_binary_drift(
    cfg: AgentVMConfig, dumpxml_text: str
) -> tuple[str, tuple[VirtiofsBinaryDrift, ...]]:
    """Compute drift between current and desired virtiofsd <binary path>.

    Returns (resolved_mode, drift_tuples). ``resolved_mode`` is the
    normalized mode string (e.g. 'prefer' or '' for disabled); the drift
    tuple is empty when no ``<filesystem>`` device needs updating.

    Reads the desired mode from ``cfg.virtiofs.inode_file_handles``.
    Empty mode means "no wrapper", in which case any current ``<binary>``
    that already points at an aivm-managed wrapper is considered drift in
    the opposite direction (revert to libvirt default).
    """
    mode = virtiofsd_wrapper.normalize_mode(
        getattr(cfg.virtiofs, 'inode_file_handles', '')
    )
    desired = (
        virtiofsd_wrapper.desired_binary_path(cfg.paths.base_dir, mode) or ''
    )

    if not dumpxml_text:
        return mode, ()
    try:
        root = ET.fromstring(dumpxml_text)
    except ET.ParseError:
        return mode, ()

    drift: list[VirtiofsBinaryDrift] = []
    for fs in root.findall('.//devices/filesystem'):
        driver = fs.find('driver')
        if driver is None:
            continue
        if driver.attrib.get('type', '').strip().lower() != 'virtiofs':
            continue
        target_el = fs.find('target')
        tag = target_el.attrib.get('dir', '') if target_el is not None else ''
        binary_el = fs.find('binary')
        current = (
            binary_el.attrib.get('path', '') if binary_el is not None else ''
        )
        if desired:
            if current != desired:
                drift.append(VirtiofsBinaryDrift(tag, current, desired))
        else:
            # Wrapper disabled in config; if the live XML still points at any
            # aivm-managed wrapper (any mode suffix), revert to default.
            if virtiofsd_wrapper.is_managed_wrapper_path(
                cfg.paths.base_dir, current
            ):
                drift.append(VirtiofsBinaryDrift(tag, current, ''))
    return mode, tuple(drift)


def _print_vm_update_plan(cfg: AgentVMConfig, drift: VMUpdateDrift) -> None:
    print(f'Planned VM update for {cfg.vm.name}:')
    if drift.cpus is not None:
        cur, want = drift.cpus
        print(f'  - cpus: {cur} -> {want}')
    if drift.ram_mb is not None:
        cur, want = drift.ram_mb
        print(f'  - ram_mb: {cur} -> {want}')
    if drift.disk_bytes is not None:
        cur, want = drift.disk_bytes
        print(
            f'  - disk_gb: {_bytes_to_gib(cur):.2f} GiB -> {_bytes_to_gib(want):.2f} GiB ({drift.disk_path})'
        )
    if drift.virtiofs_binary:
        mode_label = drift.virtiofsd_mode or 'disabled'
        print(
            f'  - virtiofsd binary path (inode-file-handles={mode_label}): '
            f'{len(drift.virtiofs_binary)} <filesystem> device(s) to update'
        )
        for d in drift.virtiofs_binary:
            cur = d.current or '(default)'
            new = d.desired or '(default)'
            print(f'      tag={d.tag}: {cur} -> {new}')


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


def _apply_virtiofs_binary_drift(
    cfg: AgentVMConfig, drift: VMUpdateDrift, *, dry_run: bool
) -> bool:
    """Install the wrapper (if needed) and rewrite the domain XML.

    The vhost-user-fs binary path cannot be changed live, so we update the
    persistent config only; the change takes effect on the next VM start.
    Returns True if any change was applied (or would be in dry-run).
    """
    mgr = CommandManager.current()
    mode = drift.virtiofsd_mode
    # Install / refresh the wrapper if any drift entry needs it.
    needs_wrapper = any(d.desired for d in drift.virtiofs_binary)
    if needs_wrapper and mode:
        virtiofsd_wrapper.ensure_wrapper_installed(
            cfg.paths.base_dir, mode, dry_run=dry_run
        )

    if dry_run:
        # In dry-run we don't actually touch libvirt: just describe the diff
        # already captured in `drift.virtiofs_binary` and report success.
        for d in drift.virtiofs_binary:
            cur = d.current or '(default)'
            new = d.desired or '(default)'
            print(
                f"DRYRUN: would set <binary path={new!r}> on virtiofs "
                f"device tag={d.tag!r} (was {cur!r})"
            )
        return True

    dumpxml = mgr.run(
        virsh_system_cmd('dumpxml', cfg.vm.name),
        sudo=True,
        check=True,
        capture=True,
        role='read',
        summary=f'Dump VM XML for {cfg.vm.name} to rewrite virtiofs binary path',
    )
    try:
        root = ET.fromstring(dumpxml.stdout)
    except ET.ParseError as ex:
        raise RuntimeError(f'Could not parse domain XML for {cfg.vm.name}: {ex}')

    drift_by_tag = {d.tag: d for d in drift.virtiofs_binary}
    touched = 0
    for fs in root.findall('.//devices/filesystem'):
        driver = fs.find('driver')
        if driver is None:
            continue
        if driver.attrib.get('type', '').strip().lower() != 'virtiofs':
            continue
        tgt = fs.find('target')
        tag = tgt.attrib.get('dir', '') if tgt is not None else ''
        if tag not in drift_by_tag:
            continue
        desired = drift_by_tag[tag].desired
        binary_el = fs.find('binary')
        if desired:
            if binary_el is None:
                binary_el = ET.Element('binary')
                # Place <binary> right after <driver> to follow libvirt convention.
                driver_idx = list(fs).index(driver)
                fs.insert(driver_idx + 1, binary_el)
            binary_el.set('path', desired)
        else:
            if binary_el is not None:
                fs.remove(binary_el)
        touched += 1

    if touched == 0:
        return False

    new_xml = ET.tostring(root, encoding='unicode')

    with tempfile.NamedTemporaryFile(
        'w', delete=False, suffix='.xml', prefix=f'aivm-{cfg.vm.name}-'
    ) as f:
        f.write(new_xml)
        tmp = f.name
    try:
        mgr.run(
            ['virsh', '-c', 'qemu:///system', 'define', tmp],
            sudo=True,
            check=True,
            capture=True,
            role='modify',
            summary=f'Redefine VM {cfg.vm.name} with updated virtiofs binary path',
            detail=f'updated {touched} <filesystem> device(s)',
        )
        print(
            f'Updated virtiofs <binary path> on {touched} device(s); '
            f'effective on next start of {cfg.vm.name}.'
        )
    finally:
        try:
            Path(tmp).unlink()
        except OSError:
            pass
    return True


def _maybe_restart_vm_after_update(
    cfg: AgentVMConfig,
    *,
    kind: RestartKind,
    restart_policy: str,
    dry_run: bool,
    yes: bool,
) -> None:
    """Restart the VM if needed, picking the right command for the drift kind.

    ``kind`` comes from ``_apply_vm_update``. For NONE this is a no-op.
    SOFT does a guest-OS reboot (``virsh reboot``). HARD does a full
    power cycle via the existing ``restart_vm`` helper, which handles
    the ACPI shutdown, polling for ``shut off``, and ``virsh start``
    (including pmsuspended corner cases).
    """
    if kind == RestartKind.NONE:
        return

    label = {
        RestartKind.SOFT: 'guest reboot',
        RestartKind.HARD: 'full power cycle (shutdown + start)',
    }[kind]

    should_restart = False
    if restart_policy == 'always':
        should_restart = True
    elif restart_policy == 'never':
        should_restart = False
    elif yes:
        should_restart = True
    elif sys.stdin.isatty():
        ans = (
            input(
                f'A {label} is needed for the applied changes to take '
                f'effect now. Restart VM now? [y/N]: '
            )
            .strip()
            .lower()
        )
        should_restart = ans in {'y', 'yes'}

    if not should_restart:
        print(
            f'Updates saved, but VM {cfg.vm.name} needs a {label} for them '
            f'to take effect.'
        )
        return

    if kind == RestartKind.SOFT:
        cmd = virsh_system_cmd('reboot', cfg.vm.name)
        if dry_run:
            print(f'DRYRUN: {" ".join(cmd)}')
        else:
            CommandManager.current().run(
                cmd, sudo=True, check=True, capture=True
            )
            print(f'Rebooted VM {cfg.vm.name}.')
        return

    # HARD: shutdown + start. Local import keeps this module decoupled from
    # the full lifecycle import chain at module load.
    from .lifecycle import restart_vm

    if dry_run:
        print(
            f'DRYRUN: virsh shutdown {cfg.vm.name} (wait for off) && virsh '
            f'start {cfg.vm.name}'
        )
        return
    restart_vm(cfg, dry_run=False)
    print(f'Power-cycled VM {cfg.vm.name}.')
