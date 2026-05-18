"""Virtiofs-specific drift detection and update helpers."""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...runtime import virsh_system_cmd
from .. import virtiofsd_wrapper
from .models import VirtiofsBinaryDrift, VMUpdateDrift


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


def _apply_virtiofs_binary_drift(
    cfg: AgentVMConfig, drift: VMUpdateDrift, *, dry_run: bool
) -> bool:
    """Rewrite virtiofs ``<binary path>`` entries in persistent XML.

    Current normal use is cleanup-only: remove legacy AIVM-generated wrapper
    paths and return to libvirt's managed virtiofsd invocation. The old path
    that installed host-side wrappers is intentionally disabled.

    The vhost-user-fs binary path cannot be changed live, so we update the
    persistent config only; the change takes effect on the next VM start.
    Returns True if any change was applied (or would be in dry-run).
    """
    mgr = CommandManager.current()
    needs_wrapper = any(d.desired for d in drift.virtiofs_binary)
    if needs_wrapper:
        raise RuntimeError(
            'Refusing to configure AIVM-generated host-side virtiofsd wrappers. '
            'Managed libvirt mode now only removes old AIVM wrapper paths. '
            'See dev/design/future/virtiofsd-inode-file-handles.md.'
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
