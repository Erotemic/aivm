"""Rename a managed VM across every artifact that carries its name.

The VM name is not a label: it is the identity. It names the libvirt domain
and appears in the disk filename, the AIVM-owned storage tree, the split
store fragment, the machine-state and bootstrap directory stems (through a
``<clean>-<sha256[:12]>`` encoding), the per-user cache, and the ``vm_name``
field of every attachment, credential, and principal record. Renaming is
therefore a coordinated move of all of them, not a field edit -- which is why
it cannot be a ``vm update`` drift dimension: ``update`` finds its subject
*by* name, so a changed name leaves it nothing to compare against.

Ordering is chosen so the desired-state store is written last. Every step
before it is a same-filesystem rename, so a failure part-way is undone by
moving the completed ones back, and the store still describes the VM the host
actually has. Once the store is saved the rename is committed.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import Store, load_store
from ..enrollment import bootstrap_identity_paths
from ..errors import AIVMError
from ..machine_store import machine_store_layout
from ..privilege import virsh_needs_sudo
from ..runtime import virsh_cmd
from ..scoped_store import StoreScope, save_scope_store
from .domain import _get_vm_state, vm_exists
from .paths import _paths

#: Libvirt accepts a wide range of domain names, but the name is also used as
#: a path component and a systemd unit suffix. Keep it to the intersection
#: that is safe in all three without escaping.
VM_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$')


class VMRenameError(AIVMError):
    """Raised when a rename cannot start or cannot be completed safely."""


def validate_vm_name(name: str) -> str:
    """Return the normalized new name or explain why it is unusable."""
    candidate = (name or '').strip()
    if not candidate:
        raise VMRenameError('New VM name must not be empty.')
    if not VM_NAME_PATTERN.match(candidate):
        raise VMRenameError(
            f'Invalid VM name {candidate!r}. Use 1-63 characters starting '
            'with a letter or digit, then letters, digits, underscore, dot, '
            'or hyphen. The name is also a path component and a systemd unit '
            'suffix, so it cannot contain anything needing escaping.'
        )
    return candidate


def _domain_is_running(name: str) -> bool:
    code, state, _err = _get_vm_state(name)
    if code != 0:
        return False
    return state.strip().lower() not in {'shut off', 'shutoff', ''}


def _persistent_replay_artifacts(cfg: AgentVMConfig) -> list[str]:
    """Return installed root-owned replay artifacts naming this VM.

    Both the approved manifest filename and the systemd unit embed the VM
    name, and both are written by root through the privileged replay path.
    Moving them is a different privilege story than moving AIVM-owned
    storage, so a rename refuses rather than silently leaving a root service
    pointed at a VM that no longer exists.
    """
    from ..attachments.persistent.manifest import (
        PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX,
        _persistent_host_replay_manifest_path,
    )

    found: list[str] = []
    manifest = _persistent_host_replay_manifest_path(cfg)
    if manifest.exists():
        found.append(str(manifest))
    unit = Path('/etc/systemd/system') / (
        f'{PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-'
        f'{cfg.vm.name}.service'
    )
    if unit.exists():
        found.append(str(unit))
    return found


def _rename_targets(
    cfg: AgentVMConfig, new_name: str
) -> list[tuple[Path, Path, str]]:
    """Return every (source, destination, label) filesystem move."""
    old_paths = _paths(cfg)
    new_cfg = replace(cfg, vm=replace(cfg.vm, name=new_name))
    new_paths = _paths(new_cfg)
    layout = machine_store_layout()
    old_boot = bootstrap_identity_paths(cfg.vm.name, layout=layout)
    new_boot = bootstrap_identity_paths(new_name, layout=layout)
    return [
        (
            old_paths['base_dir'],
            new_paths['base_dir'],
            'AIVM-managed VM storage',
        ),
        (
            old_paths['state_dir'],
            new_paths['state_dir'],
            'per-user VM cache',
        ),
        (
            layout.vm_state_dir(cfg.vm.name),
            layout.vm_state_dir(new_name),
            'machine VM state',
        ),
        (old_boot.directory, new_boot.directory, 'bootstrap identity'),
    ]


def preflight_rename(
    cfg: AgentVMConfig,
    reg: Store,
    new_name: str,
) -> None:
    """Refuse every condition a rename cannot handle, before any mutation.

    Each check runs before the first move so a rejected rename leaves the
    host exactly as it was.
    """
    old_name = cfg.vm.name
    if new_name == old_name:
        raise VMRenameError(
            f'VM is already named {new_name!r}; nothing to rename.'
        )
    if any(item.name == new_name for item in reg.vms):
        raise VMRenameError(
            f'The machine store already has a VM named {new_name!r}.'
        )
    if _domain_is_running(old_name):
        raise VMRenameError(
            f'VM {old_name!r} is running. Renaming moves the disk and '
            'redefines the domain, both of which require a shut-off VM. Run '
            f'`aivm vm down --vm {old_name}` first.'
        )
    code, _state, _err = _get_vm_state(new_name)
    if code == 0:
        raise VMRenameError(
            f'A libvirt domain named {new_name!r} already exists.'
        )
    blocking = _persistent_replay_artifacts(cfg)
    if blocking:
        raise VMRenameError(
            f'VM {old_name!r} has root-owned persistent host-bind replay '
            'artifacts that embed its name: '
            + ', '.join(blocking)
            + '. Detach its persistent attachments (`aivm vm detach`) so the '
            'manifest and unit are removed, then rename and reattach.'
        )
    for source, destination, label in _rename_targets(cfg, new_name):
        if destination.exists():
            raise VMRenameError(
                f'Rename destination for {label} already exists: {destination}'
            )
        if source.exists() and source.is_symlink():
            raise VMRenameError(
                f'Refusing to rename symlinked {label}: {source}'
            )
    # Mount enumeration authorizes moving the storage tree: renaming a
    # directory with live bind mounts underneath leaves the mount table
    # pointing at a path that no longer exists.
    from .deletion import _assert_no_mounts_below

    base_dir = _paths(cfg)['base_dir']
    if base_dir.exists():
        _assert_no_mounts_below(base_dir)


def _renamed_store(reg: Store, old_name: str, new_name: str) -> Store:
    """Return the store with every reference to ``old_name`` repointed.

    Principal ids are deliberately left alone. They are only *seeded* from
    ``(vm_name, host_user)`` and are treated as opaque afterwards, which is
    what lets ownership records survive an account rename; recomputing them
    here would orphan every attachment that already refers to one.
    """
    return replace(
        reg,
        active_vm=new_name if reg.active_vm == old_name else reg.active_vm,
        vms=[
            replace(item, name=new_name) if item.name == old_name else item
            for item in reg.vms
        ],
        attachments=[
            replace(item, vm_name=new_name)
            if item.vm_name == old_name
            else item
            for item in reg.attachments
        ],
        credentials=[
            replace(item, vm_name=new_name)
            if item.vm_name == old_name
            else item
            for item in reg.credentials
        ],
        principals=[
            replace(item, vm_name=new_name)
            if item.vm_name == old_name
            else item
            for item in reg.principals
        ],
    )


def _move(
    mgr: CommandManager, source: Path, destination: Path, label: str
) -> bool:
    """Move one artifact, returning whether anything was moved.

    ``run`` rather than ``submit``: the caller records each completed move so
    it can reverse them if a later step fails, and a queued command has not
    happened yet. Submitting would both defer the work past the point the
    rollback list is built and let an abandoned plan discard it silently.

    The move goes through the manager rather than :func:`os.rename` because
    the machine-store artifacts are root-owned -- the bootstrap directory is
    ``root:<group> 0750`` and the caller is an ordinary group member.
    """
    if not source.exists():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    mgr.run(
        ['mv', '--no-target-directory', str(source), str(destination)],
        sudo=_needs_root(source),
        role='modify',
        check=True,
        capture=True,
        summary=f'Move {label} to {destination.name}',
        detail=f'{source} -> {destination}',
    )
    return True


def _needs_root(path: Path) -> bool:
    """True when the artifact lives in the root-owned machine store."""
    layout = machine_store_layout()
    try:
        path.resolve().relative_to(layout.root.resolve())
    except ValueError:
        return False
    return True


def rename_managed_vm(
    scope: StoreScope,
    cfg: AgentVMConfig,
    cfg_path: Path,
    new_name: str,
    *,
    dry_run: bool = False,
) -> None:
    """Rename ``cfg.vm.name`` to ``new_name`` across every owned artifact."""
    new_name = validate_vm_name(new_name)
    old_name = cfg.vm.name
    reg = load_store(cfg_path)
    preflight_rename(cfg, reg, new_name)
    targets = _rename_targets(cfg, new_name)

    if dry_run:
        print(f'DRYRUN: rename VM {old_name} -> {new_name}')
        for source, destination, label in targets:
            if source.exists():
                print(f'DRYRUN: move {label}: {source} -> {destination}')
        print(f'DRYRUN: virsh domrename {old_name} {new_name}')
        print(f'DRYRUN: repoint domain XML storage paths at {new_name}')
        print(f'DRYRUN: rewrite store records naming {old_name}')
        return

    mgr = CommandManager.current()
    moved: list[tuple[Path, Path, str]] = []
    with mgr.intent(
        f'Rename VM {old_name} to {new_name}',
        why=(
            'The VM name identifies the domain, its storage tree, its '
            'machine state, and every store record that refers to it; all of '
            'them move together or the VM becomes unmanageable.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Move AIVM-owned artifacts to the new name',
            why='Storage and state directories are named after the VM.',
            approval_scope=f'vm-rename-artifacts:{old_name}',
        ):
            try:
                for source, destination, label in targets:
                    if _move(mgr, source, destination, label):
                        moved.append((source, destination, label))
            except Exception:
                _undo_moves(mgr, moved)
                raise

        try:
            with mgr.step(
                'Rename the libvirt domain and repoint its storage',
                why=(
                    'The domain name and the paths inside its XML both '
                    'carry the VM name.'
                ),
                approval_scope=f'vm-rename-domain:{old_name}',
            ):
                if vm_exists(cfg):
                    mgr.submit(
                        virsh_cmd('domrename', old_name, new_name),
                        sudo=virsh_needs_sudo(),
                        role='modify',
                        check=True,
                        capture=True,
                        summary=f'Rename domain {old_name} to {new_name}',
                    )
                    _repoint_domain_paths(mgr, cfg, new_name)
        except Exception:
            _undo_moves(mgr, moved)
            raise

    # The store is written last: until this succeeds the desired state still
    # names the VM the host had before the move.
    renamed = _renamed_store(reg, old_name, new_name)
    save_scope_store(
        scope,
        renamed,
        reason=(
            f'Rename VM {old_name} to {new_name} across VM, attachment, '
            'credential, and principal records.'
        ),
    )
    print(
        f'Renamed VM {old_name} -> {new_name}.\n'
        f"The guest's own hostname is still {old_name!r}. AIVM does not "
        'manage it after creation -- cloud-init applies `local-hostname` on '
        'first boot only -- so change it inside the guest if you want it to '
        f'match:\n    aivm vm ssh --vm {new_name} -- '
        f'sudo hostnamectl set-hostname {new_name}'
    )


def _undo_moves(
    mgr: CommandManager, moved: list[tuple[Path, Path, str]]
) -> None:
    """Move completed renames back after a later step failed.

    Best effort by construction: the store has not been written yet, so the
    host still matches the pre-rename desired state once these are restored.
    """
    for source, destination, label in reversed(moved):
        with mgr.attempt(
            f'Restore {label} after a failed rename',
            catch=Exception,
        ):
            # Immediate, for the same reason the forward move is: this runs
            # while an exception is unwinding, and a queued command would be
            # discarded with the abandoned plan instead of undoing anything.
            mgr.run(
                ['mv', '--no-target-directory', str(destination), str(source)],
                sudo=_needs_root(destination),
                role='modify',
                check=True,
                capture=True,
                summary=f'Restore {label} to {source.name}',
            )


def _repoint_domain_paths(
    mgr: CommandManager, cfg: AgentVMConfig, new_name: str
) -> None:
    """Rewrite disk and virtiofs source paths in the renamed domain XML."""
    import tempfile
    import xml.etree.ElementTree as ET

    old_base = str(_paths(cfg)['base_dir'])
    new_cfg = replace(cfg, vm=replace(cfg.vm, name=new_name))
    new_base = str(_paths(new_cfg)['base_dir'])
    result = mgr.run(
        virsh_cmd('dumpxml', new_name),
        sudo=virsh_needs_sudo(),
        check=True,
        capture=True,
        role='read',
        summary=f'Read domain XML for {new_name}',
    )
    root = ET.fromstring(result.stdout)
    touched = 0
    for disk in root.findall('./devices/disk/source'):
        current = disk.get('file') or ''
        if current.startswith(old_base):
            updated = current.replace(old_base, new_base, 1)
            # The disk file itself is named after the VM, not only its
            # directory.
            updated = updated.replace(
                f'/{cfg.vm.name}.qcow2', f'/{new_name}.qcow2'
            )
            disk.set('file', updated)
            touched += 1
    for share in root.findall('./devices/filesystem/source'):
        current = share.get('dir') or ''
        if current.startswith(old_base):
            share.set('dir', current.replace(old_base, new_base, 1))
            touched += 1
    if touched == 0:
        return
    with tempfile.NamedTemporaryFile(
        'w', delete=False, suffix='.xml', prefix=f'aivm-{new_name}-'
    ) as handle:
        handle.write(ET.tostring(root, encoding='unicode'))
        tmp = handle.name
    mgr.submit(
        virsh_cmd('define', tmp),
        sudo=virsh_needs_sudo(),
        role='modify',
        check=True,
        capture=True,
        summary=f'Repoint {touched} storage path(s) in {new_name}',
    )
