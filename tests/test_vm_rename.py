"""Coverage for renaming a managed VM across every artifact naming it."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.config_store import load_store
from aivm.scoped_store import StoreScope, resolve_store_scope
from aivm.services import load_cfg
from aivm.vm.rename import (
    VMRenameError,
    rename_managed_vm,
    validate_vm_name,
)
from tests.helpers import FakeProc, activate_manager, command_recorder


def _scope_and_cfg(cfg_path: Path) -> tuple[StoreScope, AgentVMConfig]:
    return resolve_store_scope(str(cfg_path)), load_cfg(str(cfg_path))


def _shutoff_routes(old: str, new: str) -> dict[object, object]:
    """Routes for a shut-off ``old`` and an absent ``new``."""
    return {
        ('virsh', 'domstate', old): FakeProc(0, 'shut off\n', ''),
        ('virsh', 'domstate', new): FakeProc(1, '', 'not found'),
        ('virsh', 'dominfo', old): FakeProc(0, 'Name: ' + old, ''),
        ('virsh', 'domrename', old, new): FakeProc(0, '', ''),
        ('virsh', 'dumpxml', new): FakeProc(0, '<domain/>', ''),
    }


@pytest.mark.parametrize(
    'name',
    [
        pytest.param('', id='empty'),
        pytest.param('-leading-hyphen', id='leading_hyphen'),
        pytest.param('has space', id='space'),
        pytest.param('has/slash', id='slash'),
        pytest.param('x' * 64, id='too_long'),
    ],
)
def test_invalid_new_names_are_refused(name: str) -> None:
    """The name becomes a path component and a unit suffix; keep it safe."""
    with pytest.raises(VMRenameError):
        validate_vm_name(name)


def test_rename_repoints_every_store_record(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """A rename must move VM, attachment, and principal references together.

    A record left naming the old VM is orphaned: nothing resolves it, and the
    VM it belongs to no longer exists under that name.
    """
    activate_manager(monkeypatch, yes=True)
    rec = command_recorder(
        monkeypatch,
        _shutoff_routes('test-vm', 'renamed-vm'),
        default=FakeProc(0, '', ''),
    )
    scope, cfg = _scope_and_cfg(cfg_path)

    rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')

    reg = load_store(cfg_path)
    assert [item.name for item in reg.vms] == ['renamed-vm']
    assert all(item.vm_name == 'renamed-vm' for item in reg.attachments)
    assert all(item.vm_name == 'renamed-vm' for item in reg.principals)
    assert all(item.vm_name == 'renamed-vm' for item in reg.credentials)
    assert 'domrename test-vm renamed-vm' in ' '.join(
        ' '.join(cmd) for cmd in rec.normalized
    )


def test_rename_refuses_a_running_vm(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """Moving the disk and redefining the domain both need a shut-off VM."""
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        {
            ('virsh', 'domstate', 'test-vm'): FakeProc(0, 'running\n', ''),
        },
        default=FakeProc(0, '', ''),
    )
    scope, cfg = _scope_and_cfg(cfg_path)

    with pytest.raises(VMRenameError, match='is running'):
        rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')

    # Refusal happens before the first move, so the store is untouched.
    assert [item.name for item in load_store(cfg_path).vms] == ['test-vm']


def test_rename_refuses_when_the_target_name_is_taken(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """Two VMs sharing a name would make the store ambiguous."""
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        _shutoff_routes('test-vm', 'other-vm'),
        default=FakeProc(0, '', ''),
    )
    scope, cfg = _scope_and_cfg(cfg_path)
    reg = load_store(cfg_path)
    from dataclasses import replace as dc_replace

    from aivm.config_store import save_store

    save_store(
        dc_replace(
            reg, vms=[*reg.vms, dc_replace(reg.vms[0], name='other-vm')]
        ),
        cfg_path,
        reason='second VM for collision test',
    )
    _scope, cfg = _scope_and_cfg(cfg_path)

    with pytest.raises(VMRenameError, match='already has a VM named'):
        rename_managed_vm(scope, cfg, cfg_path, 'other-vm')


def test_rename_refuses_while_root_owned_replay_artifacts_exist(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """The replay manifest and unit embed the name and are root's to move."""
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch,
        _shutoff_routes('test-vm', 'renamed-vm'),
        default=FakeProc(0, '', ''),
    )
    scope, cfg = _scope_and_cfg(cfg_path)
    manifest = tmp_path / 'persistent-host' / 'test-vm-deadbeef00.json'
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text('{}')
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest.'
        '_persistent_host_replay_manifest_path',
        lambda cfg: manifest,
    )

    with pytest.raises(VMRenameError, match='persistent host-bind replay'):
        rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')


def test_rename_moves_the_storage_tree(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """The disk lives under a directory named for the VM."""
    activate_manager(monkeypatch, yes=True)
    rec = command_recorder(
        monkeypatch,
        _shutoff_routes('test-vm', 'renamed-vm'),
        default=FakeProc(0, '', ''),
    )
    scope, cfg = _scope_and_cfg(cfg_path)
    base = Path(cfg.paths.base_dir) / 'test-vm'
    (base / 'images').mkdir(parents=True, exist_ok=True)
    (base / 'images' / 'test-vm.qcow2').write_text('disk')

    rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')

    moves = [cmd for cmd in rec.normalized if cmd and cmd[0] == 'mv']
    assert any(str(base) in ' '.join(cmd) for cmd in moves)


def test_domain_xml_storage_paths_follow_the_rename(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """Both the directory and the disk filename carry the VM name.

    Repointing only the directory leaves the domain pointed at
    ``.../renamed-vm/images/test-vm.qcow2``, which no longer exists.
    """
    activate_manager(monkeypatch, yes=True)
    scope, cfg = _scope_and_cfg(cfg_path)
    base = Path(cfg.paths.base_dir) / 'test-vm'
    xml = (
        '<domain>'
        '<devices>'
        f'<disk><source file="{base}/images/test-vm.qcow2"/></disk>'
        f'<filesystem><source dir="{base}/shared-root"/></filesystem>'
        '</devices>'
        '</domain>'
    )
    routes = dict(_shutoff_routes('test-vm', 'renamed-vm'))
    routes[('virsh', 'dumpxml', 'renamed-vm')] = FakeProc(0, xml, '')
    rec = command_recorder(monkeypatch, routes, default=FakeProc(0, '', ''))

    rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')

    define = [cmd for cmd in rec.normalized if 'define' in cmd]
    assert define, 'a repointed domain must be redefined'
    written = Path(define[0][-1]).read_text(encoding='utf-8')
    assert 'renamed-vm/images/renamed-vm.qcow2' in written
    assert 'renamed-vm/shared-root' in written
    assert 'test-vm' not in written


def test_a_failed_domain_step_restores_the_moved_artifacts(
    tmp_path: Path, monkeypatch: MonkeyPatch, cfg_path: Path
) -> None:
    """The store is written last, so a mid-rename failure must be undone.

    Leaving storage at the new name while the store still says the old one
    would make the VM unresolvable from either direction.
    """
    activate_manager(monkeypatch, yes=True)
    routes = dict(_shutoff_routes('test-vm', 'renamed-vm'))
    routes[('virsh', 'domrename', 'test-vm', 'renamed-vm')] = FakeProc(
        1, '', 'domrename failed'
    )
    rec = command_recorder(monkeypatch, routes, default=FakeProc(0, '', ''))
    scope, cfg = _scope_and_cfg(cfg_path)
    base = Path(cfg.paths.base_dir) / 'test-vm'
    (base / 'images').mkdir(parents=True, exist_ok=True)

    with pytest.raises(Exception):
        rename_managed_vm(scope, cfg, cfg_path, 'renamed-vm')

    moves = [cmd for cmd in rec.normalized if cmd and cmd[0] == 'mv']
    forward = [c for c in moves if c[-1].endswith('renamed-vm')]
    backward = [c for c in moves if c[-1].endswith('test-vm')]
    assert forward and backward, 'each completed move must be reversed'
    assert [item.name for item in load_store(cfg_path).vms] == ['test-vm']
