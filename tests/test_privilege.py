"""Tests for privilege modes, capability probes, and sudoless enforcement."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.errors import SudolessModeError
from aivm.privilege import (
    file_write_needs_sudo,
    normalize_privilege_mode,
    path_needs_sudo,
    qemu_traversal_blockers,
    user_can_write_file,
    user_can_write_path,
    virsh_needs_sudo,
)

# Captured at import time, before the conftest fixture pins the module
# attribute, so the real probe body stays testable.
from aivm.privilege import libvirt_unprivileged_ok as _real_libvirt_probe
from tests.helpers import FakeProc


def _activate(mode: str, **kw: Any) -> CommandManager:
    mgr = CommandManager(privilege_mode=mode, **kw)
    CommandManager.activate(mgr)
    return mgr


def test_normalize_privilege_mode() -> None:
    assert normalize_privilege_mode('sudo') == 'sudo'
    assert normalize_privilege_mode(' SUDOLESS ') == 'sudoless'
    assert normalize_privilege_mode('') == 'auto'
    assert normalize_privilege_mode(None) == 'auto'
    assert normalize_privilege_mode('bogus') == 'auto'


def test_virsh_needs_sudo_per_mode(monkeypatch: MonkeyPatch) -> None:
    _activate('sudo')
    assert virsh_needs_sudo() is True
    _activate('sudoless')
    assert virsh_needs_sudo() is False
    # auto consults the capability probe (pinned False by conftest)
    _activate('auto')
    assert virsh_needs_sudo() is True
    monkeypatch.setattr(
        'aivm.privilege.libvirt_unprivileged_ok', lambda: True
    )
    assert virsh_needs_sudo() is False


def test_libvirt_probe_is_cached_per_manager(monkeypatch: MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        calls.append(list(cmd))
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: 1000)
    _activate('auto', yes=True)
    assert _real_libvirt_probe() is True
    assert _real_libvirt_probe() is True
    assert len(calls) == 1
    assert calls[0][:3] == ['virsh', '-c', 'qemu:///system']


def test_path_privilege_decisions(tmp_path: Path) -> None:
    _activate('auto')
    writable = tmp_path / 'mine' / 'deep' / 'file.img'
    assert user_can_write_path(writable) is True
    assert path_needs_sudo(writable) is False
    root_only = Path('/proc/1/root/nope')
    assert user_can_write_path(root_only) is False
    assert path_needs_sudo(root_only) is True
    _activate('sudo')
    assert path_needs_sudo(writable) is True
    _activate('sudoless')
    assert path_needs_sudo(root_only) is False


def test_file_write_privilege_decisions(tmp_path: Path) -> None:
    _activate('auto')
    locked = tmp_path / 'root-owned.qcow2'
    locked.write_bytes(b'')
    locked.chmod(0o444)
    # The parent directory is writable, so the directory-based predicate
    # says no sudo — but an in-place write to the file itself must escalate.
    assert path_needs_sudo(locked) is False
    assert user_can_write_file(locked) is False
    assert file_write_needs_sudo(locked) is True
    writable = tmp_path / 'mine.qcow2'
    writable.write_bytes(b'')
    assert user_can_write_file(writable) is True
    assert file_write_needs_sudo(writable) is False
    # A missing target falls back to the directory-based check.
    missing = tmp_path / 'not-yet.qcow2'
    assert file_write_needs_sudo(missing) is False
    _activate('sudo')
    assert file_write_needs_sudo(writable) is True
    _activate('sudoless')
    assert file_write_needs_sudo(locked) is False


def test_sudoless_manager_rejects_sudo_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: 1000)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kw: FakeProc(0, 'ok', ''),
    )
    mgr = _activate('sudoless', yes=True)
    res = mgr.run(['true'], sudo=False, check=False)
    assert res.code == 0
    with pytest.raises(SudolessModeError, match='sudoless'):
        mgr.run(['whoami'], sudo=True, role='read', check=False)
    with pytest.raises(SudolessModeError):
        mgr.confirm_sudo_scope(purpose='test escalation', role='modify')


def test_attachment_resolution_is_privilege_mode_independent(
    tmp_path: Path,
) -> None:
    """Resolving a bind-mount attachment mode issues no privileged command.

    Whether the mode needs root is decided per command at execution time
    (an established bind mount needs none), so resolution must not refuse
    a mode up front.
    """
    from aivm.attachments.resolve import _resolve_attachment

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-sudoless'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    for mode in ('sudoless', 'auto', 'sudo'):
        _activate(mode)
        att = _resolve_attachment(cfg, cfg_path, host_src, '', '', '')
        assert str(att.mode) == 'persistent'
        for requested in ('persistent', 'shared-root'):
            att = _resolve_attachment(cfg, cfg_path, host_src, '', requested, '')
            assert str(att.mode) == requested


def test_existence_probe_distinguishes_absent_from_unknown(
    tmp_path: Path,
) -> None:
    """An unreadable path is unknown, not absent.

    Reporting absence would license callers to create over existing state.
    """
    from aivm.vm.host_access import _sudo_file_exists, _sudo_path_exists

    if os.geteuid() == 0:
        pytest.skip('root can stat through any directory')
    _activate('sudoless')

    present = tmp_path / 'here.qcow2'
    present.write_bytes(b'')
    assert _sudo_path_exists(present) is True
    assert _sudo_file_exists(present) is True
    assert _sudo_path_exists(tmp_path / 'absent.qcow2') is False
    assert _sudo_file_exists(tmp_path / 'absent.qcow2') is False

    # A real EACCES: the file exists but no ancestor grants traversal, and
    # sudoless forbids the privileged probe that would settle it.
    locked = tmp_path / 'locked'
    locked.mkdir()
    hidden = locked / 'disk.qcow2'
    hidden.write_bytes(b'')
    locked.chmod(0o000)
    try:
        assert _sudo_path_exists(hidden) is None
        assert _sudo_file_exists(hidden) is None
    finally:
        locked.chmod(0o700)


def test_ensure_disk_refuses_to_create_over_unknown_state(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.vm.disk import _ensure_disk

    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path)
    _activate('sudoless', yes=True)
    monkeypatch.setattr('aivm.vm.disk._sudo_path_exists', lambda p: None)
    ran: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        ran.append([str(c) for c in cmd])
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    with pytest.raises(SudolessModeError, match='Cannot determine'):
        _ensure_disk(cfg, tmp_path / 'base.img')
    assert not any('qemu-img' in c for cmd in ran for c in cmd)


def test_fetch_image_refuses_to_redownload_over_unknown_state(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.vm.images import fetch_image

    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path)
    _activate('sudoless', yes=True)
    monkeypatch.setattr('aivm.vm.images._sudo_file_exists', lambda p: None)
    monkeypatch.setattr(
        'aivm.vm.images._ensure_qemu_access', lambda *a, **k: None
    )
    # Belt and braces: an unknown cached image must not reach `curl`, so a
    # regression here fails the assertion rather than downloading 600MB.
    def fail_on_exec(cmd: list[str], **kwargs: Any) -> FakeProc:
        raise AssertionError(f'ran a command for an unknown image: {cmd}')

    monkeypatch.setattr('aivm.commands.subprocess.run', fail_on_exec)
    with pytest.raises(SudolessModeError, match='Cannot determine'):
        fetch_image(cfg)


def test_sudoless_firewall_degradation() -> None:
    from aivm.firewall import apply_firewall, read_firewall_tcp_ports
    from aivm.status import probe_firewall

    cfg = AgentVMConfig()
    cfg.firewall.enabled = True
    _activate('sudoless')
    out = probe_firewall(cfg, use_sudo=True)
    assert out.ok is None
    assert 'sudoless' in out.detail
    ports, err = read_firewall_tcp_ports(cfg, use_sudo=True)
    assert ports is None
    assert 'sudoless' in err
    with pytest.raises(SudolessModeError, match='nftables'):
        apply_firewall(cfg, dry_run=False)


def test_qemu_traversal_blockers(tmp_path: Path) -> None:
    import pwd

    try:
        pwd.getpwnam('libvirt-qemu')
    except KeyError:
        pytest.skip('libvirt-qemu user not present on this host')
    if os.geteuid() == 0:
        pytest.skip('root bypasses directory permission checks')
    _activate('auto')
    locked = tmp_path / 'locked'
    inner = locked / 'store'
    inner.mkdir(parents=True)
    locked.chmod(0o700)
    inner.chmod(0o700)
    blockers = qemu_traversal_blockers(inner)
    assert blockers is not None
    assert locked in blockers and inner in blockers
    locked.chmod(0o711)
    inner.chmod(0o711)
    blockers = qemu_traversal_blockers(inner)
    assert blockers is not None
    assert locked not in blockers and inner not in blockers
