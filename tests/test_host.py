"""Tests for ``aivm.host`` command-presence checks and dependency install."""

from __future__ import annotations

from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.errors import AIVMError
from aivm.host import (
    HostCapability,
    MachineStoreAuthorityPreparation,
    check_commands,
    check_commands_with_sudo,
    ensure_host_capability,
    host_is_debian_like,
    install_deps_debian,
    prepare_machine_store_authority,
    require_machine_store_session_access,
    required_commands,
    require_host_capability,
)
from aivm.util import CmdResult
from tests.helpers import FakeProc, activate_manager


def test_check_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    present = {'virsh', 'qemu-img', 'curl', 'ssh', 'nft'}
    monkeypatch.setattr(
        'aivm.host.which',
        lambda cmd: f'/usr/bin/{cmd}' if cmd in present else None,
    )
    missing, missing_opt = check_commands()
    assert 'virt-install' in missing
    assert 'cloud-localds' in missing
    assert 'nft' not in missing_opt


def test_named_host_capabilities_keep_libvirt_probe_minimal() -> None:
    assert required_commands(HostCapability.LIBVIRT_CLIENT) == ['virsh']
    assert 'virsh' in required_commands(HostCapability.VM_LIFECYCLE)
    assert 'virt-install' in required_commands(HostCapability.VM_LIFECYCLE)


def test_require_host_capability_reports_actionable_missing_command(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.host.which', lambda cmd: None)
    with pytest.raises(AIVMError, match='libvirt-client.*virsh'):
        require_host_capability(HostCapability.LIBVIRT_CLIENT)


def test_ensure_host_capability_yes_installs_without_prompt(
    monkeypatch: MonkeyPatch,
) -> None:
    installed = False
    prompted = False

    def fake_which(cmd: str) -> str | None:
        if installed:
            return f'/usr/bin/{cmd}'
        return None

    def fake_install(*, assume_yes: bool = True) -> None:
        nonlocal installed
        assert assume_yes is True
        installed = True

    def fail_prompt(prompt: str = '') -> str:
        nonlocal prompted
        prompted = True
        raise AssertionError(f'--yes must not prompt: {prompt}')

    monkeypatch.setattr('aivm.host.which', fake_which)
    monkeypatch.setattr('aivm.host.host_is_debian_like', lambda: True)
    monkeypatch.setattr('aivm.host.install_deps_debian', fake_install)
    monkeypatch.setattr('builtins.input', fail_prompt)

    ensure_host_capability(
        HostCapability.VM_LIFECYCLE, yes=True, dry_run=False
    )

    assert installed is True
    assert prompted is False


def test_machine_store_authority_distinguishes_configured_from_active_session(
    monkeypatch: MonkeyPatch,
) -> None:
    from aivm.host_identity import current_host_identity
    from aivm.machine_store import MachineStoreSessionRefreshRequired

    activate_manager(monkeypatch, yes=True)
    user = current_host_identity().username
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)
    monkeypatch.setattr('aivm.host.machine_group_exists', lambda name: True)
    monkeypatch.setattr(
        'aivm.host.user_has_machine_group_membership',
        lambda selected, group_name=None: True,
    )
    monkeypatch.setattr(
        'aivm.host.current_process_has_machine_group',
        lambda group_name=None: False,
    )

    preparation = prepare_machine_store_authority(user=user, dry_run=True)

    assert isinstance(preparation, MachineStoreAuthorityPreparation)
    assert preparation.membership_added is False
    assert preparation.membership_configured is True
    assert preparation.session_membership_active is False
    assert preparation.requires_session_refresh
    with pytest.raises(
        MachineStoreSessionRefreshRequired, match='kernel credentials'
    ):
        require_machine_store_session_access(preparation)


def test_check_commands_with_sudo(
    monkeypatch: MonkeyPatch,
) -> None:
    calls = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        calls.append(cmd)
        if cmd[:3] == ['sudo', '-n', 'true']:
            return CmdResult(0, '', '')
        if 'virt-install' in cmd[-1]:
            return CmdResult(1, '', '')
        return CmdResult(0, '/usr/bin/whatever\n', '')

    monkeypatch.setattr('aivm.host.CommandManager.run', fake_run_cmd)
    missing, err = check_commands_with_sudo()
    assert err is None
    assert 'virt-install' in missing
    assert calls[0][:3] == ['sudo', '-n', 'true']


def test_check_commands_with_sudo_no_passwordless(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.host.CommandManager.run',
        lambda self, cmd, **kwargs: CmdResult(
            1, '', 'sudo: a password is required'
        ),
    )
    missing, err = check_commands_with_sudo()
    assert missing == []
    assert err is not None
    assert 'sudo -n' in err


def test_host_is_debian_like(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.host.Path.read_text',
        lambda self, encoding='utf-8': 'ID=ubuntu\nID_LIKE=debian\n',
    )
    assert host_is_debian_like() is True
    monkeypatch.setattr(
        'aivm.host.Path.read_text',
        lambda self, encoding='utf-8': 'ID=fedora\nID_LIKE=rhel\n',
    )
    assert host_is_debian_like() is False


def test_install_deps_debian_behaviors(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.host.host_is_debian_like', lambda: False)
    with pytest.raises(RuntimeError):
        install_deps_debian()

    calls = []
    monkeypatch.setattr('aivm.host.host_is_debian_like', lambda: True)
    activate_manager(monkeypatch, isatty=True)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append((cmd, kwargs)) or FakeProc(),
    )
    install_deps_debian()
    assert calls[0][0][:5] == [
        'sudo',
        'env',
        'DEBIAN_FRONTEND=noninteractive',
        'NEEDRESTART_MODE=a',
        'apt-get',
    ]
    assert calls[0][0][5] == 'update'
    assert calls[1][0][:5] == [
        'sudo',
        'env',
        'DEBIAN_FRONTEND=noninteractive',
        'NEEDRESTART_MODE=a',
        'apt-get',
    ]
    assert calls[1][0][5] == 'install'
    assert calls[2][0][:5] == [
        'sudo',
        'env',
        'DEBIAN_FRONTEND=noninteractive',
        'NEEDRESTART_MODE=a',
        'apt-get',
    ]
    assert calls[2][0][5] == 'install'
    assert calls[2][0][-1] == 'virtiofsd'
    assert calls[3][0][:4] == ['sudo', 'systemctl', 'enable', '--now']
    assert calls[0][1]['capture_output'] is False
    assert calls[1][1]['capture_output'] is False


def test_install_deps_debian_reports_apt_lock_cleanly(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.host.host_is_debian_like', lambda: True)
    activate_manager(monkeypatch, isatty=True)

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        if cmd[-2:] == ['update', '-y']:
            return FakeProc(
                returncode=100,
                stderr='E: Could not get lock /var/lib/dpkg/lock-frontend. '
                'It is held by process 1234',
            )
        return FakeProc(returncode=100)

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    with pytest.raises(RuntimeError, match='apt/dpkg appears to be locked'):
        install_deps_debian()
