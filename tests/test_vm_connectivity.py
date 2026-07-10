"""Guest reachability helpers: MAC lookup, cached IP, and SSH probing.

Covers ``aivm.vm.connectivity``: parsing the guest MAC out of
``virsh domiflist`` (through both the planned and the step-wrapped code
paths), reading a cached lease IP off disk, and the retry/fail-fast
policy ``wait_for_ssh`` applies while a freshly booted guest comes up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.util import CmdResult
from aivm.vm import get_ip_cached, wait_for_ssh
from aivm.vm.connectivity import _mac_for_vm
from tests.helpers import FakeProc, activate_manager, command_recorder

_DOMIFLIST = (
    ' Interface   Type      Source     Model    MAC\n'
    '---------------------------------------------------------------\n'
    ' vnet0       network   default    virtio   52:54:00:12:34:56\n'
)


def test_mac_for_vm_parsing(monkeypatch: MonkeyPatch) -> None:
    """The guest MAC is read out of the ``virsh domiflist`` table."""
    monkeypatch.setattr(
        'aivm.vm.lifecycle.CommandManager.run',
        lambda self, *a, **k: CmdResult(0, _DOMIFLIST, ''),
    )
    monkeypatch.setattr(
        'aivm.vm.lifecycle.CommandManager.current_plan',
        lambda self: object(),
    )
    cfg = AgentVMConfig()
    assert _mac_for_vm(cfg) == '52:54:00:12:34:56'


def test_mac_for_vm_uses_step_when_ungrouped(monkeypatch: MonkeyPatch) -> None:
    """Outside a plan, the MAC probe runs under a named step."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-mac'
    activate_manager(monkeypatch)

    step_titles: list[str] = []
    orig_step = CommandManager.step

    def track_step(self: Any, title: str, **kwargs: Any) -> Any:
        step_titles.append(title)
        return orig_step(self, title, **kwargs)

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.step', track_step)
    command_recorder(
        monkeypatch, {'virsh domiflist': FakeProc(0, _DOMIFLIST, '')}
    )

    assert _mac_for_vm(cfg) == '52:54:00:12:34:56'
    assert step_titles == ['Inspect VM network interfaces']


def test_get_ip_cached(tmp_path: Path) -> None:
    """A cached lease IP is read back from the VM state directory."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.state_dir = str(tmp_path)
    ip_dir = tmp_path / 'vmx'
    ip_dir.mkdir()
    (ip_dir / 'vmx.ip').write_text('10.77.0.123\n', encoding='utf-8')
    assert get_ip_cached(cfg) == '10.77.0.123'


def test_wait_for_ssh_uses_generous_probe_timeout(
    monkeypatch: MonkeyPatch,
) -> None:
    """Each SSH probe is bounded by a generous per-attempt timeout."""
    cfg = AgentVMConfig()
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    timeouts: list[int | None] = []
    calls = {'n': 0}

    monkeypatch.setattr(
        'aivm.vm.connectivity.require_ssh_identity',
        lambda p: p or '/tmp/id_ed25519',
    )
    monkeypatch.setattr(
        'aivm.vm.connectivity.ssh_base_args',
        lambda *a, **k: ['-i', '/tmp/id_ed25519'],
    )
    monkeypatch.setattr('aivm.vm.connectivity.time.sleep', lambda s: None)

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del cmd
        calls['n'] += 1
        timeouts.append(kwargs.get('timeout'))
        if calls['n'] == 1:
            return CmdResult(124, '', 'command timed out')
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    wait_for_ssh(cfg, '10.0.0.2', timeout_s=60, dry_run=False)
    assert calls['n'] == 2
    assert all(timeout == 30 for timeout in timeouts)


def test_wait_for_ssh_fails_fast_on_host_key_mismatch(
    monkeypatch: MonkeyPatch,
) -> None:
    """A changed host key aborts immediately instead of retrying."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    calls = {'n': 0}

    monkeypatch.setattr(
        'aivm.vm.connectivity.require_ssh_identity',
        lambda p: p or '/tmp/id_ed25519',
    )
    monkeypatch.setattr(
        'aivm.vm.connectivity.ssh_base_args',
        lambda *a, **k: ['-i', '/tmp/id_ed25519'],
    )
    monkeypatch.setattr('aivm.vm.connectivity.time.sleep', lambda s: None)

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del self, cmd, kwargs
        calls['n'] += 1
        return CmdResult(
            255,
            '',
            (
                '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n'
                '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n'
                '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n'
                'Offending ED25519 key in /home/user/.ssh/known_hosts:42\n'
                'Host key verification failed.\n'
            ),
        )

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)

    with pytest.raises(RuntimeError, match='SSH host key mismatch'):
        wait_for_ssh(cfg, '10.77.0.195', timeout_s=60, dry_run=False)

    assert calls['n'] == 1


def test_wait_for_ssh_retries_transient_startup_errors(
    monkeypatch: MonkeyPatch,
) -> None:
    """Connection-refused and timeout errors are retried until SSH is up."""
    cfg = AgentVMConfig()
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    calls = {'n': 0}

    monkeypatch.setattr(
        'aivm.vm.connectivity.require_ssh_identity',
        lambda p: p or '/tmp/id_ed25519',
    )
    monkeypatch.setattr(
        'aivm.vm.connectivity.ssh_base_args',
        lambda *a, **k: ['-i', '/tmp/id_ed25519'],
    )
    monkeypatch.setattr('aivm.vm.connectivity.time.sleep', lambda s: None)

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del self, cmd, kwargs
        calls['n'] += 1
        if calls['n'] == 1:
            return CmdResult(
                255,
                '',
                'ssh: connect to host 10.0.0.2 port 22: Connection refused',
            )
        if calls['n'] == 2:
            return CmdResult(124, '', 'command timed out')
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)

    wait_for_ssh(cfg, '10.0.0.2', timeout_s=60, dry_run=False)
    assert calls['n'] == 3
