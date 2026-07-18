"""Power-state transitions for ``shutdown_vm`` and ``restart_vm``.

These exercise the graceful shutdown and restart flows in
``aivm.vm.domain``: how each reacts to the VM's initial libvirt state
(running, stopped, or ``pmsuspended``), that dry runs stay inert, and
that libvirt failures surface as clear ``RuntimeError`` messages.
"""

from __future__ import annotations

from typing import Callable

import pytest
from pytest import MonkeyPatch

from aivm.vm import restart_vm, shutdown_vm
from tests.helpers import (
    FakeProc,
    activate_manager,
    command_recorder,
    make_cfg,
)


def _domstate_route(states: list[str]) -> Callable[[list[str]], FakeProc]:
    """Reply to successive ``virsh domstate`` calls with ``states``.

    The last entry is repeated once the script is exhausted, which lets a
    flow poll ``domstate`` as many times as it likes after the VM settles.
    """
    seq = list(states)
    idx = {'n': 0}

    def route(cmd: list[str]) -> FakeProc:
        del cmd
        state = seq[min(idx['n'], len(seq) - 1)]
        idx['n'] += 1
        return FakeProc(0, f'{state}\n', '')

    return route


@pytest.mark.parametrize(
    ('name', 'states', 'extra_routes', 'expected'),
    [
        pytest.param(
            'vm-shutdown-test',
            ['running'],
            {'virsh shutdown': FakeProc(0)},
            [
                ['virsh', 'domstate', 'vm-shutdown-test'],
                ['virsh', 'shutdown', 'vm-shutdown-test'],
            ],
            id='when_running_sends_shutdown_signal',
        ),
        pytest.param(
            'vm-shutdown-off',
            ['shut off'],
            {},
            [['virsh', 'domstate', 'vm-shutdown-off']],
            id='when_not_running_does_nothing',
        ),
        pytest.param(
            'vm-shutdown-pmsuspended',
            ['pmsuspended', 'running'],
            {'virsh resume': FakeProc(0), 'virsh shutdown': FakeProc(0)},
            [
                ['virsh', 'domstate', 'vm-shutdown-pmsuspended'],
                ['virsh', 'resume', 'vm-shutdown-pmsuspended'],
                ['virsh', 'domstate', 'vm-shutdown-pmsuspended'],
                ['virsh', 'domstate', 'vm-shutdown-pmsuspended'],
                ['virsh', 'shutdown', 'vm-shutdown-pmsuspended'],
            ],
            id='when_pmsuspended_resumes_first',
        ),
    ],
)
def test_shutdown_vm(
    monkeypatch: MonkeyPatch,
    name: str,
    states: list[str],
    extra_routes: dict[str, FakeProc],
    expected: list[list[str]],
) -> None:
    """shutdown_vm acts on the VM's initial power state.

    A running VM gets an ACPI shutdown signal; a stopped VM is left alone
    after the single state probe; a ``pmsuspended`` VM is resumed first so
    it can receive the signal, then shut down.
    """
    cfg = make_cfg(None, **{'vm.name': name})
    activate_manager(monkeypatch)
    routes: dict[str, object] = {'virsh domstate': _domstate_route(states)}
    routes.update(extra_routes)
    rec = command_recorder(monkeypatch, routes)

    shutdown_vm(cfg, dry_run=False)

    assert rec.normalized == expected


def test_shutdown_vm_dry_run(monkeypatch: MonkeyPatch) -> None:
    """Test that shutdown_vm does nothing in dry-run mode."""
    cfg = make_cfg(None, **{'vm.name': 'vm-shutdown-dry'})
    activate_manager(monkeypatch)
    rec = command_recorder(monkeypatch, {})

    shutdown_vm(cfg, dry_run=True)

    assert rec.calls == []


@pytest.mark.parametrize(
    ('name', 'routes', 'match'),
    [
        pytest.param(
            'vm-shutdown-fail',
            {
                'virsh domstate': FakeProc(0, 'running\n', ''),
                'virsh shutdown': FakeProc(
                    1, '', 'error: failed to shut down domain'
                ),
            },
            'Failed to send shutdown signal',
            id='raises_on_shutdown_failure',
        ),
        pytest.param(
            'vm-shutdown-badstate',
            {'virsh domstate': FakeProc(1, '', 'error: domain is not found')},
            'domain is not found',
            id='raises_with_stderr_error_message',
        ),
    ],
)
def test_shutdown_vm_error(
    monkeypatch: MonkeyPatch,
    name: str,
    routes: dict[str, FakeProc],
    match: str,
) -> None:
    """shutdown_vm surfaces libvirt failures as ``RuntimeError``.

    A failed ``virsh shutdown`` is reported as a shutdown-signal failure,
    and a failing state probe forwards the stderr text to the caller.
    """
    cfg = make_cfg(None, **{'vm.name': name})
    activate_manager(monkeypatch)
    command_recorder(monkeypatch, routes)

    with pytest.raises(RuntimeError, match=match):
        shutdown_vm(cfg, dry_run=False)


@pytest.mark.parametrize(
    ('name', 'states', 'present', 'absent'),
    [
        pytest.param(
            'vm-restart-test',
            ['running'],
            [
                ['virsh', 'domstate', 'vm-restart-test'],
                ['virsh', 'shutdown', 'vm-restart-test'],
                ['virsh', 'start', 'vm-restart-test'],
            ],
            [],
            id='when_running_shutdowns_then_starts',
        ),
        pytest.param(
            'vm-restart-pmsuspended',
            ['pmsuspended', 'running'],
            [
                ['virsh', 'resume', 'vm-restart-pmsuspended'],
                ['virsh', 'shutdown', 'vm-restart-pmsuspended'],
                ['virsh', 'start', 'vm-restart-pmsuspended'],
            ],
            [],
            id='when_pmsuspended_resumes_then_shutsdown',
        ),
        pytest.param(
            'vm-restart-off',
            ['shut off'],
            [
                ['virsh', 'domstate', 'vm-restart-off'],
                ['virsh', 'start', 'vm-restart-off'],
            ],
            [['virsh', 'shutdown', 'vm-restart-off']],
            id='when_not_running_just_starts',
        ),
    ],
)
def test_restart_vm(
    monkeypatch: MonkeyPatch,
    name: str,
    states: list[str],
    present: list[list[str]],
    absent: list[list[str]],
) -> None:
    """restart_vm stops (if needed) then starts, driven by initial state.

    A running VM is shut down and started; a ``pmsuspended`` VM is resumed
    before the shutdown/start cycle; a stopped VM is started with no
    shutdown signal at all.
    """
    cfg = make_cfg(None, **{'vm.name': name})
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda n: True)
    monkeypatch.setattr(
        'aivm.vm.domain._wait_for_vm_state', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.vm.domain._wait_for_vm_not_state', lambda *a, **k: None
    )
    routes: dict[str, object] = {
        'virsh domstate': _domstate_route(states),
        'virsh resume': FakeProc(0),
        'virsh shutdown': FakeProc(0),
        'virsh start': FakeProc(0),
    }
    rec = command_recorder(monkeypatch, routes)

    restart_vm(cfg, dry_run=False)

    for cmd in present:
        assert cmd in rec.normalized
    for cmd in absent:
        assert cmd not in rec.normalized


def test_restart_vm_dry_run(monkeypatch: MonkeyPatch) -> None:
    """Test that restart_vm does nothing in dry-run mode."""
    cfg = make_cfg(None, **{'vm.name': 'vm-restart-dry'})
    activate_manager(monkeypatch)
    rec = command_recorder(monkeypatch, {})

    restart_vm(cfg, dry_run=True)

    assert rec.calls == []


@pytest.mark.parametrize(
    ('name', 'vm_defined', 'routes', 'match'),
    [
        pytest.param(
            'vm-restart-undefined',
            False,
            {},
            'does not exist',
            id='raises_when_vm_undefined',
        ),
        pytest.param(
            'vm-restart-badstate',
            True,
            {'virsh domstate': FakeProc(1, '', 'error: domain is not found')},
            'domain is not found',
            id='raises_with_stderr_error_message',
        ),
    ],
)
def test_restart_vm_error(
    monkeypatch: MonkeyPatch,
    name: str,
    vm_defined: bool,
    routes: dict[str, FakeProc],
    match: str,
) -> None:
    """restart_vm refuses undefined VMs and forwards libvirt stderr.

    An undefined domain raises before any command runs; a failing state
    probe on a defined VM forwards the stderr text to the caller.
    """
    cfg = make_cfg(None, **{'vm.name': name})
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda n: vm_defined)
    command_recorder(monkeypatch, routes)

    with pytest.raises(RuntimeError, match=match):
        restart_vm(cfg, dry_run=False)
