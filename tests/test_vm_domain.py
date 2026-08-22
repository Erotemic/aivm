"""Power-state transitions for ``shutdown_vm`` and ``restart_vm``.

These exercise the graceful shutdown and restart flows in
``aivm.vm.domain``: how each reacts to the VM's initial libvirt state
(running, stopped, or ``pmsuspended``), that dry runs stay inert, and
that libvirt failures surface as clear ``RuntimeError`` messages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest
from pytest import MonkeyPatch

from aivm.errors import AIVMError
from aivm.vm import restart_vm, shutdown_vm
from aivm.vm.domain import (
    _destroy_and_undefine_vm,
    _host_path_exists,
    _vm_defined,
    domain_file_storage_paths,
)
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


@pytest.mark.parametrize(
    ('vm_name', 'disk_xml'),
    [
        pytest.param(
            'vm-block-storage',
            '<disk type="block" device="disk">'
            '<source dev="/dev/vg0/vm-disk"/></disk>',
            id='rejects_non_file_disk',
        ),
        pytest.param(
            'vm-block-cdrom',
            '<disk type="block" device="cdrom"><source dev="/dev/sr0"/></disk>',
            id='rejects_non_file_cdrom_media',
        ),
    ],
)
def test_domain_storage_capture_rejects_non_file_disk(
    monkeypatch: MonkeyPatch, vm_name: str, disk_xml: str
) -> None:
    """Deletion must not proceed when libvirt storage cannot be enumerated.

    ``--remove-all-storage`` acts on every ``<disk>`` source, so an
    unverifiable source fails closed whether it is a writable disk or
    inserted cdrom media.
    """
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda name: True)
    xml = f'<domain><devices>{disk_xml}</devices></domain>'
    command_recorder(monkeypatch, {'virsh dumpxml': FakeProc(0, xml, '')})

    with pytest.raises(AIVMError, match='non-file or otherwise unverifiable'):
        domain_file_storage_paths(vm_name)


def test_domain_storage_capture_includes_cdrom_media(
    monkeypatch: MonkeyPatch,
) -> None:
    """File-backed cdrom media is inventoried alongside writable disks.

    ``virsh undefine --remove-all-storage`` deletes an attached ISO exactly
    like a qcow2, so the containment/journal inventory must include it.  An
    empty removable drive (no ``<source>``) has nothing to delete and is
    skipped rather than failing the capture.
    """
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda name: True)
    xml = """
    <domain>
      <devices>
        <disk type="file" device="disk">
          <source file="/managed/vm/images/vm.qcow2"/>
        </disk>
        <disk type="file" device="cdrom">
          <source file="/managed/vm/cloud-init/seed.iso"/>
        </disk>
        <disk type="file" device="cdrom"/>
      </devices>
    </domain>
    """
    command_recorder(monkeypatch, {'virsh dumpxml': FakeProc(0, xml, '')})

    assert domain_file_storage_paths('vm-with-cdrom') == (
        Path('/managed/vm/images/vm.qcow2'),
        Path('/managed/vm/cloud-init/seed.iso'),
    )


def test_domain_undefine_never_retries_without_storage_removal(
    monkeypatch: MonkeyPatch,
) -> None:
    """Every undefine attempt preserves the remove-all-storage contract."""
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda name: True)
    monkeypatch.setattr(
        'aivm.vm.domain.domain_file_storage_paths',
        lambda name: (Path('/tmp/vm.qcow2'),),
    )
    rec = command_recorder(
        monkeypatch,
        {
            'virsh destroy': FakeProc(0, '', ''),
            'virsh undefine': FakeProc(1, '', 'metadata flag rejected'),
        },
    )

    with pytest.raises(AIVMError, match='domain is still present'):
        _destroy_and_undefine_vm(
            'vm-storage-contract', storage_paths=(Path('/tmp/vm.qcow2'),)
        )

    undefines = [
        cmd for cmd in rec.normalized if cmd[:2] == ['virsh', 'undefine']
    ]
    assert len(undefines) == 3
    assert all('--remove-all-storage' in cmd for cmd in undefines)


def test_domain_undefine_refuses_changed_explicit_storage_inventory(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda name: True)
    monkeypatch.setattr(
        'aivm.vm.domain.domain_file_storage_paths',
        lambda name: (Path('/tmp/replacement.qcow2'),),
    )
    rec = command_recorder(monkeypatch, {})

    with pytest.raises(
        AIVMError, match='storage inventory changed before undefine'
    ):
        _destroy_and_undefine_vm(
            'vm-storage-changed',
            storage_paths=(Path('/tmp/original.qcow2'),),
        )

    assert not any(cmd[:2] == ['virsh', 'destroy'] for cmd in rec.normalized)
    assert not any(cmd[:2] == ['virsh', 'undefine'] for cmd in rec.normalized)


@pytest.mark.parametrize(
    'detail',
    [
        'error: failed to connect to the hypervisor',
        'error: authentication unavailable: permission denied',
    ],
)
def test_vm_defined_fails_closed_on_libvirt_inspection_errors(
    monkeypatch: MonkeyPatch, detail: str
) -> None:
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch, {'virsh dominfo': FakeProc(1, '', detail)}
    )

    with pytest.raises(AIVMError, match='Could not determine whether VM'):
        _vm_defined('inspect-me')

    assert ['virsh', 'dominfo', 'inspect-me'] in rec.normalized


def test_vm_defined_accepts_only_recognized_missing_domain(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch,
        {'virsh dominfo': FakeProc(1, '', 'error: failed to get domain')},
    )
    assert _vm_defined('missing-vm') is False


def test_vm_defined_pins_c_locale_on_dominfo(monkeypatch: MonkeyPatch) -> None:
    """The dominfo stderr is string-matched, so the raw argv pins LC_ALL=C.

    Localized libvirt diagnostics would otherwise turn every probe of a
    missing VM into a hard 'Could not determine' error.
    """
    activate_manager(monkeypatch, euid=0)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh dominfo': FakeProc(
                1, '', "error: failed to get domain 'missing-vm'"
            )
        },
    )

    assert _vm_defined('missing-vm') is False

    raw = rec.calls[rec.normalized.index(['virsh', 'dominfo', 'missing-vm'])]
    assert raw[:2] == ['env', 'LC_ALL=C']


def test_vm_state_probe_pins_c_locale_on_domstate(
    monkeypatch: MonkeyPatch,
) -> None:
    """State probes match English names ('running', 'shut off'), so the
    raw domstate argv pins LC_ALL=C; a translated state name would make
    shutdown flows misread an active VM as inactive."""
    cfg = make_cfg(None, **{'vm.name': 'vm-locale-state'})
    activate_manager(monkeypatch, euid=0)
    rec = command_recorder(
        monkeypatch, {'virsh domstate': FakeProc(0, 'shut off\n', '')}
    )

    shutdown_vm(cfg, dry_run=False)

    raw = rec.calls[
        rec.normalized.index(['virsh', 'domstate', 'vm-locale-state'])
    ]
    assert raw[:2] == ['env', 'LC_ALL=C']


def test_domain_storage_capture_fails_closed_on_dumpxml_error(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch)
    monkeypatch.setattr('aivm.vm.domain._vm_defined', lambda _name: True)
    command_recorder(
        monkeypatch,
        {'virsh dumpxml': FakeProc(1, '', 'error: permission denied')},
    )

    with pytest.raises(AIVMError, match='Could not capture storage paths'):
        domain_file_storage_paths('inspect-me')


@pytest.mark.parametrize(
    'detail',
    [
        'stat: cannot statx /managed/disk: Permission denied',
        'stat: cannot statx /managed/disk: Input/output error',
        'env: stat: command execution failed',
    ],
)
def test_host_storage_probe_fails_closed(
    monkeypatch: MonkeyPatch, detail: str
) -> None:
    from aivm.commands import CommandResult

    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.vm.domain.CommandManager.run',
        lambda self, *args, **kwargs: CommandResult(1, '', detail),
    )

    with pytest.raises(AIVMError, match='Could not determine whether managed'):
        _host_path_exists(Path('/managed/disk'))


def test_host_storage_probe_accepts_confirmed_enoent(
    monkeypatch: MonkeyPatch,
) -> None:
    from aivm.commands import CommandResult

    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.vm.domain.CommandManager.run',
        lambda self, *args, **kwargs: CommandResult(
            1,
            '',
            "stat: cannot statx '/managed/disk': No such file or directory",
        ),
    )
    assert _host_path_exists(Path('/managed/disk')) is False
