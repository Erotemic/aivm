"""VM creation and the create-or-start reconcile path.

Covers ``aivm.vm.create``/``aivm.vm.lifecycle``: UEFI firmware fallback
during ``virt-install``, deciding whether to start/resume/refuse an
existing domain based on its state, and mapping raw ``virt-install``
failures (missing virtiofsd, unallocatable guest RAM) onto actionable
error messages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.util import CmdError, CmdResult
from aivm.vm import create_or_start_vm
from tests.helpers import (
    FakeProc,
    activate_manager,
    command_recorder,
    make_cfg,
)


def _stub_create_inputs(monkeypatch: MonkeyPatch) -> None:
    """Stub the image/seed/disk preparation that precedes ``virt-install``."""
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: False)
    monkeypatch.setattr(
        'aivm.vm.create.fetch_image', lambda *a, **k: Path('/tmp/base.img')
    )
    monkeypatch.setattr(
        'aivm.vm.create._write_cloud_init',
        lambda *a, **k: {'seed_iso': Path('/tmp/seed.iso')},
    )
    monkeypatch.setattr(
        'aivm.vm.create._ensure_disk', lambda *a, **k: Path('/tmp/vm.qcow2')
    )


def test_create_vm_fallback_when_uefi_firmware_missing(
    monkeypatch: MonkeyPatch,
) -> None:
    """A missing UEFI binary retries ``virt-install`` without ``--boot``."""
    cfg = AgentVMConfig()
    _stub_create_inputs(monkeypatch)

    calls = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        calls.append(cmd)
        if cmd[0] == 'virt-install' and '--boot' in cmd:
            raise CmdError(
                cmd,
                CmdResult(
                    1,
                    '',
                    'ERROR    Did not find any UEFI binary path for arch '
                    "'x86_64'",
                ),
            )
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    create_or_start_vm(cfg, dry_run=False, recreate=False)

    virt_calls = [c for c in calls if c and c[0] == 'virt-install']
    assert len(virt_calls) == 2
    assert '--memorybacking' in virt_calls[0]
    assert '--memorybacking' in virt_calls[1]
    assert '--tpm' in virt_calls[0]
    assert 'none' in virt_calls[0]
    assert '--tpm' in virt_calls[1]
    assert 'none' in virt_calls[1]
    assert '--boot' in virt_calls[0]
    assert 'uefi,loader.secure=no,bios.useserial=on' in virt_calls[0]
    assert '--boot' not in virt_calls[1]


def test_create_vm_prefers_uefi_even_when_host_looks_nested(
    monkeypatch: MonkeyPatch,
) -> None:
    """UEFI boot is attempted first even under nested virtualization."""
    cfg = AgentVMConfig()
    _stub_create_inputs(monkeypatch)

    calls = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        calls.append(cmd)
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    create_or_start_vm(cfg, dry_run=False, recreate=False)

    virt_calls = [c for c in calls if c and c[0] == 'virt-install']
    assert len(virt_calls) == 1
    assert '--memorybacking' in virt_calls[0]
    assert '--tpm' in virt_calls[0]
    assert 'none' in virt_calls[0]
    assert '--boot' in virt_calls[0]
    assert 'uefi,loader.secure=no,bios.useserial=on' in virt_calls[0]


def test_create_or_start_existing_vm_uses_step_for_state_and_start(
    monkeypatch: MonkeyPatch,
) -> None:
    """An existing, stopped VM is inspected and started under a named step."""
    cfg = make_cfg(None, **{'vm.name': 'vm-existing'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)

    step_titles: list[str] = []
    orig_step = CommandManager.step

    def track_step(self: Any, title: str, **kwargs: Any) -> object:
        step_titles.append(title)
        return orig_step(self, title, **kwargs)

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.step', track_step)
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'shut off\n', ''),
            'virsh start': FakeProc(0, '', ''),
        },
    )
    create_or_start_vm(cfg, dry_run=False, recreate=False)

    assert step_titles == ['Ensure existing VM is running']
    assert rec.normalized == [
        ['virsh', 'domstate', 'vm-existing'],
        ['virsh', 'start', 'vm-existing'],
    ]


@pytest.mark.parametrize('paused_state', ['paused', 'pmsuspended'])
def test_create_or_start_paused_vm_resumes_instead_of_starting(
    monkeypatch: MonkeyPatch, paused_state: str
) -> None:
    """A paused or suspended VM is resumed rather than started."""
    cfg = make_cfg(None, **{'vm.name': 'vm-paused'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, f'{paused_state}\n', ''),
            'virsh resume': FakeProc(0, '', ''),
        },
    )
    create_or_start_vm(cfg, dry_run=False, recreate=False)

    assert rec.normalized == [
        ['virsh', 'domstate', 'vm-paused'],
        ['virsh', 'resume', 'vm-paused'],
    ]
    assert not rec.ran('virsh', 'start'), (
        'paused VM must be resumed, not started'
    )


def test_create_or_start_shutting_down_vm_raises_friendly_error(
    monkeypatch: MonkeyPatch,
) -> None:
    """A VM mid-shutdown raises a clear error instead of racing it."""
    cfg = make_cfg(None, **{'vm.name': 'vm-shutting-down'})
    monkeypatch.setattr('aivm.vm.create.vm_exists', lambda *a, **k: True)
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch, {'virsh domstate': FakeProc(0, 'in shutdown\n', '')}
    )

    with pytest.raises(RuntimeError, match='shutting down'):
        create_or_start_vm(cfg, dry_run=False, recreate=False)


def _run_virtiofsd_missing(
    self: object, cmd: list[str], **kwargs: Any
) -> CmdResult:
    del self, kwargs
    if cmd and cmd[0] == 'virt-install':
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                'operation failed: Unable to find a satisfying virtiofsd',
            ),
        )
    return CmdResult(0, '', '')


def _run_guest_memory_unavailable(
    self: object, cmd: list[str], **kwargs: Any
) -> CmdResult:
    del self, kwargs
    if cmd and cmd[0] == 'virt-install' and '--boot' in cmd:
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                "ERROR    Did not find any UEFI binary path for arch 'x86_64'",
            ),
        )
    if cmd and cmd[0] == 'virt-install':
        raise CmdError(
            cmd,
            CmdResult(
                1,
                '',
                "qemu-system-x86_64: cannot set up guest memory 'pc.ram': "
                'Cannot allocate memory',
            ),
        )
    return CmdResult(0, '', '')


@pytest.mark.parametrize(
    ('cfg_overrides', 'use_share', 'run_fn', 'match'),
    [
        pytest.param(
            {'vm.name': 'vmx'},
            True,
            _run_virtiofsd_missing,
            'virtiofsd is not available',
            id='when_virtiofsd_missing',
        ),
        pytest.param(
            {'vm.name': 'vmx', 'vm.ram_mb': 8192, 'vm.cpus': 4},
            False,
            _run_guest_memory_unavailable,
            'could not allocate guest RAM',
            id='when_guest_memory_unavailable',
        ),
    ],
)
def test_create_vm_raises_clear_error(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    cfg_overrides: dict[str, Any],
    use_share: bool,
    run_fn: Any,
    match: str,
) -> None:
    """Raw ``virt-install`` failures map onto actionable error messages.

    A missing virtiofsd binary and an unallocatable guest-memory failure
    both surface as ``RuntimeError`` with guidance rather than the opaque
    libvirt/qemu text.
    """
    cfg = make_cfg(**cfg_overrides)
    _stub_create_inputs(monkeypatch)
    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', run_fn)

    create_kwargs: dict[str, Any] = {}
    if use_share:
        create_kwargs = {
            'share_source_dir': str(tmp_path),
            'share_tag': 'hostcode',
        }

    with pytest.raises(RuntimeError, match=match):
        create_or_start_vm(cfg, dry_run=False, recreate=False, **create_kwargs)
