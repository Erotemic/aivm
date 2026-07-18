"""Tests for vm update drift detection and command behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.cli.vm_update import VMUpdateCLI
from aivm.config import AgentVMConfig
from aivm.util import CmdResult
from aivm.vm.update import (
    RestartKind,
    VirtiofsBinaryDrift,
    VMUpdateDrift,
    _apply_vm_update,
    _escalate,
    _parse_qemu_img_virtual_size,
    _parse_vm_disk_path_from_dumpxml,
    _parse_vm_network_from_dumpxml,
    _vm_update_drift,
)


def test_parse_qemu_img_virtual_size() -> None:
    assert (
        _parse_qemu_img_virtual_size('{"virtual-size": 42949672960}')
        == 42949672960
    )
    assert _parse_qemu_img_virtual_size('{"virtual-size": 0}') is None
    assert _parse_qemu_img_virtual_size('not-json') is None


def test_parse_vm_disk_and_network_from_dumpxml() -> None:
    xml = """
<domain>
  <devices>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/images/vm.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='aivm-net'/>
    </interface>
  </devices>
</domain>
"""
    assert (
        _parse_vm_disk_path_from_dumpxml(xml)
        == '/var/lib/libvirt/images/vm.qcow2'
    )
    assert _parse_vm_network_from_dumpxml(xml) == 'aivm-net'


def test_apply_vm_update_rejects_disk_shrink() -> None:
    cfg = AgentVMConfig()
    drift = VMUpdateDrift(
        disk_bytes=(40 * 1024**3, 20 * 1024**3),
        disk_path='/tmp/vm.qcow2',
    )
    try:
        _apply_vm_update(cfg, drift, dry_run=False)
    except RuntimeError as ex:
        assert 'Disk shrink is not supported safely' in str(ex)
    else:
        raise AssertionError('Expected RuntimeError on disk shrink')


def test_apply_vm_update_disk_resize_lock_error_is_graceful(
    monkeypatch: MonkeyPatch,
) -> None:
    """A write-lock failure during resize surfaces as a clean AIVMError."""
    from aivm.commands import CommandError
    from aivm.errors import AIVMError

    cfg = AgentVMConfig()
    cfg.vm.disk_gb = 60
    drift = VMUpdateDrift(
        disk_bytes=(40 * 1024**3, 60 * 1024**3),
        disk_path='/var/lib/libvirt/aivm/vm/images/vm.qcow2',
    )

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del kwargs
        if cmd[:2] == ['qemu-img', 'resize']:
            raise CommandError(
                cmd,
                CmdResult(
                    1,
                    '',
                    'qemu-img: Could not open: Failed to get "write" lock\n'
                    'Is another process using the image?',
                ),
            )
        raise AssertionError(f'Unexpected command: {cmd!r}')

    monkeypatch.setattr('aivm.vm.update.apply.CommandManager.run', fake_run)
    with pytest.raises(AIVMError) as excinfo:
        _apply_vm_update(cfg, drift, dry_run=False)
    msg = str(excinfo.value)
    assert 'VM is currently running' in msg
    assert 'write' in msg  # original qemu-img message is resurfaced


def test_apply_vm_update_disk_resize_sudo_follows_file_writability(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """qemu-img opens the image file directly, so resize escalation is
    decided by file writability, not libvirt-group access (which lets an
    unprivileged resize of a root-owned image fail with EACCES).
    """
    cfg = AgentVMConfig()
    cfg.vm.disk_gb = 60
    image = tmp_path / 'vm.qcow2'
    image.write_bytes(b'')
    drift = VMUpdateDrift(
        disk_bytes=(40 * 1024**3, 60 * 1024**3),
        disk_path=str(image),
    )
    sudo_seen: list[bool] = []

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        assert cmd[:2] == ['qemu-img', 'resize']
        sudo_seen.append(bool(kwargs.get('sudo')))
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.update.apply.CommandManager.run', fake_run)
    image.chmod(0o444)
    _apply_vm_update(cfg, drift, dry_run=False)
    image.chmod(0o644)
    _apply_vm_update(cfg, drift, dry_run=False)
    assert sudo_seen == [True, False]


def test_escalate_orders_none_soft_hard() -> None:
    assert _escalate(RestartKind.NONE, RestartKind.NONE) == RestartKind.NONE
    assert _escalate(RestartKind.NONE, RestartKind.SOFT) == RestartKind.SOFT
    assert _escalate(RestartKind.SOFT, RestartKind.NONE) == RestartKind.SOFT
    assert _escalate(RestartKind.SOFT, RestartKind.HARD) == RestartKind.HARD
    assert _escalate(RestartKind.HARD, RestartKind.SOFT) == RestartKind.HARD
    assert _escalate(RestartKind.HARD, RestartKind.HARD) == RestartKind.HARD


@pytest.mark.parametrize(
    ('vm_name', 'drift', 'expected_changed', 'expected_kind'),
    [
        pytest.param(
            'vm-noop',
            VMUpdateDrift(),
            False,
            RestartKind.NONE,
            id='no_drift_yields_none_kind',
        ),
        pytest.param(
            'vm-cpu',
            VMUpdateDrift(cpus=(2, 4)),
            True,
            RestartKind.HARD,
            # setvcpus --config writes the persistent XML only; the live
            # qemu keeps the old vCPU count, so a guest reboot is not
            # enough -- a full power cycle is required.
            id='cpu_drift_requires_hard_cycle',
        ),
        pytest.param(
            'vm-ram',
            VMUpdateDrift(ram_mb=(8192, 16384)),
            True,
            RestartKind.HARD,
            id='ram_drift_requires_hard_cycle',
        ),
        pytest.param(
            'vm-disk',
            VMUpdateDrift(
                disk_bytes=(40 * 1024**3, 60 * 1024**3),
                disk_path='/tmp/vm-disk.qcow2',
            ),
            True,
            RestartKind.NONE,
            # qemu-img resize on the backing file is honoured live; the
            # guest may rescan its partition table, but no qemu-layer
            # restart is needed.
            id='disk_grow_requires_no_restart',
        ),
        pytest.param(
            'vm-vfs',
            VMUpdateDrift(
                virtiofs_binary=(
                    VirtiofsBinaryDrift(
                        tag='aivm-persistent-root',
                        current=(
                            '/var/lib/libvirt/aivm/'
                            'virtiofsd-wrapper-prefer.sh'
                        ),
                        desired='',
                    ),
                ),
                virtiofsd_mode='',
            ),
            True,
            RestartKind.HARD,
            # vhost-user-fs <binary path> changes only when libvirt spawns
            # a fresh virtiofsd, even when removing an old wrapper path.
            id='virtiofs_cleanup_requires_hard_cycle',
        ),
        pytest.param(
            'vm-combined',
            VMUpdateDrift(
                cpus=(2, 4),
                disk_bytes=(40 * 1024**3, 60 * 1024**3),
                disk_path='/tmp/vm-combined.qcow2',
            ),
            True,
            RestartKind.HARD,
            # CPU drift demands HARD; combined with disk's NONE, escalate
            # keeps HARD.
            id='combined_drift_escalates_to_hard',
        ),
    ],
)
def test_apply_vm_update(
    vm_name: str,
    drift: VMUpdateDrift,
    expected_changed: bool,
    expected_kind: RestartKind,
) -> None:
    """A dry-run ``_apply_vm_update`` reports the change flag and the
    restart kind each drift shape demands, without invoking virsh.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is expected_changed
    assert kind == expected_kind


def test_apply_vm_update_cpu_grow_raises_maximum_first(
    monkeypatch: MonkeyPatch,
) -> None:
    """setvcpus rejects counts above the persistent <vcpu> maximum, so the
    maximum must be raised before the count (mirrors setmaxmem/setmem).
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-cpu'
    drift = VMUpdateDrift(cpus=(8, 14))
    commands: list[list[str]] = []

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del kwargs
        commands.append(list(cmd))
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.update.apply.CommandManager.run', fake_run)
    _apply_vm_update(cfg, drift, dry_run=False)
    prefix = ['virsh', '-c', 'qemu:///system']
    assert commands == [
        prefix + ['setvcpus', 'vm-cpu', '14', '--maximum', '--config'],
        prefix + ['setvcpus', 'vm-cpu', '14', '--config'],
    ]


def test_vm_update_no_changes(
    monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-noop'
    monkeypatch.setattr(
        'aivm.cli.vm_update.load_cfg_with_path',
        lambda *a, **k: (cfg, tmp_path / 'config.toml'),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_update._vm_update_drift',
        lambda *a, **k: (VMUpdateDrift(), False),
    )
    rc = VMUpdateCLI.main(argv=False, config=str(tmp_path / 'config.toml'))
    assert rc == 0
    out = capsys.readouterr().out
    assert 'already in sync' in out


def test_vm_update_restarts_when_required(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-update'
    drift = VMUpdateDrift(cpus=(2, 4))
    monkeypatch.setattr(
        'aivm.cli.vm_update.load_cfg_with_path',
        lambda *a, **k: (cfg, tmp_path / 'config.toml'),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_update._vm_update_drift',
        lambda *a, **k: (drift, True),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_update._apply_vm_update',
        lambda *a, **k: (True, True),
    )
    called: dict[str, object] = {}  # type: ignore[assignment]

    def fake_restart(*a: object, **k: Any) -> None:
        called['kwargs'] = k  # type: ignore[index]

    monkeypatch.setattr(
        'aivm.cli.vm_update._maybe_restart_vm_after_update', fake_restart
    )
    rc = VMUpdateCLI.main(
        argv=False,
        config=str(tmp_path / 'config.toml'),
        yes=True,
        restart='always',
    )
    assert rc == 0
    assert called['kwargs']['restart_policy'] == 'always'  # type: ignore


def test_vm_update_drift_escalates_for_disk_probe(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-drift'
    cfg.vm.disk_gb = 60

    def fake_run_cmd(
        self: object, cmd: list[str], *, sudo: bool = False, **kwargs: Any
    ) -> CmdResult:
        del kwargs
        if cmd[:3] == ['virsh', '-c', 'qemu:///system'] and cmd[3] == 'dominfo':
            return CmdResult(
                0,
                'CPU(s):         4\nMax memory:     8388608 KiB\n',
                '',
            )
        if (
            cmd[:3] == ['virsh', '-c', 'qemu:///system']
            and cmd[3] == 'domstate'
        ):
            return CmdResult(0, 'running\n', '')
        if (
            cmd[:3] == ['virsh', '-c', 'qemu:///system']
            and cmd[3] == 'dumpxml'
            and not sudo
        ):
            return CmdResult(1, '', 'permission denied')
        if (
            cmd[:3] == ['virsh', '-c', 'qemu:///system']
            and cmd[3] == 'dumpxml'
            and sudo
        ):
            xml = """
<domain>
  <devices>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/aivm/vm-drift/images/vm-drift.qcow2'/>
    </disk>
    <interface type='network'>
      <source network='aivm-net'/>
    </interface>
  </devices>
</domain>
""".strip()
            return CmdResult(
                0,
                xml,
                '',
            )
        if cmd[:3] == ['qemu-img', 'info', '--output=json'] and not sudo:
            return CmdResult(1, '', 'permission denied')
        if cmd[:3] == ['qemu-img', 'info', '--output=json'] and sudo:
            return CmdResult(0, '{"virtual-size": 42949672960}', '')
        raise AssertionError(f'Unexpected cmd={cmd!r} sudo={sudo}')

    monkeypatch.setattr(
        'aivm.vm.update.detect.CommandManager.run', fake_run_cmd
    )
    drift, running = _vm_update_drift(cfg, yes=False)
    assert running is True
    assert drift.disk_bytes == (40 * 1024**3, 60 * 1024**3)


def test_vm_update_drift_falls_back_to_domblkinfo_on_lock(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-lock'
    cfg.vm.disk_gb = 60

    def fake_run_cmd(
        self: object, cmd: list[str], *, sudo: bool = False, **kwargs: Any
    ) -> CmdResult:
        del kwargs, sudo
        if cmd[:3] == ['virsh', '-c', 'qemu:///system'] and cmd[3] == 'dominfo':
            return CmdResult(
                0,
                'CPU(s):         4\nMax memory:     8388608 KiB\n',
                '',
            )
        if (
            cmd[:3] == ['virsh', '-c', 'qemu:///system']
            and cmd[3] == 'domstate'
        ):
            return CmdResult(0, 'running\n', '')
        if cmd[:3] == ['virsh', '-c', 'qemu:///system'] and cmd[3] == 'dumpxml':
            xml = """
<domain>
  <devices>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/aivm/vm-lock/images/vm-lock.qcow2'/>
    </disk>
    <interface type='network'>
      <source network='aivm-net'/>
    </interface>
  </devices>
</domain>
""".strip()
            return CmdResult(0, xml, '')
        if cmd[:3] == ['qemu-img', 'info', '--output=json']:
            return CmdResult(
                1,
                '',
                'Failed to get shared "write" lock\nIs another process using the image?',
            )
        if (
            cmd[:3] == ['virsh', '-c', 'qemu:///system']
            and cmd[3] == 'domblkinfo'
        ):
            return CmdResult(0, 'Capacity: 42949672960\nAllocation: 0\n', '')
        raise AssertionError(f'Unexpected command: {cmd!r}')

    monkeypatch.setattr(
        'aivm.vm.update.detect.CommandManager.run', fake_run_cmd
    )
    drift, _running = _vm_update_drift(cfg, yes=True)
    assert drift.disk_bytes == (40 * 1024**3, 60 * 1024**3)
    assert any('falling back to virsh domblkinfo' in n for n in drift.notes)
