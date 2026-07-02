"""Tests for vm update drift detection and command behavior."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.attachments.session import ReconcileResult, _prepare_attached_session
from aivm.cli.vm_connect import _bootstrap_vm_for_folder
from aivm.cli.vm_update import VMUpdateCLI
from aivm.config import AgentVMConfig
from aivm.status import ProbeOutcome
from aivm.util import CmdResult
from aivm.vm.share import AttachmentMode, ResolvedAttachment
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

    def fake_run(
        self: object, cmd: list[str], **kwargs: Any
    ) -> CmdResult:
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


def test_apply_vm_update_no_drift_yields_none_kind() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-noop'
    changed, kind = _apply_vm_update(cfg, VMUpdateDrift(), dry_run=True)
    assert changed is False
    assert kind == RestartKind.NONE


def test_apply_vm_update_cpu_drift_requires_hard_cycle() -> None:
    """setvcpus --config writes the persistent XML only; the live qemu
    keeps the old vCPU count, so a guest reboot is not enough — we need
    a full power cycle. The dry-run path lets us check this without
    actually invoking virsh.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-cpu'
    drift = VMUpdateDrift(cpus=(2, 4))
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is True
    assert kind == RestartKind.HARD


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


def test_apply_vm_update_ram_drift_requires_hard_cycle() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ram'
    drift = VMUpdateDrift(ram_mb=(8192, 16384))
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is True
    assert kind == RestartKind.HARD


def test_apply_vm_update_disk_grow_requires_no_restart() -> None:
    """qemu-img resize on the backing file is honoured live. Guest may
    want to rescan its partition table, but no qemu-layer restart is
    needed.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-disk'
    drift = VMUpdateDrift(
        disk_bytes=(40 * 1024**3, 60 * 1024**3),
        disk_path='/tmp/vm-disk.qcow2',
    )
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is True
    assert kind == RestartKind.NONE


def test_apply_vm_update_virtiofs_cleanup_requires_hard_cycle() -> None:
    """vhost-user-fs <binary path> changes only when libvirt spawns a
    fresh virtiofsd, even when the update is removing an old wrapper path.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-vfs'
    drift = VMUpdateDrift(
        virtiofs_binary=(
            VirtiofsBinaryDrift(
                tag='aivm-persistent-root',
                current='/var/lib/libvirt/aivm/virtiofsd-wrapper-prefer.sh',
                desired='',
            ),
        ),
        virtiofsd_mode='',
    )
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is True
    assert kind == RestartKind.HARD


def test_apply_vm_update_combined_drift_escalates_to_hard() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-combined'
    drift = VMUpdateDrift(
        cpus=(2, 4),
        disk_bytes=(40 * 1024**3, 60 * 1024**3),
        disk_path='/tmp/vm-combined.qcow2',
    )
    changed, kind = _apply_vm_update(cfg, drift, dry_run=True)
    assert changed is True
    # CPU drift demands HARD; combined with disk's NONE, escalate keeps HARD.
    assert kind == RestartKind.HARD


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

    monkeypatch.setattr('aivm.vm.update.detect.CommandManager.run', fake_run_cmd)
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

    monkeypatch.setattr('aivm.vm.update.detect.CommandManager.run', fake_run_cmd)
    drift, _running = _vm_update_drift(cfg, yes=True)
    assert drift.disk_bytes == (40 * 1024**3, 60 * 1024**3)
    assert any('falling back to virsh domblkinfo' in n for n in drift.notes)


def test_prepare_attached_session_bootstraps_missing_vm(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'bootstrap-vm'
    cfg_path = tmp_path / 'config.toml'

    calls: list[str] = []
    state = {'ready': False}

    def fake_resolve_cfg_for_code(**kwargs: Any) -> tuple[AgentVMConfig, Path]:
        del kwargs
        if not state['ready']:
            raise RuntimeError(
                f'No VM definitions found in config store: {cfg_path}. '
                'Run `aivm config init` then `aivm vm create` first.'
            )
        return cfg, cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        fake_resolve_cfg_for_code,
    )
    monkeypatch.setattr(
        'aivm.cli.config.InitCLI.main',
        lambda *a, **k: calls.append('config_init') or 0,
    )

    def fake_vm_create(*a: Any, **k: Any) -> int:
        calls.append('vm_create')
        state['ready'] = True
        return 0

    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        lambda *a, **k: ResolvedAttachment(
            vm_name=cfg.vm.name,
            source_dir=str(host_src),
            guest_dst=str(host_src),
            tag='hostcode-proj',
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=ResolvedAttachment(
                vm_name=cfg.vm.name,
                source_dir=str(host_src),
                guest_dst=str(host_src),
                tag='hostcode-proj',
            ),
            cached_ip=None,
            cached_ssh_ok=False,
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment',
        lambda *a, **k: tmp_path / 'dummy',
    )
    monkeypatch.setattr(
        'aivm.attachments.session.get_ip_cached', lambda *a, **k: '10.0.0.2'
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: ProbeOutcome(True, 'ready', ''),
    )
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=None,
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=True,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=None,
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
        bootstrap_missing_vm=bootstrap,
    )
    assert session.cfg.vm.name == 'bootstrap-vm'
    assert calls == ['config_init', 'vm_create']


def test_prepare_attached_session_interactive_bootstrap_preserves_yes_false(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'bootstrap-vm'
    cfg_path = tmp_path / 'config.toml'

    state = {'ready': False}
    init_kwargs: list[dict] = []
    create_kwargs: list[dict] = []

    def fake_resolve_cfg_for_code(**kwargs: Any) -> tuple[AgentVMConfig, Path]:
        del kwargs
        if not state['ready']:
            raise RuntimeError(
                f'No VM definitions found in config store: {cfg_path}. '
                'Run `aivm config init` then `aivm vm create` first.'
            )
        return cfg, cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        fake_resolve_cfg_for_code,
    )

    def fake_init(*a: object, **k: Any) -> int:
        del a
        init_kwargs.append(dict(k))
        return 0

    create_positional: list[tuple[Any, ...]] = []

    def fake_vm_create(*a: Any, **k: Any) -> int:
        create_positional.append(a)
        create_kwargs.append(dict(k))
        state['ready'] = True
        return 0

    monkeypatch.setattr('aivm.cli.config.InitCLI.main', fake_init)
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.sys.stdin.isatty', lambda: True
    )
    monkeypatch.setattr('builtins.input', lambda prompt='': 'y')
    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        lambda *a, **k: ResolvedAttachment(
            vm_name=cfg.vm.name,
            source_dir=str(host_src),
            guest_dst=str(host_src),
            tag='hostcode-proj',
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=ResolvedAttachment(
                vm_name=cfg.vm.name,
                source_dir=str(host_src),
                guest_dst=str(host_src),
                tag='hostcode-proj',
            ),
            cached_ip=None,
            cached_ssh_ok=False,
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment',
        lambda *a, **k: tmp_path / 'dummy',
    )
    monkeypatch.setattr(
        'aivm.attachments.session.get_ip_cached', lambda *a, **k: '10.0.0.2'
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: ProbeOutcome(True, 'ready', ''),
    )
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=None,
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=False,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=None,
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=False,
        bootstrap_missing_vm=bootstrap,
    )

    assert session.cfg.vm.name == 'bootstrap-vm'
    assert init_kwargs == [
        {
            'argv': False,
            'config': None,
            'yes': False,
            'defaults': False,
            'force': False,
        }
    ]
    assert len(create_kwargs) == 1
    # ``yes=False`` propagation is the contract this test guards; the rest of
    # the call shape is verified indirectly by the function signature.
    assert create_kwargs[0]['yes'] is False
    assert create_kwargs[0]['dry_run'] is False
    assert create_kwargs[0]['force'] is False
    assert create_kwargs[0]['vm_override'] is None
    assert create_kwargs[0]['initial_attachment_host_src'] == host_src


def test_prepare_attached_session_bootstraps_create_only_when_defaults_exist(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'bootstrap-vm'
    cfg_path = tmp_path / 'config.toml'

    from aivm.config_store import Store, save_store

    store = Store()
    store.defaults = AgentVMConfig()
    save_store(store, cfg_path)

    calls: list[str] = []
    state = {'ready': False}

    def fake_resolve_cfg_for_code(**kwargs: Any) -> tuple[AgentVMConfig, Path]:
        del kwargs
        if not state['ready']:
            raise RuntimeError(
                f'No VM definitions found in config store: {cfg_path}. '
                'Run `aivm config init` then `aivm vm create` first.'
            )
        return cfg, cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        fake_resolve_cfg_for_code,
    )
    monkeypatch.setattr(
        'aivm.cli.config.InitCLI.main',
        lambda *a, **k: calls.append('config_init') or 0,
    )

    def fake_vm_create(*a: Any, **k: Any) -> int:
        calls.append('vm_create')
        state['ready'] = True
        return 0

    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        lambda *a, **k: ResolvedAttachment(
            vm_name=cfg.vm.name,
            source_dir=str(host_src),
            guest_dst=str(host_src),
            tag='hostcode-proj',
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=ResolvedAttachment(
                vm_name=cfg.vm.name,
                source_dir=str(host_src),
                guest_dst=str(host_src),
                tag='hostcode-proj',
            ),
            cached_ip=None,
            cached_ssh_ok=False,
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment',
        lambda *a, **k: tmp_path / 'dummy',
    )
    monkeypatch.setattr(
        'aivm.attachments.session.get_ip_cached', lambda *a, **k: '10.0.0.2'
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: ProbeOutcome(True, 'ready', ''),
    )
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=True,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
        bootstrap_missing_vm=bootstrap,
    )
    assert session.cfg.vm.name == 'bootstrap-vm'
    assert calls == ['vm_create']


def test_prepare_attached_session_restores_saved_vm_attachments(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.config_store import (
        Store,
        save_store,
        upsert_attachment,
        upsert_vm,
    )

    host_src = tmp_path / 'proj'
    other_src = tmp_path / 'docs'
    host_src.mkdir()
    other_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'restore-vm'
    cfg_path = tmp_path / 'config.toml'

    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=host_src,
        vm_name=cfg.vm.name,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )
    upsert_attachment(
        store,
        host_path=other_src,
        vm_name=cfg.vm.name,
        guest_dst='/workspace/docs',
        tag='hostcode-docs',
    )
    save_store(store, cfg_path)

    current_attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        source_dir=str(host_src.resolve()),
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        lambda **kwargs: (cfg, cfg_path),
    )

    def fake_resolve_attachment(
        _cfg: AgentVMConfig,
        cfg_path: Path,
        host_path: Path,
        _guest_dst_opt: str,
    ) -> ResolvedAttachment:
        host_path = Path(host_path).resolve()
        if host_path == host_src.resolve():
            return current_attachment
        if host_path == other_src.resolve():
            return ResolvedAttachment(
                vm_name=cfg.vm.name,
                source_dir=str(other_src.resolve()),
                guest_dst='/workspace/docs',
                tag='hostcode-docs',
            )
        raise AssertionError(f'unexpected host_path={host_path}')

    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        fake_resolve_attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=current_attachment,
            cached_ip='10.0.0.2',
            cached_ssh_ok=True,
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: ProbeOutcome(True, 'ready', ''),
    )

    mappings = [(str(host_src.resolve()), 'hostcode-proj')]

    def fake_vm_share_mappings(*a: Any, **k: Any) -> list:
        del a, k
        return list(mappings)

    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings', fake_vm_share_mappings
    )

    attached: list[tuple[tuple, dict]] = []

    def fake_attach_vm_share(*a: Any, **k: Any) -> None:
        attached.append((a, k))
        mappings.append((str(other_src.resolve()), 'hostcode-docs'))

    monkeypatch.setattr(
        'aivm.attachments.session.attach_vm_share', fake_attach_vm_share
    )

    mounted: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )
    recorded: list[dict] = []

    def fake_record_attachment(
        cfg_arg: AgentVMConfig,
        cfg_path_arg: Path,
        *,
        host_src: Path,
        mode: str,
        access: str,
        guest_dst: str,
        tag: str,
    ) -> Path:
        del cfg_arg, cfg_path_arg
        recorded.append(
            {
                'host_src': str(host_src),
                'mode': mode,
                'access': access,
                'guest_dst': guest_dst,
                'tag': tag,
            }
        )
        return cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment', fake_record_attachment
    )

    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
    )

    assert session.cfg.vm.name == 'restore-vm'
    assert len(attached) == 1
    attach_args, attach_kwargs = attached[0]
    assert attach_args[1] == str(other_src.resolve())
    assert attach_args[2] == 'hostcode-docs'
    assert attach_kwargs['dry_run'] is False
    assert [kwargs['guest_dst'] for _, kwargs in mounted] == [
        '/workspace/proj',
        '/workspace/docs',
    ]
    assert len(recorded) == 2
    assert recorded[1]['mode'] == 'shared'
    assert recorded[1]['guest_dst'] == '/workspace/docs'


def test_prepare_attached_session_restores_saved_shared_root_attachments(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.config_store import (
        Store,
        save_store,
        upsert_attachment,
        upsert_vm,
    )

    host_src = tmp_path / 'proj'
    other_src = tmp_path / 'docs'
    host_src.mkdir()
    other_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'restore-shared-root-vm'
    cfg_path = tmp_path / 'config.toml'

    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        guest_dst='/workspace/proj',
        tag='token-proj',
    )
    upsert_attachment(
        store,
        host_path=other_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        guest_dst='/workspace/docs',
        tag='token-docs',
    )
    save_store(store, cfg_path)

    current_attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        source_dir=str(host_src.resolve()),
        guest_dst='/workspace/proj',
        tag='token-proj',
    )

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        lambda **kwargs: (cfg, cfg_path),
    )

    def fake_resolve_attachment(
        _cfg: AgentVMConfig,
        cfg_path: Path,
        host_path: Path,
        _guest_dst_opt: str,
    ) -> ResolvedAttachment:
        host_path = Path(host_path).resolve()
        if host_path == host_src.resolve():
            return current_attachment
        if host_path == other_src.resolve():
            return ResolvedAttachment(
                vm_name=cfg.vm.name,
                mode=AttachmentMode.SHARED_ROOT,
                source_dir=str(other_src.resolve()),
                guest_dst='/workspace/docs',
                tag='token-docs',
            )
        raise AssertionError(f'unexpected host_path={host_path}')

    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        fake_resolve_attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=current_attachment,
            cached_ip='10.0.0.3',
            cached_ssh_ok=True,
        ),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: ProbeOutcome(True, 'ready', ''),
    )

    primary_ready_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.session._ensure_attachment_available_in_guest',
        lambda *a, **k: primary_ready_calls.append((a, k)) or None,
    )

    shared_root_host_binds: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_host_bind',
        lambda *a, **k: (
            shared_root_host_binds.append((a, k)) or Path('/tmp/token')
        ),
    )
    shared_root_vm_mappings: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_vm_mapping',
        lambda *a, **k: shared_root_vm_mappings.append((a, k)) or None,
    )
    shared_root_guest_binds: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_guest_bind',
        lambda *a, **k: shared_root_guest_binds.append((a, k)) or None,
    )

    recorded: list[dict] = []

    def fake_record_attachment(
        cfg_arg: AgentVMConfig,
        cfg_path_arg: Path,
        *,
        host_src: Path,
        mode: str,
        access: str,
        guest_dst: str,
        tag: str,
    ) -> Path:
        del cfg_arg, cfg_path_arg
        recorded.append(
            {
                'host_src': str(host_src),
                'mode': mode,
                'access': access,
                'guest_dst': guest_dst,
                'tag': tag,
            }
        )
        return cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment', fake_record_attachment
    )

    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
    )

    assert session.cfg.vm.name == 'restore-shared-root-vm'
    assert len(primary_ready_calls) == 2
    primary_args, primary_kwargs = primary_ready_calls[0]
    restored_args, restored_kwargs = primary_ready_calls[1]
    assert primary_args[2].guest_dst == '/workspace/proj'
    assert primary_kwargs['ensure_shared_root_host_side'] is True
    assert restored_args[2].guest_dst == '/workspace/docs'
    assert restored_kwargs['ensure_shared_root_host_side'] is True
    assert restored_kwargs['allow_disruptive_shared_root_rebind'] is False
    assert len(shared_root_host_binds) == 0
    assert len(shared_root_vm_mappings) == 0
    assert len(shared_root_guest_binds) == 0
    assert len(recorded) == 2
    assert recorded[1]['mode'] == AttachmentMode.SHARED_ROOT
    assert recorded[1]['guest_dst'] == '/workspace/docs'
