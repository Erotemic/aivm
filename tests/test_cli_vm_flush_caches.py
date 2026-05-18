"""Tests for ``aivm vm flush_caches``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.cli import AgentVMModalCLI
from aivm.cli.vm_cache import (
    VMFlushCachesCLI,
    _guest_drop_caches_script,
    _parse_drop_cache_levels,
)
from aivm.commands import CommandResult
from aivm.config import AgentVMConfig
from aivm.store import Store, save_store, upsert_vm


def _write_cfg(tmp_path: Path) -> Path:
    cfg_path = tmp_path / 'config.toml'
    cfg = AgentVMConfig()
    cfg.vm.name = 'test-vm'
    cfg.vm.user = 'agent'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    cfg.paths.state_dir = str(tmp_path / 'state')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.paths.ssh_pubkey_path = str(tmp_path / 'id_ed25519.pub')
    store = Store()
    upsert_vm(store, cfg)
    save_store(store, cfg_path)
    return cfg_path


def _run(argv: list[str]) -> int:
    rc = AgentVMModalCLI.main(argv=argv, _noexit=True)
    return 0 if rc is None else int(rc)


def test_parse_drop_cache_levels() -> None:
    assert _parse_drop_cache_levels('2') == [2]
    assert _parse_drop_cache_levels('2,3') == [2, 3]
    with pytest.raises(ValueError):
        _parse_drop_cache_levels('4')
    with pytest.raises(ValueError):
        _parse_drop_cache_levels('')


def test_guest_drop_caches_script_defaults_to_inode_dentry_eviction() -> None:
    script = _guest_drop_caches_script([2])
    assert 'sync' in script
    assert 'echo 2 > /proc/sys/vm/drop_caches' in script
    assert 'sudo -n sh -c' in script
    assert 'echo 3 > /proc/sys/vm/drop_caches' not in script


def test_guest_drop_caches_script_can_sequence_levels() -> None:
    script = _guest_drop_caches_script([2, 3], settle_seconds=5)
    assert 'echo 2 > /proc/sys/vm/drop_caches' in script
    assert 'sleep 5' in script
    assert 'echo 3 > /proc/sys/vm/drop_caches' in script


def test_vm_flush_caches_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = _write_cfg(tmp_path)
    assert (
        _run(
            [
                'vm',
                'flush_caches',
                '--dry_run',
                '--config',
                str(cfg_path),
                '--levels',
                '2,3',
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert 'DRYRUN: would flush guest caches for VM test-vm' in out
    assert 'echo 2 > /proc/sys/vm/drop_caches' in out
    assert 'echo 3 > /proc/sys/vm/drop_caches' in out


def test_vm_flush_caches_runs_guest_command(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-cache'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_aivm'

    monkeypatch.setattr('aivm.cli.vm_cache._load_cfg', lambda *a, **k: cfg)
    monkeypatch.setattr(
        'aivm.cli.vm_cache._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.123',
    )

    seen: dict[str, Any] = {}

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CommandResult:
        seen['cmd'] = cmd
        seen['kwargs'] = kwargs
        return CommandResult(0, 'guest ok\n', '')

    monkeypatch.setattr('aivm.commands.CommandManager.run', fake_run)
    rc = VMFlushCachesCLI.main(argv=False, yes=True, levels='2')
    assert rc == 0
    cmd = seen['cmd']
    assert cmd[:1] == ['ssh']
    assert 'agent@10.77.0.123' in cmd
    remote_script = cmd[-1]
    assert 'echo 2 > /proc/sys/vm/drop_caches' in remote_script
    assert seen['kwargs']['check'] is False
