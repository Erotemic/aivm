"""Tests for the guest-side virtiofs fd guard (``aivm vm fdguard``)."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aivm.cli import AgentVMModalCLI
from aivm.cli.vm_guard import VMFdGuardCLI
from aivm.commands import CommandResult
from aivm.config import AgentVMConfig
from aivm.config_store import Store, save_store, upsert_vm
from aivm.fdguard import (
    FDGUARD_BIN,
    FDGUARD_TIMER,
    fdguard_conf_text,
    fdguard_install_script,
    fdguard_python,
    fdguard_service_unit,
    fdguard_status_script,
    fdguard_timer_unit,
    fdguard_uninstall_script,
)
from aivm.fdguard import fdguard_expected_hashes, parse_fdguard_probe
from aivm.vm.cloudinit import _render_user_data_text
from aivm.vm.update import FdGuardDrift, VMUpdateDrift
from aivm.vm.update.fdguard import _apply_fdguard_drift, _fdguard_drift

STOCK_UPDATEDB_CONF = (
    'PRUNE_BIND_MOUNTS="yes"\n'
    '# PRUNENAMES=".git .bzr .hg .svn"\n'
    'PRUNEPATHS="/tmp /var/spool /media"\n'
    'PRUNEFS="NFS afs autofs fuse.sshfs tmpfs"\n'
)


def _slabinfo_text(fuse_inodes: int) -> str:
    return (
        'slabinfo - version: 2.1\n'
        '# name <active_objs> <num_objs> <objsize>\n'
        'dentry 132000 140000 192 21 1 : tunables 0 0 0\n'
        f'fuse_inode {fuse_inodes} {fuse_inodes + 400} 896 36 8 : tunables 0 0 0\n'
    )


class _GuardHarness:
    """Run the rendered guard script against fixture files."""

    def __init__(self, tmp_path: Path):
        self.tmp_path = tmp_path
        self.script = tmp_path / 'guard.py'
        self.script.write_text(fdguard_python(), encoding='utf-8')
        self.conf = tmp_path / 'guard.conf'
        self.slabinfo = tmp_path / 'slabinfo'
        self.drop_caches = tmp_path / 'drop_caches'
        self.updatedb_conf = tmp_path / 'updatedb.conf'
        self.state = tmp_path / 'state.json'
        self.conf.write_text(fdguard_conf_text(200000), encoding='utf-8')
        self.drop_caches.write_text('', encoding='utf-8')
        self.updatedb_conf.write_text(STOCK_UPDATEDB_CONF, encoding='utf-8')

    def env(self) -> dict[str, str]:
        import os

        return dict(
            os.environ,
            AIVM_VIRTIOFS_GUARD_CONF=str(self.conf),
            AIVM_VIRTIOFS_GUARD_SLABINFO=str(self.slabinfo),
            AIVM_VIRTIOFS_GUARD_DROP_CACHES=str(self.drop_caches),
            AIVM_VIRTIOFS_GUARD_UPDATEDB_CONF=str(self.updatedb_conf),
            AIVM_VIRTIOFS_GUARD_STATE=str(self.state),
        )

    def run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.script), *argv],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=30,
        )


def test_fdguard_python_compiles() -> None:
    compile(fdguard_python(), 'aivm-virtiofs-guard', 'exec')


def test_fdguard_adds_virtiofs_to_prunefs_idempotently(tmp_path: Path) -> None:
    harness = _GuardHarness(tmp_path)
    harness.slabinfo.write_text(_slabinfo_text(100), encoding='utf-8')
    res = harness.run()
    assert res.returncode == 0
    assert 'added virtiofs fuse.virtiofs to PRUNEFS' in res.stdout
    prunefs = [
        line
        for line in harness.updatedb_conf.read_text().splitlines()
        if line.startswith('PRUNEFS')
    ][0]
    assert prunefs.startswith('PRUNEFS="virtiofs fuse.virtiofs NFS')
    # Non-PRUNEFS lines are untouched.
    assert 'PRUNE_BIND_MOUNTS="yes"' in harness.updatedb_conf.read_text()
    # Second run makes no further edits and stays silent.
    res2 = harness.run()
    assert res2.returncode == 0
    assert res2.stdout == ''
    assert harness.updatedb_conf.read_text().count('virtiofs') == 2


def test_fdguard_flushes_above_threshold(tmp_path: Path) -> None:
    harness = _GuardHarness(tmp_path)
    harness.slabinfo.write_text(_slabinfo_text(250000), encoding='utf-8')
    res = harness.run()
    assert res.returncode == 0
    assert 'flushed guest dentry/inode caches' in res.stdout
    assert harness.drop_caches.read_text() == '2\n'
    state = json.loads(harness.state.read_text())
    assert state['post'] == 250000
    # The fixture count cannot shrink, so the pinned-floor warning fires.
    assert 'pinned by open files or inotify watchers' in res.stdout


def test_fdguard_silent_below_threshold(tmp_path: Path) -> None:
    harness = _GuardHarness(tmp_path)
    harness.slabinfo.write_text(_slabinfo_text(100), encoding='utf-8')
    harness.updatedb_conf.write_text(
        'PRUNEFS="virtiofs fuse.virtiofs NFS"\n', encoding='utf-8'
    )
    res = harness.run()
    assert res.returncode == 0
    assert res.stdout == ''
    assert harness.drop_caches.read_text() == ''


def test_fdguard_cooldown_suppresses_reflush(tmp_path: Path) -> None:
    harness = _GuardHarness(tmp_path)
    harness.slabinfo.write_text(_slabinfo_text(250000), encoding='utf-8')
    assert 'flushed' in harness.run().stdout
    harness.drop_caches.write_text('', encoding='utf-8')
    # Count unchanged (pinned floor) within cooldown: no second flush.
    res = harness.run()
    assert 'flushed' not in res.stdout
    assert harness.drop_caches.read_text() == ''


def test_fdguard_status_reports_fields(tmp_path: Path) -> None:
    harness = _GuardHarness(tmp_path)
    harness.slabinfo.write_text(_slabinfo_text(1234), encoding='utf-8')
    res = harness.run('--status')
    assert res.returncode == 0
    assert 'fuse_inode active: 1234' in res.stdout
    assert 'threshold: 200000' in res.stdout
    assert 'updatedb prunes virtiofs: NO' in res.stdout
    # Status is read-only: it must not edit updatedb.conf or flush.
    assert harness.updatedb_conf.read_text() == STOCK_UPDATEDB_CONF
    assert harness.drop_caches.read_text() == ''


def test_fdguard_conf_and_units_render() -> None:
    assert 'THRESHOLD=42' in fdguard_conf_text(42)
    with pytest.raises(ValueError):
        fdguard_conf_text(0)
    assert f'ExecStart={FDGUARD_BIN}' in fdguard_service_unit()
    assert 'OnUnitActiveSec=90s' in fdguard_timer_unit(90)
    with pytest.raises(ValueError):
        fdguard_timer_unit(-1)


def test_fdguard_install_script_payloads_round_trip() -> None:
    script = fdguard_install_script(threshold=314159, interval_sec=45)
    payloads = re.findall(r"printf '%s' ([A-Za-z0-9+/=]+) \| base64 -d", script)
    assert len(payloads) == 4
    decoded = [base64.b64decode(p).decode('utf-8') for p in payloads]
    assert decoded[0] == fdguard_python()
    assert decoded[1] == fdguard_conf_text(314159)
    assert decoded[2] == fdguard_service_unit()
    assert decoded[3] == fdguard_timer_unit(45)
    assert f'systemctl enable --now {FDGUARD_TIMER}' in script
    assert 'sudo -n' in script


def test_fdguard_status_and_uninstall_scripts() -> None:
    assert FDGUARD_BIN in fdguard_status_script()
    assert f'systemctl disable --now {FDGUARD_TIMER}' in fdguard_uninstall_script()


def test_cloud_init_includes_fdguard_by_default() -> None:
    cfg = AgentVMConfig()
    text = _render_user_data_text(cfg, pubkey='ssh-ed25519 AAAA test')
    assert FDGUARD_BIN in text
    assert f'systemctl enable --now {FDGUARD_TIMER}' in text
    assert 'THRESHOLD=500000' in text


def test_cloud_init_omits_fdguard_when_disabled() -> None:
    cfg = AgentVMConfig()
    cfg.virtiofs.fd_guard = False
    text = _render_user_data_text(cfg, pubkey='ssh-ed25519 AAAA test')
    assert 'aivm-virtiofs-guard' not in text


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


def test_vm_fdguard_dry_run_actions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg_path = _write_cfg(tmp_path)
    for action in ('status', 'install', 'uninstall'):
        assert (
            _run(
                [
                    'vm',
                    'fdguard',
                    '--dry_run',
                    '--action',
                    action,
                    '--config',
                    str(cfg_path),
                ]
            )
            == 0
        )
        out = capsys.readouterr().out
        assert f'DRYRUN: would run fdguard {action} for VM test-vm' in out


def test_vm_fdguard_rejects_bad_action(tmp_path: Path) -> None:
    cfg_path = _write_cfg(tmp_path)
    with pytest.raises(RuntimeError, match='invalid action'):
        VMFdGuardCLI.main(
            argv=False,
            action='explode',
            dry_run=True,
            config=str(cfg_path),
        )


def test_parse_fdguard_probe_ignores_noise() -> None:
    state = parse_fdguard_probe(
        "Warning: Permanently added '10.0.0.5' to known hosts.\n"
        'installed=yes\n'
        'timer_enabled=enabled\n'
        'sha_bin=abc123\n'
        'sha_conf=\n'
        '\n'
    )
    assert state['installed'] == 'yes'
    assert state['sha_bin'] == 'abc123'
    assert state['sha_conf'] == ''
    assert 'Warning: Permanently added' not in state


def test_vm_update_drift_has_changes_includes_fd_guard() -> None:
    empty = VMUpdateDrift()
    assert not empty.has_changes()
    with_guard = VMUpdateDrift(
        fd_guard=FdGuardDrift(action='install', reason='missing')
    )
    assert with_guard.has_changes()


def _drift_cfg(tmp_path: Path) -> AgentVMConfig:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-drift'
    cfg.vm.user = 'agent'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    cfg.paths.state_dir = str(tmp_path / 'state')
    identity = tmp_path / 'id_ed25519'
    identity.write_text('key', encoding='utf-8')
    cfg.paths.ssh_identity_file = str(identity)
    return cfg


def _probe_output(cfg: AgentVMConfig, **overrides: str) -> str:
    expected = fdguard_expected_hashes(
        threshold=int(cfg.virtiofs.fd_guard_threshold),
        interval_sec=int(cfg.virtiofs.fd_guard_interval_sec),
    )
    state = {
        'installed': 'yes',
        'timer_enabled': 'enabled',
        **expected,
        **overrides,
    }
    return ''.join(f'{key}={value}\n' for key, value in state.items())


def _patch_reachable_guest(
    monkeypatch: pytest.MonkeyPatch, probe_stdout: str
) -> dict[str, Any]:
    from types import SimpleNamespace

    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        'aivm.vm.update.fdguard.get_ip_cached', lambda cfg: '10.0.0.5'
    )
    monkeypatch.setattr(
        'aivm.vm.update.fdguard.probe_ssh_ready',
        lambda cfg, ip: SimpleNamespace(ok=True),
    )

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CommandResult:
        seen.setdefault('cmds', []).append(cmd)
        seen['kwargs'] = kwargs
        return CommandResult(0, probe_stdout, '')

    monkeypatch.setattr('aivm.vm.update.fdguard.CommandManager.run', fake_run)
    return seen


def test_fdguard_drift_skips_when_vm_not_running(tmp_path: Path) -> None:
    cfg = _drift_cfg(tmp_path)
    drift, notes = _fdguard_drift(cfg, vm_running=False)
    assert drift is None
    assert any('not running' in note for note in notes)


def test_fdguard_drift_skips_when_guest_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    monkeypatch.setattr(
        'aivm.vm.update.fdguard.get_ip_cached', lambda cfg: None
    )
    drift, notes = _fdguard_drift(cfg, vm_running=True)
    assert drift is None
    assert any('SSH' in note for note in notes)


def test_fdguard_drift_none_when_in_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    _patch_reachable_guest(monkeypatch, _probe_output(cfg))
    drift, notes = _fdguard_drift(cfg, vm_running=True)
    assert drift is None
    assert notes == ()


def test_fdguard_drift_installs_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    _patch_reachable_guest(
        monkeypatch,
        'installed=no\ntimer_enabled=not-found\nsha_bin=\n',
    )
    drift, _ = _fdguard_drift(cfg, vm_running=True)
    assert drift is not None
    assert drift.action == 'install'
    assert 'not installed' in drift.reason
    assert drift.ip == '10.0.0.5'


def test_fdguard_drift_installs_on_stale_conf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    _patch_reachable_guest(
        monkeypatch, _probe_output(cfg, sha_conf='deadbeef')
    )
    drift, _ = _fdguard_drift(cfg, vm_running=True)
    assert drift is not None
    assert drift.action == 'install'
    assert 'conf' in drift.reason


def test_fdguard_drift_uninstalls_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    cfg.virtiofs.fd_guard = False
    _patch_reachable_guest(monkeypatch, _probe_output(cfg))
    drift, _ = _fdguard_drift(cfg, vm_running=True)
    assert drift is not None
    assert drift.action == 'uninstall'


def test_fdguard_drift_none_when_disabled_and_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    cfg.virtiofs.fd_guard = False
    _patch_reachable_guest(
        monkeypatch, 'installed=no\ntimer_enabled=not-found\n'
    )
    drift, _ = _fdguard_drift(cfg, vm_running=True)
    assert drift is None


def test_apply_fdguard_drift_dry_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _drift_cfg(tmp_path)
    drift = VMUpdateDrift(
        fd_guard=FdGuardDrift(action='install', reason='missing', ip='10.0.0.5')
    )
    assert _apply_fdguard_drift(cfg, drift, dry_run=True) is True
    out = capsys.readouterr().out
    assert 'DRYRUN: would install virtiofs fd guard' in out


def test_apply_fdguard_drift_runs_install_over_ssh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _drift_cfg(tmp_path)
    seen = _patch_reachable_guest(monkeypatch, 'aivm: virtiofs guard installed\n')
    drift = VMUpdateDrift(
        fd_guard=FdGuardDrift(action='install', reason='missing', ip='10.0.0.5')
    )
    assert _apply_fdguard_drift(cfg, drift, dry_run=False) is True
    cmd = seen['cmds'][-1]
    assert cmd[:1] == ['ssh']
    assert 'agent@10.0.0.5' in cmd
    assert cmd[-1].startswith("sh -c 'set -eu")
    assert 'base64 -d' in cmd[-1]
    assert seen['kwargs']['check'] is True
    assert 'Installed/refreshed virtiofs fd guard' in capsys.readouterr().out


def test_apply_fdguard_drift_runs_uninstall_over_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _drift_cfg(tmp_path)
    seen = _patch_reachable_guest(
        monkeypatch, 'aivm: virtiofs guard uninstalled\n'
    )
    drift = VMUpdateDrift(
        fd_guard=FdGuardDrift(
            action='uninstall', reason='disabled', ip='10.0.0.5'
        )
    )
    assert _apply_fdguard_drift(cfg, drift, dry_run=False) is True
    assert 'systemctl disable --now' in seen['cmds'][-1][-1]


def test_vm_fdguard_install_runs_quoted_remote_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-guard'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_aivm'

    monkeypatch.setattr('aivm.cli.vm_guard._load_cfg', lambda *a, **k: cfg)
    monkeypatch.setattr(
        'aivm.cli.vm_guard._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.123',
    )

    seen: dict[str, Any] = {}

    def fake_run(self: object, cmd: list[str], **kwargs: Any) -> CommandResult:
        seen['cmd'] = cmd
        return CommandResult(0, 'aivm: virtiofs guard installed\n', '')

    monkeypatch.setattr('aivm.commands.CommandManager.run', fake_run)
    rc = VMFdGuardCLI.main(argv=False, yes=True, action='install')
    assert rc == 0
    cmd = seen['cmd']
    assert cmd[:1] == ['ssh']
    assert 'agent@10.77.0.123' in cmd
    remote_command = cmd[-1]
    # The whole guest script must be one properly quoted sh -c argument so
    # `set -eu` semantics apply on the remote side.
    assert remote_command.startswith("sh -c 'set -eu")
    assert 'base64 -d' in remote_command
