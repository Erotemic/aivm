"""Host-side orchestration for persistent attachments.

Covers the manifest text, host/guest manifest sync and hash-gated helper
install, the reconcile flow (skip/replay/propagate/continue-on-error) and
the host bind-mount that stages a folder under the export root.
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aivm.attachments.persistent import (
    _install_guest_text_if_changed,
    _install_persistent_host_bind_replay,
    _persistent_attachment_manifest_text,
    _persistent_host_manifest_path,
    _reconcile_persistent_attachments_in_guest,
    _run_guest_root_script,
    _sync_persistent_attachment_manifest_on_host,
    _sync_persistent_attachment_manifest_to_guest,
    _write_text_if_changed,
)
from aivm.commands import CommandError, CommandManager
from aivm.config import AgentVMConfig
from aivm.config_store import AttachmentEntry, Store, save_store
from tests.helpers import FakeCommandManager, FakeProc, activate_manager


def test_persistent_manifest_persists_records_and_access_modes(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    store.attachments.extend(
        [
            AttachmentEntry(
                host_path=str((tmp_path / 'proj-rw').resolve()),
                vm_name=cfg.vm.name,
                mode='persistent',
                access='rw',
                guest_dst='/workspace/rw',
                tag='hostcode-rw',
                host_lexical_paths=[],
            ),
            AttachmentEntry(
                host_path=str((tmp_path / 'proj-ro').resolve()),
                vm_name=cfg.vm.name,
                mode='persistent',
                access='ro',
                guest_dst='/workspace/ro',
                tag='hostcode-ro',
                host_lexical_paths=[str(tmp_path / 'link-ro')],
            ),
            AttachmentEntry(
                host_path=str((tmp_path / 'legacy').resolve()),
                vm_name=cfg.vm.name,
                mode='shared-root',
                access='rw',
                guest_dst='/workspace/legacy',
                tag='hostcode-legacy',
                host_lexical_paths=[],
            ),
        ]
    )
    save_store(store, cfg_path)

    payload = json.loads(_persistent_attachment_manifest_text(cfg, cfg_path))

    assert payload['vm_name'] == cfg.vm.name
    assert payload['shared_root_mount'] == '/mnt/aivm-persistent'
    assert [item['shared_root_token'] for item in payload['records']] == [
        'hostcode-ro',
        'hostcode-rw',
    ]
    assert [item['access'] for item in payload['records']] == ['ro', 'rw']
    assert payload['records'][0]['host_lexical_paths'] == [
        str(tmp_path / 'link-ro')
    ]


def test_persistent_manifest_write_is_byte_for_byte_noop(
    tmp_path: Path,
) -> None:
    path = tmp_path / 'state' / 'persistent-attachments.json'
    assert _write_text_if_changed(path, 'alpha\n') is True
    before = path.read_bytes()
    assert _write_text_if_changed(path, 'alpha\n') is False
    assert path.read_bytes() == before


def test_persistent_host_manifest_path_uses_app_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-app-data'
    cfg.paths.base_dir = '/var/lib/libvirt/aivm/aivm-2404'

    calls: list[tuple[str, str]] = []

    def fake_appdir(appname: str, kind: str) -> Path:
        calls.append((appname, kind))
        return tmp_path / kind

    monkeypatch.setattr('aivm.config_store.paths._appdir', fake_appdir)

    path = _persistent_host_manifest_path(cfg)

    assert calls == [('aivm', 'data')]
    assert (
        path
        == tmp_path
        / 'data'
        / cfg.vm.name
        / 'state'
        / 'persistent-attachments.json'
    )
    assert str(cfg.paths.base_dir) not in str(path)


def test_persistent_manifest_sync_uses_checksum_rsync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)
    activate_manager(monkeypatch)

    calls: list[list[str]] = []

    def handler(cmd: list) -> SimpleNamespace | None:
        if cmd and cmd[0] == 'rsync':
            return SimpleNamespace(
                stdout='>f..t...... persistent-attachments.json\n'
            )
        return SimpleNamespace(stdout='')

    monkeypatch.setattr(
        'aivm.attachments.persistent.CommandManager.current',
        lambda: FakeCommandManager(handler, calls=calls),
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg,
        '10.0.0.5',
        dry_run=False,
    )

    assert changed is True
    assert calls[0][:3] == ['ssh', '-o', 'BatchMode=yes']
    assert any(cmd[0] == 'rsync' for cmd in calls)
    rsync_cmd = next(cmd for cmd in calls if cmd and cmd[0] == 'rsync')
    assert '--checksum' in rsync_cmd
    assert '--itemize-changes' in rsync_cmd


def test_persistent_manifest_sync_retries_transient_ssh_banner_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync-retry'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport.time.sleep', lambda s: None
    )

    calls: list[list[str]] = []
    rsync_calls = {'n': 0}

    def handler(cmd: list) -> SimpleNamespace | None:
        if cmd and cmd[0] == 'ssh':
            return SimpleNamespace(stdout='')
        if cmd and cmd[0] == 'rsync':
            rsync_calls['n'] += 1
            if rsync_calls['n'] == 1:
                return SimpleNamespace(
                    stdout='',
                    stderr=(
                        'Connection timed out during banner exchange\n'
                        'Connection to 10.0.0.5 port 22 timed out'
                    ),
                    code=255,
                )
            return SimpleNamespace(
                stdout='>f..t...... persistent-attachments.json\n',
                stderr='',
                code=0,
            )
        return SimpleNamespace(stdout='')

    monkeypatch.setattr(
        'aivm.attachments.persistent.CommandManager.current',
        lambda: FakeCommandManager(handler, calls=calls),
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg,
        '10.0.0.5',
        dry_run=False,
    )

    assert changed is True
    assert rsync_calls['n'] == 2
    ssh_cmd = next(cmd for cmd in calls if cmd and cmd[0] == 'ssh')
    assert any('ConnectTimeout=15' in arg for arg in ssh_cmd)
    rsync_cmd = next(cmd for cmd in calls if cmd and cmd[0] == 'rsync')
    assert any('ConnectTimeout=15' in arg for arg in rsync_cmd)


@pytest.mark.parametrize(
    'status, expect_install',
    [('MISSING', True), ('MATCH', False), ('MISMATCH', True)],
)
def test_persistent_guest_text_sync_checks_hash_before_installing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
    expect_install: bool,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-install-{status.lower()}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)

    calls: list[tuple[str, str, str | None]] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        del args
        summary = str(kwargs.get('summary') or '')
        script = str(kwargs.get('script') or '')
        role = kwargs.get('role')
        calls.append((summary, script, role))
        if summary == 'Check guest replay helper hash':
            assert 'cmp -s' not in script
            assert 'sha256sum' in script
            assert (
                'MISSING' in script
                and 'MATCH' in script
                and 'MISMATCH' in script
            )
            return SimpleNamespace(stdout=f'{status}\n')
        if summary == 'Install guest replay helper':
            assert expect_install
            assert "printf '%s'" in script
            assert 'install -m 0755' in script
            assert role == 'modify'
            return SimpleNamespace(stdout='')
        if summary == 'Verify guest replay helper hash after install':
            assert expect_install
            return SimpleNamespace(stdout='MATCH\n')
        raise AssertionError(f'unexpected summary: {summary}')

    monkeypatch.setattr(
        'aivm.attachments.persistent.transport._run_guest_root_script',
        fake_run,
    )

    changed = _install_guest_text_if_changed(
        cfg,
        '10.0.0.5',
        target='/usr/local/libexec/aivm-persistent-attachment-replay',
        text='helper body\n',
        mode='0755',
        label='guest replay helper',
        dry_run=False,
    )

    assert changed is expect_install
    assert [summary for summary, _, _ in calls] == (
        [
            'Check guest replay helper hash',
            'Install guest replay helper',
            'Verify guest replay helper hash after install',
        ]
        if expect_install
        else ['Check guest replay helper hash']
    )
    assert all(
        role == 'read' for summary, _, role in calls if 'Check' in summary
    )


def test_persistent_reconcile_skips_replay_when_not_forced_and_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-reconcile-skip'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    activate_manager(monkeypatch)

    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: calls.append(('host', a, k))
        or _persistent_host_manifest_path(cfg),
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
        lambda *a, **k: calls.append(('guest-sync', a, k)) or False,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
        lambda *a, **k: calls.append(('install', a, k)) or False,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport._run_guest_root_script',
        lambda *a, **k: calls.append(('replay', a, k)) or None,
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        replay_even_if_unchanged=False,
    )

    assert [item[0] for item in calls] == ['host', 'guest-sync', 'install']


def test_persistent_manifest_sync_returns_false_when_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync-unchanged'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)

    calls: list[list[str]] = []

    monkeypatch.setattr(
        'aivm.attachments.persistent.CommandManager.current',
        lambda: FakeCommandManager(calls=calls),
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg,
        '10.0.0.5',
        dry_run=False,
    )

    assert changed is False
    assert any(cmd[0] == 'rsync' for cmd in calls)


@pytest.mark.parametrize(
    'phase',
    ['sync', 'install', 'replay'],
)
def test_persistent_reconcile_propagates_primary_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-fail-{phase}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    activate_manager(monkeypatch)

    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: cfg_path,
    )
    if phase == 'sync':
        monkeypatch.setattr(
            'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError('sync boom')),
        )
        monkeypatch.setattr(
            'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
            lambda *a, **k: False,
        )
        monkeypatch.setattr(
            'aivm.attachments.persistent.transport._run_guest_root_script',
            lambda *a, **k: None,
        )
        with pytest.raises(RuntimeError, match='sync boom'):
            _reconcile_persistent_attachments_in_guest(
                cfg,
                cfg_path,
                '10.0.0.5',
                dry_run=False,
            )
    elif phase == 'install':
        monkeypatch.setattr(
            'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
            lambda *a, **k: False,
        )
        monkeypatch.setattr(
            'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError('install boom')),
        )
        monkeypatch.setattr(
            'aivm.attachments.persistent.transport._run_guest_root_script',
            lambda *a, **k: None,
        )
        with pytest.raises(RuntimeError, match='install boom'):
            _reconcile_persistent_attachments_in_guest(
                cfg,
                cfg_path,
                '10.0.0.5',
                dry_run=False,
            )
    else:
        monkeypatch.setattr(
            'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
            lambda *a, **k: False,
        )
        monkeypatch.setattr(
            'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
            lambda *a, **k: False,
        )

        def fake_run(*args: Any, **kwargs: Any) -> Any:
            del args
            if (
                kwargs.get('summary')
                == 'Replay persistent attachment mounts inside guest'
            ):
                raise RuntimeError('replay boom')
            return SimpleNamespace(stdout='')

        monkeypatch.setattr(
            'aivm.attachments.persistent.transport._run_guest_root_script',
            fake_run,
        )
        with pytest.raises(RuntimeError, match='replay boom'):
            _reconcile_persistent_attachments_in_guest(
                cfg,
                cfg_path,
                '10.0.0.5',
                dry_run=False,
            )


@pytest.mark.parametrize(
    'phase',
    [
        pytest.param('sync', id='logs_and_continues'),
        pytest.param('install', id='on_late_failures-install'),
        pytest.param('replay', id='on_late_failures-replay'),
    ],
)
def test_persistent_reconcile_continue_on_error_logs_and_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str
) -> None:
    """continue_on_error demotes a failure at any reconcile phase to a warning.

    Merges the former ``_logs_and_continues`` (sync failure) and
    ``_on_late_failures`` (install/replay failure) tests; the phase axis is
    exactly the stage that raises, mirroring
    ``test_persistent_reconcile_propagates_primary_failures``.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-continue-on-error-{phase}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    activate_manager(monkeypatch)

    warnings: list[str] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay.log.warning',
        lambda fmt, *args: warnings.append(fmt.format(*args)),
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: cfg_path,
    )

    if phase == 'sync':
        monkeypatch.setattr(
            'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError('sync boom')),
        )
    else:
        monkeypatch.setattr(
            'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
            lambda *a, **k: False,
        )
        if phase == 'install':
            monkeypatch.setattr(
                'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
                lambda *a, **k: (_ for _ in ()).throw(
                    RuntimeError('install boom')
                ),
            )
            monkeypatch.setattr(
                'aivm.attachments.persistent.transport._run_guest_root_script',
                lambda *a, **k: None,
            )
        else:
            monkeypatch.setattr(
                'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
                lambda *a, **k: False,
            )

            def fake_run(*args: Any, **kwargs: Any) -> Any:
                del args
                if (
                    kwargs.get('summary')
                    == 'Replay persistent attachment mounts inside guest'
                ):
                    raise RuntimeError('replay boom')
                return SimpleNamespace(stdout='')

            monkeypatch.setattr(
                'aivm.attachments.persistent.transport._run_guest_root_script',
                fake_run,
            )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        continue_on_error=True,
    )

    assert any('persistent-reconcile: VM' in msg for msg in warnings)


def test_persistent_reconcile_continue_on_error_isolates_outer_command_queue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-continue-on-error-isolation'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    outer = CommandManager(yes=True, yes_sudo=True)
    CommandManager.activate(outer)

    pending = outer.submit(
        ['python', '-c', 'import sys; sys.exit(7)'],
        summary='pending outer command',
        eager=False,
    )

    warnings: list[str] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay.log.warning',
        lambda fmt, *args: warnings.append(fmt.format(*args)),
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: cfg_path,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
        lambda *a, **k: False,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
        lambda *a, **k: False,
    )
    replay_calls: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport._run_guest_root_script',
        lambda *a, **k: replay_calls.append(k)
        or SimpleNamespace(code=1, stdout='', stderr='replay boom'),
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        continue_on_error=True,
    )

    assert any('persistent-reconcile: VM' in msg for msg in warnings)
    assert replay_calls and replay_calls[0]['check'] is False
    assert pending.done() is False
    with pytest.raises(CommandError):
        pending.result()


def test_persistent_replay_script_nonchecking_path_avoids_error_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-nonchecking-replay'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)

    calls: list[list[str]] = []

    def fake_subprocess_run(cmd: list, **kwargs: Any) -> Any:
        del kwargs
        calls.append(list(cmd))
        return SimpleNamespace(returncode=1, stdout='', stderr='replay boom')

    errors: list[tuple] = []
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        fake_subprocess_run,
    )
    monkeypatch.setattr(
        'aivm.commands.log.error',
        lambda *args, **kwargs: errors.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match='replay boom'):
        _run_guest_root_script(
            cfg,
            '10.0.0.5',
            script='echo replay',
            summary='Replay persistent attachment mounts inside guest',
            detail='',
            dry_run=False,
            check=False,
        )

    assert calls
    assert not errors


def test_persistent_guest_root_script_retries_transient_banner_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-guest-root-retry'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport.time.sleep', lambda s: None
    )

    calls: list[list[str]] = []
    attempts = {'n': 0}

    def handler(cmd: list) -> SimpleNamespace | None:
        del cmd
        attempts['n'] += 1
        if attempts['n'] == 1:
            return SimpleNamespace(
                code=255,
                stdout='',
                stderr=(
                    'Connection timed out during banner exchange\n'
                    'Connection to 10.0.0.5 port 22 timed out'
                ),
            )
        return SimpleNamespace(code=0, stdout='ok\n', stderr='')

    monkeypatch.setattr(
        'aivm.attachments.persistent.CommandManager.current',
        lambda: FakeCommandManager(handler, calls=calls),
    )

    result = _run_guest_root_script(
        cfg,
        '10.0.0.5',
        script='echo ok',
        summary='Check guest helper',
        detail='',
        dry_run=False,
        check=True,
    )

    assert attempts['n'] == 2
    assert result is not None
    ssh_cmd = calls[0]
    assert ssh_cmd[0] == 'ssh'
    assert any('ConnectTimeout=15' in arg for arg in ssh_cmd)


def test_persistent_reconcile_replays_when_guest_manifest_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-reconcile-changed'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    activate_manager(monkeypatch)

    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: calls.append(('host', a, k))
        or _persistent_host_manifest_path(cfg),
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest._sync_persistent_attachment_manifest_to_guest',
        lambda *a, **k: calls.append(('guest-sync', a, k)) or True,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay._install_persistent_attachment_replay',
        lambda *a, **k: calls.append(('install', a, k)) or False,
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport._run_guest_root_script',
        lambda *a, **k: calls.append(('replay', a, k)) or None,
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
    )

    assert [item[0] for item in calls] == [
        'host',
        'guest-sync',
        'install',
        'replay',
    ]
    assert (
        calls[-1][2]['summary']
        == 'Replay persistent attachment mounts inside guest'
    )


def test_install_persistent_host_bind_replay_enables_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-host-service'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    activate_manager(monkeypatch)

    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport._install_host_text_if_changed',
        lambda *a, **k: calls.append(('install-host-text', a, k)) or True,
    )

    class FakeManager:
        def step(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            return nullcontext()

        def submit(self, cmd: list, **kwargs: Any) -> SimpleNamespace:
            calls.append(('submit', tuple(cmd), kwargs))
            return SimpleNamespace(code=0, stdout='', stderr='')

    monkeypatch.setattr(
        'aivm.attachments.persistent.CommandManager.current',
        lambda: FakeManager(),
    )

    changed = _install_persistent_host_bind_replay(
        cfg,
        cfg_path,
        dry_run=False,
    )

    assert changed is True
    submit_cmds = [item[1] for item in calls if item[0] == 'submit']
    assert ('systemctl', 'daemon-reload') in submit_cmds
    assert (
        'systemctl',
        'enable',
        'aivm-persistent-host-bind-replay-vm-persistent-host-service.service',
    ) in submit_cmds


def test_persistent_root_host_bind_short_circuits_when_already_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Skip the privileged step entirely when target is already bound to source."""
    from aivm.attachments.persistent.host_bind import (
        _ensure_persistent_root_host_bind,
    )
    from aivm.vm.share import AttachmentMode, ResolvedAttachment

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-bound'
    cfg.paths.base_dir = str(tmp_path / 'base')
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(source_dir.resolve()),
        guest_dst='/workspace/source',
        tag='hostcode-source',
    )

    activate_manager(monkeypatch)

    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind._target_is_bind_of',
        lambda *_a, **_k: True,
    )

    def _fail_subprocess(*_a: object, **_k: object) -> FakeProc:
        raise AssertionError(
            'no subprocess should run when the bind is already in place'
        )

    monkeypatch.setattr('aivm.commands.subprocess.run', _fail_subprocess)

    _ensure_persistent_root_host_bind(cfg, attachment, dry_run=False)


def test_persistent_root_host_bind_issues_direct_mount_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When binding is needed, use a plain `mount --bind` argv (no bash script)."""
    from aivm.attachments.persistent.host_bind import (
        _ensure_persistent_root_host_bind,
    )
    from aivm.vm.share import AttachmentMode, ResolvedAttachment

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-bind'
    cfg.paths.base_dir = str(tmp_path / 'base')
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(source_dir.resolve()),
        guest_dst='/workspace/source',
        tag='hostcode-source',
    )

    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind._target_is_bind_of',
        lambda *_a, **_k: False,
    )

    calls: list[list[str]] = []

    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> FakeProc:
        del kwargs
        parts = [str(part) for part in cmd]
        normalized = parts[2:] if parts[:2] == ['sudo', '-n'] else parts
        calls.append(normalized)
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)

    _ensure_persistent_root_host_bind(cfg, attachment, dry_run=False)

    flat = [' '.join(c) for c in calls]
    assert any(line.startswith('mount --bind ') for line in flat), flat
    assert all(not line.startswith('bash -c ') for line in flat), flat


def test_persistent_host_bind_escalates_only_for_the_bind_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`persistent` is the default attachment mode, so this is the hot path.

    On a user-owned storage tree the export directories are created without
    privileges; only `mount --bind`, which has no unprivileged form, escalates.
    """
    from aivm.attachments.persistent.host_bind import (
        _ensure_persistent_root_host_bind,
    )
    from aivm.vm.share import AttachmentMode, ResolvedAttachment

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persist'
    cfg.paths.base_dir = str(tmp_path / 'base')
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(source_dir.resolve()),
        guest_dst='/workspace/source',
        tag='proj',
    )

    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: 1000)
    CommandManager.activate(
        CommandManager(yes=True, yes_sudo=True, privilege_mode='as-needed')
    )
    raw: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        parts = [str(p) for p in cmd]
        raw.append(parts)
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)

    _ensure_persistent_root_host_bind(cfg, attachment, dry_run=False)

    def program(parts: list[str]) -> str:
        rest = parts[2:] if parts[:2] == ['sudo', '-n'] else parts
        rest = rest[1:] if rest[:1] == ['sudo'] else rest
        return rest[0] if rest else ''

    real = [p for p in raw if p[-1:] != ['true']]
    escalated = {program(p) for p in real if p[:1] == ['sudo']}
    plain = {program(p) for p in real if p[:1] != ['sudo']}
    assert 'mkdir' in plain, raw
    assert escalated == {'mount'}, raw
