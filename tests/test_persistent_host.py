"""Host-side orchestration for persistent attachments.

Covers the manifest text, host/guest manifest sync and hash-gated helper
install, the reconcile flow (skip/replay/propagate/continue-on-error) and
the host bind-mount that stages a folder under the export root.

These tests fake only the real process boundary
(``aivm.commands.subprocess.run``, via :func:`command_recorder`) and let the
production ``transport``/``manifest``/``replay`` code run for real.  They
assert on observable artifacts -- the manifest file written to disk, the
recorded command log, and captured log output -- rather than on which
internal collaborator was called.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Callable

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
from aivm.persistent_replay import (
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
)
from tests.helpers import (
    CommandRecorder,
    FakeProc,
    activate_manager,
    capture_logs,
    command_recorder,
)

REPLAY_INVOCATION = f'sudo -n {shlex.quote(PERSISTENT_ATTACHMENT_REPLAY_BIN)}'
"""The exact remote script the reconcile flow runs to replay guest mounts."""


# ---------------------------------------------------------------------------
# Local helpers for reading artifacts back out of the recorder
# ---------------------------------------------------------------------------


def _redirect_appdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the user-owned app-data dir (host manifest home) at ``tmp_path``.

    This is the enabler that lets the real
    ``_sync_persistent_attachment_manifest_on_host`` write the canonical
    manifest into the sandbox where the test can read it back.
    """
    monkeypatch.setattr(
        'aivm.config_store.paths._appdir',
        lambda appname, kind: tmp_path / kind,
    )


def _ssh_scripts(rec: CommandRecorder) -> list[str]:
    """Every remote script (the last argv token) an ``ssh`` command carried."""
    return [cmd[-1] for cmd in rec.normalized if cmd and cmd[0] == 'ssh']


def _redirect_replay_state_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """Point the root-owned replay-manifest namespace at ``tmp_path``.

    Keeps the ``exists()`` gate and any securing/install commands aimed at
    the sandbox rather than the host's real ``/var/lib/aivm``.  The sandbox
    dir does not exist and is not root-owned, so when replay state *is*
    needed the safety probe deterministically reports it unsafe.
    """
    state_dir = tmp_path / 'approved-replay-state'
    monkeypatch.setattr(
        'aivm.attachments.persistent.manifest.'
        'PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR',
        str(state_dir),
    )
    return state_dir


def _record_persistent_attachment(
    cfg: AgentVMConfig, cfg_path: Path, tmp_path: Path
) -> None:
    """Persist one enabled persistent attachment record for ``cfg``'s VM."""
    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str((tmp_path / 'proj').resolve()),
            vm_name=cfg.vm.name,
            mode='persistent',
            access='rw',
            guest_dst='/workspace/proj',
            tag='hostcode-proj',
            host_lexical_paths=[],
        )
    )
    save_store(store, cfg_path)


def _replay_state_routes() -> dict[str, FakeProc]:
    """Recorder routes for the host-side root replay-manifest sync.

    When a VM has persistent records (or a previously installed manifest),
    reconcile secures a root-owned state dir (``bash -c 'install -d ...'``)
    and installs the approved manifest (``install``/``rm``) before touching
    the guest; these argv commands are host-local and never carry an ssh
    script, so they stay out of ``_ssh_scripts`` assertions.
    """
    return {
        'bash': FakeProc(),
        'install': FakeProc(),
        'rm': FakeProc(),
    }


def _hash_route(
    initial_status: str,
    *,
    fail_when: Callable[[str], bool] | None = None,
    fail_proc: FakeProc | None = None,
) -> Callable[[list[str]], FakeProc]:
    """Build a guest-ssh route for the recorder.

    The first hash-check of any given script reports ``initial_status`` (the
    drift the guest starts in); a later check of the same script -- the
    post-install verify -- reports ``MATCH`` so installs are accepted.  When
    ``fail_when`` matches a remote script, ``fail_proc`` is returned so a
    single reconcile phase can be made to fail.
    """
    seen: dict[str, int] = {}

    def route(cmd: list[str]) -> FakeProc:
        script = cmd[-1]
        if fail_when is not None and fail_proc is not None:
            if fail_when(script):
                return fail_proc
        if 'sha256sum' in script:
            count = seen.get(script, 0)
            seen[script] = count + 1
            status = initial_status if count == 0 else 'MATCH'
            return FakeProc(stdout=f'{status}\n')
        return FakeProc()

    return route


# ---------------------------------------------------------------------------
# Manifest model + on-disk write (pure; no process boundary involved)
# ---------------------------------------------------------------------------


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

    # The manifest is a wire format: the host writes it, the in-guest replay
    # helper reads it. Nothing in the code validates schema_version, so pin
    # it here -- bumping it is a guest-compatibility decision, not a typo.
    assert payload['schema_version'] == 1
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


def test_persistent_host_replay_manifest_path_is_root_owned_namespace() -> None:
    """The replay manifest lives in root-owned storage, VM name flattened."""
    from aivm.attachments.persistent import (
        _persistent_host_replay_manifest_path,
    )

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm/unsafe name'
    path = _persistent_host_replay_manifest_path(cfg)

    assert path.parent == Path('/var/lib/aivm/persistent-host')
    assert '/' not in path.name
    assert path.suffix == '.json'


def test_persistent_manifest_sync_uses_checksum_rsync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The host manifest lands on disk and rsync pushes it by checksum.

    Asserts the artifacts: the JSON file the on-host sync writes into the
    sandbox and the exact rsync/ssh argv the guest push records.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    store.attachments.append(
        AttachmentEntry(
            host_path=str((tmp_path / 'proj').resolve()),
            vm_name=cfg.vm.name,
            mode='persistent',
            access='rw',
            guest_dst='/workspace/proj',
            tag='hostcode-proj',
            host_lexical_paths=[],
        )
    )
    save_store(store, cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    manifest_path = _sync_persistent_attachment_manifest_on_host(
        cfg, cfg_path, dry_run=False
    )
    # The canonical manifest is really on disk with the real record content.
    payload = json.loads(manifest_path.read_text())
    assert payload['vm_name'] == cfg.vm.name
    assert [rec['shared_root_token'] for rec in payload['records']] == [
        'hostcode-proj'
    ]

    rec = command_recorder(
        monkeypatch,
        {
            'ssh': FakeProc(stdout=''),
            'rsync': FakeProc(
                stdout='>f..t...... persistent-attachments.json\n'
            ),
        },
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg, '10.0.0.5', dry_run=False
    )

    assert changed is True
    ssh_cmd = rec.only('ssh')
    assert ssh_cmd[:3] == ['ssh', '-o', 'BatchMode=yes']
    rsync_cmd = rec.only('rsync')
    assert '--checksum' in rsync_cmd
    assert '--itemize-changes' in rsync_cmd
    # The push writes through the guest's privileged rsync.
    idx = rsync_cmd.index('--rsync-path')
    assert rsync_cmd[idx + 1] == 'sudo -n rsync'
    # The source really is the manifest the on-host step just wrote.
    assert str(manifest_path) in rsync_cmd


def test_persistent_manifest_sync_retries_transient_ssh_banner_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A transient rsync banner failure is retried, then succeeds.

    Asserts on the recorded rsync argv (retried twice, carrying the connect
    timeout) rather than on a stubbed sync collaborator.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync-retry'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport.time.sleep', lambda s: None
    )
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)

    attempts = {'rsync': 0}

    def rsync_route(cmd: list[str]) -> FakeProc:
        attempts['rsync'] += 1
        if attempts['rsync'] == 1:
            return FakeProc(
                returncode=255,
                stderr=(
                    'Connection timed out during banner exchange\n'
                    'Connection to 10.0.0.5 port 22 timed out'
                ),
            )
        return FakeProc(stdout='>f..t...... persistent-attachments.json\n')

    rec = command_recorder(
        monkeypatch,
        {'ssh': FakeProc(stdout=''), 'rsync': rsync_route},
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg, '10.0.0.5', dry_run=False
    )

    assert changed is True
    assert attempts['rsync'] == 2
    assert rec.count('rsync') == 2
    ssh_cmd = rec.calls[0]
    assert ssh_cmd[0] == 'ssh'
    assert any('ConnectTimeout=15' in arg for arg in ssh_cmd)
    rsync_cmd = next(cmd for cmd in rec.normalized if cmd[:1] == ['rsync'])
    assert any('ConnectTimeout=15' in arg for arg in rsync_cmd)


def test_persistent_manifest_sync_returns_false_when_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty rsync itemize report means the guest manifest was unchanged."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-sync-unchanged'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)

    rec = command_recorder(
        monkeypatch,
        {'ssh': FakeProc(stdout=''), 'rsync': FakeProc(stdout='')},
    )

    changed = _sync_persistent_attachment_manifest_to_guest(
        cfg, '10.0.0.5', dry_run=False
    )

    assert changed is False
    assert rec.ran('rsync')


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
    """A checksum probe gates the guest install; MATCH installs nothing.

    Lets the real hash-check / install / verify scripts run over ssh and
    asserts on the sequence and content of the recorded remote scripts.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-install-{status.lower()}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)

    rec = command_recorder(monkeypatch, {'ssh': _hash_route(status)})

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
    scripts = _ssh_scripts(rec)

    def _kind(script: str) -> str:
        if 'install -m' in script:
            return 'install'
        if 'sha256sum' in script:
            return 'check'
        return 'other'

    if expect_install:
        assert [_kind(s) for s in scripts] == ['check', 'install', 'check']
        install_script = scripts[1]
        assert 'install -m 0755' in install_script
        assert "printf '%s'" in install_script
    else:
        assert [_kind(s) for s in scripts] == ['check']
    # Every check script really does a checksum comparison, not a byte cmp.
    check_script = scripts[0]
    assert 'sha256sum' in check_script
    assert 'cmp -s' not in check_script
    assert all(
        token in check_script for token in ('MISSING', 'MATCH', 'MISMATCH')
    )


def test_persistent_reconcile_skips_replay_when_not_forced_and_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When nothing drifted and replay is not forced, no replay runs.

    The observable artifact is the recorded command log: hash checks happen
    but no install, no daemon-reload and no replay-helper invocation appear.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-reconcile-skip'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {
            'ssh': _hash_route('MATCH'),
            'rsync': FakeProc(stdout=''),
        },
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        replay_even_if_unchanged=False,
    )

    # Host manifest really landed on disk.
    manifest_path = _persistent_host_manifest_path(cfg)
    assert json.loads(manifest_path.read_text())['vm_name'] == cfg.vm.name

    scripts = _ssh_scripts(rec)
    assert rec.ran('rsync')
    assert any('sha256sum' in s for s in scripts)
    assert not any('install -m' in s for s in scripts)
    assert not any('systemctl daemon-reload' in s for s in scripts)
    assert REPLAY_INVOCATION not in scripts


def test_persistent_reconcile_replays_when_guest_manifest_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Drift triggers install (with daemon-reload) and a final replay.

    Exercises the whole install path -- helper + unit are written, the unit
    change reloads systemd, and the replay helper runs last -- asserting on
    the recorded remote scripts.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-reconcile-changed'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {
            'ssh': _hash_route('MISSING'),
            'rsync': FakeProc(
                stdout='>f..t...... persistent-attachments.json\n'
            ),
        },
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
    )

    scripts = _ssh_scripts(rec)
    # Both guest text files were installed (helper 0755, unit 0644).
    assert any('install -m 0755' in s for s in scripts)
    assert any('install -m 0644' in s for s in scripts)
    # The changed unit reloads systemd and re-enables the replay service.
    assert any(
        'systemctl daemon-reload' in s
        and f'systemctl enable {PERSISTENT_ATTACHMENT_REPLAY_SERVICE}' in s
        for s in scripts
    )
    # Replay is the final remote action.
    assert scripts[-1] == REPLAY_INVOCATION


@pytest.mark.parametrize('phase', ['sync', 'install', 'replay'])
def test_persistent_reconcile_propagates_primary_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, phase: str
) -> None:
    """A failure at any reconcile phase propagates as a CommandError.

    The failure is a real non-zero exit from the faked process boundary at
    the phase under test, not a stubbed collaborator raising.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-fail-{phase}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    boom = FakeProc(returncode=1, stderr=f'{phase} boom')
    if phase == 'sync':
        routes: dict[Any, Any] = {'ssh': FakeProc(), 'rsync': boom}
    elif phase == 'install':
        routes = {
            'ssh': _hash_route(
                'MISSING',
                fail_when=lambda s: 'install -m' in s,
                fail_proc=boom,
            ),
            'rsync': FakeProc(stdout=''),
        }
    else:
        routes = {
            'ssh': _hash_route(
                'MATCH',
                fail_when=lambda s: s == REPLAY_INVOCATION,
                fail_proc=boom,
            ),
            'rsync': FakeProc(stdout=''),
        }

    command_recorder(monkeypatch, routes)

    with pytest.raises(CommandError):
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
    ``test_persistent_reconcile_propagates_primary_failures``.  The captured
    warning is the artifact.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-persistent-continue-on-error-{phase}'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    warnings = capture_logs(
        monkeypatch,
        'aivm.attachments.persistent.replay.log',
        levels=('warning',),
    )

    boom = FakeProc(returncode=1, stderr=f'{phase} boom')
    if phase == 'sync':
        routes: dict[Any, Any] = {'ssh': FakeProc(), 'rsync': boom}
    elif phase == 'install':
        routes = {
            'ssh': _hash_route(
                'MISSING',
                fail_when=lambda s: 'install -m' in s,
                fail_proc=boom,
            ),
            'rsync': FakeProc(stdout=''),
        }
    else:
        routes = {
            'ssh': _hash_route(
                'MATCH',
                fail_when=lambda s: s == REPLAY_INVOCATION,
                fail_proc=boom,
            ),
            'rsync': FakeProc(stdout=''),
        }

    command_recorder(monkeypatch, routes)

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
    """A failing reconcile runs on an isolated manager, sparing outer work.

    The pending command queued on the outer manager is neither flushed nor
    discarded by the reconcile's failure; it still runs (and fails) only when
    the caller later awaits it.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-continue-on-error-isolation'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: 1000)
    outer = CommandManager(yes=True, yes_sudo=True)
    CommandManager.activate(outer)

    pending = outer.submit(
        ['python', '-c', 'import sys; sys.exit(7)'],
        summary='pending outer command',
        eager=False,
    )

    warnings = capture_logs(
        monkeypatch,
        'aivm.attachments.persistent.replay.log',
        levels=('warning',),
    )
    rec = command_recorder(
        monkeypatch,
        {
            'ssh': _hash_route(
                'MATCH',
                fail_when=lambda s: s == REPLAY_INVOCATION,
                fail_proc=FakeProc(returncode=1, stderr='replay boom'),
            ),
            'rsync': FakeProc(stdout=''),
            'python': FakeProc(returncode=7),
        },
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        continue_on_error=True,
    )

    assert any('persistent-reconcile: VM' in msg for msg in warnings)
    # The reconcile really attempted the replay (and it really failed).
    assert REPLAY_INVOCATION in _ssh_scripts(rec)
    # The outer manager's queued command is untouched until awaited.
    assert pending.done() is False
    with pytest.raises(CommandError):
        pending.result()


def test_persistent_replay_script_nonchecking_path_avoids_error_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-checking guest failure raises but stays off the error log.

    ``check=False`` means the command layer must not itself log an error;
    the caller re-raises the guest stderr as a RuntimeError instead.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-nonchecking-replay'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {'ssh': FakeProc(returncode=1, stderr='replay boom')},
    )
    errors: list[tuple[Any, Any]] = []
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

    assert rec.ran('ssh')
    assert not errors


def test_persistent_guest_root_script_retries_transient_banner_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A transient ssh banner failure is retried before succeeding.

    Asserts on the recorded ssh argv (two attempts, carrying the connect
    timeout) rather than on a scripted command manager.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-guest-root-retry'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.persistent.transport.time.sleep', lambda s: None
    )

    attempts = {'n': 0}

    def ssh_route(cmd: list[str]) -> FakeProc:
        attempts['n'] += 1
        if attempts['n'] == 1:
            return FakeProc(
                returncode=255,
                stderr=(
                    'Connection timed out during banner exchange\n'
                    'Connection to 10.0.0.5 port 22 timed out'
                ),
            )
        return FakeProc(returncode=0, stdout='ok\n')

    rec = command_recorder(monkeypatch, {'ssh': ssh_route})

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
    assert rec.count('ssh') == 2
    assert result is not None
    ssh_cmd = rec.calls[0]
    assert ssh_cmd[0] == 'ssh'
    assert any('ConnectTimeout=15' in arg for arg in ssh_cmd)


def test_install_persistent_host_bind_replay_enables_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Installing the host replay unit reloads systemd and enables the service.

    Lets the real host-text install run and asserts on the recorded
    ``install`` / ``systemctl`` argv it submits.  The VM has a persistent
    attachment recorded -- without one the install is deliberately a no-op
    (see the state-gate tests below).
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-host-service'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    _record_persistent_attachment(cfg, cfg_path, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(monkeypatch, default=FakeProc())

    changed = _install_persistent_host_bind_replay(
        cfg,
        cfg_path,
        dry_run=False,
    )

    assert changed is True
    # The helper and unit are installed to their host locations.
    assert rec.ran('install', '-m', '0755')
    assert rec.ran('install', '-m', '0644')
    # The changed unit reloads systemd and enables the per-VM service.
    service_name = (
        'aivm-persistent-host-bind-replay-vm-persistent-host-service.service'
    )
    assert ['systemctl', 'daemon-reload'] in rec.normalized
    assert ['systemctl', 'enable', service_name] in rec.normalized


def test_persistent_host_replay_state_untouched_without_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No persistent records and nothing installed → zero host commands.

    The root-owned replay state (/var/lib/aivm) exists for persistent
    attachments; a VM that has none must not demand root to materialize it.
    This is the `vm up` path under privilege_mode='never': the recorder has
    no routes, so any command at all -- notably the sudo `install -d`
    securing step -- fails the test.
    """
    from aivm.attachments.persistent import (
        _reconcile_persistent_host_binds,
        _sync_persistent_host_replay_manifest,
    )

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-no-persistent'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)  # a VM with no attachments at all
    _redirect_appdir(monkeypatch, tmp_path)
    state_dir = _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    target = _sync_persistent_host_replay_manifest(
        cfg, cfg_path, dry_run=False
    )
    installed = _install_persistent_host_bind_replay(
        cfg, cfg_path, dry_run=False
    )
    _reconcile_persistent_host_binds(cfg, cfg_path, dry_run=False)

    assert rec.normalized == []
    assert installed is False
    assert target.parent == state_dir
    assert not state_dir.exists()


def test_persistent_host_replay_manifest_still_updates_after_last_detach(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An installed manifest keeps tracking records down to empty.

    Detaching the last persistent folder leaves no records, but the root
    replay service still holds the old manifest; the sync must rewrite it to
    the empty desired state rather than skip.  The staged manifest content
    is captured at the faked install boundary and is the artifact.
    """
    from aivm.attachments.persistent import (
        _sync_persistent_host_replay_manifest,
    )

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-detached-persistent'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)  # records already gone
    _redirect_appdir(monkeypatch, tmp_path)
    state_dir = _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    # The previously installed manifest, still naming a record.
    from aivm.attachments.persistent import (
        _persistent_host_replay_manifest_path,
    )

    state_dir.mkdir(parents=True)
    manifest_path = _persistent_host_replay_manifest_path(cfg)
    manifest_path.write_text('{"records": [{"tag": "old"}]}', encoding='utf-8')

    staged: list[str] = []

    def capture_manifest(cmd: list[str]) -> FakeProc:
        # install -m 0644 -o root -g root <tmpfile> <target>: read the staged
        # file now, before the sync's finally-block unlinks it.
        staged.append(Path(cmd[-2]).read_text(encoding='utf-8'))
        return FakeProc()

    rec = command_recorder(
        monkeypatch,
        {**_replay_state_routes(), ('install', '-m', '0644'): capture_manifest},
    )

    _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)

    assert rec.ran('install')
    assert len(staged) == 1
    assert json.loads(staged[0])['records'] == []


def test_persistent_root_host_bind_short_circuits_when_already_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An existing bind is probed for access mode but never re-mounted."""
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

    # Strict recorder: the read-only findmnt access probe is the only
    # subprocess allowed; a mount/remount would raise as unrouted.
    rec = command_recorder(
        monkeypatch,
        {
            'findmnt -P -n': FakeProc(
                0,
                'SOURCE="/source" ROOT="" FSTYPE="none" OPTIONS="rw"',
                '',
            ),
        },
    )

    _ensure_persistent_root_host_bind(cfg, attachment, dry_run=False)

    assert len(rec.normalized) == 1
    assert rec.only('findmnt')[:6] == [
        'findmnt',
        '-P',
        '-n',
        '-o',
        'SOURCE,ROOT,FSTYPE,OPTIONS',
        '--mountpoint',
    ]


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

    rec = command_recorder(monkeypatch, default=FakeProc(0, '', ''))

    _ensure_persistent_root_host_bind(cfg, attachment, dry_run=False)

    flat = [' '.join(c) for c in rec.normalized]
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
