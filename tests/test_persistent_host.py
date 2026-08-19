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

import importlib.util
import json
import shlex
from pathlib import Path
from typing import Any, Callable

import pytest

from aivm.attachments.persistent import (
    _approved_binds_already_applied,
    _install_guest_text_if_changed,
    _install_persistent_host_bind_replay,
    _mounted_child_names,
    _persistent_attachment_manifest_text,
    _persistent_host_manifest_path,
    _reconcile_persistent_attachments_in_guest,
    _run_guest_root_script,
    _sync_persistent_attachment_manifest_on_host,
    _sync_persistent_attachment_manifest_to_guest,
    _write_text_if_changed,
)
from aivm.attachments.persistent import (
    manifest as persistent_manifest,
)
from aivm.commands import CommandError, CommandManager
from aivm.config import AgentVMConfig
from aivm.config_store import AttachmentEntry, Store, save_store
from aivm.fs_identity import directory_identity
from aivm.persistent_replay import (
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    persistent_host_replay_python,
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


def test_source_unavailable_diagnostics_parses_only_machine_records() -> None:
    from aivm.attachments.persistent import host_bind

    stderr = '\n'.join(
        [
            'WARNING: human readable detail',
            (
                'AIVM_PERSISTENT_SOURCE_UNAVAILABLE '
                '{"detail": "identity changed", "source_dir": "/src/project", '
                '"token": "hostcode-project"}'
            ),
            'AIVM_PERSISTENT_SOURCE_UNAVAILABLE not-json',
        ]
    )

    assert host_bind._source_unavailable_diagnostics(stderr) == (
        ('hostcode-project', '/src/project', 'identity changed'),
    )


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
        lambda appname, kind, **kwargs: tmp_path / kind,
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


def _persistent_entry(
    path: Path,
    *,
    vm_name: str,
    access: str = 'rw',
    guest_dst: str = '/workspace/proj',
    tag: str = 'hostcode-proj',
    aliases: list[str] | None = None,
) -> AttachmentEntry:
    path.mkdir(parents=True, exist_ok=True)
    identity = directory_identity(path)
    return AttachmentEntry(
        host_path=str(path.resolve()),
        vm_name=vm_name,
        mode='persistent',
        access=access,
        guest_dst=guest_dst,
        tag=tag,
        source_dev=identity.dev,
        source_ino=identity.ino,
        host_lexical_paths=list(aliases or []),
    )


def _record_persistent_attachment(
    cfg: AgentVMConfig, cfg_path: Path, tmp_path: Path
) -> None:
    """Persist one enabled persistent attachment record for ``cfg``'s VM."""
    store = Store()
    store.attachments.append(
        _persistent_entry(tmp_path / 'proj', vm_name=cfg.vm.name)
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
        if 'sha256sum --check --status -' in script:
            count = seen.get(script, 0)
            seen[script] = count + 1
            status = initial_status if count == 0 else 'MATCH'
            return FakeProc(returncode=0 if status == 'MATCH' else 1)
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
            _persistent_entry(
                tmp_path / 'proj-rw',
                vm_name=cfg.vm.name,
                access='rw',
                guest_dst='/workspace/rw',
                tag='hostcode-rw',
            ),
            _persistent_entry(
                tmp_path / 'proj-ro',
                vm_name=cfg.vm.name,
                access='ro',
                guest_dst='/workspace/ro',
                tag='hostcode-ro',
                aliases=[str(tmp_path / 'link-ro')],
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
    assert payload['schema_version'] == 2
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


def test_legacy_unpinned_persistent_attachment_instructs_migration(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-legacy-unpinned'
    cfg_path = tmp_path / 'config.toml'
    store = Store(
        attachments=[
            AttachmentEntry(
                host_path='/data/audio-tools',
                vm_name=cfg.vm.name,
                mode='persistent',
                guest_dst='/data/audio-tools',
                tag='hostcode-audio-tools',
            )
        ]
    )
    save_store(store, cfg_path)

    with pytest.raises(RuntimeError) as exc_info:
        persistent_manifest._persistent_attachment_records_for_vm(cfg, cfg_path)

    message = str(exc_info.value)
    assert 'pre-0.6 legacy store' in message
    assert 'aivm config migrate plan' in message
    assert 'aivm config migrate apply --yes' in message
    assert 'source is unavailable' in message


def test_machine_unpinned_persistent_attachment_instructs_reattach(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-machine-unpinned'
    cfg_path = tmp_path / 'machine-store.toml'
    store = Store(
        store_kind='machine',
        attachments=[
            AttachmentEntry(
                host_path='/data/audio-tools',
                vm_name=cfg.vm.name,
                mode='persistent',
                guest_dst='/data/audio-tools',
                tag='hostcode-audio-tools',
            )
        ],
    )
    save_store(store, cfg_path)
    monkeypatch.setattr(
        persistent_manifest,
        'is_machine_store_path',
        lambda path: True,
    )

    with pytest.raises(RuntimeError) as exc_info:
        persistent_manifest._persistent_attachment_records_for_vm(cfg, cfg_path)

    message = str(exc_info.value)
    assert 'Detach and reattach this attachment' in message
    assert 'config migrate' not in message


def test_persistent_manifest_write_is_byte_for_byte_noop(
    tmp_path: Path,
) -> None:
    path = tmp_path / 'state' / 'persistent-attachments.json'
    assert _write_text_if_changed(path, 'alpha\n') is True
    before = path.read_bytes()
    assert _write_text_if_changed(path, 'alpha\n') is False
    assert path.read_bytes() == before


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


def test_detaching_record_requires_host_replay_state_for_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A retry can rebuild replay state after cleanup removed its artifacts."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-detach-retry'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    entry = _persistent_entry(tmp_path / 'proj', vm_name=cfg.vm.name)
    entry.state = 'detaching'
    store = Store(attachments=[entry])
    save_store(store, cfg_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)

    approved = persistent_manifest._persistent_host_replay_manifest_path(cfg)
    assert not approved.exists()
    assert persistent_manifest._persistent_host_replay_state_needed(
        cfg, cfg_path
    )
    payload = json.loads(
        persistent_manifest._persistent_attachment_manifest_text(cfg, cfg_path)
    )
    assert payload['records'][0]['enabled'] is False


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
        _persistent_entry(tmp_path / 'proj', vm_name=cfg.vm.name)
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
    # The check remains an exact, copy/pasteable command rather than a
    # multiline MATCH/MISMATCH mini-program hidden inside ssh.
    check_script = scripts[0]
    assert 'sha256sum --check --status -' in check_script
    assert 'cmp -s' not in check_script
    assert '\n' not in check_script
    assert not any(
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


def test_persistent_reconcile_can_scope_foreground_guest_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Foreground replay tells the guest helper to touch only one path."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-reconcile-scoped'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(
        monkeypatch,
        {
            'ssh': _hash_route('MATCH'),
            'rsync': FakeProc(stdout=''),
        },
    )

    host_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        'aivm.attachments.persistent.replay.host_bind._reconcile_persistent_host_binds',
        lambda *a, **k: host_calls.append(dict(k)) or (),
    )

    _reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        only_guest_dst='/workspace/proj',
        preserve_live_mounts=True,
    )

    assert host_calls == [
        {
            'dry_run': False,
            'vm_running': True,
            'only_guest_dst': '/workspace/proj',
            'preserve_live_binds': True,
        }
    ]
    scripts = _ssh_scripts(rec)
    assert scripts[-1] == (
        f'{REPLAY_INVOCATION} --only-guest-dst /workspace/proj '
        '--preserve-live-mounts'
    )


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


def test_persistent_guest_root_script_accepts_degraded_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-degraded-replay'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.vm.user = 'agent'
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch,
        {'ssh': FakeProc(returncode=3, stderr='source unavailable')},
    )

    result = _run_guest_root_script(
        cfg,
        '10.0.0.5',
        script='echo replay',
        summary='Replay degraded persistent attachments',
        detail='',
        dry_run=False,
        check=True,
        allowed_exit_codes=(0, 3),
    )

    assert result is not None
    assert result.code == 3
    assert result.stderr == 'source unavailable'


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
    monkeypatch.setattr(
        'aivm.attachments.persistent.host_bind.'
        'PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN',
        str(tmp_path / 'libexec' / 'aivm-persistent-host-bind-replay'),
    )
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

    target = _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)
    installed = _install_persistent_host_bind_replay(
        cfg, cfg_path, dry_run=False
    )
    _reconcile_persistent_host_binds(cfg, cfg_path, dry_run=False)

    assert rec.normalized == []
    assert installed is False
    assert target.parent == state_dir
    assert not state_dir.exists()


def test_persistent_host_replay_dry_run_executes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--dry_run must not run the privileged replay (or anything else).

    Regression: the replay submit had no dry-run gate, so `aivm vm
    persistent_host_replay --dry_run` executed the real sudo bind replay
    against a stale manifest and then printed DRYRUN.
    """
    from aivm.attachments.persistent import _reconcile_persistent_host_binds

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-replay-dry-run'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    store.attachments.append(
        _persistent_entry(tmp_path / 'proj', vm_name=cfg.vm.name)
    )
    save_store(store, cfg_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    # The virtiofs-mapping probe is a legitimate read; everything else --
    # notably the sudo replay helper, mkdir, install, systemctl -- is strict.
    rec = command_recorder(
        monkeypatch, {'virsh': FakeProc(stdout='<domain/>')}
    )

    _reconcile_persistent_host_binds(cfg, cfg_path, dry_run=True)

    assert [cmd for cmd in rec.normalized if cmd[0] != 'virsh'] == []


def test_persistent_host_replay_can_scope_foreground_reconcile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Scoped host replay neither requests nor performs global stale pruning."""
    from aivm.attachments.persistent import host_bind

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-replay-scoped'
    cfg.paths.base_dir = str(tmp_path / 'base')
    cfg_path = tmp_path / 'config.toml'
    _record_persistent_attachment(cfg, cfg_path, tmp_path)
    _redirect_appdir(monkeypatch, tmp_path)
    _redirect_replay_state_dir(monkeypatch, tmp_path)
    activate_manager(monkeypatch)

    rec = command_recorder(monkeypatch, default=FakeProc())

    host_bind._run_persistent_host_replay(
        cfg,
        cfg_path,
        dry_run=False,
        only_guest_dst='/workspace/proj',
    )

    replay_cmd = next(
        cmd
        for cmd in rec.normalized
        if cmd and cmd[0].endswith('aivm-persistent-host-bind-replay')
    )
    assert replay_cmd[-2:] == ['--only-guest-dst', '/workspace/proj']
    assert '--prune-stale' not in replay_cmd


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


def _load_host_replay_helper(tmp_path: Path) -> Any:
    helper_path = tmp_path / 'aivm_persistent_host_replay.py'
    helper_path.write_text(persistent_host_replay_python(), encoding='utf-8')
    spec = importlib.util.spec_from_file_location(
        'aivm_test_persistent_host_replay', helper_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_host_replay_rejects_source_replacement(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    source = tmp_path / 'source'
    source.mkdir()
    info = source.stat()
    record = {
        'shared_root_token': 'token',
        'source_dir': str(source),
        'source_dev': info.st_dev,
        'source_ino': info.st_ino,
    }
    source.rename(tmp_path / 'approved-source')
    source.mkdir()
    with pytest.raises(
        helper.SourceUnavailableError, match='approved persistent source changed'
    ):
        helper.open_approved_source(record)


def test_host_replay_rejects_symlink_replacement(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    source = tmp_path / 'source'
    source.mkdir()
    info = source.stat()
    record = {
        'shared_root_token': 'token',
        'source_dir': str(source),
        'source_dev': info.st_dev,
        'source_ino': info.st_ino,
    }
    approved = tmp_path / 'approved-source'
    source.rename(approved)
    source.symlink_to(approved, target_is_directory=True)
    with pytest.raises(helper.SourceUnavailableError):
        helper.open_approved_source(record)


def test_host_replay_rejects_intermediate_symlink(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    real_parent = tmp_path / 'real-parent'
    real_parent.mkdir()
    source = real_parent / 'source'
    source.mkdir()
    info = source.stat()
    alias = tmp_path / 'alias'
    alias.symlink_to(real_parent, target_is_directory=True)
    record = {
        'shared_root_token': 'token',
        'source_dir': str(alias / 'source'),
        'source_dev': info.st_dev,
        'source_ino': info.st_ino,
    }
    with pytest.raises(helper.SourceUnavailableError):
        helper.open_approved_source(record)


def test_held_source_descriptor_survives_path_replacement(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    source = tmp_path / 'source'
    source.mkdir()
    approved = source.stat()
    record = {
        'shared_root_token': 'token',
        'source_dir': str(source),
        'source_dev': approved.st_dev,
        'source_ino': approved.st_ino,
    }
    fd = helper.open_approved_source(record)
    try:
        source.rename(tmp_path / 'approved-source')
        source.mkdir()
        held = helper.os.fstat(fd)
        replacement = source.stat()
        assert (held.st_dev, held.st_ino) == (
            approved.st_dev,
            approved.st_ino,
        )
        assert (held.st_dev, held.st_ino) != (
            replacement.st_dev,
            replacement.st_ino,
        )
    finally:
        helper.os.close(fd)


def test_host_replay_mounts_only_through_held_descriptors() -> None:
    source = persistent_host_replay_python()
    assert 'mount", "--bind", fd_path(source_fd), fd_path(target_fd)' in source
    assert 'pass_fds=(source_fd, target_fd)' in source
    assert 'expected_dev' in source and 'expected_ino' in source


def test_host_replay_prunes_with_path_only_export_root_descriptor(
    tmp_path: Path,
) -> None:
    """O_PATH pins the root, while procfs provides an enumerable view."""
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    export_root.mkdir()
    root_fd = helper.open_absolute_directory(
        str(export_root), label='export root'
    )
    try:
        helper.prune_stale_mounts(root_fd, set())
    finally:
        helper.os.close(root_fd)


def test_host_replay_unmounts_through_held_parent_not_open_child(
    tmp_path: Path,
) -> None:
    """Closing the child descriptor avoids making its own mount look busy."""
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    target = export_root / 'token'
    target.mkdir(parents=True)
    root_fd = helper.open_absolute_directory(
        str(export_root), label='export root'
    )
    calls: list[tuple[list[str], tuple[int, ...]]] = []

    class Result:
        returncode = 0
        stdout = ''
        stderr = ''

    def fake_run(
        cmd: list[str],
        *,
        check: bool = True,
        capture: bool = False,
        pass_fds: tuple[int, ...] = (),
    ) -> Result:
        del check, capture
        calls.append((cmd, pass_fds))
        return Result()

    helper.run = fake_run
    try:
        helper.unmount_child(root_fd, 'token')
    finally:
        helper.os.close(root_fd)

    assert calls == [
        (
            ['umount', f'/proc/self/fd/{root_fd}/token'],
            (root_fd,),
        )
    ]


def test_host_replay_lazily_detaches_genuinely_busy_child(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    (export_root / 'token').mkdir(parents=True)
    root_fd = helper.open_absolute_directory(
        str(export_root), label='export root'
    )
    calls: list[list[str]] = []

    class Result:
        def __init__(
            self,
            returncode: int,
            *,
            stdout: str = '',
            stderr: str = '',
        ) -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(
        cmd: list[str],
        *,
        check: bool = True,
        capture: bool = False,
        pass_fds: tuple[int, ...] = (),
    ) -> Result:
        del check, capture, pass_fds
        calls.append(cmd)
        if cmd[:2] == ['umount', '--lazy']:
            return Result(0)
        if cmd[0] == 'umount':
            return Result(32, stderr='target is busy')
        if cmd[0] == 'mountpoint':
            return Result(0)
        raise AssertionError(cmd)

    helper.run = fake_run
    try:
        helper.unmount_child(root_fd, 'token')
    finally:
        helper.os.close(root_fd)

    target = f'/proc/self/fd/{root_fd}/token'
    assert calls == [
        ['umount', target],
        ['mountpoint', '-q', target],
        ['umount', '--lazy', target],
    ]


def test_host_replay_prune_closes_child_before_unmount(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    (export_root / 'token').mkdir(parents=True)
    root_fd = helper.open_absolute_directory(
        str(export_root), label='export root'
    )
    opened_children: list[int] = []
    real_open_child = helper.open_child_directory

    def recording_open_child(*args: Any, **kwargs: Any) -> int:
        fd = real_open_child(*args, **kwargs)
        opened_children.append(fd)
        return fd

    def assert_closed_before_unmount(parent_fd: int, name: str) -> None:
        assert parent_fd == root_fd
        assert name == 'token'
        with pytest.raises(OSError):
            helper.os.fstat(opened_children[-1])

    helper.open_child_directory = recording_open_child
    helper.is_mountpoint_fd = lambda fd: True
    helper.unmount_child = assert_closed_before_unmount
    try:
        helper.prune_stale_mounts(root_fd, set())
    finally:
        helper.os.close(root_fd)


def test_held_export_root_descriptor_survives_path_replacement(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    export_root.mkdir()
    approved = export_root.stat()
    fd = helper.open_absolute_directory(str(export_root), label='export root')
    try:
        export_root.rename(tmp_path / 'approved-export-root')
        export_root.mkdir()
        held = helper.os.fstat(fd)
        replacement = export_root.stat()
        assert (held.st_dev, held.st_ino) == (
            approved.st_dev,
            approved.st_ino,
        )
        assert (held.st_dev, held.st_ino) != (
            replacement.st_dev,
            replacement.st_ino,
        )
    finally:
        helper.os.close(fd)


def test_held_target_descriptor_survives_child_replacement(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export-root'
    export_root.mkdir()
    root_fd = helper.open_absolute_directory(
        str(export_root), label='export root'
    )
    target_fd = helper.open_child_directory(root_fd, 'token', create=True)
    try:
        target = export_root / 'token'
        approved = target.stat()
        target.rename(export_root / 'approved-token')
        target.mkdir()
        held = helper.os.fstat(target_fd)
        replacement = target.stat()
        assert (held.st_dev, held.st_ino) == (
            approved.st_dev,
            approved.st_ino,
        )
        assert (held.st_dev, held.st_ino) != (
            replacement.st_dev,
            replacement.st_ino,
        )
    finally:
        helper.os.close(target_fd)
        helper.os.close(root_fd)


def test_attachment_approval_rejects_intermediate_symlink(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / 'real-parent'
    real_parent.mkdir()
    source = real_parent / 'source'
    source.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises((NotADirectoryError, OSError)):
        directory_identity(alias / 'source')


# ---------------------------------------------------------------------------
# The privileged replay is skipped when there is nothing for it to do
# ---------------------------------------------------------------------------


def _write_mountinfo(path: Path, export_root: Path, *names: str) -> Path:
    """Write a mountinfo table listing ``names`` as mounts under the export root.

    Real bind mounts need root, so the kernel's answer is supplied rather
    than produced. Crucially the fixture mirrors the same-filesystem case:
    every entry shares one device with its parent, which is what defeats
    ``st_dev``-based mount inference.
    """
    lines = [
        # id parent major:minor root mountpoint options - fstype source opts
        f'{40 + index} 30 259:2 /src/{name} {export_root}/{name} '
        f'rw,relatime shared:1 - ext4 /dev/root rw'
        for index, name in enumerate(names)
    ]
    path.write_text(
        '\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8'
    )
    return path


def _approved_manifest_for(
    tmp_path: Path,
    *,
    access: str = 'rw',
    bound: bool = True,
    mounted: tuple[str, ...] = ('token-a',),
) -> tuple[Path, Path, Path]:
    """Write an approved manifest describing one already-applied bind.

    A real bind target *is* its source directory, so a test can stand in for
    one by recording the target's own identity as the approved source: that
    is precisely the equality a live bind produces.
    """
    export_root = tmp_path / 'export'
    target = export_root / 'token-a'
    target.mkdir(parents=True)
    info = target.stat()
    manifest_path = tmp_path / 'approved.json'
    manifest_path.write_text(
        json.dumps(
            {
                'schema_version': 2,
                'vm_name': 'vm-shared',
                'records': [
                    {
                        'shared_root_token': 'token-a',
                        'guest_dst': '/workspace/a',
                        'source_dev': info.st_dev,
                        # An unbound target is some other directory, so its
                        # inode is not the approved source's.
                        'source_ino': info.st_ino if bound else info.st_ino + 1,
                        'access': access,
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )
    mountinfo = _write_mountinfo(
        tmp_path / 'mountinfo', export_root, *mounted
    )
    return manifest_path, export_root, mountinfo


def test_converged_persistent_binds_need_no_privileged_replay(
    tmp_path: Path,
) -> None:
    """An already-applied manifest is not re-applied through sudo.

    On a shared machine this manifest covers every principal's persistent
    attachments, so demanding root here meant any user starting the VM had
    to escalate just to re-assert binds that were already in place.
    """
    manifest_path, export_root, mountinfo = _approved_manifest_for(tmp_path)

    assert _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_unapplied_persistent_bind_still_requires_the_replay(
    tmp_path: Path,
) -> None:
    """A target that is not the approved source is work the helper must do."""
    manifest_path, export_root, mountinfo = _approved_manifest_for(
        tmp_path, bound=False
    )

    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_missing_bind_target_requires_the_replay(tmp_path: Path) -> None:
    manifest_path, export_root, mountinfo = _approved_manifest_for(
        tmp_path, mounted=()
    )
    (export_root / 'token-a').rmdir()

    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_readonly_mismatch_requires_the_replay(tmp_path: Path) -> None:
    """A bind whose access no longer matches must be remounted."""
    # The tmp_path filesystem is writable, so an 'ro' record cannot already
    # be satisfied -- exactly the drift the helper exists to correct.
    manifest_path, export_root, mountinfo = _approved_manifest_for(
        tmp_path, access='ro'
    )

    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_stale_mount_under_the_export_root_requires_the_replay(
    tmp_path: Path,
) -> None:
    """A detached attachment leaves a mount only the helper can prune.

    Regression: this was decided with ``Path.is_mount()``, which infers a
    mount from a ``st_dev`` difference against the parent. A bind mount
    whose source shares a filesystem with the export root -- both on the
    host root filesystem, the normal layout -- shows no such difference, so
    a live bind read as "not mounted". Detach then concluded there was no
    privileged work to do and went on to delete the record, the manifest and
    the replay unit, leaving the host folder still exported to the guest and
    the state needed to retry the cleanup gone.
    """
    manifest_path, export_root, mountinfo = _approved_manifest_for(
        tmp_path, mounted=('token-a', 'token-detached')
    )
    (export_root / 'token-detached').mkdir()

    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_scoped_convergence_ignores_unrelated_stale_host_mount(
    tmp_path: Path,
) -> None:
    """Foreground attachment checks only the export it is about to use."""
    manifest_path, export_root, mountinfo = _approved_manifest_for(
        tmp_path, mounted=('token-a', 'token-unrelated')
    )
    (export_root / 'token-unrelated').mkdir()

    assert _approved_binds_already_applied(
        manifest_path,
        export_root,
        mountinfo=mountinfo,
        only_guest_dst='/workspace/a',
    )
    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=mountinfo
    )


def test_mount_detection_sees_a_same_filesystem_bind(tmp_path: Path) -> None:
    """The mount table is consulted, not a st_dev comparison.

    Guards the specific inference that failed: every entry in this fixture
    shares one device with its parent, exactly as a same-filesystem bind
    mount does, and must still be reported as mounted.
    """
    export_root = tmp_path / 'export'
    export_root.mkdir()
    (export_root / 'token-a').mkdir()
    mountinfo = _write_mountinfo(tmp_path / 'mountinfo', export_root, 'token-a')

    assert _mounted_child_names(export_root, mountinfo=mountinfo) == {'token-a'}
    # The inference this replaced would answer False for the same directory.
    assert not (export_root / 'token-a').is_mount()


def test_mount_detection_decodes_escaped_mountinfo_paths(
    tmp_path: Path,
) -> None:
    """A mount point containing a space arrives octal-escaped from the kernel."""
    export_root = tmp_path / 'export root'
    export_root.mkdir()
    mountinfo = tmp_path / 'mountinfo'
    escaped = str(export_root).replace(' ', r'\040')
    mountinfo.write_text(
        f'40 30 259:2 /src {escaped}/token-a rw - ext4 /dev/root rw\n',
        encoding='utf-8',
    )

    assert _mounted_child_names(export_root, mountinfo=mountinfo) == {'token-a'}


def test_unreadable_mount_table_requires_the_replay(tmp_path: Path) -> None:
    """Not knowing what is mounted is never read as "nothing is mounted"."""
    manifest_path, export_root, _mountinfo = _approved_manifest_for(tmp_path)

    assert not _approved_binds_already_applied(
        manifest_path, export_root, mountinfo=tmp_path / 'absent-mountinfo'
    )


def test_unreadable_approved_manifest_requires_the_replay(
    tmp_path: Path,
) -> None:
    """Every uncertainty falls through to the privileged helper."""
    export_root = tmp_path / 'export'
    export_root.mkdir()
    mountinfo = _write_mountinfo(tmp_path / 'mountinfo', export_root)

    assert not _approved_binds_already_applied(
        tmp_path / 'never-written.json', export_root, mountinfo=mountinfo
    )


def test_host_replay_isolates_source_failure_and_continues(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    manifest_path = tmp_path / 'approved.json'
    manifest_path.write_text(
        json.dumps(
            {
                'vm_name': 'vm',
                'records': [
                    {'shared_root_token': 'bad', 'enabled': True},
                    {'shared_root_token': 'good', 'enabled': True},
                ],
            }
        ),
        encoding='utf-8',
    )
    export_root = tmp_path / 'export'
    export_root.mkdir()
    helper.open_validated_manifest = lambda path: helper.os.open(path, helper.os.O_RDONLY)
    seen: list[str] = []
    quarantined: list[str] = []

    def ensure_record(_export_root_fd: int, record: dict[str, object], **_kwargs: object) -> None:
        token = str(record['shared_root_token'])
        seen.append(token)
        if token == 'bad':
            raise helper.SourceUnavailableError('approved persistent source changed')

    helper.ensure_record = ensure_record
    helper.quarantine_unavailable_token = (
        lambda _export_root_fd, token: quarantined.append(str(token))
    )
    code = helper.main(
        [
            '--manifest',
            str(manifest_path),
            '--export-root',
            str(export_root),
            '--vm-name',
            'vm',
        ]
    )

    assert code == helper.DEGRADED_EXIT
    assert seen == ['bad', 'good']
    assert quarantined == ['bad']
    assert (
        'WARNING: skipping persistent host attachment bad: '
        'approved persistent source changed'
        in capsys.readouterr().err
    )



def test_host_replay_preserves_existing_export_on_source_failure_in_foreground(
    tmp_path: Path,
) -> None:
    """A source-pin problem during session entry must not quarantine a live export."""
    helper = _load_host_replay_helper(tmp_path)
    manifest_path = tmp_path / 'approved.json'
    manifest_path.write_text(
        json.dumps(
            {
                'vm_name': 'vm',
                'records': [
                    {
                        'shared_root_token': 'token',
                        'guest_dst': '/workspace/proj',
                        'source_dir': '/host/proj',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )
    export_root = tmp_path / 'export'
    export_root.mkdir()
    helper.open_validated_manifest = lambda path: helper.os.open(
        path, helper.os.O_RDONLY
    )

    def unavailable(
        _export_root_fd: int,
        _record: dict[str, object],
        **_kwargs: object,
    ) -> None:
        raise helper.SourceUnavailableError('approved source identity changed')

    helper.ensure_record = unavailable
    helper.quarantine_unavailable_token = lambda *_a, **_k: pytest.fail(
        'foreground source failure must not quarantine a live export'
    )

    code = helper.main(
        [
            '--manifest',
            str(manifest_path),
            '--export-root',
            str(export_root),
            '--vm-name',
            'vm',
            '--only-guest-dst',
            '/workspace/proj',
            '--preserve-live-binds',
        ]
    )
    assert code == helper.DEGRADED_EXIT


def test_host_replay_reports_live_bind_conflict_as_degraded_in_foreground(
    tmp_path: Path,
) -> None:
    """A preserved live host bind warns without aborting foreground entry."""
    helper = _load_host_replay_helper(tmp_path)
    manifest_path = tmp_path / 'approved.json'
    manifest_path.write_text(
        json.dumps(
            {
                'vm_name': 'vm',
                'records': [
                    {
                        'shared_root_token': 'token',
                        'guest_dst': '/workspace/proj',
                        'source_dir': '/host/proj',
                        'enabled': True,
                    }
                ],
            }
        ),
        encoding='utf-8',
    )
    export_root = tmp_path / 'export'
    export_root.mkdir()
    helper.open_validated_manifest = lambda path: helper.os.open(
        path, helper.os.O_RDONLY
    )

    def conflict(
        _export_root_fd: int,
        _record: dict[str, object],
        **_kwargs: object,
    ) -> None:
        raise helper.LiveBindConflictError(
            'live export points at a different directory; '
            'foreground session preparation leaves live binds untouched'
        )

    helper.ensure_record = conflict
    helper.quarantine_unavailable_token = lambda *_a, **_k: pytest.fail(
        'foreground live-bind conflict must not quarantine the live export'
    )

    code = helper.main(
        [
            '--manifest',
            str(manifest_path),
            '--export-root',
            str(export_root),
            '--vm-name',
            'vm',
            '--only-guest-dst',
            '/workspace/proj',
            '--preserve-live-binds',
        ]
    )
    assert code == helper.DEGRADED_EXIT


def test_host_replay_does_not_swallow_mount_or_access_failure(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    manifest_path = tmp_path / 'approved.json'
    manifest_path.write_text(
        json.dumps(
            {
                'vm_name': 'vm',
                'records': [
                    {'shared_root_token': 'bad', 'enabled': True},
                    {'shared_root_token': 'good', 'enabled': True},
                ],
            }
        ),
        encoding='utf-8',
    )
    export_root = tmp_path / 'export'
    export_root.mkdir()
    helper.open_validated_manifest = lambda path: helper.os.open(path, helper.os.O_RDONLY)
    seen: list[str] = []

    def ensure_record(_export_root_fd: int, record: dict[str, object], **_kwargs: object) -> None:
        token = str(record['shared_root_token'])
        seen.append(token)
        if token == 'bad':
            raise RuntimeError('remount,bind,ro failed')

    helper.ensure_record = ensure_record

    with pytest.raises(RuntimeError, match='remount,bind,ro failed'):
        helper.main(
            [
                '--manifest',
                str(manifest_path),
                '--export-root',
                str(export_root),
                '--vm-name',
                'vm',
            ]
        )

    assert seen == ['bad']



def test_host_replay_preserve_live_bind_never_unmounts_conflict(
    tmp_path: Path,
) -> None:
    """Foreground host replay reports a conflict without replacing the live bind."""
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export'
    source = tmp_path / 'source'
    token_dir = export_root / 'token'
    source.mkdir()
    token_dir.mkdir(parents=True)
    export_root_fd = helper.open_absolute_directory(
        export_root, label='export root'
    )
    source_fd = helper.open_absolute_directory(source, label='source')
    helper.open_approved_source = lambda _record: helper.os.dup(source_fd)
    helper.is_mountpoint_fd = lambda _fd: True
    helper.same_tree_fds = lambda _left, _right: False
    helper.unmount_child = lambda *_a, **_k: pytest.fail(
        'foreground replay must not unmount a live host bind'
    )
    try:
        with pytest.raises(
            helper.LiveBindConflictError,
            match='leaves live binds untouched',
        ):
            helper.ensure_record(
                export_root_fd,
                {
                    'shared_root_token': 'token',
                    'enabled': True,
                    'access': 'rw',
                },
                preserve_live_binds=True,
            )
    finally:
        helper.os.close(source_fd)
        helper.os.close(export_root_fd)



def test_host_replay_preserve_live_bind_never_remounts_access(
    tmp_path: Path,
) -> None:
    """Foreground host replay also preserves a live bind's access mode."""
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export'
    source = tmp_path / 'source'
    token_dir = export_root / 'token'
    source.mkdir()
    token_dir.mkdir(parents=True)
    export_root_fd = helper.open_absolute_directory(
        export_root, label='export root'
    )
    source_fd = helper.open_absolute_directory(source, label='source')
    helper.open_approved_source = lambda _record: helper.os.dup(source_fd)
    helper.is_mountpoint_fd = lambda _fd: True
    helper.same_tree_fds = lambda _left, _right: True
    helper.access_matches_fd = lambda _fd, _access: False
    helper.enforce_access_fd = lambda *_a, **_k: pytest.fail(
        'foreground replay must not remount a live host bind'
    )
    try:
        with pytest.raises(
            helper.LiveBindConflictError,
            match='leaves live binds untouched',
        ):
            helper.ensure_record(
                export_root_fd,
                {
                    'shared_root_token': 'token',
                    'enabled': True,
                    'access': 'ro',
                },
                preserve_live_binds=True,
            )
    finally:
        helper.os.close(source_fd)
        helper.os.close(export_root_fd)


def test_host_replay_quarantines_unavailable_empty_token_directory(
    tmp_path: Path,
) -> None:
    helper = _load_host_replay_helper(tmp_path)
    export_root = tmp_path / 'export'
    token_dir = export_root / 'stale-token'
    token_dir.mkdir(parents=True)
    export_root_fd = helper.open_absolute_directory(
        export_root, label='export root'
    )
    helper.is_mountpoint_fd = lambda _fd: False
    try:
        helper.quarantine_unavailable_token(export_root_fd, 'stale-token')
    finally:
        helper.os.close(export_root_fd)

    assert not token_dir.exists()


def test_host_replay_probe_source_uses_descriptor_walk(tmp_path: Path) -> None:
    helper = _load_host_replay_helper(tmp_path)
    source = tmp_path / 'source'
    source.mkdir()

    assert helper.main(['--probe-source', str(source)]) == 0


def test_host_replay_probe_source_rejects_symlink(tmp_path: Path) -> None:
    helper = _load_host_replay_helper(tmp_path)
    source = tmp_path / 'source'
    source.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(source, target_is_directory=True)

    with pytest.raises(OSError):
        helper.main(['--probe-source', str(alias)])
