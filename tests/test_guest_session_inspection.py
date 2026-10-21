"""Batch inspection must execute only verified helpers and fail closed."""

import argparse
import hashlib
import json
from subprocess import CompletedProcess

import pytest

from aivm.attachments.persistent import inspection
from aivm.commands import CommandManager, CommandResult
from aivm.config import AgentVMConfig
from aivm.config_store import Store, save_store
from aivm.rc.guest import session_inspect
from tests.helpers import FakeProc, activate_manager, command_recorder


@pytest.mark.parametrize('current', [True, False])
def test_batch_guest_checks_execute_only_matching_helpers(
    tmp_path, monkeypatch, current
):
    paths = {}
    for name in ('REPLAY', 'SYMLINK', 'UNIT', 'MANIFEST'):
        path = tmp_path / name
        path.write_text('standalone helper')
        monkeypatch.setattr(session_inspect, name, str(path))
        paths[name] = str(path)
    expected = (
        hashlib.sha256(b'standalone helper').hexdigest()
        if current
        else '0' * 64
    )
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return CompletedProcess(argv, 10, stdout='', stderr='repair needed')

    monkeypatch.setattr(session_inspect.subprocess, 'run', run)
    args = argparse.Namespace(
        file=[
            (paths[name], expected) for name in ('REPLAY', 'SYMLINK', 'UNIT')
        ],
        symlink=[('/link', '/workspace')],
        remove_symlink=[],
        guest_dst='/workspace',
    )
    result = session_inspect.inspect(args)
    assert result['manifest_directory'] is True
    assert all(value is current for value in result['files'].values())
    if current:
        assert [cmd[0] for cmd in calls] == [paths['SYMLINK'], paths['REPLAY']]
        assert all('--check' in cmd for cmd in calls)
    else:
        assert calls == []
        assert result['symlinks'][0]['result'] is None
        assert result['replay'] is None


def _response(files, links):
    return {
        'version': 1,
        'files': {key: True for key in files},
        'manifest_directory': True,
        'symlinks': [
            {
                'link': link,
                'target': target,
                'remove': remove,
                'result': {'code': 0, 'stderr': ''},
            }
            for link, target, remove in links
        ],
        'replay': {'code': 0, 'stderr': ''},
    }


def test_batch_mirror_removal_inspection_preserves_matching_link(
    tmp_path, monkeypatch
):
    target = tmp_path / 'target'
    link = tmp_path / 'link'
    link.symlink_to(target)
    before = link.lstat()
    monkeypatch.setattr(session_inspect, 'MANIFEST', str(tmp_path / 'absent'))
    result = session_inspect.inspect(
        argparse.Namespace(
            file=[],
            symlink=[],
            remove_symlink=[(str(link), str(target))],
            guest_dst='/workspace',
        )
    )
    assert result['symlinks'][0]['result']['code'] == 10
    assert link.is_symlink() and link.lstat() == before


@pytest.mark.parametrize(
    'defect',
    ['version', 'missing-file', 'not-bool', 'wrong-link', 'invalid-code'],
)
def test_batch_response_cannot_claim_readiness_with_missing_or_invalid_evidence(
    defect,
):
    files, links = {'/helper': 'body'}, [('/link', '/workspace', False)]
    response = _response(files, links)
    if defect == 'version':
        response['version'] = True
    elif defect == 'missing-file':
        response['files'] = {}
    elif defect == 'not-bool':
        response['files']['/helper'] = 1
    elif defect == 'wrong-link':
        response['symlinks'][0]['link'] = '/another-user'
    else:
        response['replay']['code'] = True
    with pytest.raises(ValueError):
        inspection._decode(json.dumps(response), files, links)


def test_batch_host_command_is_read_only_and_keeps_arguments_visible(
    monkeypatch,
):
    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    monkeypatch.setattr(
        'builtins.input',
        lambda prompt: pytest.fail('healthy inspection asked approval'),
    )
    cfg = AgentVMConfig()
    cfg.paths.ssh_identity_file = '/tmp/id'
    links = [('/link with spaces', '/target; $(literal)', False)]
    files = {
        inspection.PERSISTENT_ATTACHMENT_REPLAY_BIN: '',
        f'/etc/systemd/system/{inspection.PERSISTENT_ATTACHMENT_REPLAY_SERVICE}': '',
        inspection.GUEST_SYMLINK_BIN: '',
    }
    recorder = command_recorder(
        monkeypatch,
        {'ssh': FakeProc(stdout=json.dumps(_response(files, links)))},
        stub_sudo_scope=False,
    )
    result = inspection.inspect_foreground(cfg, '10.0.0.5', '/workspace', links)
    assert result.replay is not None and result.replay.code == 0
    cmd = recorder.only('ssh')
    assert inspection.GUEST_SESSION_INSPECT_BIN in cmd
    assert all(type(arg) is str and len(arg) < 400 for arg in cmd)
    assert '--symlink' in cmd and '--guest-dst' in cmd
    assert CommandManager.current().plan_stack == []


@pytest.mark.parametrize('installed', [True, False])
def test_inspection_helper_upgrade_is_bounded_and_never_masks_runtime_failure(
    monkeypatch, installed
):
    activate_manager(monkeypatch)
    cfg = AgentVMConfig()
    cfg.paths.ssh_identity_file = '/tmp/id'
    files = {
        inspection.PERSISTENT_ATTACHMENT_REPLAY_BIN: '',
        f'/etc/systemd/system/{inspection.PERSISTENT_ATTACHMENT_REPLAY_SERVICE}': '',
    }
    attempts = []

    def route(argv):
        attempts.append(argv)
        return (
            FakeProc(1, stderr='helper absent or failed')
            if len(attempts) == 1
            else FakeProc(stdout=json.dumps(_response(files, [])))
        )

    monkeypatch.setattr(
        inspection.transport,
        '_install_guest_text_if_changed',
        lambda *args, **kwargs: installed,
    )
    command_recorder(monkeypatch, {'ssh': route})
    if installed:
        assert (
            inspection.inspect_foreground(
                cfg, '10.0.0.5', '/workspace', []
            ).replay.code
            == 0
        )
        assert len(attempts) == 2
    else:
        with pytest.raises(RuntimeError, match='helper absent or failed'):
            inspection.inspect_foreground(cfg, '10.0.0.5', '/workspace', [])
        assert len(attempts) == 1


@pytest.mark.parametrize('manifest_changed', [False, True])
@pytest.mark.parametrize('symlinks_changed', [False, True])
def test_repairs_invalidate_batched_mount_result(
    monkeypatch, tmp_path, manifest_changed, symlinks_changed
):
    from aivm.attachments.persistent import replay

    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-live-inspection'
    cfg.paths.ssh_identity_file = '/tmp/id'
    cfg_path = tmp_path / 'config.toml'
    save_store(Store(), cfg_path)
    live = inspection.GuestInspection(
        {
            inspection.PERSISTENT_ATTACHMENT_REPLAY_BIN: True,
            f'/etc/systemd/system/{inspection.PERSISTENT_ATTACHMENT_REPLAY_SERVICE}': True,
        },
        True,
        [],
        CommandResult(0, '', ''),
    )
    monkeypatch.setattr(
        replay.manifest,
        '_sync_persistent_attachment_manifest_on_host',
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        replay.manifest,
        '_sync_persistent_attachment_manifest_to_guest',
        lambda *args, **kwargs: manifest_changed,
    )
    monkeypatch.setattr(inspection, 'inspect_foreground', lambda *args: live)
    monkeypatch.setattr(
        inspection, 'apply_symlink_repairs', lambda *args: symlinks_changed
    )
    monkeypatch.setattr(
        replay,
        '_install_persistent_attachment_replay',
        lambda *args, **kwargs: pytest.fail(
            'verified helper rechecked separately'
        ),
    )
    checks = []

    def root_command(*args, **kwargs):
        assert kwargs['role'] == 'read'
        assert kwargs['script'].endswith(' --check')
        checks.append(kwargs['script'])
        return CommandResult(3, '', 'new manifest exposes an access conflict')

    monkeypatch.setattr(
        replay.transport, '_run_guest_root_script', root_command
    )
    replay._reconcile_persistent_attachments_in_guest(
        cfg,
        cfg_path,
        '10.0.0.5',
        dry_run=False,
        reconcile_host=False,
        only_guest_dst='/workspace',
        preserve_live_mounts=True,
        replay_even_if_unchanged=False,
        symlink_checks=[],
    )
    assert len(checks) == int(manifest_changed or symlinks_changed)
