"""Tests for VM-scoped GitHub deploy-key credentials."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.cli.config.lint import _lint_store_text
from aivm.cli.vm_lifecycle import VMDeleteCLI
from aivm.commands import CommandManager, CommandResult
from aivm.config_store import (
    CredentialEntry,
    Store,
    find_credentials_for_vm,
    load_store,
    save_store,
    upsert_credential,
    upsert_vm,
)
from aivm.credentials import github
from aivm.credentials.guest import render_git_config, render_ssh_config
from aivm.credentials.keys import (
    host_credential_dir,
    host_private_key_path,
    host_public_key_path,
    public_key_fingerprint,
)
from aivm.credentials.models import GitRepository, ProviderDeployKey
from aivm.credentials.resolve import parse_repository_url
from aivm.credentials.service import (
    grant_repository_credential,
    revoke_repository_credential,
)
from aivm.errors import AIVMError
from tests.helpers import make_cfg, run_cli, write_store


def _public_key(comment: str = 'test') -> str:
    blob = base64.b64encode(b'aivm synthetic ed25519 blob').decode('ascii')
    return f'ssh-ed25519 {blob} {comment}\n'


def _entry(vm_name: str = 'test-vm') -> CredentialEntry:
    public = _public_key()
    return CredentialEntry(
        id='git-123456789abc',
        vm_name=vm_name,
        provider_host='github.com',
        owner='Kitware',
        repository='kwimage',
        access='write',
        provider_key_id='77',
        provider_key_title='aivm:test:test-vm:Kitware/kwimage:git-123456789abc',
        key_fingerprint=public_key_fingerprint(public),
        state='active',
    )


def test_parse_repository_common_spellings() -> None:
    expected = GitRepository('github.com', 'Kitware', 'kwimage')
    values = [
        'Kitware/kwimage',
        'github.com/Kitware/kwimage',
        'git@github.com:Kitware/kwimage.git',
        'ssh://git@github.com/Kitware/kwimage.git',
        'https://github.com/Kitware/kwimage.git',
        'https://github.com/Kitware/kwimage',
    ]
    for value in values:
        assert parse_repository_url(value) == expected

    enterprise = parse_repository_url(
        'git@git.example.com:team/project.git'
    )
    assert enterprise.host == 'git.example.com'
    assert enterprise.owner == 'team'
    assert enterprise.name == 'project'


def test_store_roundtrip_nested_credentials(tmp_path: Path) -> None:
    store = Store()
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    upsert_vm(store, cfg)
    upsert_credential(store, _entry('vm-a'))
    path = tmp_path / 'config.toml'

    save_store(store, path)
    text = path.read_text(encoding='utf-8')
    loaded = load_store(path)

    assert 'schema_version = 8' in text
    assert '[[vms.credentials]]' in text
    assert len(loaded.credentials) == 1
    assert loaded.credentials[0] == _entry('vm-a')


def test_config_lint_accepts_nested_credentials(tmp_path: Path) -> None:
    store = Store()
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    upsert_vm(store, cfg)
    upsert_credential(store, _entry('vm-a'))
    path = tmp_path / 'config.toml'

    save_store(store, path)

    assert _lint_store_text(path.read_text(encoding='utf-8')) == []


def test_managed_guest_configs_are_repository_specific() -> None:
    entry = _entry()
    ssh_text = render_ssh_config([entry])
    git_text = render_git_config([entry])

    assert f'Host aivm-cred-{entry.id}' in ssh_text
    assert 'HostName github.com' in ssh_text
    assert f'credentials/{entry.id}/id_ed25519' in ssh_text
    assert (
        f'[url "git@aivm-cred-{entry.id}:Kitware/kwimage.git"]'
        in git_text
    )
    assert 'insteadOf = git@github.com:Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage' in git_text


class _GitHubManager:
    def __init__(self, public_key: str) -> None:
        self.public_key = public_key
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        del kwargs
        self.calls.append(list(cmd))
        if 'list' in cmd:
            import json

            return SimpleNamespace(
                code=0,
                stdout=json.dumps(
                    [
                        {
                            'id': 17,
                            'key': self.public_key,
                            'readOnly': False,
                            'title': 'managed-key',
                        }
                    ]
                ),
                stderr='',
            )
        return SimpleNamespace(code=0, stdout='', stderr='')


def test_github_backend_uses_repo_deploy_key_cli(tmp_path: Path) -> None:
    public_path = tmp_path / 'id.pub'
    public_path.write_text(_public_key(), encoding='utf-8')
    manager = _GitHubManager(public_path.read_text(encoding='utf-8'))
    repo = GitRepository('github.com', 'Kitware', 'kwimage')

    result = github.add_deploy_key(
        repo,
        public_key_path=public_path,
        title='managed-key',
        write=True,
        manager=manager,  # type: ignore[arg-type]
    )
    github.delete_deploy_key(
        repo, result.key_id, manager=manager  # type: ignore[arg-type]
    )

    add = manager.calls[0]
    assert add[:4] == ['gh', 'repo', 'deploy-key', 'add']
    assert '--allow-write' in add
    assert ['--repo', 'Kitware/kwimage'] == add[
        add.index('--repo') : add.index('--repo') + 2
    ]
    assert manager.calls[-1][:5] == [
        'gh',
        'repo',
        'deploy-key',
        'delete',
        '17',
    ]


def _patch_generated_key(
    monkeypatch: MonkeyPatch, tmp_path: Path, events: list[str]
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))

    def fake_generate(
        entry: CredentialEntry, *, manager: CommandManager
    ) -> CredentialEntry:
        del manager
        events.append('generate')
        private_path = host_private_key_path(entry.vm_name, entry.id)
        public_path = host_public_key_path(entry.vm_name, entry.id)
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_text('PRIVATE KEY\n', encoding='utf-8')
        public = _public_key(entry.provider_key_title)
        public_path.write_text(public, encoding='utf-8')
        return replace(
            entry, key_fingerprint=public_key_fingerprint(public)
        )

    monkeypatch.setattr(
        'aivm.credentials.service._generate_host_key', fake_generate
    )


def test_grant_service_persists_active_credential(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    events: list[str] = []
    _patch_generated_key(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *names: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.check_auth',
        lambda *a, **k: events.append('auth'),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.add_deploy_key',
        lambda *a, **k: events.append('provider-add')
        or ProviderDeployKey('44', _public_key(), 'title', False),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )

    def fake_reconcile(*args: Any, **kwargs: Any) -> None:
        del args
        events.append('guest-install')
        assert kwargs['private_key'][1] == 'PRIVATE KEY\n'

    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        fake_reconcile,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(0, 'ok', ''),
    )

    entry = grant_repository_credential(
        cfg,
        store,
        path,
        GitRepository('github.com', 'Kitware', 'kwimage'),
        write=True,
        manager=CommandManager(yes=True),
    )

    assert entry.state == 'active'
    assert entry.provider_key_id == '44'
    loaded = load_store(path)
    assert find_credentials_for_vm(loaded, 'vm-a') == [entry]
    assert events == ['auth', 'generate', 'provider-add', 'guest-install']


def test_revoke_invalidates_provider_before_guest_cleanup(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    store = Store()
    upsert_vm(store, cfg)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    path = tmp_path / 'config.toml'
    save_store(store, path)
    store = load_store(path)
    events: list[str] = []
    _patch_generated_key(monkeypatch, tmp_path, events)
    # Create the host copies without changing the stored entry.
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text(_public_key(), encoding='utf-8')

    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *names: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key',
        lambda *a, **k: ProviderDeployKey(
            entry.provider_key_id, _public_key(), entry.provider_key_title, False
        ),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.delete_deploy_key',
        lambda *a, **k: events.append('provider-delete'),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: events.append('guest-cleanup'),
    )

    revoke_repository_credential(
        cfg,
        store,
        path,
        entry,
        manager=CommandManager(yes=True),
    )

    assert events[:2] == ['provider-delete', 'guest-cleanup']
    assert find_credentials_for_vm(load_store(path), 'vm-a') == []
    assert not private.parent.exists()


def test_revoke_keeps_recoverable_state_when_guest_cleanup_fails(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    store = Store()
    upsert_vm(store, cfg)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    path = tmp_path / 'config.toml'
    save_store(store, path)
    store = load_store(path)
    events: list[str] = []
    _patch_generated_key(monkeypatch, tmp_path, events)
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text(_public_key(), encoding='utf-8')

    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *names: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key',
        lambda *a, **k: ProviderDeployKey(
            entry.provider_key_id, _public_key(), entry.provider_key_title, False
        ),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.delete_deploy_key',
        lambda *a, **k: events.append('provider-delete'),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: (_ for _ in ()).throw(AIVMError('VM unavailable')),
    )

    with pytest.raises(AIVMError, match='VM unavailable'):
        revoke_repository_credential(
            cfg,
            store,
            path,
            entry,
            manager=CommandManager(yes=True),
        )

    assert events == ['provider-delete']
    [pending] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert pending.state == 'revocation-pending'
    assert private.exists()


def test_creds_add_dry_run_and_help_tree(
    cfg_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = run_cli(
        [
            'vm',
            'creds',
            'add',
            'Kitware/kwimage',
            '--write',
            '--dry_run',
            '--yes',
            '--config',
            str(cfg_path),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert 'Repository credential grant' in out
    assert 'github.com/Kitware/kwimage' in out
    assert 'Access:      write' in out
    assert find_credentials_for_vm(load_store(cfg_path), 'test-vm') == []

    assert run_cli(['help', 'tree', '--yes', '--config', str(cfg_path)]) == 0
    tree = capsys.readouterr().out
    assert 'aivm vm creds - Manage scoped credentials installed in a VM.' in tree
    assert 'aivm vm creds add - Grant a VM repository access' in tree


def test_vm_delete_refuses_to_orphan_credentials(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    upsert_credential(store, _entry('vm-a'))
    save_store(store, path)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.destroy_vm',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('destroy must not run')
        ),
    )

    with pytest.raises(AIVMError, match='still owns repository credentials'):
        VMDeleteCLI.main(
            argv=False,
            vm='vm-a',
            config=str(path),
            yes=True,
            dry_run=True,
        )


def test_vm_delete_cleans_revoked_pending_credentials(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = replace(_entry('vm-a'), state='revocation-pending')
    upsert_credential(store, entry)
    save_store(store, path)
    key_dir = host_credential_dir(entry.vm_name, entry.id)
    key_dir.mkdir(parents=True)
    (key_dir / 'id_ed25519').write_text('revoked', encoding='utf-8')
    destroyed: list[str] = []
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.destroy_vm',
        lambda cfg, **kwargs: destroyed.append(cfg.vm.name),
    )

    rc = VMDeleteCLI.main(
        argv=False,
        vm='vm-a',
        config=str(path),
        yes=True,
        dry_run=False,
    )

    assert rc == 0
    assert destroyed == ['vm-a']
    assert not key_dir.exists()
    loaded = load_store(path)
    assert loaded.vms == []
    assert loaded.credentials == []

