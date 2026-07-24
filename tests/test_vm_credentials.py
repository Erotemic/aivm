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
from aivm.credentials.guest import (
    guest_private_key_relpath,
    render_git_config,
    render_ssh_config,
    verify_guest_repository,
)
from aivm.credentials.keys import (
    credential_id,
    host_credential_dir,
    host_private_key_path,
    host_public_key_path,
    public_key_fingerprint,
)
from aivm.credentials.models import GitRepository, ProviderDeployKey
from aivm.credentials.resolve import parse_repository_url
from aivm.credentials.service import (
    _generate_host_key,
    _select_remote_key,
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
)
from aivm.errors import AIVMError
from tests.helpers import make_cfg, run_cli, write_store


def _public_key(comment: str = 'test') -> str:
    blob = base64.b64encode(b'aivm synthetic ed25519 blob').decode('ascii')
    return f'ssh-ed25519 {blob} {comment}\n'


def _entry(vm_name: str = 'test-vm') -> CredentialEntry:
    public = _public_key()
    repo = GitRepository('github.com', 'Kitware', 'kwimage')
    cred_id = credential_id(vm_name, repo.canonical)
    return CredentialEntry(
        id=cred_id,
        vm_name=vm_name,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access='write',
        provider_key_id='77',
        provider_key_title=(
            f'aivm:test:{vm_name}:Kitware/kwimage:{cred_id}'
        ),
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


def test_store_roundtrip_split_credentials(tmp_path: Path) -> None:
    from aivm.config_store import save_store_split

    store = Store()
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    upsert_vm(store, cfg)
    upsert_credential(store, _entry('vm-a'))
    path = tmp_path / 'config.toml'

    save_store_split(store, path)
    loaded = load_store(path)

    assert loaded.credentials == [_entry('vm-a')]
    vm_fragment = tmp_path / 'vms' / 'vm-a.toml'
    assert '[[vms.credentials]]' in vm_fragment.read_text(encoding='utf-8')


def test_config_lint_accepts_nested_credentials(tmp_path: Path) -> None:
    store = Store()
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    upsert_vm(store, cfg)
    upsert_credential(store, _entry('vm-a'))
    path = tmp_path / 'config.toml'

    save_store(store, path)

    assert _lint_store_text(path.read_text(encoding='utf-8')) == []


def test_config_lint_rejects_incomplete_and_invalid_credentials() -> None:
    text = '''
    schema_version = 8
    [[vms]]
    name = "vm-a"
    [[vms.credentials]]
    id = "git-bad"
    kind = "unknown"
    provider_host = "github.com"
    owner = "Kitware"
    repository = "kwimage"
    access = "admin"
    provider_key_title = ""
    key_fingerprint = ""
    state = "mystery"
    '''
    problems = _lint_store_text(text)
    assert any('missing required key(s)' in item for item in problems)
    assert any('unsupported kind' in item for item in problems)
    assert any('invalid access' in item for item in problems)
    assert any('invalid state' in item for item in problems)


def test_managed_guest_configs_are_repository_specific() -> None:
    entry = _entry()
    ssh_text = render_ssh_config([entry])
    git_text = render_git_config([entry])

    assert f'Host aivm-cred-{entry.id}' in ssh_text
    assert 'HostName github.com' in ssh_text
    assert f'credentials/{entry.id}/id_ed25519' in ssh_text
    assert 'BatchMode yes' in ssh_text
    assert 'StrictHostKeyChecking accept-new' in ssh_text
    assert (
        f'[url "git@aivm-cred-{entry.id}:Kitware/kwimage.git"]'
        in git_text
    )
    assert 'insteadOf = git@github.com:Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage\n' not in git_text


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


def test_github_backend_read_only_omits_allow_write(tmp_path: Path) -> None:
    public_path = tmp_path / 'id.pub'
    public_path.write_text(_public_key(), encoding='utf-8')
    manager = _GitHubManager(public_path.read_text(encoding='utf-8'))
    repo = GitRepository('github.com', 'Kitware', 'kwimage')

    github.add_deploy_key(
        repo,
        public_key_path=public_path,
        title='managed-key',
        write=False,
        manager=manager,  # type: ignore[arg-type]
    )

    assert '--allow-write' not in manager.calls[0]


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
    remote_results = iter(
        [
            ProviderDeployKey(
                entry.provider_key_id,
                _public_key(),
                entry.provider_key_title,
                False,
            ),
            None,
        ]
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key',
        lambda *a, **k: next(remote_results),
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
    remote_results = iter(
        [
            ProviderDeployKey(
                entry.provider_key_id,
                _public_key(),
                entry.provider_key_title,
                False,
            ),
            None,
        ]
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key',
        lambda *a, **k: next(remote_results),
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

def test_parse_repository_rejects_config_injection_syntax() -> None:
    bad = [
        'owner with space/repo',
        'owner/repo"bad',
        'https://github.com/owner/repo.git?unexpected=1',
        'git@bad host:owner/repo.git',
    ]
    for value in bad:
        with pytest.raises(AIVMError):
            parse_repository_url(value)


def test_git_rewrite_does_not_capture_prefixed_sibling(tmp_path: Path) -> None:
    import os
    import subprocess

    config_path = tmp_path / 'gitconfig'
    config_path.write_text(render_git_config([_entry()]), encoding='utf-8')
    repo_dir = tmp_path / 'repo'
    subprocess.run(['git', 'init', '-q', str(repo_dir)], check=True)
    env = {
        **os.environ,
        'GIT_CONFIG_GLOBAL': str(config_path),
        'GIT_CONFIG_NOSYSTEM': '1',
    }
    sibling = 'https://github.com/Kitware/kwimage-extra.git'
    subprocess.run(
        ['git', '-C', str(repo_dir), 'remote', 'add', 'origin', sibling],
        check=True,
        env=env,
    )
    result = subprocess.run(
        ['git', '-C', str(repo_dir), 'remote', 'get-url', 'origin'],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.stdout.strip() == sibling


def test_remote_identity_uses_recorded_fingerprint_not_host_file() -> None:
    entry = _entry()
    expected = ProviderDeployKey(
        entry.provider_key_id,
        _public_key(),
        entry.provider_key_title,
        False,
    )
    unrelated = ProviderDeployKey(
        '99',
        _public_key('unrelated').replace(
            base64.b64encode(b'aivm synthetic ed25519 blob').decode('ascii'),
            base64.b64encode(b'another synthetic key blob').decode('ascii'),
        ),
        'other-key',
        False,
    )
    assert _select_remote_key(entry, [unrelated, expected]) == expected

    wrong_id = replace(unrelated, key_id=entry.provider_key_id)
    with pytest.raises(AIVMError, match='fingerprint recorded by AIVM'):
        _select_remote_key(entry, [wrong_id])


def test_existing_host_key_fingerprint_drift_is_rejected(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = _entry('vm-a')
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    private.parent.mkdir(parents=True)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    changed_blob = base64.b64encode(b'changed key material').decode('ascii')
    public.write_text(f'ssh-ed25519 {changed_blob} changed\n', encoding='utf-8')

    with pytest.raises(AIVMError, match='does not match the fingerprint'):
        _generate_host_key(entry, manager=CommandManager(yes=True))


def test_store_rejects_malformed_credential_instead_of_dropping_it(
    tmp_path: Path,
) -> None:
    path = tmp_path / 'config.toml'
    path.write_text(
        'schema_version = 8\n'
        '[[vms]]\n'
        'name = "vm-a"\n'
        '[[vms.credentials]]\n'
        'id = "git-deadbeef"\n'
        'repository = "kwimage"\n',
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='missing required field'):
        load_store(path)


def test_store_rejects_duplicate_credential_id(tmp_path: Path) -> None:
    store = Store()
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    upsert_vm(store, cfg)
    first = _entry('vm-a')
    store.credentials = [first, replace(first, provider_key_id='88')]
    path = tmp_path / 'config.toml'
    save_store(store, path)
    with pytest.raises(ValueError, match='duplicate credential id'):
        load_store(path)


def test_revoke_refuses_cleanup_when_provider_key_remains(
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
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *names: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.check_auth', lambda *a, **k: None
    )
    remote = ProviderDeployKey(
        entry.provider_key_id, _public_key(), entry.provider_key_title, False
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key', lambda *a, **k: remote
    )
    monkeypatch.setattr(
        'aivm.credentials.service.github.delete_deploy_key', lambda *a, **k: None
    )

    with pytest.raises(AIVMError, match='still reports deploy key'):
        revoke_repository_credential(
            cfg,
            store,
            path,
            entry,
            manager=CommandManager(yes=True),
        )

    [still_active] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert still_active.state == 'active'


def test_store_rejects_credential_path_escape(tmp_path: Path) -> None:
    fingerprint = public_key_fingerprint(_public_key())
    path = tmp_path / 'config.toml'
    path.write_text(
        'schema_version = 8\n'
        '[[vms]]\n'
        'name = "vm-a"\n'
        '[[vms.credentials]]\n'
        'id = "../../../../.ssh"\n'
        'kind = "github-deploy-key"\n'
        'provider_host = "github.com"\n'
        'owner = "Kitware"\n'
        'repository = "kwimage"\n'
        'access = "write"\n'
        'provider_key_id = "77"\n'
        'provider_key_title = "managed"\n'
        f'key_fingerprint = "{fingerprint}"\n'
        'state = "active"\n',
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='Invalid credential id'):
        load_store(path)


def test_store_rejects_credential_identity_mismatch(tmp_path: Path) -> None:
    fingerprint = public_key_fingerprint(_public_key())
    path = tmp_path / 'config.toml'
    path.write_text(
        'schema_version = 8\n'
        '[[vms]]\n'
        'name = "vm-a"\n'
        '[[vms.credentials]]\n'
        'id = "git-000000000000"\n'
        'kind = "github-deploy-key"\n'
        'provider_host = "github.com"\n'
        'owner = "Kitware"\n'
        'repository = "kwimage"\n'
        'access = "write"\n'
        'provider_key_id = "77"\n'
        'provider_key_title = "managed"\n'
        f'key_fingerprint = "{fingerprint}"\n'
        'state = "active"\n',
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='does not match VM'):
        load_store(path)


def test_store_rejects_credential_config_injection(tmp_path: Path) -> None:
    entry = _entry('vm-a')
    path = tmp_path / 'config.toml'
    path.write_text(
        'schema_version = 8\n'
        '[[vms]]\n'
        'name = "vm-a"\n'
        '[[vms.credentials]]\n'
        f'id = "{entry.id}"\n'
        'kind = "github-deploy-key"\n'
        'provider_host = "github.com"\n'
        'owner = "Kitware\\nHost injected"\n'
        'repository = "kwimage"\n'
        'access = "write"\n'
        'provider_key_id = "77"\n'
        'provider_key_title = "managed"\n'
        f'key_fingerprint = "{entry.key_fingerprint}"\n'
        'state = "active"\n',
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='control characters'):
        load_store(path)


def test_credential_path_helpers_reject_unsafe_ids(tmp_path: Path) -> None:
    with pytest.raises(AIVMError, match='Invalid credential id'):
        host_credential_dir('vm-a', '../../../../.ssh')
    with pytest.raises(AIVMError, match='Invalid credential id'):
        guest_private_key_relpath('../../../../.ssh')


def test_repository_transport_requires_exact_git_suffix() -> None:
    for value in (
        'https://github.com/Kitware/kwimage',
        'git@github.com:Kitware/kwimage',
    ):
        with pytest.raises(AIVMError, match='must end in .git'):
            parse_repository_url(value)


def test_repository_custom_ports_are_rejected() -> None:
    with pytest.raises(AIVMError, match='explicit ports'):
        parse_repository_url(
            'ssh://git@ghe.example.com:2222/team/project.git'
        )


def test_guest_verification_uses_selected_transport_url(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    original = 'https://github.com/Kitware/kwimage.git'
    repo = parse_repository_url(original)
    scripts: list[str] = []

    def fake_run_guest(*args: Any, **kwargs: Any) -> CommandResult:
        del args
        scripts.append(kwargs['script'])
        return CommandResult(code=0, stdout='', stderr='')

    monkeypatch.setattr(
        'aivm.credentials.guest._run_guest', fake_run_guest
    )
    verify_guest_repository(
        cfg,
        '10.0.0.5',
        repo,
        manager=CommandManager(yes=True),
    )
    assert scripts == [f'GIT_TERMINAL_PROMPT=0 git ls-remote {original} HEAD']


def test_status_reports_malformed_host_public_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = _entry('vm-a')
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    private.parent.mkdir(parents=True)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text('not a public key\n', encoding='utf-8')
    monkeypatch.setattr(
        'aivm.credentials.service.github.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._find_remote_key', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.get_ip_cached', lambda *a, **k: None
    )

    report = inspect_credential(
        make_cfg(tmp_path, **{'vm.name': 'vm-a'}),
        entry,
        manager=CommandManager(yes=True),
    )

    assert report['host_ok'] is True
    assert report['fingerprint_ok'] is False
    assert 'Malformed SSH public key' in report['host_detail']
