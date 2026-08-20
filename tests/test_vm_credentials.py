"""Tests for VM-scoped GitHub deploy-key credentials."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.cli.config.lint import _lint_store_text
from aivm.cli.vm_creds import (
    VMCredsAddCLI,
    _print_agent_grant_readiness,
    _resolve_credential_selector,
)
from aivm.cli.vm_lifecycle import VMCreateCLI, VMDeleteCLI, VMUpCLI
from aivm.commands import (
    CommandError,
    CommandManager,
    CommandResult,
    CommandRole,
)
from aivm.config_store import (
    CredentialEntry,
    Store,
    find_credentials_for_vm,
    load_store,
    save_store,
    upsert_credential,
    upsert_vm,
)
from aivm.credentials import github, providers
from aivm.credentials.agent_transport import (
    AgentForwarding,
    AgentGrantForwardingReadiness,
)
from aivm.credentials.errors import (
    ProviderPermissionError,
    ProviderRejectedError,
)
from aivm.credentials.gitlab import (
    GitLabAuthenticationError,
    GitLabTransportError,
)
from aivm.credentials.guest import (
    _ensure_guest_includes,
    guest_private_key_relpath,
    reconcile_guest_credentials,
    render_git_config,
    render_ssh_config,
    verify_guest_repository,
)
from aivm.credentials.keys import (
    generate_host_key,
    host_credential_dir,
    host_private_key_path,
    host_public_key_path,
    inspect_host_keypair,
    public_key_fingerprint,
)
from aivm.credentials.models import GitRepository, ProviderDeployKey
from aivm.credentials.resolve import parse_repository_url
from aivm.credentials.schema import (
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
    CREDENTIAL_STATE_ABANDON_PENDING,
    CREDENTIAL_STATE_ACTIVE,
    CREDENTIAL_STATE_PENDING,
    CREDENTIAL_STATE_REVOCATION_PENDING,
    CredentialKind,
    credential_allows_vm_delete,
    credential_is_guest_usable,
    normalize_credential_access,
)
from aivm.credentials.service import (
    abandon_repository_credential,
    describe_unregistered_credential,
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
)
from aivm.credentials.validation import credential_id
from aivm.errors import AIVMError, ApprovalUnavailableError, UserDeclinedError
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
        provider_key_title=(f'aivm:test:{vm_name}:Kitware/kwimage:{cred_id}'),
        key_fingerprint=public_key_fingerprint(public),
        state='active',
    )


def _make_managed_credential_dirs(
    directory: Path,
    *,
    include_parent: bool = True,
    include_leaf: bool = True,
) -> None:
    """Create protected managed descendants without implicit parent modes."""

    def secure_mkdir(path: Path) -> None:
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)

    vm_directory = directory.parent.parent
    secure_mkdir(vm_directory)
    if include_parent:
        secure_mkdir(directory.parent)
    if include_leaf:
        secure_mkdir(directory)


def test_credential_state_predicates() -> None:
    entry = _entry()
    assert credential_is_guest_usable(
        replace(entry, state=CREDENTIAL_STATE_PENDING)
    )
    assert credential_is_guest_usable(
        replace(entry, state=CREDENTIAL_STATE_ACTIVE)
    )
    revoked = replace(entry, state=CREDENTIAL_STATE_REVOCATION_PENDING)
    abandoned = replace(entry, state=CREDENTIAL_STATE_ABANDON_PENDING)
    assert not credential_is_guest_usable(revoked)
    assert not credential_is_guest_usable(abandoned)
    assert credential_allows_vm_delete(revoked)
    assert not credential_allows_vm_delete(abandoned)


def test_resolve_credential_selector_prefers_exact_id(
    monkeypatch: MonkeyPatch,
) -> None:
    entry = _entry('vm-a')
    store = Store(credentials=[entry])

    def fail_resolve(*args: Any, **kwargs: Any) -> GitRepository:
        raise AssertionError('exact credential ids must not resolve as URLs')

    monkeypatch.setattr('aivm.cli.vm_creds.resolve_repository', fail_resolve)
    result = _resolve_credential_selector(
        store,
        vm_name=entry.vm_name,
        selector=entry.id,
        remote='origin',
        manager=CommandManager(yes=True),
    )
    assert result is entry


def test_resolve_credential_selector_accepts_repository(
    monkeypatch: MonkeyPatch,
) -> None:
    entry = _entry('vm-a')
    store = Store(credentials=[entry])
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)
    monkeypatch.setattr(
        'aivm.cli.vm_creds.resolve_repository',
        lambda *args, **kwargs: repo,
    )
    result = _resolve_credential_selector(
        store,
        vm_name=entry.vm_name,
        selector='Kitware/kwimage',
        remote='origin',
        manager=CommandManager(yes=True),
    )
    assert result is entry


def _write_real_host_keypair(
    entry: CredentialEntry,
) -> tuple[CredentialEntry, Path, Path]:
    if shutil.which('ssh-keygen') is None:
        pytest.skip('ssh-keygen is required for host key integrity tests')
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    _make_managed_credential_dirs(private.parent)
    subprocess.run(
        [
            'ssh-keygen',
            '-q',
            '-t',
            'ed25519',
            '-N',
            '',
            '-f',
            str(private),
            '-C',
            entry.provider_key_title,
        ],
        check=True,
    )
    private.chmod(0o600)
    public.chmod(0o644)
    fingerprint = public_key_fingerprint(public.read_text(encoding='utf-8'))
    return replace(entry, key_fingerprint=fingerprint), private, public


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

    enterprise = parse_repository_url('git@git.example.com:team/project.git')
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
    text = """
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
    """
    problems = _lint_store_text(text)
    assert any('missing required key(s)' in item for item in problems)
    assert any('unsupported kind' in item for item in problems)
    assert any('invalid access' in item for item in problems)
    assert any('invalid state' in item for item in problems)


def test_guest_include_rejects_symlinked_ssh_config(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, str] = {}

    def capture_submit(*args: Any, **kwargs: Any) -> None:
        del args
        captured['script'] = kwargs['script']

    monkeypatch.setattr('aivm.credentials.guest._submit_guest', capture_submit)
    _ensure_guest_includes(
        make_cfg(tmp_path),
        '10.0.0.5',
        manager=CommandManager(yes=True),
    )

    home = tmp_path / 'home'
    ssh_dir = home / '.ssh'
    ssh_dir.mkdir(parents=True)
    target = tmp_path / 'dotfiles' / 'ssh-config'
    target.parent.mkdir()
    original = 'Host example\n    User agent\n'
    target.write_text(original, encoding='utf-8')
    original_mode = target.stat().st_mode & 0o777
    config = ssh_dir / 'config'
    config.symlink_to(target)

    result = subprocess.run(
        ['/bin/sh', '-c', captured['script']],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, 'HOME': str(home)},
    )

    assert result.returncode == 78
    assert 'refuses to replace symlinked ~/.ssh/config' in result.stderr
    assert config.is_symlink()
    assert config.resolve() == target.resolve()
    assert target.read_text(encoding='utf-8') == original
    assert target.stat().st_mode & 0o777 == original_mode


def test_guest_include_accepts_symlink_with_exact_include(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, str] = {}

    def capture_submit(*args: Any, **kwargs: Any) -> None:
        del args
        captured['script'] = kwargs['script']

    monkeypatch.setattr('aivm.credentials.guest._submit_guest', capture_submit)
    _ensure_guest_includes(
        make_cfg(tmp_path),
        '10.0.0.5',
        manager=CommandManager(yes=True),
    )

    home = tmp_path / 'home'
    ssh_dir = home / '.ssh'
    ssh_dir.mkdir(parents=True)
    target = tmp_path / 'dotfiles' / 'ssh-config'
    target.parent.mkdir()
    original = 'Include ~/.ssh/aivm.d/*.conf\nHost example\n    User agent\n'
    target.write_text(original, encoding='utf-8')
    original_mode = target.stat().st_mode & 0o777
    config = ssh_dir / 'config'
    config.symlink_to(target)

    result = subprocess.run(
        ['/bin/sh', '-c', captured['script']],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, 'HOME': str(home)},
    )

    assert result.returncode == 0, result.stderr
    assert config.is_symlink()
    assert config.resolve() == target.resolve()
    assert target.read_text(encoding='utf-8') == original
    assert target.stat().st_mode & 0o777 == original_mode


def test_guest_include_preflight_precedes_key_install(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        'aivm.credentials.guest._ensure_guest_includes',
        lambda *a, **k: events.append('include-preflight'),
    )
    monkeypatch.setattr(
        'aivm.credentials.guest._install_guest_file',
        lambda *a, **k: events.append(f'install:{k["label"]}'),
    )

    entry = _entry()
    reconcile_guest_credentials(
        make_cfg(tmp_path),
        '10.0.0.5',
        credentials=[entry],
        private_key=(entry.id, 'PRIVATE KEY\n'),
        manager=CommandManager(yes=True),
    )

    assert events[0] == 'include-preflight'
    assert events[1].startswith('install:private deploy key')


def test_managed_guest_configs_are_repository_specific() -> None:
    entry = _entry()
    ssh_text = render_ssh_config([entry])
    git_text = render_git_config([entry])

    assert f'Host aivm-cred-{entry.id}' in ssh_text
    assert 'HostName github.com' in ssh_text
    assert f'credentials/{entry.id}/id_ed25519' in ssh_text
    assert 'BatchMode yes' in ssh_text
    assert 'StrictHostKeyChecking accept-new' in ssh_text
    assert f'[url "git@aivm-cred-{entry.id}:Kitware/kwimage.git"]' in git_text
    assert 'insteadOf = git@github.com:Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage.git' in git_text
    assert 'insteadOf = https://github.com/Kitware/kwimage\n' not in git_text


def test_guest_renders_accept_principal_scoped_credentials() -> None:
    # Machine stores (and every credential rewritten by the pre-0.6
    # migration) salt the credential id with the owning principal; the guest
    # render path must validate against the same salted id.
    repo = GitRepository('github.com', 'Kitware', 'kwimage')
    principal = 'principal:agent'
    cred_id = credential_id('test-vm', repo.canonical, principal)
    entry = _entry()
    entry.id = cred_id
    entry.principal_id = principal
    entry.provider_key_title = f'aivm:test:test-vm:Kitware/kwimage:{cred_id}'

    ssh_text = render_ssh_config([entry])
    git_text = render_git_config([entry])

    assert f'Host aivm-cred-{cred_id}' in ssh_text
    assert f'[url "git@aivm-cred-{cred_id}:Kitware/kwimage.git"]' in git_text


class _GitHubManager(CommandManager):
    def __init__(
        self,
        public_key: str,
        *,
        pages: list[list[dict[str, object]]] | None = None,
        exact: dict[str, object] | None = None,
        exact_missing: bool = False,
        exact_error: str = '',
        list_error: str = '',
    ) -> None:
        super().__init__(yes=True)
        self.public_key = public_key
        self.pages = pages
        self.exact = exact
        self.exact_missing = exact_missing
        self.exact_error = exact_error
        self.list_error = list_error
        self.deleted = False
        self.calls: list[list[str]] = []

    def run(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: str = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandResult:
        del (
            sudo,
            role,
            capture,
            text,
            input_text,
            env,
            timeout,
            summary,
            detail,
        )
        self.calls.append(list(cmd))
        if list(cmd[:2]) == ['gh', 'api']:
            import json

            if '--paginate' in cmd:
                if self.list_error:
                    result = CommandResult(
                        code=1, stdout='', stderr=self.list_error
                    )
                    if check:
                        raise CommandError(list(cmd), result)
                    return result
                pages: list[list[dict[str, object]]]
                if self.deleted:
                    pages = [[]]
                else:
                    pages = self.pages or [
                        [
                            {
                                'id': 17,
                                'key': self.public_key,
                                'read_only': False,
                                'title': 'managed-key',
                            }
                        ]
                    ]
                return CommandResult(
                    code=0,
                    stdout='\n'.join(json.dumps(page) for page in pages),
                    stderr='',
                )
            if self.exact_error:
                return CommandResult(code=1, stdout='', stderr=self.exact_error)
            if self.exact_missing or self.deleted:
                return CommandResult(
                    code=1, stdout='', stderr='gh: Not Found (HTTP 404)'
                )
            exact = self.exact or {
                'id': 17,
                'key': self.public_key,
                'read_only': False,
                'title': 'managed-key',
            }
            return CommandResult(code=0, stdout=json.dumps(exact), stderr='')
        if list(cmd[:4]) == ['gh', 'repo', 'deploy-key', 'delete']:
            self.deleted = True
        return CommandResult(code=0, stdout='', stderr='')


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
        manager=manager,
    )
    github.delete_deploy_key(repo, result.key_id, manager=manager)

    add = manager.calls[0]
    assert add[:4] == ['gh', 'repo', 'deploy-key', 'add']
    assert '--allow-write' in add
    assert ['--repo', 'Kitware/kwimage'] == add[
        add.index('--repo') : add.index('--repo') + 2
    ]
    discovery = manager.calls[1]
    assert discovery[:5] == [
        'gh',
        'api',
        '--hostname',
        'github.com',
        '--paginate',
    ]
    assert '--slurp' not in discovery
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
        manager=manager,
    )

    assert '--allow-write' not in manager.calls[0]


def test_recorded_provider_key_uses_exact_id_endpoint() -> None:
    entry = _entry()
    exact: dict[str, object] = {
        'id': int(entry.provider_key_id),
        'key': _public_key(),
        'read_only': False,
        'title': entry.provider_key_title,
    }
    manager = _GitHubManager(_public_key(), exact=exact)
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    result = github.find_recorded_provider_key(repo, entry, manager=manager)

    assert result is not None
    assert result.key_id == entry.provider_key_id
    assert manager.calls == [
        [
            'gh',
            'api',
            '--hostname',
            'github.com',
            f'repos/Kitware/kwimage/keys/{entry.provider_key_id}',
        ]
    ]


def test_recorded_provider_key_exact_404_requires_collection_confirmation() -> (
    None
):
    entry = _entry()
    manager = _GitHubManager(_public_key(), exact_missing=True, pages=[[]])
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    assert (
        github.find_recorded_provider_key(repo, entry, manager=manager) is None
    )
    assert len(manager.calls) == 2
    assert '--paginate' not in manager.calls[0]
    assert '--paginate' in manager.calls[1]


def test_recorded_provider_key_exact_404_finds_key_in_collection() -> None:
    entry = _entry()
    target: dict[str, object] = {
        'id': int(entry.provider_key_id),
        'key': _public_key(),
        'read_only': False,
        'title': entry.provider_key_title,
    }
    manager = _GitHubManager(
        _public_key(), exact_missing=True, pages=[[target]]
    )
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    result = github.find_recorded_provider_key(repo, entry, manager=manager)

    assert result is not None
    assert result.key_id == entry.provider_key_id
    assert len(manager.calls) == 2
    assert '--paginate' in manager.calls[1]


def test_recorded_provider_key_exact_404_detects_id_drift() -> None:
    entry = _entry()
    target: dict[str, object] = {
        'id': 999,
        'key': _public_key(),
        'read_only': False,
        'title': entry.provider_key_title,
    }
    manager = _GitHubManager(
        _public_key(), exact_missing=True, pages=[[target]]
    )
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    result = github.find_recorded_provider_key(repo, entry, manager=manager)

    assert result is not None
    assert result.key_id == '999'


def test_recorded_provider_key_exact_404_collection_failure_is_not_absence() -> (
    None
):
    """A collection read that failed must raise, never read as "no key".

    The failure is reported as a typed error naming what gh actually said,
    but the invariant under test is that it propagates instead of letting the
    caller conclude the provider holds no matching key.
    """
    entry = _entry()
    manager = _GitHubManager(
        _public_key(),
        exact_missing=True,
        list_error='gh: authentication required (HTTP 404)',
    )
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    with pytest.raises(AIVMError, match='authentication required'):
        github.find_recorded_provider_key(repo, entry, manager=manager)


def test_recorded_provider_key_non_404_failure_is_not_absence() -> None:
    entry = _entry()
    manager = _GitHubManager(_public_key(), exact_error='gh: connection failed')
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    with pytest.raises(CommandError, match='connection failed'):
        github.find_recorded_provider_key(repo, entry, manager=manager)


def test_recorded_provider_key_without_id_uses_all_pages() -> None:
    entry = replace(_entry(), provider_key_id='')
    unrelated: list[dict[str, object]] = []
    for index in range(100):
        blob = base64.b64encode(f'unrelated-{index}'.encode()).decode()
        unrelated.append(
            {
                'id': index + 1,
                'key': f'ssh-ed25519 {blob} unrelated-{index}\n',
                'read_only': True,
                'title': f'unrelated-{index}',
            }
        )
    target: dict[str, object] = {
        'id': 101,
        'key': _public_key(),
        'read_only': False,
        'title': entry.provider_key_title,
    }
    manager = _GitHubManager(_public_key(), pages=[unrelated, [target]])
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)

    result = github.find_recorded_provider_key(repo, entry, manager=manager)

    assert result is not None
    assert result.key_id == '101'
    [call] = manager.calls
    assert call[:5] == [
        'gh',
        'api',
        '--hostname',
        'github.com',
        '--paginate',
    ]
    assert '--slurp' not in call
    assert call[-1] == 'repos/Kitware/kwimage/keys?per_page=100'


def _patch_provider_reachable(monkeypatch: MonkeyPatch) -> None:
    """Pretend provider automation is usable.

    The test host has no ``gh``, and registration is optional, so without this
    every grant would take the manual-handoff path and the tests that mean to
    exercise real provider responses would quietly stop doing so.
    """
    monkeypatch.setattr(
        'aivm.credentials.service.providers.automation_unavailable_reason',
        lambda *a, **k: '',
    )


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
        _make_managed_credential_dirs(private_path.parent)
        private_path.write_text('PRIVATE KEY\n', encoding='utf-8')
        public = _public_key(entry.provider_key_title)
        public_path.write_text(public, encoding='utf-8')
        return replace(entry, key_fingerprint=public_key_fingerprint(public))

    monkeypatch.setattr(
        'aivm.credentials.keys.generate_host_key', fake_generate
    )


def test_grant_service_persists_active_credential(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    events: list[str] = []
    _patch_generated_key(monkeypatch, tmp_path, events)
    _patch_provider_reachable(monkeypatch)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth',
        lambda *a, **k: events.append('auth'),
    )
    monkeypatch.setattr(
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.add_deploy_key',
        lambda *a, **k: (
            events.append('provider-add')
            or ProviderDeployKey('44', _public_key(), 'title', False)
        ),
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
        access='write',
        manager=CommandManager(yes=True),
    )

    assert entry.state == 'active'
    assert entry.provider_key_id == '44'
    loaded = load_store(path)
    assert find_credentials_for_vm(loaded, 'vm-a') == [entry]
    # No separate auth step: signing in is part of asking whether provider
    # automation is available at all, which is optional and happens after the
    # key exists.
    assert events == ['generate', 'provider-add', 'guest-install']


class _RefusingGitHubManager(CommandManager):
    """Fail one gh command with a real error payload; succeed at the rest."""

    def __init__(
        self,
        stderr: str,
        failing_command: Sequence[str] = ('gh', 'repo', 'deploy-key', 'add'),
    ) -> None:
        super().__init__(yes=True)
        self.stderr = stderr
        self.failing_command = list(failing_command)

    def run(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: str = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandResult:
        del (
            sudo,
            role,
            check,
            capture,
            text,
            input_text,
            env,
            timeout,
            summary,
            detail,
        )
        if list(cmd[: len(self.failing_command)]) == self.failing_command:
            raise CommandError(
                list(cmd), CommandResult(code=1, stdout='', stderr=self.stderr)
            )
        if list(cmd[:2]) == ['gh', 'api']:
            # A well-formed empty page: the repository has no deploy keys.
            return CommandResult(code=0, stdout='[]', stderr='')
        return CommandResult(code=0, stdout='', stderr='')


def _grant_against_refusing_provider(
    monkeypatch: MonkeyPatch, tmp_path: Path, stderr: str
) -> tuple[Path, CredentialEntry]:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    _patch_generated_key(monkeypatch, tmp_path, [])
    _patch_provider_reachable(monkeypatch)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(255, '', 'Permission denied (publickey)'),
    )
    repo = GitRepository('github.com', 'Kitware', 'kwimage')
    entry = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        manager=_RefusingGitHubManager(stderr),
    )
    return path, entry


def test_refused_deploy_key_becomes_admin_handoff(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Provider policy must not block local credential creation."""
    stderr = (
        'HTTP 422: Validation Failed '
        '(https://api.github.com/repos/Kitware/kwimage/keys)\n'
        'Deploy keys are disabled for this repository'
    )

    store_path, entry = _grant_against_refusing_provider(
        monkeypatch, tmp_path, stderr
    )

    assert entry.provider_managed is False
    assert entry.provider_key_id == ''
    assert entry.state == 'pending'
    [persisted] = find_credentials_for_vm(load_store(store_path), 'vm-a')
    assert persisted == entry
    assert host_credential_dir('vm-a', entry.id).exists()


@pytest.mark.parametrize(
    'failing_command, stderr',
    [
        pytest.param(
            ['gh', 'repo', 'deploy-key', 'add'],
            'gh: Must have admin rights to Repository. (HTTP 403)',
            id='denied-on-create',
        ),
        # A non-admin cannot read deploy keys either, so the denial can land
        # one step earlier, before creation is ever attempted.
        pytest.param(
            ['gh', 'api'],
            'gh: Must have admin rights to Repository. (HTTP 403)',
            id='denied-on-read',
        ),
    ],
)
def test_permission_denial_hands_the_grant_off_instead_of_failing(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    failing_command: list[str],
    stderr: str,
) -> None:
    """AIVM does everything it can, then asks a human for the one step it cannot.

    The installed private key is inert until GitHub accepts its public half,
    so installing it before registration costs no access and lets the grant
    complete by itself once an admin acts.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    _patch_generated_key(monkeypatch, tmp_path, [])
    _patch_provider_reachable(monkeypatch)
    installed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: installed.append(k['private_key']),
    )
    # Nobody has registered the public key yet, so Git access legitimately
    # fails. That must not fail the command.
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(255, '', 'Permission denied (publickey)'),
    )
    repo = GitRepository('github.com', 'Kitware', 'kwimage')

    entry = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        manager=_RefusingGitHubManager(stderr, failing_command),
    )

    assert entry.provider_managed is False
    assert entry.provider_key_id == ''
    assert entry.state == 'pending', 'unverified access must not read as active'
    assert installed and installed[0][0] == entry.id, 'key never reached the VM'

    # The handoff names the key an admin has to add.
    notice = describe_unregistered_credential(entry, repo)
    assert 'ssh-ed25519' in notice, 'the public key an admin needs is missing'
    assert 'write' in notice
    assert 'Nothing else needs to be run' in notice

    cred_id = credential_id('vm-a', repo.canonical)
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert recorded.provider_managed is False
    assert host_private_key_path('vm-a', cred_id).exists()


def test_creds_list_marks_unregistered_credentials(
    cfg_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A credential nobody registered must not read as a working grant."""
    store = load_store(cfg_path)
    upsert_credential(
        store,
        replace(
            _entry('test-vm'),
            state='pending',
            provider_managed=False,
            provider_key_id='',
        ),
    )
    save_store(store, cfg_path, reason='test fixture')

    rc = run_cli(['vm', 'creds', 'list', '--yes', '--config', str(cfg_path)])

    out = capsys.readouterr().out
    assert rc == 0
    assert '(unregistered)' in out
    assert 'an admin must' in out


def test_grant_works_on_a_host_with_no_github_cli(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """gh automates registration; it is not required to hold a credential.

    Nothing about generating a scoped keypair, installing it in the VM, or
    configuring Git needs a provider tool, so a host without gh still gets a
    working credential once someone adds the public key.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    _patch_generated_key(monkeypatch, tmp_path, [])
    # No gh on this host at all.
    monkeypatch.setattr(
        'aivm.credentials.github.shutil.which', lambda name: None
    )
    monkeypatch.setattr(
        'aivm.credentials.setup.shutil.which',
        lambda name: None if name == 'gh' else f'/usr/bin/{name}',
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    installed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: installed.append(k['private_key']),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(255, '', 'Permission denied (publickey)'),
    )
    repo = GitRepository('github.com', 'Kitware', 'kwimage')

    entry = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        # Any gh call would fail on this manager, proving none is made.
        manager=_RefusingGitHubManager('unused', ('gh',)),
    )

    assert entry.provider_managed is False
    assert installed, 'the key never reached the VM'
    notice = describe_unregistered_credential(entry, repo)
    assert 'ssh-ed25519' in notice
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert recorded.provider_managed is False


def test_unregistered_credential_cannot_be_revoked(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """AIVM will not claim a provider deletion it never had the rights to make."""
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    entry = replace(_entry('vm-a'), provider_managed=False, provider_key_id='')

    with pytest.raises(AIVMError, match='never registered'):
        revoke_repository_credential(
            cfg,
            load_store(path),
            path,
            entry,
            manager=CommandManager(yes=True),
        )


class _NotFoundGitHubManager(CommandManager):
    """Answer the deploy-key endpoints with 404, as GitHub does for non-admins.

    ``repository_visible`` decides what the disambiguating repository probe
    reports, which is the only thing separating "not an admin of a private
    repository" from "no such repository".
    """

    def __init__(self, *, repository_visible: bool) -> None:
        super().__init__(yes=True)
        self.repository_visible = repository_visible
        self.calls: list[list[str]] = []

    def run(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: str = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandResult:
        del (
            sudo,
            role,
            capture,
            text,
            input_text,
            env,
            timeout,
            summary,
            detail,
        )
        self.calls.append(list(cmd))
        not_found = CommandResult(
            code=1,
            stdout='{"message":"Not Found","status":"404"}',
            stderr='gh: Not Found (HTTP 404)',
        )
        if list(cmd[:2]) == ['gh', 'api'] and cmd[-1].endswith('/keys'):
            if check:
                raise CommandError(list(cmd), not_found)
            return not_found
        if list(cmd[:2]) == ['gh', 'api'] and '?per_page=' in cmd[-1]:
            if check:
                raise CommandError(list(cmd), not_found)
            return not_found
        if list(cmd[:2]) == ['gh', 'api']:
            # The repository visibility probe.
            if self.repository_visible:
                return CommandResult(0, '{"full_name":"Kitware/kwimage"}', '')
            return not_found
        return CommandResult(code=0, stdout='', stderr='')


def _grant_against_not_found(
    monkeypatch: MonkeyPatch, tmp_path: Path, *, repository_visible: bool
) -> tuple[Path, CredentialEntry | None]:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    _patch_generated_key(monkeypatch, tmp_path, [])
    _patch_provider_reachable(monkeypatch)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(255, '', 'Permission denied (publickey)'),
    )
    entry = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        GitRepository('github.com', 'Kitware', 'kwimage'),
        access='write',
        manager=_NotFoundGitHubManager(repository_visible=repository_visible),
    )
    return path, entry


def test_visible_repository_404_is_treated_as_a_permission_failure(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """GitHub answers 404, not 403, when a non-admin reads a private repo."""
    path, entry = _grant_against_not_found(
        monkeypatch, tmp_path, repository_visible=True
    )

    assert entry is not None
    assert entry.provider_managed is False
    notice = describe_unregistered_credential(
        entry, GitRepository('github.com', 'Kitware', 'kwimage')
    )
    assert 'ssh-ed25519' in notice
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert recorded.state == 'pending'


def test_invisible_repository_404_still_hands_over_the_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A failed read must never leave the user without the key.

    Nothing was created, so the generated key is inert and handing it over is
    always safe -- and it is the only thing that can unblock the user,
    whatever the read failed for.
    """
    path, entry = _grant_against_not_found(
        monkeypatch, tmp_path, repository_visible=False
    )

    assert entry is not None
    assert entry.provider_managed is False
    notice = describe_unregistered_credential(
        entry, GitRepository('github.com', 'Kitware', 'kwimage')
    )
    assert 'ssh-ed25519' in notice, 'the public key an admin needs is missing'
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert recorded.provider_managed is False


def test_admin_added_key_is_adopted_on_the_next_run(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """After an admin adds the key, a rerun finds it by fingerprint."""
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    _patch_generated_key(monkeypatch, tmp_path, [])
    _patch_provider_reachable(monkeypatch)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(0, 'ok', ''),
    )
    repo = GitRepository('github.com', 'Kitware', 'kwimage')

    # The first grant cannot register the key, so it hands off unmanaged.
    handed_off = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        manager=_RefusingGitHubManager(
            'gh: Must have admin rights to Repository. (HTTP 403)'
        ),
    )
    assert handed_off.provider_managed is False
    cred_id = credential_id('vm-a', repo.canonical)
    admin_added = host_public_key_path('vm-a', cred_id).read_text(
        encoding='utf-8'
    )

    # An admin adds exactly that public key; AIVM never created it itself.
    monkeypatch.setattr(
        'aivm.credentials.github.list_deploy_keys',
        lambda *a, **k: [
            ProviderDeployKey('91', admin_added, 'added-by-admin', False)
        ],
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.add_deploy_key',
        lambda *a, **k: pytest.fail('must adopt the existing key, not add one'),
    )

    entry = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        manager=CommandManager(yes=True),
    )

    assert entry.provider_key_id == '91'
    assert entry.state == 'active'
    # Once the provider side is readable, AIVM manages the credential again
    # and revocation becomes possible.
    assert entry.provider_managed is True


def test_unresolved_provider_failure_becomes_admin_handoff(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """An uncertain API outcome must not block the local grant."""
    stderr = 'HTTP 503: Service Unavailable (https://api.github.com/repos)'

    store_path, entry = _grant_against_refusing_provider(
        monkeypatch, tmp_path, stderr
    )

    [pending] = find_credentials_for_vm(load_store(store_path), 'vm-a')
    assert pending == entry
    assert pending.state == 'pending'
    assert pending.provider_managed is False
    assert pending.key_fingerprint
    assert host_private_key_path('vm-a', entry.id).exists()


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
    _patch_provider_reachable(monkeypatch)
    # Create the host copies without changing the stored entry.
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    _make_managed_credential_dirs(private.parent)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text(_public_key(), encoding='utf-8')

    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
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
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: next(remote_results),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.delete_deploy_key',
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


def test_revoke_uses_exact_provider_id_lookup(
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

    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    _make_managed_credential_dirs(private.parent)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text(_public_key(), encoding='utf-8')

    exact: dict[str, object] = {
        'id': int(entry.provider_key_id),
        'key': _public_key(),
        'read_only': False,
        'title': entry.provider_key_title,
    }
    manager = _GitHubManager(_public_key(), exact=exact)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )

    revoke_repository_credential(cfg, store, path, entry, manager=manager)

    api_calls = [call for call in manager.calls if call[:2] == ['gh', 'api']]
    assert len(api_calls) == 3
    exact_calls = [call for call in api_calls if '--paginate' not in call]
    assert len(exact_calls) == 2
    assert all(
        call[-1].endswith(f'/keys/{entry.provider_key_id}')
        for call in exact_calls
    )
    [collection_call] = [call for call in api_calls if '--paginate' in call]
    assert '--slurp' not in collection_call
    assert any(
        call[:5]
        == ['gh', 'repo', 'deploy-key', 'delete', entry.provider_key_id]
        for call in manager.calls
    )
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
    _patch_provider_reachable(monkeypatch)
    private = host_private_key_path(entry.vm_name, entry.id)
    public = host_public_key_path(entry.vm_name, entry.id)
    _make_managed_credential_dirs(private.parent)
    private.write_text('PRIVATE KEY\n', encoding='utf-8')
    public.write_text(_public_key(), encoding='utf-8')

    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
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
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: next(remote_results),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.delete_deploy_key',
        lambda *a, **k: events.append('provider-delete'),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: (_ for _ in ()).throw(AIVMError('VM unavailable')),
    )

    with pytest.raises(AIVMError) as exc_info:
        revoke_repository_credential(
            cfg,
            store,
            path,
            entry,
            manager=CommandManager(yes=True),
        )

    message = str(exc_info.value)
    assert f'Provider access for credential {entry.id} was revoked' in message
    assert 'VM unavailable' in message
    assert 'remains recorded as revocation-pending' in message
    assert f'`aivm vm creds revoke {entry.id}`' in message
    assert events == ['provider-delete']
    [pending] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert pending.state == 'revocation-pending'
    assert private.exists()


def test_agent_grant_readiness_output_requires_reconnect(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    readiness = AgentGrantForwardingReadiness(
        forwarding=AgentForwarding(
            socket_path=tmp_path / 'agent.sock',
            credential_count=1,
            fingerprints=('SHA256:test',),
        ),
        ip='10.77.0.195',
    )

    _print_agent_grant_readiness(readiness)

    out = capsys.readouterr().out
    assert 'repository authentication preflight passed' in out
    assert 'Use this ssh-agent credential from a fresh managed session' in out
    assert '`aivm vm ssh` or `aivm vm code`' in out


def test_agent_grant_readiness_output_explains_deferred_activation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    readiness = AgentGrantForwardingReadiness(
        forwarding=None,
        ip=None,
        deferred_reason="VM aivm-2404 is not running (state='shut off').",
    )

    _print_agent_grant_readiness(readiness)

    out = capsys.readouterr().out
    assert 'Guest activation deferred:' in out
    assert 'shut off' in out
    assert 'next managed SSH/Remote-SSH session' in out
    assert 'Use this ssh-agent credential from a fresh managed session' in out
    assert '`aivm vm ssh` or `aivm vm code`' in out


def test_creds_add_dry_run_and_help_tree(
    cfg_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = run_cli(
        [
            'vm',
            'creds',
            'add',
            'Kitware/kwimage',
            '--access',
            'write',
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
    assert (
        'aivm vm creds - Manage scoped repository credentials for a VM.' in tree
    )
    assert 'aivm vm creds add - Grant a VM repository access' in tree
    assert (
        'aivm vm creds abandon - Forget an inaccessible provider grant' in tree
    )


@pytest.mark.parametrize(
    'requested, expected',
    [
        pytest.param('read', 'read', id='read'),
        pytest.param('write', 'write', id='write'),
        pytest.param('ro', 'read', id='ro-alias'),
        pytest.param('RW', 'write', id='rw-alias-uppercase'),
        pytest.param('read-only', 'read', id='read-only-alias'),
    ],
)
def test_normalize_credential_access_accepts_known_spellings(
    requested: str, expected: str
) -> None:
    assert normalize_credential_access(requested) == expected


@pytest.mark.parametrize('requested', ['', 'admin', 'w', 'none'])
def test_normalize_credential_access_rejects_unknown_values(
    requested: str,
) -> None:
    with pytest.raises(AIVMError, match='Unsupported credential access'):
        normalize_credential_access(requested)


def test_creds_add_defaults_to_read_access(
    cfg_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Omitting --access must never widen a grant to push rights."""
    rc = run_cli(
        [
            'vm',
            'creds',
            'add',
            'Kitware/kwimage',
            '--dry_run',
            '--yes',
            '--config',
            str(cfg_path),
        ]
    )

    assert rc == 0
    assert 'Access:      read' in capsys.readouterr().out


@pytest.mark.parametrize(
    'spelling, expected',
    [
        pytest.param('read', 'read', id='read'),
        pytest.param('ro', 'read', id='ro'),
        pytest.param('write', 'write', id='write'),
        pytest.param('rw', 'write', id='rw'),
    ],
)
def test_creds_add_accepts_access_spellings_on_the_command_line(
    cfg_path: Path,
    capsys: pytest.CaptureFixture[str],
    spelling: str,
    expected: str,
) -> None:
    """argparse builds its choices from the annotation, so assert on argv.

    A normalizer alias that is missing from the declared Literal is rejected
    before the normalizer ever runs.
    """
    rc = run_cli(
        [
            'vm',
            'creds',
            'add',
            'Kitware/kwimage',
            f'--access={spelling}',
            '--dry_run',
            '--yes',
            '--config',
            str(cfg_path),
        ]
    )

    assert rc == 0
    assert f'Access:      {expected}' in capsys.readouterr().out


def test_creds_add_rejects_unknown_access_value(cfg_path: Path) -> None:
    # kwconf only warns when a programmatic call leaves the declared Literal,
    # so the grant path itself has to refuse the value.
    with pytest.raises(AIVMError, match='Unsupported credential access'):
        VMCredsAddCLI.main(
            argv=False,
            repository='Kitware/kwimage',
            access='admin',
            dry_run=True,
            yes=True,
            config=str(cfg_path),
        )


def test_vm_delete_refuses_to_orphan_credentials(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    upsert_credential(store, _entry('vm-a'))
    save_store(store, path)
    with pytest.raises(AIVMError, match='still owns repository credentials'):
        VMDeleteCLI.main(
            argv=False,
            vm='vm-a',
            config=str(path),
            yes=True,
            dry_run=True,
        )


def test_vm_up_recreate_refuses_active_credentials(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.maybe_install_missing_host_deps',
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.vm.create.vm_exists',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError(
                'VM probing must not run before credential preflight'
            )
        ),
    )

    with pytest.raises(AIVMError, match='cannot be recreated'):
        VMUpCLI.main(
            argv=False,
            config=str(path),
            recreate=True,
            dry_run=False,
            yes=True,
        )

    assert load_store(path).credentials == [entry]


def test_vm_create_force_refuses_active_credentials(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = tmp_path / 'config.toml'
    store = Store(defaults=cfg)
    upsert_vm(store, cfg)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    monkeypatch.setattr(
        'aivm.vm.create_ops.vm_resource_warning_lines', lambda cfg: []
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.vm_resource_impossible_lines', lambda cfg: []
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.maybe_install_missing_host_deps',
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.ensure_network', lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.apply_firewall', lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops._ensure_initial_share_source_for_create',
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.vm.create.vm_exists',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError(
                'VM probing must not run before credential preflight'
            )
        ),
    )

    with pytest.raises(AIVMError, match='cannot be recreated'):
        VMCreateCLI.main(
            argv=False,
            config=str(path),
            vm='vm-a',
            force=True,
            dry_run=False,
            yes=True,
        )

    loaded = load_store(path)
    assert loaded.credentials == [entry]
    assert [item.name for item in loaded.vms] == ['vm-a']


def test_vm_delete_decline_preserves_revoked_credential_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda prompt: 'n')
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = replace(_entry('vm-a'), state='revocation-pending')
    upsert_credential(store, entry)
    save_store(store, path)
    key_dir = host_credential_dir(entry.vm_name, entry.id)
    _make_managed_credential_dirs(key_dir)
    key_file = key_dir / 'id_ed25519'
    key_file.write_text('revoked', encoding='utf-8')
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.delete_managed_vm',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError(
                'deletion service must not run after declined approval'
            )
        ),
    )

    with pytest.raises(AIVMError, match='Aborted by user'):
        VMDeleteCLI.main(
            argv=False,
            vm='vm-a',
            config=str(path),
            yes=False,
            dry_run=False,
        )

    assert key_file.read_text(encoding='utf-8') == 'revoked'
    loaded = load_store(path)
    assert [item.name for item in loaded.vms] == ['vm-a']
    assert loaded.credentials == [entry]


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
    _make_managed_credential_dirs(key_dir)
    (key_dir / 'id_ed25519').write_text('revoked', encoding='utf-8')
    destroyed: list[str] = []
    prompts: list[str] = []
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return 'y'

    monkeypatch.setattr('builtins.input', answer)

    from aivm.vm.domain import DomainRemovalReport

    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined', lambda name: False
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *a, **k: None,
    )

    def fake_remove_domain(*args: Any, **kwargs: Any) -> DomainRemovalReport:
        CommandManager.current().confirm_file_update(
            path=tmp_path / 'nested-operation',
            purpose='Confirm nested deletion work is already approved.',
        )
        destroyed.append(cfg.vm.name)
        return DomainRemovalReport((), ())

    monkeypatch.setattr(
        'aivm.vm.deletion._destroy_and_undefine_vm', fake_remove_domain
    )
    monkeypatch.setattr('aivm.vm.deletion._path_exists', lambda path: False)
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_owned_trees', lambda *a, **k: None
    )

    rc = VMDeleteCLI.main(
        argv=False,
        vm='vm-a',
        config=str(path),
        yes=False,
        dry_run=False,
    )

    assert rc == 0
    assert destroyed == ['vm-a']
    assert prompts == ['Continue? [y/N]: ']
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
    assert (
        github.select_recorded_provider_key(entry, [unrelated, expected])
        == expected
    )

    wrong_id = replace(unrelated, key_id=entry.provider_key_id)
    with pytest.raises(AIVMError, match='fingerprint recorded by AIVM'):
        github.select_recorded_provider_key(entry, [wrong_id])


def test_existing_host_key_fingerprint_drift_is_rejected(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, _, _ = _write_real_host_keypair(_entry('vm-a'))
    changed_blob = base64.b64encode(b'changed key material').decode('ascii')
    changed_fingerprint = public_key_fingerprint(
        f'ssh-ed25519 {changed_blob} changed\n'
    )
    entry = replace(entry, key_fingerprint=changed_fingerprint)

    with pytest.raises(AIVMError, match='does not match the fingerprint'):
        generate_host_key(entry, manager=CommandManager(yes=True))


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
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )
    remote = ProviderDeployKey(
        entry.provider_key_id, _public_key(), entry.provider_key_title, False
    )
    monkeypatch.setattr(
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: remote,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.delete_deploy_key',
        lambda *a, **k: None,
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
        parse_repository_url('ssh://git@ghe.example.com:2222/team/project.git')


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

    monkeypatch.setattr('aivm.credentials.guest._run_guest', fake_run_guest)
    verify_guest_repository(
        cfg,
        '10.0.0.5',
        repo,
        _entry('vm-a').id,
        manager=CommandManager(yes=True),
    )
    [script] = scripts
    assert f'git ls-remote --get-url {original}' in script
    assert f'git@aivm-cred-{_entry("vm-a").id}:Kitware/kwimage.git' in script
    assert f'GIT_TERMINAL_PROMPT=0 git ls-remote {original} HEAD' in script


def test_status_reports_malformed_host_public_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, _, public = _write_real_host_keypair(_entry('vm-a'))
    public.write_text('not a public key\n', encoding='utf-8')
    public.chmod(0o644)
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.github.find_recorded_provider_key',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.get_ip_cached', lambda *a, **k: None
    )

    report = inspect_credential(
        make_cfg(tmp_path, **{'vm.name': 'vm-a'}),
        entry,
        manager=CommandManager(yes=True),
    )

    assert report['host_ok'] is False
    assert report['fingerprint_ok'] is False
    assert 'Malformed SSH public key' in report['host_detail']


@pytest.mark.parametrize(
    'value, message',
    [
        (
            'https://token@github.com/Kitware/kwimage.git',
            'may not contain userinfo',
        ),
        (
            'http://github.com/Kitware/kwimage.git',
            'support only canonical HTTPS and SSH',
        ),
        (
            'git://github.com/Kitware/kwimage.git',
            'support only canonical HTTPS and SSH',
        ),
        (
            'ssh://alice@github.com/Kitware/kwimage.git',
            'must use the git user',
        ),
        (
            'alice@github.com:Kitware/kwimage.git',
            'must use the git user',
        ),
        (
            'HTTPS://github.com/Kitware/kwimage.git',
            'canonical spelling',
        ),
    ],
)
def test_repository_transport_rejects_unmanaged_forms(
    value: str, message: str
) -> None:
    with pytest.raises(AIVMError, match=message):
        parse_repository_url(value)


def test_managed_git_rewrite_resolves_expected_alias(tmp_path: Path) -> None:
    entry = _entry()
    config_path = tmp_path / 'gitconfig'
    config_path.write_text(render_git_config([entry]), encoding='utf-8')
    env = {
        **os.environ,
        'GIT_CONFIG_GLOBAL': str(config_path),
        'GIT_CONFIG_NOSYSTEM': '1',
    }
    source = 'https://github.com/Kitware/kwimage.git'
    result = subprocess.run(
        ['git', 'ls-remote', '--get-url', source],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.stdout.strip() == (
        f'git@aivm-cred-{entry.id}:Kitware/kwimage.git'
    )


def test_host_key_inspection_validates_private_key_and_permissions(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, private, _ = _write_real_host_keypair(_entry('vm-a'))

    _, fingerprint = inspect_host_keypair(
        entry, manager=CommandManager(yes=True)
    )
    assert fingerprint == entry.key_fingerprint

    private.chmod(0o644)
    with pytest.raises(AIVMError, match='permissions are too broad'):
        inspect_host_keypair(entry, manager=CommandManager(yes=True))


def test_host_key_inspection_rejects_mismatched_public_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, _, public = _write_real_host_keypair(_entry('vm-a'))
    other_dir = tmp_path / 'other-key'
    subprocess.run(
        [
            'ssh-keygen',
            '-q',
            '-t',
            'ed25519',
            '-N',
            '',
            '-f',
            str(other_dir),
        ],
        check=True,
    )
    public.write_text(
        Path(str(other_dir) + '.pub').read_text(encoding='utf-8'),
        encoding='utf-8',
    )
    public.chmod(0o644)

    with pytest.raises(AIVMError, match='do not form a matching keypair'):
        inspect_host_keypair(entry, manager=CommandManager(yes=True))


def test_host_key_inspection_rejects_symlinked_private_key(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, private, _ = _write_real_host_keypair(_entry('vm-a'))
    moved = private.with_name('moved-private-key')
    private.rename(moved)
    private.symlink_to(moved)

    with pytest.raises(AIVMError, match='regular file, not a symlink'):
        inspect_host_keypair(entry, manager=CommandManager(yes=True))


def test_generate_refuses_untracked_existing_keypair(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry, _, _ = _write_real_host_keypair(_entry('vm-a'))
    untracked = replace(entry, key_fingerprint='')

    with pytest.raises(AIVMError, match='Untracked host key material'):
        generate_host_key(untracked, manager=CommandManager(yes=True))


def test_grant_refuses_to_replace_missing_recorded_keypair(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    repo = GitRepository(entry.provider_host, entry.owner, entry.repository)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service.providers.check_auth', lambda *a, **k: None
    )

    with pytest.raises(AIVMError, match='recorded credential.*is missing'):
        grant_repository_credential(
            cfg,
            load_store(path),
            path,
            repo,
            access='write',
            manager=CommandManager(yes=True),
        )

    loaded = load_store(path)
    assert loaded.credentials == [entry]
    assert not host_credential_dir(entry.vm_name, entry.id).exists()


def test_generate_rejects_symlinked_credential_directory_before_mutation(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = replace(
        _entry('vm-a'),
        provider_key_id='',
        key_fingerprint='',
        state='pending',
    )
    directory = host_credential_dir(entry.vm_name, entry.id)
    _make_managed_credential_dirs(directory, include_leaf=False)
    victim = tmp_path / 'victim'
    victim.mkdir()
    victim.chmod(0o755)
    directory.symlink_to(victim, target_is_directory=True)
    before_mode = victim.stat().st_mode & 0o777

    with pytest.raises(AIVMError, match='real directory, not a symlink'):
        generate_host_key(entry, manager=CommandManager(yes=True))

    assert (victim.stat().st_mode & 0o777) == before_mode
    assert list(victim.iterdir()) == []


def test_abandon_removes_local_state_and_writes_tombstone(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    store = load_store(path)
    key_dir = host_credential_dir(entry.vm_name, entry.id)
    _make_managed_credential_dirs(key_dir)
    (key_dir / 'id_ed25519').write_text('private', encoding='utf-8')
    events: list[str] = []
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: events.append('guest-cleanup'),
    )

    tombstone = abandon_repository_credential(
        cfg,
        store,
        path,
        entry,
        manager=CommandManager(yes=True),
    )

    assert events == ['guest-cleanup']
    assert not key_dir.exists()
    assert find_credentials_for_vm(load_store(path), 'vm-a') == []
    data = json.loads(tombstone.read_text(encoding='utf-8'))
    assert data['provider_revocation_verified'] is False
    assert data['guest_cleanup_verified'] is True
    assert data['credential']['key_fingerprint'] == entry.key_fingerprint


def test_abandon_records_unverified_guest_cleanup(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    store = load_store(path)
    key_dir = host_credential_dir(entry.vm_name, entry.id)
    _make_managed_credential_dirs(key_dir)
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: (_ for _ in ()).throw(AIVMError('VM unavailable')),
    )

    tombstone = abandon_repository_credential(
        cfg,
        store,
        path,
        entry,
        manager=CommandManager(yes=True),
    )

    data = json.loads(tombstone.read_text(encoding='utf-8'))
    assert data['provider_revocation_verified'] is False
    assert data['guest_cleanup_verified'] is False
    assert data['guest_cleanup_error'] == 'VM unavailable'
    assert find_credentials_for_vm(load_store(path), 'vm-a') == []


def test_vm_delete_preserves_record_when_key_cleanup_fails(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = replace(_entry('vm-a'), state='revocation-pending')
    upsert_credential(store, entry)
    save_store(store, path)
    destroyed: list[str] = []
    monkeypatch.setattr(
        'aivm.credentials.keys.shutil.rmtree',
        lambda *a, **k: (_ for _ in ()).throw(
            PermissionError('cannot remove private key')
        ),
    )
    from aivm.vm.domain import DomainRemovalReport

    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined', lambda name: False
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *a, **k: None,
    )

    def fake_remove_domain(*args: Any, **kwargs: Any) -> DomainRemovalReport:
        destroyed.append(cfg.vm.name)
        return DomainRemovalReport((), ())

    monkeypatch.setattr(
        'aivm.vm.deletion._destroy_and_undefine_vm', fake_remove_domain
    )
    monkeypatch.setattr('aivm.vm.deletion._path_exists', lambda path: False)
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_owned_trees', lambda *a, **k: None
    )

    with pytest.raises(PermissionError, match='cannot remove private key'):
        VMDeleteCLI.main(
            argv=False,
            vm='vm-a',
            config=str(path),
            yes=True,
            dry_run=False,
        )

    assert destroyed == []
    loaded = load_store(path)
    assert [item.name for item in loaded.vms] == ['vm-a']
    assert loaded.credentials == [entry]


def test_abandon_preserves_pending_record_when_host_cleanup_fails(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    store = load_store(path)
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.credentials.keys.shutil.rmtree',
        lambda *a, **k: (_ for _ in ()).throw(
            PermissionError('cannot remove private key')
        ),
    )

    with pytest.raises(PermissionError, match='cannot remove private key'):
        abandon_repository_credential(
            cfg,
            store,
            path,
            entry,
            manager=CommandManager(yes=True),
        )

    [pending] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert pending.state == 'abandon-pending'


def test_generate_rejects_symlinked_credentials_parent_before_mutation(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = replace(
        _entry('vm-a'),
        provider_key_id='',
        key_fingerprint='',
        state='pending',
    )
    directory = host_credential_dir(entry.vm_name, entry.id)
    _make_managed_credential_dirs(
        directory,
        include_parent=False,
        include_leaf=False,
    )
    victim = tmp_path / 'credentials-victim'
    victim.mkdir()
    victim.chmod(0o755)
    directory.parent.symlink_to(victim, target_is_directory=True)
    before_mode = victim.stat().st_mode & 0o777

    with pytest.raises(AIVMError, match='credential parent.*symlink'):
        generate_host_key(entry, manager=CommandManager(yes=True))

    assert (victim.stat().st_mode & 0o777) == before_mode
    assert list(victim.iterdir()) == []


def test_generate_rejects_symlinked_vm_data_directory_before_mutation(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = replace(
        _entry('vm-a'),
        provider_key_id='',
        key_fingerprint='',
        state='pending',
    )
    directory = host_credential_dir(entry.vm_name, entry.id)
    vm_directory = directory.parent.parent
    victim = tmp_path / 'vm-victim'
    victim.mkdir()
    victim.chmod(0o755)
    vm_directory.symlink_to(victim, target_is_directory=True)
    before_mode = victim.stat().st_mode & 0o777

    with pytest.raises(AIVMError, match='VM data directory.*symlink'):
        generate_host_key(entry, manager=CommandManager(yes=True))

    assert (victim.stat().st_mode & 0o777) == before_mode
    assert list(victim.iterdir()) == []


@pytest.mark.parametrize('ancestor', ['vm', 'credentials'])
@pytest.mark.parametrize('operation', ['revoke', 'abandon'])
def test_credential_cleanup_refuses_symlinked_ancestor(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    ancestor: str,
    operation: str,
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    entry = _entry('vm-a')
    upsert_credential(store, entry)
    save_store(store, path)
    store = load_store(path)

    directory = host_credential_dir(entry.vm_name, entry.id)
    victim = tmp_path / f'{operation}-{ancestor}-victim'
    victim.mkdir()
    if ancestor == 'vm':
        protected = victim / 'credentials' / entry.id
        protected.mkdir(parents=True)
        directory.parent.parent.symlink_to(victim, target_is_directory=True)
        expected = 'VM data directory.*symlink'
    else:
        _make_managed_credential_dirs(
            directory,
            include_parent=False,
            include_leaf=False,
        )
        protected = victim / entry.id
        protected.mkdir()
        directory.parent.symlink_to(victim, target_is_directory=True)
        expected = 'credential parent.*symlink'
    sentinel = protected / 'sentinel'
    sentinel.write_text('do not delete\n', encoding='utf-8')

    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: None,
    )
    if operation == 'revoke':
        monkeypatch.setattr(
            'aivm.credentials.service._require_tools', lambda *a, **k: None
        )
        monkeypatch.setattr(
            'aivm.credentials.service.providers.check_auth',
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            'aivm.credentials.github.find_recorded_provider_key',
            lambda *a, **k: None,
        )
    with pytest.raises(AIVMError, match=expected):
        if operation == 'revoke':
            revoke_repository_credential(
                cfg,
                store,
                path,
                entry,
                manager=CommandManager(yes=True),
            )
        else:
            abandon_repository_credential(
                cfg,
                store,
                path,
                entry,
                manager=CommandManager(yes=True),
            )

    assert sentinel.read_text(encoding='utf-8') == 'do not delete\n'
    [pending] = find_credentials_for_vm(load_store(path), 'vm-a')
    expected_state = (
        'revocation-pending' if operation == 'revoke' else 'abandon-pending'
    )
    assert pending.state == expected_state


@pytest.mark.parametrize(
    ('mode', 'writer'),
    [
        (0o770, 'group'),
        (0o707, 'other users'),
    ],
)
@pytest.mark.parametrize('ancestor', ['root', 'vm', 'credentials'])
def test_writable_managed_ancestor_warns_by_default(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    mode: int,
    writer: str,
    ancestor: str,
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = _entry('vm-a')
    directory = host_credential_dir(entry.vm_name, entry.id)
    root = directory.parent.parent.parent
    vm_directory = directory.parent.parent
    credentials_directory = directory.parent

    if ancestor == 'root':
        unsafe = root
    elif ancestor == 'vm':
        vm_directory.mkdir(mode=0o700)
        unsafe = vm_directory
    else:
        vm_directory.mkdir(mode=0o700)
        credentials_directory.mkdir(mode=0o700)
        unsafe = credentials_directory
    unsafe.chmod(mode)

    assert host_credential_dir(entry.vm_name, entry.id) == directory
    assert unsafe.stat().st_mode & 0o777 == mode, (
        f'{ancestor} writable by {writer} was unexpectedly changed'
    )


def test_fresh_app_data_root_is_safe_under_group_writable_umask(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    if shutil.which('ssh-keygen') is None:
        pytest.skip('ssh-keygen is required for deploy-key generation tests')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    entry = replace(
        _entry('vm-a'),
        provider_key_id='',
        key_fingerprint='',
        state='pending',
    )

    previous_umask = os.umask(0o002)
    try:
        generated = generate_host_key(entry, manager=CommandManager(yes=True))
    finally:
        os.umask(previous_umask)

    directory = host_credential_dir(entry.vm_name, entry.id)
    root = directory.parent.parent.parent
    root_mode = root.stat().st_mode & 0o777

    assert root_mode == 0o700
    assert generated.key_fingerprint.startswith('SHA256:')
    assert host_private_key_path(entry.vm_name, entry.id).exists()
    assert host_public_key_path(entry.vm_name, entry.id).exists()


def _nonblocking_grant_env(
    monkeypatch: MonkeyPatch, tmp_path: Path, events: list[str]
) -> None:
    """Everything a grant needs except the provider decision under test."""
    _patch_generated_key(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: events.append('guest-install'),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(0, 'ok', ''),
    )
    monkeypatch.setattr(
        providers, 'automation_unavailable_reason', lambda *a, **k: ''
    )
    monkeypatch.setattr(
        providers, 'find_recorded_provider_key', lambda *a, **k: None
    )


@pytest.mark.parametrize(
    ('kind', 'host'),
    [
        pytest.param(
            CREDENTIAL_KIND_GITHUB_DEPLOY_KEY, 'github.com', id='github'
        ),
        pytest.param(
            CREDENTIAL_KIND_GITLAB_DEPLOY_KEY, 'gitlab.com', id='gitlab'
        ),
    ],
)
def test_declining_publication_stops_before_the_key_reaches_the_vm(
    monkeypatch: MonkeyPatch, tmp_path: Path, kind: CredentialKind, host: str
) -> None:
    """A refusal is the user's answer, not the provider being unhelpful.

    Publication used to run under `attempt(catch=AIVMError)`, and an approval
    refusal raises `AIVMError`. Saying no therefore installed the private key
    in the VM anyway and printed a handoff telling the user to give the public
    key to an administrator -- the opposite of what they asked for.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    events: list[str] = []
    _nonblocking_grant_env(monkeypatch, tmp_path, events)

    def declined(*a: object, **k: object) -> None:
        raise UserDeclinedError('Aborted by user.')

    monkeypatch.setattr(providers, 'add_deploy_key', declined)

    with pytest.raises(UserDeclinedError):
        grant_repository_credential(
            cfg,
            load_store(path),
            path,
            GitRepository(host, 'Kitware', 'kwimage'),
            access='write',
            kind=kind,
            manager=CommandManager(yes=True),
        )

    assert 'guest-install' not in events, (
        'the private key was installed after the user declined'
    )


def test_unavailable_approval_stops_before_the_key_reaches_the_vm(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Nobody to ask is not the same as being told yes."""
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    events: list[str] = []
    _nonblocking_grant_env(monkeypatch, tmp_path, events)

    def unavailable(*a: object, **k: object) -> None:
        raise ApprovalUnavailableError('stdin is not interactive')

    monkeypatch.setattr(providers, 'add_deploy_key', unavailable)

    with pytest.raises(ApprovalUnavailableError):
        grant_repository_credential(
            cfg,
            load_store(path),
            path,
            GitRepository('gitlab.com', 'Kitware', 'kwimage'),
            access='write',
            kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
            manager=CommandManager(yes=True),
        )

    assert 'guest-install' not in events


@pytest.mark.parametrize(
    'failure',
    [
        pytest.param(ProviderPermissionError('not an admin'), id='permission'),
        pytest.param(
            GitLabAuthenticationError('token is missing'), id='authentication'
        ),
        pytest.param(
            GitLabTransportError('request did not complete'), id='transport'
        ),
        pytest.param(
            ProviderRejectedError('deploy keys are disabled'), id='rejected'
        ),
    ],
)
def test_provider_bureaucracy_still_produces_a_handoff(
    monkeypatch: MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    """The nonblocking policy survives the narrowed catch.

    Narrowing `attempt(catch=...)` to keep refusals out must not also start
    blocking on the failures it exists to absorb.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    events: list[str] = []
    _nonblocking_grant_env(monkeypatch, tmp_path, events)

    def refuses(*a: object, **k: object) -> None:
        raise failure

    monkeypatch.setattr(providers, 'add_deploy_key', refuses)
    repo = GitRepository('gitlab.com', 'Kitware', 'kwimage')

    entry = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )

    assert entry.provider_managed is False
    assert 'guest-install' in events
    assert 'ssh-ed25519' in describe_unregistered_credential(entry, repo)


def test_transient_provider_failure_keeps_a_known_deploy_key_revocable(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A run that cannot see the provider is not evidence the key is gone.

    Clearing the recorded id stranded a live deploy key: `revoke` then refused
    to touch it, on the grounds that AIVM had never registered one.
    """
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    events: list[str] = []
    _nonblocking_grant_env(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        providers,
        'add_deploy_key',
        lambda *a, **k: ProviderDeployKey('12', _public_key(), 'title', False),
    )
    repo = GitRepository('gitlab.com', 'Kitware', 'kwimage')

    first = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )
    assert first.provider_key_id == '12'

    # The token expires. Nothing about the remote key changed.
    monkeypatch.setattr(
        providers,
        'automation_unavailable_reason',
        lambda *a, **k: 'GitLab API token is missing.',
    )
    second = grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )

    assert second.provider_key_id == '12', (
        'the only handle for revoke was erased'
    )
    assert second.provider_managed is True
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert recorded.provider_key_id == '12'
    assert recorded.provider_managed is True


def test_revoke_still_works_after_a_transient_provider_failure(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """The point of preserving the id: the key stays deletable."""
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    events: list[str] = []
    _nonblocking_grant_env(monkeypatch, tmp_path, events)
    remote = ProviderDeployKey('12', _public_key(), 'title', False)
    monkeypatch.setattr(providers, 'add_deploy_key', lambda *a, **k: remote)
    repo = GitRepository('gitlab.com', 'Kitware', 'kwimage')

    grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )
    monkeypatch.setattr(
        providers,
        'automation_unavailable_reason',
        lambda *a, **k: 'GitLab API token is missing.',
    )
    grant_repository_credential(
        cfg,
        load_store(path),
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )

    # Access is restored; revocation must be able to target key 12.
    deleted: list[str] = []
    found: list[ProviderDeployKey | None] = [remote, None]
    monkeypatch.setattr(providers, 'check_auth', lambda *a, **k: None)
    monkeypatch.setattr(
        providers, 'find_recorded_provider_key', lambda *a, **k: found.pop(0)
    )
    monkeypatch.setattr(
        providers,
        'delete_deploy_key',
        lambda kind, repo, key_id, **k: deleted.append(key_id),
    )
    [recorded] = find_credentials_for_vm(load_store(path), 'vm-a')
    revoke_repository_credential(
        cfg,
        load_store(path),
        path,
        recorded,
        manager=CommandManager(yes=True),
    )

    assert deleted == ['12'], 'revoke could not target the recorded key'
    assert find_credentials_for_vm(load_store(path), 'vm-a') == []
