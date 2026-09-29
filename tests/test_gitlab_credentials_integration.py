"""Integration tests for GitLab deploy keys in the credential lifecycle."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

import pytest

from aivm.cli.vm_creds import VMCredsAddCLI, VMCredsSetupCLI
from aivm.commands import CommandManager, CommandResult
from aivm.config_store import (
    CredentialEntry,
    find_credentials_for_vm,
    load_store,
    save_store,
    upsert_credential,
)
from aivm.credentials import gh_install, providers
from aivm.credentials.gitlab import (
    GitLabIdentity,
    GitLabProject,
    GitLabTransportError,
)
from aivm.credentials.guest import render_git_config, render_ssh_config
from aivm.credentials.keys import (
    host_credential_dir,
    host_private_key_path,
    host_public_key_path,
    public_key_fingerprint,
)
from aivm.credentials.models import GitRepository, ProviderDeployKey
from aivm.credentials.resolve import parse_repository_url
from aivm.credentials.schema import CREDENTIAL_KIND_GITLAB_DEPLOY_KEY
from aivm.credentials.service import grant_repository_credential
from aivm.credentials.setup import (
    GitLabCredentialSetupReport,
    inspect_gitlab_credential_setup,
)
from aivm.credentials.validation import credential_id
from aivm.errors import AIVMError
from tests.helpers import make_cfg, write_store


def _public_key(comment: str = 'test') -> str:
    blob = base64.b64encode(b'aivm gitlab synthetic key').decode('ascii')
    return f'ssh-ed25519 {blob} {comment}\n'


def _patch_generated_host_key(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_generate(
        entry: CredentialEntry, *, manager: CommandManager
    ) -> CredentialEntry:
        del manager
        private_path = host_private_key_path(entry.vm_name, entry.id)
        public_path = host_public_key_path(entry.vm_name, entry.id)
        private_path.parent.mkdir(parents=True, mode=0o700)
        private_path.parent.chmod(0o700)
        private_path.write_text('PRIVATE KEY\n', encoding='utf-8')
        public = _public_key(entry.provider_key_title)
        public_path.write_text(public, encoding='utf-8')
        return replace(entry, key_fingerprint=public_key_fingerprint(public))

    monkeypatch.setattr(
        'aivm.credentials.keys.generate_host_key', fake_generate
    )


class _FakeGitLabBackend:
    def __init__(self, key: ProviderDeployKey | None = None) -> None:
        self.key = key
        self.deleted: list[str] = []

    def check_auth(self) -> GitLabIdentity:
        return GitLabIdentity('7', 'alice', 'Alice')

    def resolve_project(self, project: str) -> GitLabProject:
        return GitLabProject('42', project, f'https://gitlab.com/{project}')

    def list_deploy_keys(
        self, project: GitLabProject
    ) -> list[ProviderDeployKey]:
        del project
        return [] if self.key is None else [self.key]

    def get_deploy_key(
        self, project: GitLabProject, key_id: str
    ) -> ProviderDeployKey | None:
        del project
        if self.key is not None and self.key.key_id == str(key_id):
            return self.key
        return None

    def add_deploy_key(
        self,
        project: GitLabProject,
        *,
        public_key_path: Path,
        title: str,
        write: bool,
    ) -> ProviderDeployKey:
        del project
        self.key = ProviderDeployKey(
            '12',
            public_key_path.read_text(encoding='utf-8').strip(),
            title,
            not write,
        )
        return self.key

    def delete_deploy_key(self, project: GitLabProject, key_id: str) -> None:
        del project
        self.deleted.append(str(key_id))
        self.key = None


def test_parse_nested_gitlab_repository_and_select_provider() -> None:
    repo = parse_repository_url('git@gitlab.com:group/subgroup/project.git')
    assert repo.host == 'gitlab.com'
    assert repo.owner == 'group/subgroup'
    assert repo.name == 'project'
    assert repo.path == 'group/subgroup/project'
    assert providers.resolve_provider(repo) == 'gitlab'
    assert (
        providers.kind_for_provider('gitlab')
        == CREDENTIAL_KIND_GITLAB_DEPLOY_KEY
    )


def test_nested_shorthand_needs_explicit_gitlab_context() -> None:
    with pytest.raises(AIVMError, match='nested repository namespace'):
        parse_repository_url('group/subgroup/project')

    repo = parse_repository_url(
        'group/subgroup/project',
        default_host='gitlab.com',
    )
    assert repo == GitRepository('gitlab.com', 'group/subgroup', 'project')


def test_auto_provider_uses_setup_hostname() -> None:
    assert (
        providers.resolve_provider(None, 'auto', hostname='gitlab.com')
        == 'gitlab'
    )
    assert (
        providers.resolve_provider(None, 'auto', hostname='github.com')
        == 'github'
    )
    with pytest.raises(AIVMError, match='cannot be managed'):
        providers.resolve_provider(
            GitRepository('github.com', 'group', 'project'),
            'gitlab',
        )
    with pytest.raises(AIVMError, match='cannot be managed'):
        providers.resolve_provider(
            GitRepository('gitlab.com', 'group', 'project'),
            'github',
        )


@pytest.mark.parametrize(
    ('host', 'expected'),
    [
        pytest.param('gitlab.com', 'gitlab', id='canonical'),
        pytest.param('gitlab.kitware.com', 'gitlab', id='self_managed'),
        pytest.param('gitlab.example.co.uk', 'gitlab', id='multi_label_domain'),
        pytest.param('github.com', 'github', id='canonical_github'),
        pytest.param('ghe.corp.example', 'github', id='enterprise_github'),
        pytest.param(
            'notgitlab.example.com', 'github', id='not_a_gitlab_label'
        ),
    ],
)
def test_auto_provider_recognizes_self_managed_gitlab(
    host: str, expected: str
) -> None:
    """The forge decides the API, the required tools, and the stored kind.

    Defaulting every non-gitlab.com host to GitHub recorded a
    ``github-deploy-key`` for a GitLab project, gated it on ``gh``, and named
    the wrong forge in the administrator handoff.
    """
    repo = GitRepository(host, 'group', 'project')
    assert providers.resolve_provider(repo) == expected


def test_github_rejects_a_nested_namespace() -> None:
    """GitHub has no subgroups, so a nested path is a different repository.

    ``github.com/a/b/c`` used to parse as owner ``a/b``, recording a
    credential for a repository that cannot exist.
    """
    with pytest.raises(AIVMError, match='no nested namespaces'):
        parse_repository_url('github.com/a/b/c')


def test_gitlab_api_token_is_never_sent_over_plaintext_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The token rides in a header on every call, so the transport matters."""
    monkeypatch.setenv('GITLAB_API_URL', 'http://gitlab.example.com/api/v4')
    with pytest.raises(AIVMError, match='over http'):
        providers._gitlab_api_url('gitlab.example.com')

    # Loopback stays usable for a local server or a forwarded port.
    monkeypatch.setenv('GITLAB_API_URL', 'http://localhost/api/v4')
    assert providers._gitlab_api_url('localhost') == 'http://localhost/api/v4'


def test_nested_gitlab_repository_renders_guest_routes() -> None:
    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    cred_id = credential_id('vm-a', repo.canonical)
    entry = CredentialEntry(
        id=cred_id,
        vm_name='vm-a',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        provider_key_title='aivm:test',
        key_fingerprint='SHA256:AAAA',
    )
    ssh = render_ssh_config([entry])
    git = render_git_config([entry])
    assert 'HostName gitlab.com' in ssh
    assert f'git@aivm-cred-{cred_id}:group/subgroup/project.git' in git
    assert 'https://gitlab.com/group/subgroup/project.git' in git


def test_gitlab_credential_roundtrips_in_store(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    entry = CredentialEntry(
        id=credential_id('vm-a', repo.canonical),
        vm_name='vm-a',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        provider_key_id='12',
        provider_key_title='aivm:test',
        key_fingerprint='SHA256:AAAA',
        state='active',
    )
    upsert_credential(store, entry)
    save_store(store, path, reason='test GitLab credential roundtrip')
    assert find_credentials_for_vm(load_store(path), 'vm-a') == [entry]


def test_gitlab_setup_checks_token_and_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeGitLabBackend()
    monkeypatch.setattr(
        'aivm.credentials.setup.shutil.which', lambda name: f'/usr/bin/{name}'
    )
    monkeypatch.setattr(
        providers, 'gitlab_backend_for_host', lambda host: backend
    )
    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    report = inspect_gitlab_credential_setup(
        hostname='gitlab.com',
        repository=repo,
        manager=CommandManager(yes=True),
    )
    assert report.ready
    assert report.identity == 'alice'
    assert report.repository_ok is True


def test_setup_auto_selects_gitlab_from_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = GitLabCredentialSetupReport(
        hostname='gitlab.com',
        tool_paths={'ssh': '/usr/bin/ssh', 'ssh-keygen': '/usr/bin/ssh-keygen'},
        auth_ok=True,
        auth_detail='Authenticated.',
        identity='alice',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_creds.inspect_gitlab_credential_setup',
        lambda **kwargs: report,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_creds.inspect_credential_setup',
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError('GitHub setup must not run')
        ),
    )

    assert (
        VMCredsSetupCLI.main(
            argv=False,
            hostname='gitlab.com',
            check=True,
        )
        == 0
    )


def test_add_explicit_gitlab_shorthand_dry_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)

    rc = VMCredsAddCLI.main(
        argv=False,
        repository='group/subgroup/project',
        provider='gitlab',
        access='write',
        dry_run=True,
        yes=True,
        config=str(path),
    )

    assert rc == 0
    output = capsys.readouterr().out
    assert 'Repository:  gitlab.com/group/subgroup/project' in output
    assert 'Provider:    gitlab' in output
    assert 'Access:      write' in output


def test_gitlab_tool_install_error_does_not_point_to_gh_docs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gh_install, 'detect_backend', lambda: '')
    with pytest.raises(AIVMError) as exc_info:
        gh_install.plan_tool_install(
            ('ssh',),
            include_gh=False,
            manager=CommandManager(yes=True),
        )
    assert 'GitHub CLI' not in str(exc_info.value)


def test_gitlab_provider_dispatch_crud(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public = tmp_path / 'id_ed25519.pub'
    public.write_text(_public_key(), encoding='utf-8')
    backend = _FakeGitLabBackend()
    monkeypatch.setattr(providers, 'gitlab_backend', lambda repo: backend)
    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    created = providers.add_deploy_key(
        CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        repo,
        public_key_path=public,
        title='aivm:test',
        write=True,
        manager=CommandManager(yes=True),
    )
    entry = CredentialEntry(
        id=credential_id('vm-a', repo.canonical),
        vm_name='vm-a',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        provider_key_id=created.key_id,
        provider_key_title=created.title,
        key_fingerprint=public_key_fingerprint(created.key),
        state='active',
    )
    found = providers.find_recorded_provider_key(
        entry.kind,
        repo,
        entry,
        manager=CommandManager(yes=True),
    )
    assert found == created
    providers.delete_deploy_key(
        entry.kind,
        repo,
        created.key_id,
        manager=CommandManager(yes=True),
    )
    assert backend.deleted == ['12']


def test_grant_service_persists_gitlab_kind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    events: list[str] = []
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))

    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    _patch_generated_host_key(monkeypatch)
    monkeypatch.setattr(
        providers,
        'automation_unavailable_reason',
        lambda *a, **k: events.append('automation') or '',
    )
    monkeypatch.setattr(
        providers, 'find_recorded_provider_key', lambda *a, **k: None
    )
    monkeypatch.setattr(
        providers,
        'add_deploy_key',
        lambda *a, **k: (
            events.append('provider-add')
            or ProviderDeployKey('12', _public_key(), 'title', False)
        ),
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

    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    entry = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )
    assert entry.kind == CREDENTIAL_KIND_GITLAB_DEPLOY_KEY
    assert entry.state == 'active'
    assert find_credentials_for_vm(load_store(path), 'vm-a') == [entry]
    assert events == ['automation', 'provider-add', 'guest-install']


@pytest.mark.parametrize('definitive', [True, False])
def test_gitlab_publication_failure_becomes_admin_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    definitive: bool,
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    _patch_generated_host_key(monkeypatch)
    monkeypatch.setattr(
        providers, 'automation_unavailable_reason', lambda *a, **k: ''
    )
    monkeypatch.setattr(
        providers, 'find_recorded_provider_key', lambda *a, **k: None
    )
    if definitive:
        error: Exception = providers.ProviderRejectedError('request rejected')
    else:
        error = GitLabTransportError('request outcome is unknown')
    monkeypatch.setattr(
        providers,
        'add_deploy_key',
        lambda *a, **k: (_ for _ in ()).throw(error),
    )
    installed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.0.0.5',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        lambda *a, **k: installed.append(k['private_key']),
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *a, **k: CommandResult(255, '', 'Permission denied (publickey)'),
    )

    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    entry = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )

    assert entry.provider_managed is False
    assert entry.provider_key_id == ''
    assert entry.state == 'pending'
    assert installed and installed[0][0] == entry.id
    [persisted] = find_credentials_for_vm(load_store(path), 'vm-a')
    assert persisted == entry
    assert host_credential_dir('vm-a', entry.id).exists()


def test_gitlab_missing_token_still_creates_admin_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'vm-a'})
    path = write_store(tmp_path / 'config.toml', cfg)
    store = load_store(path)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(
        'aivm.credentials.service._require_tools', lambda *a, **k: None
    )
    _patch_generated_host_key(monkeypatch)
    monkeypatch.setattr(
        providers,
        'automation_unavailable_reason',
        lambda *a, **k: 'GITLAB_TOKEN is not set',
    )
    monkeypatch.setattr(
        providers,
        'find_recorded_provider_key',
        lambda *a, **k: pytest.fail('provider lookup must be skipped'),
    )
    monkeypatch.setattr(
        providers,
        'add_deploy_key',
        lambda *a, **k: pytest.fail('provider publication must be skipped'),
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

    repo = GitRepository('gitlab.com', 'group/subgroup', 'project')
    entry = grant_repository_credential(
        cfg,
        store,
        path,
        repo,
        access='write',
        kind=CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
        manager=CommandManager(yes=True),
    )

    assert entry.provider_managed is False
    assert entry.state == 'pending'
    assert host_private_key_path(entry.vm_name, entry.id).exists()
