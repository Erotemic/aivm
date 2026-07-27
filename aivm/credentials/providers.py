"""Provider selection and deploy-key dispatch for supported Git forges."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlparse

from ..commands import CommandManager
from ..config_store.models import CredentialEntry
from ..errors import AIVMError, CommandControlError
from . import github
from .errors import ProviderRejectedError
from .gitlab import (
    GitLabDeployKeyBackend,
    GitLabProviderRejectedError,
    default_api_url,
)
from .keys import normalized_public_key, public_key_fingerprint
from .models import GitRepository, ProviderDeployKey
from .schema import (
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
    CredentialKind,
)

CredentialProvider = Literal['auto', 'github', 'gitlab']
ResolvedCredentialProvider = Literal['github', 'gitlab']

VALID_CREDENTIAL_PROVIDERS: frozenset[str] = frozenset(
    {'auto', 'github', 'gitlab'}
)


def normalize_provider(value: object) -> CredentialProvider:
    raw = str(value or 'auto').strip().lower()
    if raw not in VALID_CREDENTIAL_PROVIDERS:
        allowed = ', '.join(sorted(VALID_CREDENTIAL_PROVIDERS))
        raise AIVMError(
            f'Unsupported credential provider {value!r}; expected one of: '
            f'{allowed}'
        )
    return cast(CredentialProvider, raw)


def _host_looks_like_gitlab(host: str) -> bool:
    """Recognize the conventional hostname of a self-managed GitLab.

    Guessing wrong is not cosmetic: the provider decides which API is called,
    which tools are required, and which ``kind`` is written into the config
    store for the life of the credential. A self-managed instance almost
    always answers on ``gitlab.<domain>``, and defaulting those to GitHub
    recorded a ``github-deploy-key`` for a GitLab project, then reported the
    handoff under the wrong forge name. ``--provider`` still overrides this.
    """
    labels = host.lower().split('.')
    return len(labels) > 1 and labels[0] == 'gitlab'


def resolve_provider(
    repo: GitRepository | None,
    requested: object = 'auto',
    *,
    hostname: str = '',
) -> ResolvedCredentialProvider:
    """Resolve an explicit provider or infer the forge from its host."""
    provider = normalize_provider(requested)
    host = repo.host if repo is not None else hostname
    if provider != 'auto':
        if provider == 'gitlab' and host.lower() == 'github.com':
            raise AIVMError(
                'github.com cannot be managed with the GitLab provider.'
            )
        if provider == 'github' and host.lower() == 'gitlab.com':
            raise AIVMError(
                'gitlab.com cannot be managed with the GitHub provider.'
            )
        return provider
    if _host_looks_like_gitlab(host):
        return 'gitlab'
    return 'github'


def kind_for_provider(provider: ResolvedCredentialProvider) -> CredentialKind:
    if provider == 'gitlab':
        return CREDENTIAL_KIND_GITLAB_DEPLOY_KEY
    return CREDENTIAL_KIND_GITHUB_DEPLOY_KEY


def provider_for_kind(kind: CredentialKind | str) -> ResolvedCredentialProvider:
    if kind == CREDENTIAL_KIND_GITLAB_DEPLOY_KEY:
        return 'gitlab'
    if kind == CREDENTIAL_KIND_GITHUB_DEPLOY_KEY:
        return 'github'
    raise AIVMError(f'Unsupported credential kind: {kind!r}')


def provider_label(kind: CredentialKind | str) -> str:
    return 'GitLab' if provider_for_kind(kind) == 'gitlab' else 'GitHub'


def required_tools(kind: CredentialKind | str) -> tuple[str, ...]:
    """Host commands required for provider administration.

    SSH and ssh-keygen are required by credential creation itself and are
    checked by the lifecycle layer. Provider administration adds only gh for
    GitHub; GitLab uses direct HTTPS API calls.
    """
    if provider_for_kind(kind) == 'gitlab':
        return ()
    return ('gh',)


def _gitlab_api_url(host: str) -> str:
    configured = os.environ.get('GITLAB_API_URL', '').strip()
    api_url = configured or default_api_url(host)
    parsed = urlparse(api_url)
    if (parsed.hostname or '').lower() != host.lower():
        raise AIVMError(
            'GITLAB_API_URL must use the same hostname as the repository. '
            f'Repository host: {host}; API URL: {api_url}'
        )
    require_encrypted_api_url(api_url)
    return api_url


def require_encrypted_api_url(api_url: str) -> None:
    """Refuse to send an API token over an unencrypted transport.

    The token travels in a ``PRIVATE-TOKEN`` request header on every call, so
    plaintext HTTP hands a long-lived credential to anything on the path.
    ``default_api_url`` always builds an ``https`` URL; only an explicit
    ``GITLAB_API_URL`` can downgrade it. Loopback is exempt so a local test
    server or an SSH-forwarded port still works.
    """
    parsed = urlparse(api_url)
    if parsed.scheme.lower() == 'https':
        return
    hostname = (parsed.hostname or '').lower()
    if hostname in {'localhost', '127.0.0.1', '::1'}:
        return
    scheme = parsed.scheme.lower() or 'an unrecognized scheme'
    raise AIVMError(
        f'Refusing to send a GitLab API token to {hostname or api_url} over '
        f'{scheme}: the token is sent as a request header on every call. Set '
        'GITLAB_API_URL to an https endpoint.'
    )


def gitlab_backend_for_host(host: str) -> GitLabDeployKeyBackend:
    """Construct the host-token GitLab client for one forge hostname."""
    return GitLabDeployKeyBackend.from_env(
        host,
        api_url=_gitlab_api_url(host),
    )


def gitlab_backend(repo: GitRepository) -> GitLabDeployKeyBackend:
    return gitlab_backend_for_host(repo.host)


def _gitlab_project_path(repo: GitRepository) -> str:
    return f'{repo.owner}/{repo.name}'


def automation_unavailable_reason(
    kind: CredentialKind,
    repo: GitRepository,
    *,
    manager: CommandManager,
) -> str:
    """Return why automatic publication is unavailable, or ``''``.

    Publication is intentionally optional. A missing client, missing token,
    stale login, or provider bureaucracy must not prevent AIVM from creating
    and installing the repository-scoped SSH credential for administrator
    handoff.
    """
    if provider_for_kind(kind) == 'github':
        return github.automation_unavailable_reason(repo, manager=manager)
    try:
        gitlab_backend(repo).check_auth()
    except CommandControlError:
        raise
    except AIVMError as ex:
        return (
            f'GitLab API automation is unavailable for {repo.host}: {ex} '
            'Set GITLAB_TOKEN to automate publication, or send the generated '
            'public key to a project administrator.'
        )
    return ''


def check_auth(
    kind: CredentialKind,
    repo: GitRepository,
    *,
    manager: CommandManager,
) -> None:
    if provider_for_kind(kind) == 'github':
        github.check_auth(repo, manager=manager)
        return
    gitlab_backend(repo).check_auth()


def list_deploy_keys(
    kind: CredentialKind,
    repo: GitRepository,
    *,
    manager: CommandManager,
) -> list[ProviderDeployKey]:
    if provider_for_kind(kind) == 'github':
        return github.list_deploy_keys(repo, manager=manager)
    backend = gitlab_backend(repo)
    project = backend.resolve_project(_gitlab_project_path(repo))
    return backend.list_deploy_keys(project)


def _provider_key_fingerprint(
    key: ProviderDeployKey,
    *,
    label: str,
) -> str:
    try:
        return public_key_fingerprint(key.key)
    except AIVMError as ex:
        raise AIVMError(
            f'{label} deploy key {key.key_id or "<unknown>"} has malformed '
            'public-key data; refusing to make an identity decision.'
        ) from ex


def _select_recorded_key(
    entry: CredentialEntry,
    keys: list[ProviderDeployKey],
    *,
    label: str,
) -> ProviderDeployKey | None:
    if not entry.key_fingerprint:
        raise AIVMError(
            f'Credential {entry.id} has no recorded key fingerprint; refusing '
            'to identify or revoke a provider key.'
        )

    if entry.provider_key_id:
        by_id = [item for item in keys if item.key_id == entry.provider_key_id]
        if len(by_id) > 1:
            raise AIVMError(
                f'{label} returned duplicate deploy-key id '
                f'{entry.provider_key_id!r}.'
            )
        if by_id:
            match = by_id[0]
            actual = _provider_key_fingerprint(match, label=label)
            if actual != entry.key_fingerprint:
                raise AIVMError(
                    f'{label} key id {entry.provider_key_id} no longer matches '
                    'the fingerprint recorded by AIVM; refusing to touch it.'
                )
            return match

    by_fingerprint = [
        item
        for item in keys
        if _provider_key_fingerprint(item, label=label)
        == entry.key_fingerprint
    ]
    if len(by_fingerprint) > 1:
        raise AIVMError(
            f'Multiple {label} deploy keys match credential {entry.id}. '
            'Refusing to choose one.'
        )
    if by_fingerprint:
        return by_fingerprint[0]

    title_matches = [
        item for item in keys if item.title == entry.provider_key_title
    ]
    if title_matches:
        raise AIVMError(
            f'A {label} deploy key uses title {entry.provider_key_title!r}, '
            'but its fingerprint does not match AIVM state.'
        )
    return None


def find_recorded_provider_key(
    kind: CredentialKind,
    repo: GitRepository,
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> ProviderDeployKey | None:
    if provider_for_kind(kind) == 'github':
        return github.find_recorded_provider_key(repo, entry, manager=manager)

    backend = gitlab_backend(repo)
    project = backend.resolve_project(_gitlab_project_path(repo))
    if entry.provider_key_id:
        exact = backend.get_deploy_key(project, entry.provider_key_id)
        if exact is not None:
            return _select_recorded_key(entry, [exact], label='GitLab')
    return _select_recorded_key(
        entry,
        backend.list_deploy_keys(project),
        label='GitLab',
    )


def add_deploy_key(
    kind: CredentialKind,
    repo: GitRepository,
    *,
    public_key_path: Path,
    title: str,
    write: bool,
    manager: CommandManager,
) -> ProviderDeployKey:
    if provider_for_kind(kind) == 'github':
        return github.add_deploy_key(
            repo,
            public_key_path=public_key_path,
            title=title,
            write=write,
            manager=manager,
        )

    backend = gitlab_backend(repo)
    project = backend.resolve_project(_gitlab_project_path(repo))
    try:
        with manager.approved_action(
            purpose=(
                f'Publish a {"write" if write else "read-only"} deploy key '
                f'to GitLab project {repo.display}.'
            )
        ):
            remote = backend.add_deploy_key(
                project,
                public_key_path=public_key_path,
                title=title,
                write=write,
            )
    except GitLabProviderRejectedError as ex:
        raise ProviderRejectedError(
            f'GitLab refused to create a deploy key for {repo.display}: {ex}. '
            'No key was created. Confirm that deploy keys are allowed and '
            'that the token owner has Maintainer access, then rerun '
            '`aivm vm creds add`.'
        ) from ex

    expected_key = normalized_public_key(
        public_key_path.read_text(encoding='utf-8')
    )
    if not remote.key or normalized_public_key(remote.key) != expected_key:
        raise AIVMError(
            'GitLab returned a deploy key that does not match the public key '
            'AIVM submitted. The pending credential was kept for recovery.'
        )
    return remote


def delete_deploy_key(
    kind: CredentialKind,
    repo: GitRepository,
    key_id: str,
    *,
    manager: CommandManager,
) -> None:
    if provider_for_kind(kind) == 'github':
        github.delete_deploy_key(repo, key_id, manager=manager)
        return
    backend = gitlab_backend(repo)
    project = backend.resolve_project(_gitlab_project_path(repo))
    with manager.approved_action(
        purpose=f'Delete GitLab deploy key {key_id} from {repo.display}.'
    ):
        backend.delete_deploy_key(project, key_id)
