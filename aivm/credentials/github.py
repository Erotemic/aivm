"""GitHub/GHES deploy-key backend implemented through the host ``gh`` CLI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from ..commands import CommandError, CommandManager, CommandResult
from ..config_store.models import CredentialEntry
from ..errors import AIVMError
from .keys import normalized_public_key, public_key_fingerprint
from .models import GitRepository, ProviderDeployKey


def _repo_args(repo: GitRepository) -> list[str]:
    return ['--repo', repo.gh_repo_arg]


def check_auth(repo: GitRepository, *, manager: CommandManager) -> None:
    manager.run(
        ['gh', 'auth', 'status', '--hostname', repo.host],
        sudo=False,
        role='read',
        check=True,
        capture=True,
        summary=f'Check gh authentication for {repo.host}',
    )


def _deploy_keys_endpoint(repo: GitRepository) -> str:
    return f'repos/{repo.owner}/{repo.name}/keys'


def _parse_deploy_key(raw: object) -> ProviderDeployKey:
    if not isinstance(raw, dict):
        raise AIVMError('GitHub returned an unexpected deploy-key response.')
    item = cast(dict[str, object], raw)
    read_only = item.get('read_only', item.get('readOnly', True))
    return ProviderDeployKey(
        key_id=str(item.get('id', '')).strip(),
        key=str(item.get('key', '')).strip(),
        title=str(item.get('title', '')).strip(),
        read_only=bool(read_only),
    )


def _decode_json(result: CommandResult, *, label: str) -> object:
    try:
        return json.loads(result.stdout or 'null')
    except json.JSONDecodeError as ex:
        raise AIVMError(f'gh returned invalid JSON while {label}.') from ex


def _is_not_found(result: CommandResult) -> bool:
    detail = f'{result.stderr}\n{result.stdout}'
    return bool(re.search(r'\bHTTP\s+404\b', detail, re.IGNORECASE))


def list_deploy_keys(
    repo: GitRepository, *, manager: CommandManager
) -> list[ProviderDeployKey]:
    """List every deploy key using GitHub REST pagination."""
    result = manager.run(
        [
            'gh',
            'api',
            '--hostname',
            repo.host,
            '--paginate',
            '--slurp',
            f'{_deploy_keys_endpoint(repo)}?per_page=100',
        ],
        sudo=False,
        role='read',
        check=True,
        capture=True,
        summary=f'List all deploy keys for {repo.display}',
    )
    raw = _decode_json(result, label='listing deploy keys')
    if not isinstance(raw, list):
        raise AIVMError('gh returned an unexpected paginated deploy-key response.')

    # ``gh api --paginate --slurp`` returns one array per response page. Accept
    # a flat array as well so recorded command fixtures can remain simple.
    items: list[object]
    if all(isinstance(page, list) for page in raw):
        pages = cast(list[list[object]], raw)
        items = [item for page in pages for item in page]
    elif all(isinstance(item, dict) for item in raw):
        items = cast(list[object], raw)
    else:
        raise AIVMError('gh returned malformed paginated deploy-key data.')
    return [_parse_deploy_key(item) for item in items]


def get_deploy_key(
    repo: GitRepository, key_id: str, *, manager: CommandManager
) -> ProviderDeployKey | None:
    """Fetch one recorded deploy key directly by provider id."""
    cmd = [
        'gh',
        'api',
        '--hostname',
        repo.host,
        f'{_deploy_keys_endpoint(repo)}/{key_id}',
    ]
    result = manager.run(
        cmd,
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary=f'Inspect deploy key {key_id} for {repo.display}',
    )
    if result.code != 0:
        if _is_not_found(result):
            return None
        raise CommandError(cmd, result)
    return _parse_deploy_key(
        _decode_json(result, label=f'inspecting deploy key {key_id}')
    )


def find_added_key_by_public_key(
    keys: list[ProviderDeployKey],
    *,
    public_key: str,
    title: str,
) -> ProviderDeployKey | None:
    wanted = normalized_public_key(public_key)
    by_key = [
        item
        for item in keys
        if item.key and normalized_public_key(item.key) == wanted
    ]
    if len(by_key) > 1:
        raise AIVMError('GitHub returned duplicate deploy keys for one SSH key.')
    if by_key:
        return by_key[0]
    by_title = [item for item in keys if item.title == title]
    if by_title:
        raise AIVMError(
            f'A different GitHub deploy key already uses title {title!r}. '
            'Revoke or rename it before retrying.'
        )
    return None


def _provider_key_fingerprint(key: ProviderDeployKey) -> str:
    try:
        return public_key_fingerprint(key.key)
    except AIVMError as ex:
        raise AIVMError(
            f'GitHub deploy key {key.key_id or "<unknown>"} has malformed '
            'public-key data; refusing to make an identity decision.'
        ) from ex


def select_recorded_provider_key(
    entry: CredentialEntry,
    keys: list[ProviderDeployKey],
) -> ProviderDeployKey | None:
    """Resolve provider state from immutable recorded identity metadata.

    The host-side public-key file is intentionally not consulted here. It is a
    mutable cache that may be missing or tampered with. Revocation must identify
    the provider key from the stored provider id and cryptographic fingerprint.
    """
    if not entry.key_fingerprint:
        raise AIVMError(
            f'Credential {entry.id} has no recorded key fingerprint; refusing '
            'to identify or revoke a provider key.'
        )

    if entry.provider_key_id:
        by_id = [
            item for item in keys if item.key_id == entry.provider_key_id
        ]
        if len(by_id) > 1:
            raise AIVMError(
                'GitHub returned duplicate deploy-key id '
                f'{entry.provider_key_id!r}.'
            )
        if not by_id:
            return None
        match = by_id[0]
        actual = _provider_key_fingerprint(match)
        if actual != entry.key_fingerprint:
            raise AIVMError(
                f'GitHub key id {entry.provider_key_id} no longer matches '
                'the fingerprint recorded by AIVM; refusing to touch it.'
            )
        return match

    by_fingerprint = [
        item
        for item in keys
        if _provider_key_fingerprint(item) == entry.key_fingerprint
    ]
    if len(by_fingerprint) > 1:
        raise AIVMError(
            f'Multiple GitHub deploy keys match credential {entry.id}. '
            'Refusing to choose one.'
        )
    if by_fingerprint:
        return by_fingerprint[0]

    title_matches = [
        item for item in keys if item.title == entry.provider_key_title
    ]
    if title_matches:
        raise AIVMError(
            f'A GitHub deploy key uses title {entry.provider_key_title!r}, but '
            'its fingerprint does not match AIVM state.'
        )
    return None


def find_recorded_provider_key(
    repo: GitRepository,
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> ProviderDeployKey | None:
    """Inspect the provider using the immutable identity recorded by AIVM."""
    if entry.provider_key_id:
        exact = get_deploy_key(
            repo, entry.provider_key_id, manager=manager
        )
        if exact is None:
            return None
        return select_recorded_provider_key(entry, [exact])
    keys = list_deploy_keys(repo, manager=manager)
    return select_recorded_provider_key(entry, keys)


def add_deploy_key(
    repo: GitRepository,
    *,
    public_key_path: Path,
    title: str,
    write: bool,
    manager: CommandManager,
) -> ProviderDeployKey:
    cmd = [
        'gh',
        'repo',
        'deploy-key',
        'add',
        str(public_key_path),
        *_repo_args(repo),
        '--title',
        title,
    ]
    if write:
        cmd.append('--allow-write')
    manager.run(
        cmd,
        sudo=False,
        role='modify',
        check=True,
        capture=True,
        summary=f'Add deploy key to {repo.display}',
        detail='access=write' if write else 'access=read',
    )
    public_key = public_key_path.read_text(encoding='utf-8')
    match = find_added_key_by_public_key(
        list_deploy_keys(repo, manager=manager),
        public_key=public_key,
        title=title,
    )
    if match is None:
        raise AIVMError(
            'GitHub accepted the deploy-key command, but the key could not '
            'be found afterward. The pending AIVM credential record was kept '
            f'for recovery. Expected title: {title}'
        )
    return match


def delete_deploy_key(
    repo: GitRepository,
    key_id: str,
    *,
    manager: CommandManager,
) -> None:
    manager.run(
        [
            'gh',
            'repo',
            'deploy-key',
            'delete',
            str(key_id),
            *_repo_args(repo),
        ],
        sudo=False,
        role='modify',
        check=True,
        capture=True,
        summary=f'Delete deploy key from {repo.display}',
        detail=f'key_id={key_id}',
    )
