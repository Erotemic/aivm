"""GitHub/GHES deploy-key backend implemented through the host ``gh`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from ..commands import CommandManager
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


def list_deploy_keys(
    repo: GitRepository, *, manager: CommandManager
) -> list[ProviderDeployKey]:
    result = manager.run(
        [
            'gh',
            'repo',
            'deploy-key',
            'list',
            *_repo_args(repo),
            '--json',
            'id,key,readOnly,title',
        ],
        sudo=False,
        role='read',
        check=True,
        capture=True,
        summary=f'List deploy keys for {repo.display}',
    )
    try:
        raw = json.loads(result.stdout or '[]')
    except json.JSONDecodeError as ex:
        raise AIVMError('gh returned invalid deploy-key JSON.') from ex
    if not isinstance(raw, list):
        raise AIVMError('gh returned an unexpected deploy-key response.')
    keys: list[ProviderDeployKey] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        keys.append(
            ProviderDeployKey(
                key_id=str(item.get('id', '')).strip(),
                key=str(item.get('key', '')).strip(),
                title=str(item.get('title', '')).strip(),
                read_only=bool(item.get('readOnly', True)),
            )
        )
    return keys


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
        if by_id:
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
