"""GitHub/GHES deploy-key backend implemented through the host ``gh`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from ..commands import CommandManager
from ..errors import AIVMError
from .keys import normalized_public_key
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


def find_matching_key(
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
    match = find_matching_key(
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
