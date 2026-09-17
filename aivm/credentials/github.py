"""GitHub/GHES deploy-key backend implemented through the host ``gh`` CLI."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import cast

from ..commands import CommandError, CommandManager, CommandResult
from ..config_store.models import CredentialEntry
from ..errors import AIVMError, CommandControlError
from .errors import ProviderPermissionError, ProviderRejectedError
from .keys import normalized_public_key, public_key_fingerprint
from .models import GitRepository, ProviderDeployKey

_HTTP_STATUS_RE = re.compile(r'\bHTTP (\d{3})\b')

__all__ = [
    'ProviderPermissionError',
    'ProviderRejectedError',
    'add_deploy_key',
    'automation_unavailable_reason',
    'check_auth',
    'delete_deploy_key',
    'find_recorded_provider_key',
    'list_deploy_keys',
]


def _provider_failure_reason(text: str, status: str) -> str:
    """Extract GitHub's human-readable reason from a gh error payload."""
    # gh writes either "HTTP 422: Validation Failed (url)" followed by the
    # reason, or a single "gh: <reason> (HTTP 403)" line. Keep the reason; the
    # URL and argv add nothing a reader can act on.
    reason = ' '.join(
        line.strip() for line in text.splitlines()[1:] if line.strip()
    )
    detail = reason or text
    if f'HTTP {status}' in detail:
        return detail
    return f'{detail} (HTTP {status})'


def _classify_provider_failure(
    ex: CommandError,
    *,
    action: str,
    repo: GitRepository,
    permission_only: bool = False,
) -> AIVMError | None:
    """Turn a failed ``gh`` command into a typed, actionable provider error.

    ``permission_only`` is for read operations. A failed read establishes
    nothing about provider state, so it must never be reported as a refusal
    that lets a caller discard local state -- only failures that say something
    about the *caller* are recognized there.
    """
    text = (ex.result.stderr or ex.result.stdout or '').strip()
    match = _HTTP_STATUS_RE.search(text)
    if match is None or not 400 <= int(match.group(1)) < 500:
        return None
    status = match.group(1)
    detail = _provider_failure_reason(text, status)
    if status == '403':
        return ProviderPermissionError(
            f'GitHub refused to {action} for {repo.display}: {detail}. '
            'Deploy-key endpoints require admin permission on the '
            'repository; write access is not enough.'
        )
    if status == '404':
        # On a private repository GitHub answers 404 rather than 403 so a
        # response never confirms what exists, which leaves the status
        # ambiguous between "not an admin" and "no such repository". Report
        # both rather than probing: an extra probe cannot be worth the risk of
        # leaving another failed command behind, and the caller hands the key
        # over either way.
        return ProviderPermissionError(
            f'GitHub refused to {action} for {repo.display}: {detail}. '
            'Deploy-key endpoints require admin permission on the repository, '
            'and GitHub answers 404 instead of 403 on private repositories '
            'rather than reveal what exists. So either this account is not an '
            f'admin of {repo.display}, or it cannot see that repository at '
            f'all -- check `gh repo view {repo.owner}/{repo.name}`, '
            '`gh auth status`, and SAML authorization for the organization.'
        )
    if permission_only:
        return None
    return ProviderRejectedError(
        f'GitHub refused to {action} for {repo.display}: {detail}. No key was '
        'created. Deploy keys can be disabled per repository or across an '
        'organization; ask an administrator to enable them, then rerun '
        '`aivm vm creds add`.'
    )


def automation_unavailable_reason(
    repo: GitRepository, *, manager: CommandManager
) -> str:
    """Return why this host cannot register deploy keys, or '' when it can.

    Registering a key with the provider is a convenience, not a requirement:
    AIVM can always generate a scoped keypair, install it in the guest, and
    hand the public half to a human. So an absent, outdated, or signed-out
    ``gh`` is a reason to fall back to that handoff -- never an error, and
    never a reason to refuse to create the credential at all.
    """
    if shutil.which('gh') is None:
        return (
            'The GitHub CLI (gh) is not installed on this host, so AIVM '
            'cannot register the deploy key for you. Install it with '
            '`aivm vm creds setup` to automate this next time.'
        )
    # Imported here because setup imports this module for its readiness
    # report, so the dependency cannot also run the other way at import time.
    from .setup import MINIMUM_GH_VERSION, gh_version, too_old_gh_message

    version = gh_version(manager=manager)
    if version is None or version < MINIMUM_GH_VERSION:
        return too_old_gh_message(version)
    try:
        check_auth(repo, manager=manager)
    except CommandControlError:
        # "gh is not signed in" is a reason to hand the key to a human;
        # "the user declined" is a reason to stop.
        raise
    except AIVMError as ex:
        return (
            f'The GitHub CLI is not authenticated for {repo.host}: {ex} '
            'Run `aivm vm creds setup` to sign in and automate this next time.'
        )
    return ''


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


def _decode_json_stream(result: CommandResult, *, label: str) -> list[object]:
    """Decode the consecutive JSON documents emitted by ``gh --paginate``.

    Older GitHub CLI releases, including Ubuntu 24.04's packaged version, do
    not provide ``gh api --slurp``. Without that flag, each response page is
    written as another complete JSON document. ``raw_decode`` lets us consume
    that stream without depending on line-oriented formatting.
    """
    text = result.stdout or ''
    decoder = json.JSONDecoder()
    values: list[object] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as ex:
            raise AIVMError(f'gh returned invalid JSON while {label}.') from ex
        values.append(value)
    if not values:
        raise AIVMError(f'gh returned no JSON while {label}.')
    return values


def _is_not_found(result: CommandResult) -> bool:
    detail = f'{result.stderr}\n{result.stdout}'
    return bool(re.search(r'\bHTTP\s+404\b', detail, re.IGNORECASE))


def list_deploy_keys(
    repo: GitRepository, *, manager: CommandManager
) -> list[ProviderDeployKey]:
    """List every deploy key using version-compatible REST pagination."""
    try:
        result = manager.run(
            [
                'gh',
                'api',
                '--hostname',
                repo.host,
                '--paginate',
                f'{_deploy_keys_endpoint(repo)}?per_page=100',
            ],
            sudo=False,
            role='read',
            check=True,
            capture=True,
            summary=f'List all deploy keys for {repo.display}',
        )
    except CommandError as ex:
        # Reading deploy keys needs admin too, so a non-admin identity fails
        # here rather than at creation. Only a 403 is reinterpreted: any other
        # failed read stays a raw CommandError, because a read that did not
        # complete proves nothing about what exists at the provider.
        failure = _classify_provider_failure(
            ex,
            action='read deploy keys',
            repo=repo,
            permission_only=True,
        )
        if failure is None:
            raise
        raise failure from ex
    pages = _decode_json_stream(result, label='listing deploy keys')
    items: list[object] = []
    for page in pages:
        if not isinstance(page, list):
            raise AIVMError(
                'gh returned an unexpected paginated deploy-key response.'
            )
        items.extend(cast(list[object], page))
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
        raise AIVMError(
            'GitHub returned duplicate deploy keys for one SSH key.'
        )
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
        by_id = [item for item in keys if item.key_id == entry.provider_key_id]
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
    if entry.provider_key_id:
        exact = get_deploy_key(repo, entry.provider_key_id, manager=manager)
        if exact is not None:
            return select_recorded_provider_key(entry, [exact])
        # GitHub deliberately uses 404 for some authorization failures on
        # private resources. Corroborate an exact-key 404 with a successful,
        # fully paginated collection read before concluding provider absence.
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
    try:
        manager.run(
            cmd,
            sudo=False,
            role='modify',
            check=True,
            capture=True,
            summary=f'Add deploy key to {repo.display}',
            detail='access=write' if write else 'access=read',
        )
    except CommandError as ex:
        failure = _classify_provider_failure(
            ex, action='create a deploy key', repo=repo
        )
        if failure is None:
            raise
        raise failure from ex
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
