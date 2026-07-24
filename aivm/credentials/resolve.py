"""Resolve user-facing repository selectors into canonical identities."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from ..commands import CommandManager
from ..errors import AIVMError
from .models import GitRepository
from .validation import (
    CredentialValidationError,
    validate_repository_identity,
)

_SCP_RE = re.compile(r'^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?P<path>.+)$')


def _strip_repo_suffix(path: str) -> str:
    clean = path.strip().strip('/')
    if clean.endswith('.git'):
        clean = clean[:-4]
    return clean.strip('/')


def parse_repository_url(value: str) -> GitRepository:
    """Parse common GitHub/GHES repository spellings."""
    raw = str(value or '').strip()
    if not raw:
        raise AIVMError('Repository selector is empty.')

    host = 'github.com'
    repo_path = raw
    source_url = ''
    scp_match = _SCP_RE.match(raw)
    if scp_match is not None and '://' not in raw:
        host = scp_match.group('host')
        repo_path = scp_match.group('path')
        source_url = raw
    elif '://' in raw:
        parsed = urlparse(raw)
        if parsed.query or parsed.fragment:
            raise AIVMError('Repository URLs may not contain a query or fragment.')
        try:
            explicit_port = parsed.port
        except ValueError as ex:
            raise AIVMError(f'Invalid repository URL port: {raw!r}') from ex
        if explicit_port is not None:
            raise AIVMError(
                'Repository URLs with explicit ports are not supported yet; '
                'AIVM cannot safely infer the corresponding SSH endpoint.'
            )
        if parsed.scheme.lower() not in {'http', 'https', 'ssh', 'git'}:
            raise AIVMError(
                f'Unsupported repository URL scheme: {parsed.scheme!r}'
            )
        if parsed.password is not None:
            raise AIVMError('Repository URLs may not embed a password or token.')
        host = parsed.hostname or ''
        repo_path = parsed.path
        source_url = raw
    else:
        parts = raw.strip('/').split('/')
        if len(parts) == 3 and ('.' in parts[0] or parts[0] == 'localhost'):
            host, repo_path = parts[0], '/'.join(parts[1:])

    if source_url and not repo_path.rstrip('/').endswith('.git'):
        raise AIVMError(
            'Repository transport URLs must end in .git so AIVM can install '
            'an exact repository-scoped Git rewrite without capturing sibling '
            'repository names. Update the remote URL or use OWNER/REPO.'
        )

    parts = _strip_repo_suffix(repo_path).split('/')
    if not host or len(parts) != 2 or not all(parts):
        raise AIVMError(
            'Could not resolve repository. Expected a local checkout, '
            'OWNER/REPO, [HOST/]OWNER/REPO, or a Git SSH/HTTPS URL.'
        )
    owner, name = parts
    try:
        repo = validate_repository_identity(host, owner, name)
    except CredentialValidationError as ex:
        raise AIVMError(str(ex)) from ex
    return GitRepository(
        host=repo.host,
        owner=repo.owner,
        name=repo.name,
        source_url=source_url,
    )


def resolve_repository(
    selector: str | Path,
    *,
    remote: str = 'origin',
    manager: CommandManager | None = None,
) -> GitRepository:
    """Resolve a local checkout or explicit repository selector."""
    text = str(selector or '.').strip() or '.'
    path = Path(text).expanduser()
    is_local = text == '.' or path.exists()
    if not is_local:
        return parse_repository_url(text)

    checkout = path if path.is_dir() else path.parent
    mgr = manager or CommandManager.current()
    result = mgr.run(
        ['git', '-C', str(checkout), 'remote', 'get-url', remote],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary=f'Resolve Git remote {remote}',
        detail=f'checkout={checkout}',
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Could not read Git remote {remote!r} from {checkout}: '
            f'{detail or "git remote get-url failed"}'
        )
    return parse_repository_url(result.stdout.strip())
