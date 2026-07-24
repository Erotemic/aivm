"""Resolve user-facing repository selectors into canonical identities."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from ..commands import CommandManager
from ..errors import AIVMError
from .models import GitRepository

_SCP_RE = re.compile(r'^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?P<path>.+)$')
_HOST_RE = re.compile(r'^[A-Za-z0-9.-]+$')
_REPO_PART_RE = re.compile(r'^[A-Za-z0-9_.-]+$')


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
    scp_match = _SCP_RE.match(raw)
    if scp_match is not None and '://' not in raw:
        host = scp_match.group('host')
        repo_path = scp_match.group('path')
    elif '://' in raw:
        parsed = urlparse(raw)
        if parsed.query or parsed.fragment:
            raise AIVMError('Repository URLs may not contain a query or fragment.')
        host = parsed.hostname or ''
        repo_path = parsed.path
    else:
        parts = raw.strip('/').split('/')
        if len(parts) == 3 and ('.' in parts[0] or parts[0] == 'localhost'):
            host, repo_path = parts[0], '/'.join(parts[1:])

    host = host.strip().lower()
    parts = _strip_repo_suffix(repo_path).split('/')
    if not host or len(parts) != 2 or not all(parts):
        raise AIVMError(
            'Could not resolve repository. Expected a local checkout, '
            'OWNER/REPO, [HOST/]OWNER/REPO, or a Git SSH/HTTPS URL.'
        )
    owner, name = parts
    if not _HOST_RE.fullmatch(host):
        raise AIVMError(f'Unsupported repository host syntax: {host!r}')
    if not _REPO_PART_RE.fullmatch(owner) or not _REPO_PART_RE.fullmatch(name):
        raise AIVMError(
            'Repository owner and name may contain only letters, numbers, '
            "'.', '_', and '-'."
        )
    return GitRepository(host=host, owner=owner, name=name)


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
