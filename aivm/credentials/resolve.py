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

_SCP_RE = re.compile(
    r'^(?P<user>[^@/\s]+)@(?P<host>[^:/\s]+):(?P<path>.+)$'
)


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
    transport_kind = ''
    if scp_match is not None and '://' not in raw:
        if scp_match.group('user') != 'git':
            raise AIVMError(
                'SCP-style repository URLs must use the git user so AIVM '
                'can route them through the managed deploy key.'
            )
        host = scp_match.group('host')
        repo_path = scp_match.group('path')
        source_url = raw
        transport_kind = 'scp'
    elif '://' in raw:
        parsed = urlparse(raw)
        if parsed.query or parsed.fragment:
            raise AIVMError('Repository URLs may not contain a query or fragment.')
        try:
            explicit_port = parsed.port
        except ValueError as ex:
            raise AIVMError('Invalid repository URL port.') from ex
        if explicit_port is not None:
            raise AIVMError(
                'Repository URLs with explicit ports are not supported yet; '
                'AIVM cannot safely infer the corresponding SSH endpoint.'
            )
        scheme = parsed.scheme.lower()
        if scheme not in {'https', 'ssh'}:
            raise AIVMError(
                'AIVM deploy-key credentials support only canonical HTTPS '
                'and SSH repository URLs. HTTP and git:// transports cannot '
                'be proven to use the managed key.'
            )
        if parsed.password is not None:
            raise AIVMError('Repository URLs may not embed a password or token.')
        if scheme == 'https' and parsed.username is not None:
            raise AIVMError(
                'HTTPS repository URLs may not contain userinfo. It can leak '
                'through command logging and bypass managed-key routing.'
            )
        if scheme == 'ssh' and parsed.username != 'git':
            raise AIVMError(
                'SSH repository URLs must use the git user so AIVM can route '
                'them through the managed deploy key.'
            )
        host = parsed.hostname or ''
        repo_path = parsed.path
        source_url = raw
        transport_kind = scheme
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
    normalized = GitRepository(
        host=repo.host,
        owner=repo.owner,
        name=repo.name,
        source_url=source_url,
    )
    if source_url:
        expected_by_kind = {
            'scp': normalized.ssh_url,
            'ssh': (
                f'ssh://git@{normalized.host}/'
                f'{normalized.owner}/{normalized.name}.git'
            ),
            'https': normalized.https_url,
        }
        expected = expected_by_kind[transport_kind]
        if source_url != expected:
            raise AIVMError(
                'Repository transport URLs must use the canonical spelling '
                f'{expected!r}. AIVM requires an exact form so Git rewrite '
                'verification cannot succeed through another transport.'
            )
    return normalized


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
