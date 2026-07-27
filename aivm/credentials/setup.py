"""Host prerequisite setup for VM-scoped repository credentials."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from ..commands import CommandError, CommandManager, CommandResult
from ..errors import AIVMError
from ..host import (
    _debian_apt_install_cmd,
    _debian_noninteractive_cmd,
    host_is_debian_like,
)
from . import github
from .models import GitRepository

CREDENTIAL_TOOLS = ('gh', 'ssh', 'ssh-keygen')


@dataclass(frozen=True)
class CredentialSetupReport:
    """Observed host readiness for GitHub deploy-key management."""

    hostname: str
    tool_paths: dict[str, str | None]
    auth_ok: bool
    auth_detail: str
    repository: GitRepository | None = None
    repository_ok: bool | None = None
    repository_detail: str = ''

    @property
    def missing_tools(self) -> tuple[str, ...]:
        return tuple(
            name for name in CREDENTIAL_TOOLS if not self.tool_paths.get(name)
        )

    @property
    def ready(self) -> bool:
        repository_ready = self.repository is None or self.repository_ok is True
        return not self.missing_tools and self.auth_ok and repository_ready


def _auth_status(
    hostname: str, *, manager: CommandManager
) -> CommandResult:
    """Return a non-raising ``gh auth status`` result for one host."""
    return manager.run(
        ['gh', 'auth', 'status', '--hostname', hostname],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary=f'Check gh authentication for {hostname}',
    )


def inspect_credential_setup(
    *,
    hostname: str,
    repository: GitRepository | None,
    manager: CommandManager,
) -> CredentialSetupReport:
    """Inspect tools, host authentication, and optional repository access."""
    tool_paths = {name: shutil.which(name) for name in CREDENTIAL_TOOLS}
    if not tool_paths['gh']:
        return CredentialSetupReport(
            hostname=hostname,
            tool_paths=tool_paths,
            auth_ok=False,
            auth_detail='GitHub CLI is not installed.',
            repository=repository,
            repository_ok=None,
            repository_detail='Not checked because GitHub CLI is unavailable.',
        )

    auth_result = _auth_status(hostname, manager=manager)
    auth_ok = auth_result.code == 0
    auth_detail = (auth_result.stderr or auth_result.stdout or '').strip()
    if auth_ok:
        auth_detail = 'Authenticated.'
    elif not auth_detail:
        auth_detail = f'GitHub CLI is not authenticated for {hostname}.'

    repository_ok: bool | None = None
    repository_detail = ''
    if repository is not None:
        if not auth_ok:
            repository_detail = 'Not checked because authentication is unavailable.'
        else:
            try:
                github.list_deploy_keys(repository, manager=manager)
            except (AIVMError, CommandError) as ex:
                repository_ok = False
                repository_detail = str(ex)
            else:
                repository_ok = True
                repository_detail = 'Deploy-key administration is available.'

    return CredentialSetupReport(
        hostname=hostname,
        tool_paths=tool_paths,
        auth_ok=auth_ok,
        auth_detail=auth_detail,
        repository=repository,
        repository_ok=repository_ok,
        repository_detail=repository_detail,
    )


def require_credential_tools(*names: str) -> None:
    """Require host tools with an actionable setup command in the error."""
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise AIVMError(
            'Missing host command(s) required for VM credentials: '
            + ', '.join(missing)
            + '. Run `aivm vm creds setup` and retry.'
        )


def install_missing_credential_tools(
    missing: tuple[str, ...], *, manager: CommandManager
) -> None:
    """Install credential tools on supported Debian/Ubuntu hosts."""
    if not missing:
        return
    if not host_is_debian_like():
        raise AIVMError(
            'Automatic credential-tool installation is currently supported '
            'only on Debian/Ubuntu. Install the missing command(s) manually: '
            + ', '.join(missing)
        )

    packages: list[str] = []
    if 'gh' in missing:
        packages.append('gh')
    if {'ssh', 'ssh-keygen'} & set(missing):
        packages.append('openssh-client')
    packages = list(dict.fromkeys(packages))

    try:
        with manager.step(
            'Install host credential tools',
            why=(
                'VM repository credentials use GitHub CLI for deploy-key '
                'administration and OpenSSH for scoped key generation.'
            ),
            approval_scope='vm-credentials-install-tools',
        ):
            manager.submit(
                _debian_noninteractive_cmd('apt-get', 'update', '-y'),
                sudo=True,
                role='modify',
                check=True,
                capture=False,
                summary='Refresh apt package metadata',
            )
            manager.submit(
                _debian_apt_install_cmd(*packages),
                sudo=True,
                role='modify',
                check=True,
                capture=False,
                summary='Install host credential tools',
                detail='packages=' + ','.join(packages),
            )
    except CommandError as ex:
        raise AIVMError(
            'Could not install host credential tools. Install '
            + ', '.join(packages)
            + ' manually, then rerun `aivm vm creds setup`.'
        ) from ex


def authenticate_github(hostname: str, *, manager: CommandManager) -> None:
    """Start GitHub CLI login without uploading an ordinary user SSH key."""
    try:
        manager.run(
            [
                'gh',
                'auth',
                'login',
                '--hostname',
                hostname,
                '--web',
                '--skip-ssh-key',
            ],
            sudo=False,
            role='modify',
            check=True,
            capture=False,
            summary=f'Authenticate GitHub CLI for {hostname}',
            detail='AIVM manages repository deploy keys separately.',
        )
    except CommandError as ex:
        raise AIVMError(
            f'GitHub CLI authentication failed for {hostname}. Rerun '
            '`aivm vm creds setup` to try again.'
        ) from ex
