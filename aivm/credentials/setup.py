"""Host prerequisite setup for VM-scoped repository credentials."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass

from loguru import logger as log

from ..commands import CommandError, CommandManager, CommandResult
from ..errors import AIVMError
from . import gh_install, github
from .gh_install import GH_INSTALL_DOCS
from .models import GitRepository

CREDENTIAL_TOOLS = ('gh', 'ssh', 'ssh-keygen')

# `gh repo deploy-key` -- the command this whole feature is built on -- was
# added in GitHub CLI 2.5.0. An older gh can authenticate and read the API but
# cannot manage deploy keys at all, so installing one is not useful.
MINIMUM_GH_VERSION = (2, 5, 0)

# `gh auth login --skip-ssh-key` was added in 2.48.0. Without it, login may
# offer to upload the user's ordinary SSH key, which AIVM never wants.
GH_SKIP_SSH_KEY_VERSION = (2, 48, 0)

_GH_VERSION_RE = re.compile(r'(\d+)\.(\d+)\.(\d+)')


def format_gh_version(version: tuple[int, int, int] | None) -> str:
    return '.'.join(str(part) for part in version) if version else 'unknown'


def gh_version(*, manager: CommandManager) -> tuple[int, int, int] | None:
    """Return the installed GitHub CLI version, or None if unreadable."""
    result = manager.run(
        ['gh', '--version'],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        summary='Read the GitHub CLI version',
    )
    if result.code != 0:
        return None
    match = _GH_VERSION_RE.search(result.stdout or '')
    if match is None:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )


def _too_old_message(version: tuple[int, int, int] | None) -> str:
    return (
        f'GitHub CLI {format_gh_version(version)} cannot manage deploy keys; '
        f'`gh repo deploy-key` requires {format_gh_version(MINIMUM_GH_VERSION)} '
        'or newer. Some distributions package a much older gh (Ubuntu 22.04 '
        'ships 2.4.0), so install a current release from '
        f'{GH_INSTALL_DOCS} and rerun `aivm vm creds setup`.'
    )


def require_supported_gh(*, manager: CommandManager) -> None:
    """Refuse credential work when gh cannot manage deploy keys."""
    version = gh_version(manager=manager)
    if version is None or version < MINIMUM_GH_VERSION:
        raise AIVMError(_too_old_message(version))


@dataclass(frozen=True)
class CredentialSetupReport:
    """Observed host readiness for GitHub deploy-key management."""

    hostname: str
    tool_paths: dict[str, str | None]
    auth_ok: bool
    auth_detail: str
    gh_version: tuple[int, int, int] | None = None
    repository: GitRepository | None = None
    repository_ok: bool | None = None
    repository_detail: str = ''

    @property
    def missing_tools(self) -> tuple[str, ...]:
        return tuple(
            name for name in CREDENTIAL_TOOLS if not self.tool_paths.get(name)
        )

    @property
    def gh_supported(self) -> bool:
        """Whether the installed gh can manage deploy keys at all."""
        return (
            self.gh_version is not None
            and self.gh_version >= MINIMUM_GH_VERSION
        )

    @property
    def gh_can_skip_ssh_key(self) -> bool:
        return (
            self.gh_version is not None
            and self.gh_version >= GH_SKIP_SSH_KEY_VERSION
        )

    @property
    def gh_detail(self) -> str:
        if not self.tool_paths.get('gh'):
            return 'not installed'
        if self.gh_version is None:
            return 'version could not be determined'
        text = format_gh_version(self.gh_version)
        if not self.gh_supported:
            return (
                f'{text} -- too old; deploy keys need '
                f'{format_gh_version(MINIMUM_GH_VERSION)}+'
            )
        return text

    @property
    def ready(self) -> bool:
        repository_ready = self.repository is None or self.repository_ok is True
        return (
            not self.missing_tools
            and self.gh_supported
            and self.auth_ok
            and repository_ready
        )


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

    version = gh_version(manager=manager)
    if version is None or version < MINIMUM_GH_VERSION:
        # An old gh can still authenticate, but it cannot manage deploy keys,
        # so probing auth or repository access would only report readiness
        # this host does not have.
        return CredentialSetupReport(
            hostname=hostname,
            tool_paths=tool_paths,
            auth_ok=False,
            auth_detail=_too_old_message(version),
            gh_version=version,
            repository=repository,
            repository_ok=None,
            repository_detail='Not checked because GitHub CLI is too old.',
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
        gh_version=version,
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
    missing: tuple[str, ...],
    *,
    upgrade_gh: bool = False,
    manager: CommandManager,
) -> None:
    """Install missing credential tools using the host's package backend.

    ``upgrade_gh`` handles the case that prompted this path: gh is present but
    predates ``gh repo deploy-key``, so it must be replaced from GitHub's own
    repository rather than left alone.
    """
    include_gh = 'gh' in missing or upgrade_gh
    if not missing and not upgrade_gh:
        return

    plan = gh_install.plan_tool_install(
        missing, include_gh=include_gh, manager=manager
    )
    why = (
        'VM repository credentials use GitHub CLI for deploy-key '
        'administration and OpenSSH for scoped key generation.'
    )
    if include_gh and plan.backend in {'apt', 'dnf5', 'dnf', 'zypper'}:
        why += (
            ' Installing from GitHub\'s own package repository, because '
            'distribution packages of gh are often too old to manage deploy '
            f'keys ({GH_INSTALL_DOCS}).'
        )

    try:
        with manager.step(
            'Install host credential tools',
            why=why,
            approval_scope='vm-credentials-install-tools',
        ):
            for step in plan.steps:
                manager.submit(
                    step.cmd,
                    sudo=step.sudo,
                    role='modify',
                    check=True,
                    capture=False,
                    input_text=step.input_text,
                    summary=step.summary,
                    detail=step.detail,
                )
    except CommandError as ex:
        raise AIVMError(
            'Could not install host credential tools with the '
            f'{plan.backend} backend. Install them manually (see '
            f'{GH_INSTALL_DOCS} for the GitHub CLI), then rerun '
            '`aivm vm creds setup`.'
        ) from ex


def authenticate_github(
    hostname: str,
    *,
    manager: CommandManager,
    version: tuple[int, int, int] | None = None,
) -> None:
    """Start GitHub CLI login without uploading an ordinary user SSH key.

    ``--skip-ssh-key`` only exists in gh 2.48.0 and newer. Passing it to an
    older gh fails the whole login with ``unknown flag``, so it is included
    only when the installed version supports it.
    """
    cmd = ['gh', 'auth', 'login', '--hostname', hostname, '--web']
    if version is not None and version >= GH_SKIP_SSH_KEY_VERSION:
        cmd.append('--skip-ssh-key')
    else:
        log.warning(
            'GitHub CLI {} predates --skip-ssh-key ({}+). If the login offers '
            'to upload an SSH public key, decline: AIVM creates '
            'repository-scoped deploy keys and never needs your personal key '
            'on GitHub.',
            format_gh_version(version),
            format_gh_version(GH_SKIP_SSH_KEY_VERSION),
        )
    try:
        manager.run(
            cmd,
            sudo=False,
            role='modify',
            check=True,
            capture=False,
            summary=f'Authenticate GitHub CLI for {hostname}',
            detail='AIVM manages repository deploy keys separately.',
        )
    except CommandError as ex:
        raise AIVMError(
            f'GitHub CLI authentication failed for {hostname}; see the gh '
            'output above. Rerun `aivm vm creds setup` to try again.'
        ) from ex
