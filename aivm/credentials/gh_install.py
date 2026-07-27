"""Host install backends for the GitHub CLI and OpenSSH client.

Distribution packages of ``gh`` run far behind upstream: Ubuntu 22.04 ships
2.4.0, which predates the ``gh repo deploy-key`` commands this feature is built
on. Installing the distro package there produces a gh that can authenticate but
can never manage a deploy key. So ``gh`` is installed from GitHub's own
repository wherever one exists, following the official instructions:

    https://github.com/cli/cli/blob/trunk/docs/install_linux.md

Each backend is expressed as a list of :class:`InstallStep` rather than run
here. The caller submits them through the command manager, so every privileged
action -- including adding a third-party apt/rpm repository, which is a
persistent change to the host -- appears in one approval prompt before anything
executes.

The OpenSSH client is a stock distribution package everywhere and is installed
natively; only its package name varies by backend.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from ..commands import CommandManager
from ..errors import AIVMError
from ..host import (
    _debian_apt_install_cmd,
    _debian_noninteractive_cmd,
    host_is_debian_like,
)

GH_INSTALL_DOCS = 'https://github.com/cli/cli/blob/trunk/docs/install_linux.md'

_GH_APT_KEYRING = '/etc/apt/keyrings/githubcli-archive-keyring.gpg'
_GH_APT_KEY_URL = 'https://cli.github.com/packages/githubcli-archive-keyring.gpg'
_GH_APT_SOURCE = '/etc/apt/sources.list.d/github-cli.list'
_GH_RPM_REPO = 'https://cli.github.com/packages/rpm/gh-cli.repo'

# Backends whose gh package tracks upstream closely enough to trust, keyed by
# the command that identifies them. Order matters: dnf5 must win over dnf.
_OPENSSH_PACKAGES = {
    'apt': 'openssh-client',
    'dnf5': 'openssh-clients',
    'dnf': 'openssh-clients',
    'zypper': 'openssh-clients',
    'pacman': 'openssh',
    'apk': 'openssh-client',
}


@dataclass(frozen=True)
class InstallStep:
    """One privileged command in an install plan."""

    cmd: list[str]
    summary: str
    sudo: bool = True
    input_text: str | None = None
    detail: str = ''


@dataclass(frozen=True)
class InstallPlan:
    """What installing a set of tools on this host would run."""

    backend: str
    steps: list[InstallStep] = field(default_factory=list)

    @property
    def packages(self) -> tuple[str, ...]:
        return tuple(
            step.detail.removeprefix('package=')
            for step in self.steps
            if step.detail.startswith('package=')
        )


def detect_backend() -> str:
    """Return the host's package backend, or '' when none is recognized."""
    if host_is_debian_like() and shutil.which('apt-get'):
        return 'apt'
    if shutil.which('dnf5'):
        return 'dnf5'
    if shutil.which('dnf'):
        return 'dnf'
    if shutil.which('zypper'):
        return 'zypper'
    if shutil.which('pacman'):
        return 'pacman'
    if shutil.which('apk'):
        return 'apk'
    return ''


def _unsupported(tools: tuple[str, ...]) -> AIVMError:
    return AIVMError(
        'AIVM does not know how to install '
        + ', '.join(tools)
        + ' on this host: no supported package backend was detected. Install '
        f'them manually (see {GH_INSTALL_DOCS} for the GitHub CLI) and rerun '
        '`aivm vm creds setup`.'
    )


def _apt_gh_steps(*, manager: CommandManager) -> list[InstallStep]:
    """Add GitHub's apt repository, then install gh from it.

    This mirrors the official Debian/Ubuntu instructions. Those are published
    as a shell pipeline; the same effect is expressed here as discrete argv
    commands so each one is reviewable and none needs a shell.
    """
    arch = manager.run(
        ['dpkg', '--print-architecture'],
        sudo=False,
        role='read',
        check=True,
        capture=True,
        summary='Read the host package architecture',
    )
    architecture = (arch.stdout or '').strip() or 'amd64'
    source_line = (
        f'deb [arch={architecture} signed-by={_GH_APT_KEYRING}] '
        'https://cli.github.com/packages stable main\n'
    )

    if shutil.which('wget'):
        fetch = [
            'wget',
            '-nv',
            '-O',
            _GH_APT_KEYRING,
            _GH_APT_KEY_URL,
        ]
    elif shutil.which('curl'):
        fetch = ['curl', '-fsSL', '-o', _GH_APT_KEYRING, _GH_APT_KEY_URL]
    else:
        raise AIVMError(
            'Installing the GitHub CLI from its official apt repository needs '
            'wget or curl on the host. Install one of them, or follow '
            f'{GH_INSTALL_DOCS} manually, then rerun `aivm vm creds setup`.'
        )

    return [
        InstallStep(
            cmd=['mkdir', '-p', '-m', '755', '/etc/apt/keyrings'],
            summary='Create the apt keyring directory',
        ),
        InstallStep(
            cmd=fetch,
            summary='Download the GitHub CLI apt signing key',
            detail=_GH_APT_KEY_URL,
        ),
        InstallStep(
            cmd=['chmod', 'go+r', _GH_APT_KEYRING],
            summary='Make the GitHub CLI signing key world-readable',
        ),
        InstallStep(
            cmd=['mkdir', '-p', '-m', '755', '/etc/apt/sources.list.d'],
            summary='Create the apt sources directory',
        ),
        InstallStep(
            cmd=['tee', _GH_APT_SOURCE],
            summary='Register the GitHub CLI apt repository',
            input_text=source_line,
            detail=source_line.strip(),
        ),
        InstallStep(
            cmd=_debian_noninteractive_cmd('apt-get', 'update', '-y'),
            summary='Refresh apt package metadata',
        ),
        InstallStep(
            cmd=_debian_apt_install_cmd('gh'),
            summary='Install the GitHub CLI from its official repository',
            detail='package=gh',
        ),
    ]


def _rpm_gh_steps(backend: str) -> list[InstallStep]:
    if backend == 'dnf5':
        return [
            InstallStep(
                cmd=['dnf', 'install', '-y', 'dnf5-plugins'],
                summary='Install the dnf5 repository plugin',
            ),
            InstallStep(
                cmd=[
                    'dnf',
                    'config-manager',
                    'addrepo',
                    f'--from-repofile={_GH_RPM_REPO}',
                ],
                summary='Register the GitHub CLI dnf repository',
                detail=_GH_RPM_REPO,
            ),
            InstallStep(
                cmd=['dnf', 'install', '-y', 'gh'],
                summary='Install the GitHub CLI from its official repository',
                detail='package=gh',
            ),
        ]
    if backend == 'dnf':
        return [
            InstallStep(
                cmd=['dnf', 'install', '-y', 'dnf-command(config-manager)'],
                summary='Install the dnf repository plugin',
            ),
            InstallStep(
                cmd=['dnf', 'config-manager', '--add-repo', _GH_RPM_REPO],
                summary='Register the GitHub CLI dnf repository',
                detail=_GH_RPM_REPO,
            ),
            InstallStep(
                cmd=['dnf', 'install', '-y', 'gh'],
                summary='Install the GitHub CLI from its official repository',
                detail='package=gh',
            ),
        ]
    return [
        InstallStep(
            cmd=['zypper', 'addrepo', _GH_RPM_REPO],
            summary='Register the GitHub CLI zypper repository',
            detail=_GH_RPM_REPO,
        ),
        InstallStep(
            cmd=['zypper', 'ref'],
            summary='Refresh zypper repository metadata',
        ),
        InstallStep(
            cmd=['zypper', '--non-interactive', 'install', 'gh'],
            summary='Install the GitHub CLI from its official repository',
            detail='package=gh',
        ),
    ]


def _gh_steps(backend: str, *, manager: CommandManager) -> list[InstallStep]:
    if backend == 'apt':
        return _apt_gh_steps(manager=manager)
    if backend in {'dnf5', 'dnf', 'zypper'}:
        return _rpm_gh_steps(backend)
    if backend == 'pacman':
        # Arch tracks upstream closely, so its own package is current.
        return [
            InstallStep(
                cmd=['pacman', '-S', '--noconfirm', 'github-cli'],
                summary='Install the GitHub CLI',
                detail='package=github-cli',
            )
        ]
    # Alpine, likewise.
    return [
        InstallStep(
            cmd=['apk', 'add', 'github-cli'],
            summary='Install the GitHub CLI',
            detail='package=github-cli',
        )
    ]


def _package_steps(backend: str, packages: list[str]) -> list[InstallStep]:
    """Install stock distribution packages with the detected backend."""
    detail = 'package=' + ','.join(packages)
    if backend == 'apt':
        return [
            InstallStep(
                cmd=_debian_noninteractive_cmd('apt-get', 'update', '-y'),
                summary='Refresh apt package metadata',
            ),
            InstallStep(
                cmd=_debian_apt_install_cmd(*packages),
                summary='Install host credential tools',
                detail=detail,
            ),
        ]
    if backend in {'dnf5', 'dnf'}:
        cmd = ['dnf', 'install', '-y', *packages]
    elif backend == 'zypper':
        cmd = ['zypper', '--non-interactive', 'install', *packages]
    elif backend == 'pacman':
        cmd = ['pacman', '-S', '--noconfirm', *packages]
    else:
        cmd = ['apk', 'add', *packages]
    return [
        InstallStep(
            cmd=cmd, summary='Install host credential tools', detail=detail
        )
    ]


def plan_tool_install(
    tools: tuple[str, ...],
    *,
    include_gh: bool,
    manager: CommandManager,
) -> InstallPlan:
    """Build the install plan for missing credential tools on this host.

    ``include_gh`` covers both a missing gh and one too old to manage deploy
    keys, since the remedy -- install from GitHub's repository -- is the same.
    """
    backend = detect_backend()
    if not backend:
        raise _unsupported(tools)

    steps: list[InstallStep] = []
    openssh_needed = bool({'ssh', 'ssh-keygen'} & set(tools))
    if openssh_needed:
        steps.extend(_package_steps(backend, [_OPENSSH_PACKAGES[backend]]))
    if include_gh:
        steps.extend(_gh_steps(backend, manager=manager))
    return InstallPlan(backend=backend, steps=steps)
