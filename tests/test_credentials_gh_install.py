"""Install-backend selection for the GitHub CLI.

Asserts the produced command plan, not that some function was called: an
install plan is the artifact, and getting the backend wrong means running
someone else's package manager as root.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager, CommandResult
from aivm.credentials import gh_install
from aivm.errors import AIVMError


class _ProbeManager:
    """Answers the architecture probe the apt plan needs."""

    def __init__(self, architecture: str = 'amd64') -> None:
        self.architecture = architecture

    def run(self, cmd: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        if cmd == ['dpkg', '--print-architecture']:
            return CommandResult(0, f'{self.architecture}\n', '')
        return CommandResult(0, '', '')


def _only(names: set[str]) -> Any:
    """Fake ``shutil.which`` where exactly ``names`` are present."""
    return lambda name: f'/usr/bin/{name}' if name in names else None


@pytest.mark.parametrize(
    'present, debian_like, expected',
    [
        pytest.param({'apt-get'}, True, 'apt', id='debian'),
        pytest.param({'dnf5', 'dnf'}, False, 'dnf5', id='dnf5-wins-over-dnf'),
        pytest.param({'dnf'}, False, 'dnf', id='dnf4'),
        pytest.param({'zypper'}, False, 'zypper', id='opensuse'),
        pytest.param({'pacman'}, False, 'pacman', id='arch'),
        pytest.param({'apk'}, False, 'apk', id='alpine'),
        pytest.param(set(), False, '', id='unrecognized'),
        # An apt binary on a non-Debian host must not select the apt backend.
        pytest.param({'apt-get'}, False, '', id='apt-without-debian'),
    ],
)
def test_detect_backend(
    monkeypatch: MonkeyPatch,
    present: set[str],
    debian_like: bool,
    expected: str,
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.shutil.which', _only(present)
    )
    monkeypatch.setattr(
        'aivm.credentials.gh_install.host_is_debian_like', lambda: debian_like
    )

    assert gh_install.detect_backend() == expected


def test_apt_plan_follows_the_official_repository_instructions(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.shutil.which', _only({'apt-get', 'wget'})
    )
    monkeypatch.setattr(
        'aivm.credentials.gh_install.host_is_debian_like', lambda: True
    )

    plan = gh_install.plan_tool_install(
        ('gh',),
        include_gh=True,
        manager=cast(CommandManager, _ProbeManager('arm64')),
    )

    assert plan.backend == 'apt'
    commands = [step.cmd for step in plan.steps]
    keyring = '/etc/apt/keyrings/githubcli-archive-keyring.gpg'
    assert ['mkdir', '-p', '-m', '755', '/etc/apt/keyrings'] in commands
    assert [
        'wget',
        '-nv',
        '-O',
        keyring,
        'https://cli.github.com/packages/githubcli-archive-keyring.gpg',
    ] in commands
    assert ['chmod', 'go+r', keyring] in commands

    # The source line is written through stdin rather than a shell redirect,
    # and carries the probed architecture.
    [source_step] = [step for step in plan.steps if step.cmd[:1] == ['tee']]
    assert source_step.cmd == ['tee', '/etc/apt/sources.list.d/github-cli.list']
    assert source_step.input_text is not None
    assert f'arch=arm64 signed-by={keyring}' in source_step.input_text
    assert (
        'https://cli.github.com/packages stable main' in source_step.input_text
    )

    # gh comes last, after the repository exists.
    assert 'gh' in commands[-1]
    assert all(step.sudo for step in plan.steps)


def test_apt_plan_falls_back_to_curl(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.shutil.which', _only({'apt-get', 'curl'})
    )
    monkeypatch.setattr(
        'aivm.credentials.gh_install.host_is_debian_like', lambda: True
    )

    plan = gh_install.plan_tool_install(
        ('gh',), include_gh=True, manager=cast(CommandManager, _ProbeManager())
    )

    assert any(step.cmd[:1] == ['curl'] for step in plan.steps)


def test_apt_plan_without_a_downloader_is_an_actionable_error(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.shutil.which', _only({'apt-get'})
    )
    monkeypatch.setattr(
        'aivm.credentials.gh_install.host_is_debian_like', lambda: True
    )

    with pytest.raises(AIVMError, match='wget or curl'):
        gh_install.plan_tool_install(
            ('gh',),
            include_gh=True,
            manager=cast(CommandManager, _ProbeManager()),
        )


@pytest.mark.parametrize(
    'backend, expected_repo_cmd',
    [
        pytest.param(
            'dnf5',
            [
                'dnf',
                'config-manager',
                'addrepo',
                '--from-repofile=' + gh_install._GH_RPM_REPO,
            ],
            id='dnf5',
        ),
        pytest.param(
            'dnf',
            ['dnf', 'config-manager', '--add-repo', gh_install._GH_RPM_REPO],
            id='dnf4',
        ),
        pytest.param(
            'zypper',
            ['zypper', 'addrepo', gh_install._GH_RPM_REPO],
            id='zypper',
        ),
    ],
)
def test_rpm_backends_add_the_official_repository(
    monkeypatch: MonkeyPatch, backend: str, expected_repo_cmd: list[str]
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.detect_backend', lambda: backend
    )

    plan = gh_install.plan_tool_install(
        ('gh',), include_gh=True, manager=cast(CommandManager, _ProbeManager())
    )

    assert expected_repo_cmd in [step.cmd for step in plan.steps]


@pytest.mark.parametrize(
    'backend, expected',
    [
        pytest.param(
            'pacman', ['pacman', '-S', '--noconfirm', 'github-cli'], id='arch'
        ),
        pytest.param('apk', ['apk', 'add', 'github-cli'], id='alpine'),
    ],
)
def test_rolling_distros_use_their_own_current_package(
    monkeypatch: MonkeyPatch, backend: str, expected: list[str]
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.detect_backend', lambda: backend
    )

    plan = gh_install.plan_tool_install(
        ('gh',), include_gh=True, manager=cast(CommandManager, _ProbeManager())
    )

    assert [step.cmd for step in plan.steps] == [expected]


@pytest.mark.parametrize(
    'backend, package',
    [
        pytest.param('apt', 'openssh-client', id='apt'),
        pytest.param('dnf', 'openssh-clients', id='dnf'),
        pytest.param('pacman', 'openssh', id='pacman'),
    ],
)
def test_openssh_uses_the_backend_package_name(
    monkeypatch: MonkeyPatch, backend: str, package: str
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.detect_backend', lambda: backend
    )

    plan = gh_install.plan_tool_install(
        ('ssh', 'ssh-keygen'),
        include_gh=False,
        manager=cast(CommandManager, _ProbeManager()),
    )

    assert any(package in step.cmd for step in plan.steps)
    assert not any('gh' in step.cmd for step in plan.steps)


def test_unrecognized_backend_names_the_tools_and_the_docs(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.credentials.gh_install.detect_backend', lambda: ''
    )

    with pytest.raises(AIVMError, match='install_linux.md') as excinfo:
        gh_install.plan_tool_install(
            ('gh', 'ssh'),
            include_gh=True,
            manager=cast(CommandManager, _ProbeManager()),
        )

    assert 'gh, ssh' in str(excinfo.value)
