"""Focused tests for host credential setup and root permission warnings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
from pytest import MonkeyPatch

from aivm.cli.vm_creds import VMCredsSetupCLI
from aivm.commands import CommandManager, CommandResult
from aivm.credentials.keys import host_credential_dir
from aivm.credentials.models import GitRepository
from aivm.credentials.setup import (
    CredentialSetupReport,
    authenticate_github,
    inspect_credential_setup,
    require_supported_gh,
)
from aivm.errors import AIVMError


class _RecordingManager:
    def __init__(
        self,
        result: CommandResult | None = None,
        *,
        gh_version: str = '2.62.0',
    ) -> None:
        self.result = result or CommandResult(0, '', '')
        self.gh_version = gh_version
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(cmd)
        if list(cmd[:2]) == ['gh', '--version']:
            if not self.gh_version:
                return CommandResult(1, '', 'gh: not found')
            return CommandResult(
                0, f'gh version {self.gh_version} (2024-11-05)\n', ''
            )
        return self.result


def test_inspect_credential_setup_checks_repository_admin(
    monkeypatch: MonkeyPatch,
) -> None:
    repo = GitRepository('github.com', 'Kitware', 'kwimage')
    manager = _RecordingManager(CommandResult(0, 'ok', ''))
    checked: list[GitRepository] = []
    monkeypatch.setattr(
        'aivm.credentials.setup.shutil.which', lambda name: f'/usr/bin/{name}'
    )
    monkeypatch.setattr(
        'aivm.credentials.setup.github.list_deploy_keys',
        lambda repository, manager: checked.append(repository) or [],
    )

    report = inspect_credential_setup(
        hostname=repo.host,
        repository=repo,
        manager=cast(CommandManager, manager),
    )

    assert report.ready
    assert report.gh_version == (2, 62, 0)
    assert report.repository_ok is True
    assert checked == [repo]


@pytest.mark.parametrize(
    'version, expect_flag',
    [
        pytest.param((2, 48, 0), True, id='first-supported'),
        pytest.param((2, 62, 0), True, id='current'),
        # Ubuntu 22.04 ships 2.4.0. Passing --skip-ssh-key to it fails the
        # whole login with "unknown flag", taking setup down with it.
        pytest.param((2, 4, 0), False, id='ubuntu-22.04'),
        pytest.param((2, 45, 0), False, id='ubuntu-24.04'),
        pytest.param(None, False, id='unknown-version'),
    ],
)
def test_authenticate_github_only_skips_ssh_key_where_supported(
    version: tuple[int, int, int] | None, expect_flag: bool
) -> None:
    manager = _RecordingManager()

    authenticate_github(
        'github.com', manager=cast(CommandManager, manager), version=version
    )

    [call] = manager.calls
    assert call[:6] == [
        'gh',
        'auth',
        'login',
        '--hostname',
        'github.com',
        '--web',
    ]
    assert ('--skip-ssh-key' in call) is expect_flag


def test_too_old_gh_is_reported_instead_of_probed(
    monkeypatch: MonkeyPatch,
) -> None:
    """gh 2.4.0 predates `gh repo deploy-key`, so the host is not usable."""
    monkeypatch.setattr(
        'aivm.credentials.setup.shutil.which', lambda name: f'/usr/bin/{name}'
    )
    manager = _RecordingManager(gh_version='2.4.0')

    report = inspect_credential_setup(
        hostname='github.com',
        repository=None,
        manager=cast(CommandManager, manager),
    )

    assert not report.ready
    assert not report.gh_supported
    assert report.gh_version == (2, 4, 0)
    assert '2.5.0' in report.auth_detail
    assert 'install_linux.md' in report.auth_detail
    # Authentication is never probed: it cannot make this host usable.
    assert manager.calls == [['gh', '--version']]


def test_require_supported_gh_blocks_credential_work(
    monkeypatch: MonkeyPatch,
) -> None:
    manager = _RecordingManager(gh_version='2.4.0')

    with pytest.raises(AIVMError, match='cannot manage deploy keys'):
        require_supported_gh(manager=cast(CommandManager, manager))


def test_creds_setup_check_reports_missing_tools(
    monkeypatch: MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = CredentialSetupReport(
        hostname='github.com',
        tool_paths={
            'gh': None,
            'ssh': '/usr/bin/ssh',
            'ssh-keygen': '/usr/bin/ssh-keygen',
        },
        auth_ok=False,
        auth_detail='GitHub CLI is not installed.',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_creds.inspect_credential_setup', lambda **kwargs: report
    )

    rc = VMCredsSetupCLI.main(argv=False, check=True)

    out = capsys.readouterr().out
    assert rc == 2
    assert 'gh                 missing' in out
    assert 'aivm vm creds setup' in out


def test_creds_setup_rejects_invalid_hostname() -> None:
    with pytest.raises(AIVMError, match='Unsupported repository host syntax'):
        VMCredsSetupCLI.main(
            argv=False,
            hostname='github.com; touch /tmp/nope',
            check=True,
        )


def test_writable_app_data_root_warns_but_does_not_block(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / 'aivm'
    root.mkdir(mode=0o775)
    root.chmod(0o775)
    monkeypatch.setattr('aivm.credentials.keys.app_data_dir', lambda: root)

    path = host_credential_dir('example-vm', 'git-123456789abc')

    assert path == root / 'example-vm' / 'credentials' / 'git-123456789abc'
    assert os.stat(root).st_mode & 0o777 == 0o775
