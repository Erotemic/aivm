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
)
from aivm.errors import AIVMError


class _RecordingManager:
    def __init__(self, result: CommandResult | None = None) -> None:
        self.result = result or CommandResult(0, '', '')
        self.calls: list[list[str]] = []

    def run(self, cmd: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(cmd)
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
    assert report.repository_ok is True
    assert checked == [repo]


def test_authenticate_github_skips_user_ssh_key_upload() -> None:
    manager = _RecordingManager()

    authenticate_github('github.com', manager=cast(CommandManager, manager))

    assert manager.calls == [
        [
            'gh',
            'auth',
            'login',
            '--hostname',
            'github.com',
            '--web',
            '--skip-ssh-key',
        ]
    ]


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
