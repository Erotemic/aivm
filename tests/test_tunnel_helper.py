"""Tests for the inspectable guest-side VS Code tunnel helper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aivm.rc.guest import tunnel_helper


def test_check_reports_missing_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        tunnel_helper.shutil,
        'which',
        lambda name: '/usr/bin/tmux' if name == 'tmux' else None,
    )
    assert tunnel_helper.main(['check']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {'missing': ['code']}


def test_start_existing_session_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(tunnel_helper, 'missing_commands', lambda: ())
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')

    monkeypatch.setattr(tunnel_helper, '_run', fake_run)
    assert (
        tunnel_helper.main(
            [
                'start',
                '--guest-path',
                str(tmp_path),
                '--name',
                'aivm-builder',
            ]
        )
        == 0
    )
    assert calls == [['tmux', 'has-session', '-t', 'aivm-tunnel']]


def test_start_new_session_uses_tmux_working_directory_and_safe_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    work = tmp_path / 'project with space; safe'
    work.mkdir()
    monkeypatch.setattr(tunnel_helper, 'missing_commands', lambda: ())
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        call = list(argv)
        calls.append(call)
        if call[1] == 'has-session':
            return subprocess.CompletedProcess(call, 1, stdout='', stderr='')
        return subprocess.CompletedProcess(call, 0, stdout='', stderr='')

    monkeypatch.setattr(tunnel_helper, '_run', fake_run)
    assert (
        tunnel_helper.main(
            [
                'start',
                '--guest-path',
                str(work),
                '--name',
                'name with space; safe',
                '--session',
                'aivm-tunnel',
            ]
        )
        == 0
    )
    assert calls[0] == ['tmux', 'has-session', '-t', 'aivm-tunnel']
    start = calls[1]
    assert start[:8] == [
        'tmux',
        'new-session',
        '-d',
        '-s',
        'aivm-tunnel',
        '-c',
        str(work),
        "code tunnel --name 'name with space; safe' --accept-server-license-terms",
    ]


def test_start_reports_missing_prerequisites_without_shell_expansion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(tunnel_helper, 'missing_commands', lambda: ('code',))
    assert (
        tunnel_helper.main(
            [
                'start',
                '--guest-path',
                str(tmp_path),
                '--name',
                'aivm-builder',
            ]
        )
        == 2
    )
    err = capsys.readouterr().err
    assert 'missing VS Code tunnel prerequisite(s): code' in err
    assert '`' not in err
