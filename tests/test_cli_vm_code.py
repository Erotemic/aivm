"""Tests for ``aivm code`` SSH-aware fallback logic.

The pure detection rule lives in ``_vscode_can_open_locally``; that's
what we exercise here. The actual launch path (which would invoke
``code --remote``) is exercised manually on a workstation and is not
unit-testable without significant subprocess stubbing.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aivm.cli.vm import (
    _print_remote_session_recipe,
    _vscode_can_open_locally,
)


def _scrub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'VSCODE_IPC_HOOK_CLI'):
        monkeypatch.delenv(var, raising=False)


def test_vscode_can_open_locally_when_local_and_code_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scrub_env(monkeypatch)
    monkeypatch.setattr('aivm.cli.vm.which', lambda name: '/usr/bin/code')
    can, reason = _vscode_can_open_locally()
    assert can is True
    assert reason is None


def test_vscode_skipped_when_ssh_connection_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user's primary case: ssh'd into a remote machine, no VS Code
    terminal wrapping the shell. Skip the launch and print recipe."""
    _scrub_env(monkeypatch)
    monkeypatch.setenv('SSH_CONNECTION', '10.0.0.1 22 10.0.0.2 49152')
    # `which('code')` could return either; SSH should take precedence.
    monkeypatch.setattr('aivm.cli.vm.which', lambda name: '/usr/bin/code')
    can, reason = _vscode_can_open_locally()
    assert can is False
    assert 'SSH_CONNECTION' in (reason or '')


def test_vscode_allowed_when_inside_vscode_terminal_over_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VSCODE_IPC_HOOK_CLI takes precedence over SSH_CONNECTION: the user
    is inside a VS Code integrated terminal (possibly remote-ssh'd), so
    `code --remote` will route to their workstation correctly."""
    _scrub_env(monkeypatch)
    monkeypatch.setenv('SSH_CONNECTION', '10.0.0.1 22 10.0.0.2 49152')
    monkeypatch.setenv('VSCODE_IPC_HOOK_CLI', '/run/user/1000/vscode-ipc.sock')
    monkeypatch.setattr('aivm.cli.vm.which', lambda name: '/usr/bin/code')
    can, reason = _vscode_can_open_locally()
    assert can is True
    assert reason is None


def test_vscode_skipped_when_code_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scrub_env(monkeypatch)
    monkeypatch.setattr('aivm.cli.vm.which', lambda name: None)
    can, reason = _vscode_can_open_locally()
    assert can is False
    assert '`code`' in (reason or '')


def test_print_remote_session_recipe_includes_connect_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = SimpleNamespace(vm=SimpleNamespace(name='aivm-2404', user='agent'))
    session = SimpleNamespace(
        ip='10.77.0.103',
        share_guest_dst='/home/joncrall/code/aivm',
        reg_path='/home/joncrall/.config/aivm/config.toml',
    )
    _print_remote_session_recipe(
        cfg,
        session,
        ssh_cfg='~/.ssh/config',
        ssh_cfg_updated=True,
        reason='running in an SSH session (SSH_CONNECTION set)',
    )
    out = capsys.readouterr().out
    # User's primary case must produce a paste-able remote-ssh recipe.
    assert (
        'code --remote ssh-remote+aivm-2404 /home/joncrall/code/aivm'
        in out
    )
    assert 'ssh aivm-2404' in out
    # And report the basics they need to verify the session is ready.
    assert '10.77.0.103' in out
    assert 'agent' in out
    # ssh_cfg_updated=True should be surfaced.
    assert 'SSH entry updated in ~/.ssh/config' in out
