"""Tests for CommandManager approval and probe-cache behavior."""

from __future__ import annotations

import builtins
from typing import Any

from pytest import MonkeyPatch

from aivm.commands import CommandManager


class _Proc:
    def __init__(
        self, returncode: int = 0, stdout: str = '', stderr: str = ''
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_runtime(
    monkeypatch: MonkeyPatch,
    fake_run: Any,
    *,
    isatty: bool = True,
) -> list[str]:
    prompts: list[str] = []
    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    monkeypatch.setattr('aivm.commands.os.geteuid', lambda: 1000)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: isatty)
    monkeypatch.setattr(
        builtins, 'input', lambda prompt: prompts.append(prompt) or 'y'
    )
    monkeypatch.setattr(
        CommandManager, 'sudo_authentication_required', lambda self: False
    )
    return prompts


def test_sudo_command_added_after_plan_approval_requires_confirmation(
    monkeypatch: MonkeyPatch,
) -> None:
    """A sudo command appended to an approved step must not skip approval.

    Steps are approved based on the commands present at flush time; a later
    sudo escalation (e.g. a privileged read fallback) is appended after that
    approval and must be confirmed individually.
    """

    def fake_run(cmd: list[str], **kwargs: Any) -> _Proc:
        del kwargs
        if cmd[0] == 'sudo':
            return _Proc(0, 'privileged-ok', '')
        return _Proc(1, '', 'error: access denied')

    prompts = _patch_runtime(monkeypatch, fake_run)
    mgr = CommandManager(auto_approve_readonly_sudo=False)
    CommandManager.activate(mgr)
    with mgr.step('inspect with escalation'):
        first = mgr.submit(
            ['virsh', 'dumpxml', 'vm'],
            sudo=False,
            role='read',
            check=False,
            summary='unprivileged probe',
        ).result()
        assert first.code != 0
        second = mgr.submit(
            ['virsh', 'dumpxml', 'vm'],
            sudo=True,
            role='read',
            check=False,
            summary='privileged probe fallback',
        ).result()
        assert second.code == 0
    assert prompts, 'late-added sudo command must be confirmed'


def test_modify_sudo_command_added_after_plan_approval_prompts(
    monkeypatch: MonkeyPatch,
) -> None:
    """State-changing sudo commands appended post-approval must prompt."""

    def fake_run(cmd: list[str], **kwargs: Any) -> _Proc:
        del kwargs
        return _Proc(0, 'ok', '')

    prompts = _patch_runtime(monkeypatch, fake_run)
    mgr = CommandManager()
    CommandManager.activate(mgr)
    with mgr.step('inspect then mutate'):
        mgr.submit(
            ['virsh', 'domstate', 'vm'],
            sudo=True,
            role='read',
            check=False,
            summary='inspect state',
        ).result()
        mgr.submit(
            ['virsh', 'resume', 'vm'],
            sudo=True,
            role='modify',
            summary='resume VM',
        ).result()
    assert prompts, 'late-added state-changing sudo command must prompt'


def test_yes_sudo_manager_keeps_auto_approving_late_added_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    """--yes-sudo managers stay non-interactive for post-approval additions."""

    def fake_run(cmd: list[str], **kwargs: Any) -> _Proc:
        del kwargs
        return _Proc(0, 'ok', '')

    prompts = _patch_runtime(monkeypatch, fake_run, isatty=False)
    mgr = CommandManager(yes_sudo=True)
    CommandManager.activate(mgr)
    with mgr.step('inspect then mutate'):
        mgr.submit(
            ['virsh', 'domstate', 'vm'],
            sudo=True,
            role='read',
            check=False,
            summary='inspect state',
        ).result()
        mgr.submit(
            ['virsh', 'resume', 'vm'],
            sudo=True,
            role='modify',
            summary='resume VM',
        ).result()
    assert prompts == []


def test_mutation_generation_bumps_only_for_modify_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    """Probe caches key on mutation_generation; reads must not invalidate."""

    def fake_run(cmd: list[str], **kwargs: Any) -> _Proc:
        del kwargs
        return _Proc(0, 'ok', '')

    _patch_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)
    CommandManager.activate(mgr)
    start = mgr.mutation_generation
    mgr.run(['virsh', 'dominfo', 'vm'], role='read', check=False)
    assert mgr.mutation_generation == start
    mgr.run(['virsh', 'resume', 'vm'], role='modify')
    assert mgr.mutation_generation == start + 1
