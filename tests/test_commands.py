"""Tests for CommandManager approval and probe-cache behavior."""

from __future__ import annotations

from typing import Any

from pytest import MonkeyPatch

from aivm.commands import CommandManager
from tests.helpers import FakeProc, patch_command_runtime


def test_sudo_command_added_after_plan_approval_requires_confirmation(
    monkeypatch: MonkeyPatch,
) -> None:
    """A sudo command appended to an approved step must not skip approval.

    Steps are approved based on the commands present at flush time; a later
    sudo escalation (e.g. a privileged read fallback) is appended after that
    approval and must be confirmed individually.
    """

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        if cmd[0] == 'sudo':
            return FakeProc(0, 'privileged-ok', '')
        return FakeProc(1, '', 'error: access denied')

    prompts = patch_command_runtime(monkeypatch, fake_run)
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

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    prompts = patch_command_runtime(monkeypatch, fake_run)
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

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    prompts = patch_command_runtime(monkeypatch, fake_run, isatty=False)
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

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)
    CommandManager.activate(mgr)
    start = mgr.mutation_generation
    mgr.run(['virsh', 'dominfo', 'vm'], role='read', check=False)
    assert mgr.mutation_generation == start
    mgr.run(['virsh', 'resume', 'vm'], role='modify')
    assert mgr.mutation_generation == start + 1


def test_unprivileged_libvirt_mutation_keeps_approval_contract(
    monkeypatch: MonkeyPatch,
) -> None:
    """State-changing virsh commands prompt even when sudo is not needed.

    With libvirt group membership, destructive hypervisor operations run
    without sudo in as-needed/never modes; they must not silently lose the
    confirmation prompt they had in the sudo era.
    """

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    prompts = patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(privilege_mode='never')
    CommandManager.activate(mgr)
    # Unprivileged reads stay promptless.
    mgr.run(
        ['virsh', '-c', 'qemu:///system', 'dominfo', 'vm'],
        sudo=False,
        role='read',
        check=False,
    )
    assert prompts == []
    # Unprivileged hypervisor mutations prompt.
    mgr.run(
        ['virsh', '-c', 'qemu:///system', 'destroy', 'vm'],
        sudo=False,
        role='modify',
        summary='Destroy VM vm',
    )
    assert prompts == ['Continue? [y]es/[a]ll/[N]o: ']
    # Non-libvirt unprivileged mutations (guest ssh, file ops) stay
    # promptless as before.
    mgr.run(['mkdir', '-p', '/tmp/x'], sudo=False, role='modify', check=False)
    assert len(prompts) == 1


def test_never_privilege_plan_approval_never_touches_sudo(
    monkeypatch: MonkeyPatch,
) -> None:
    """A sudo command entering a plan under privilege_mode=never is rejected before
    any approval side effect (`sudo -n true`, `sudo -v`, prompts) runs."""
    from aivm.errors import SudoRequiredError

    sudo_calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        if cmd and cmd[0] == 'sudo':
            sudo_calls.append(list(cmd))
        return FakeProc(1, '', 'should not run')

    # Do not bypass sudo_authentication_required here: the point is that
    # it must never be consulted with a live sudo probe.
    prompts = patch_command_runtime(
        monkeypatch, fake_run, bypass_sudo_auth=False
    )
    mgr = CommandManager(privilege_mode='never')
    CommandManager.activate(mgr)
    import pytest as _pytest

    with _pytest.raises(SudoRequiredError):
        with mgr.step('inspect'):
            mgr.submit(
                ['nft', 'list', 'ruleset'],
                sudo=True,
                role='read',
                check=False,
                summary='read rules',
            ).result()
    assert sudo_calls == []
    assert prompts == []


def test_dash_dash_sudo_does_not_abbreviate_to_never_sudo() -> None:
    """`--sudo` on commands without a sudo flag must not silently parse as
    the never-sudo flag (argparse prefix abbreviation)."""
    import pytest as _pytest

    from aivm.cli.main import ListCLI

    with _pytest.raises(SystemExit):
        ListCLI.cli(argv=['--sudo'])


def test_real_sudo_is_forbidden_in_unit_tests() -> None:
    """The conftest guard fails any unit test reaching real ``sudo``.

    A test that forgets to fake ``aivm.commands.subprocess.run`` and
    escalates would otherwise run real root commands on hosts with
    passwordless sudo and die on a password prompt everywhere else; the
    guard makes the outcome deterministic. This pins the guard itself.
    """
    import subprocess

    import pytest

    with pytest.raises(AssertionError, match='real sudo command'):
        subprocess.run(['sudo', '-n', 'true'])
