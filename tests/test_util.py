"""Tests for command orchestration helpers."""

from __future__ import annotations

import builtins
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import (
    CommandManager,
    IntentScope,
    PlanScope,
    shell_join,
)
from aivm.util import CmdError
from tests.helpers import FakeLog, FakeProc, activate_manager


def test_shell_join_quotes() -> None:
    cmd = ['echo', 'a b', "c'd"]
    s = shell_join(cmd)
    assert 'a b' in s
    assert 'echo' in s


def test_manager_run_success_and_failure(monkeypatch: MonkeyPatch) -> None:
    mgr = activate_manager(monkeypatch, yes_sudo=False)
    ok = mgr.run(['bash', '-c', 'printf ok'], check=True, capture=True)
    assert ok.code == 0
    assert ok.stdout == 'ok'
    bad = mgr.run(['bash', '-c', 'exit 7'], check=False, capture=True)
    assert bad.code == 7
    with pytest.raises(CmdError):
        mgr.run(['bash', '-c', 'exit 9'], check=True, capture=True)


def test_nested_intent_breadcrumb_rendering(monkeypatch: MonkeyPatch) -> None:
    mgr = activate_manager(monkeypatch, yes_sudo=False)
    with IntentScope(mgr, 'Create VM'):
        assert mgr.render_breadcrumb() == 'Create VM'
        with IntentScope(mgr, 'Ensure network'):
            assert mgr.render_breadcrumb() == 'Create VM > Ensure network'
        assert mgr.render_breadcrumb() == 'Create VM'
    assert mgr.render_breadcrumb() == ''


def test_plan_prompts_once_for_multiple_sudo_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    calls = []
    prompts = []

    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'y',
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append((cmd, kwargs)) or FakeProc(),
    )

    mgr = CommandManager.current()
    with IntentScope(mgr, 'Create VM'):
        with PlanScope(
            mgr,
            'Prepare network',
            why='Need a managed network before VM startup.',
        ):
            mgr.submit(
                ['virsh', 'net-define', '/tmp/net.xml'],
                sudo=True,
                role='modify',
                summary='Define libvirt network',
            )
            mgr.submit(
                ['virsh', 'net-start', 'aivm-net'],
                sudo=True,
                role='modify',
                summary='Start libvirt network',
            )

    assert len(prompts) == 1
    # Approval no longer runs a side-effect `sudo -n true` probe; the plan's
    # own commands are the only sudo invocations.
    assert calls[0][0][:2] == ['sudo', 'virsh']
    assert calls[1][0][:2] == ['sudo', 'virsh']
    assert len(calls) == 2


def test_command_handle_result_flushes_through_handle(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=True, isatty=True)
    calls = []

    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append(cmd) or FakeProc(0, 'ok', ''),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Two commands'):
        first = mgr.submit(
            ['echo', 'one'], sudo=True, role='modify', summary='first'
        )
        second = mgr.submit(
            ['echo', 'two'], sudo=True, role='modify', summary='second'
        )
        assert calls == []
        assert first.stdout == 'ok'
        assert calls == [['sudo', 'echo', 'one']]
        assert second.done() is False
    assert calls == [['sudo', 'echo', 'one'], ['sudo', 'echo', 'two']]
    assert second.done() is True


def test_plan_yes_approves_current_block_only(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    prompts = []

    answers = iter(['y', 'y'])
    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or next(answers),
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Step one'):
        mgr.submit(['true'], sudo=True, role='modify', summary='step one')
    with PlanScope(mgr, 'Step two'):
        mgr.submit(['true'], sudo=True, role='modify', summary='step two')

    assert prompts == [
        'Approve this step? [y]es/[a]ll/[s]how/[N]o: ',
        'Approve this step? [y]es/[a]ll/[s]how/[N]o: ',
    ]


def test_plan_all_approves_current_and_future_blocks(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    prompts = []

    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'a',
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Step one'):
        mgr.submit(['true'], sudo=True, role='modify', summary='step one')
    with PlanScope(mgr, 'Step two'):
        mgr.submit(['true'], sudo=True, role='modify', summary='step two')

    assert prompts == ['Approve this step? [y]es/[a]ll/[s]how/[N]o: ']


def test_plan_show_full_commands_then_reprompts(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False, isatty=True)
    prompts = []
    messages: list[str] = []

    answers = iter(['s', 'y'])
    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or next(answers),
    )
    monkeypatch.setattr(
        'aivm.commands.log.opt',
        lambda **kwargs: FakeLog(messages, ('info', 'debug')),
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Write cloud-init'):
        mgr.submit(
            ['bash', '-c', "cat > /tmp/user-data <<'EOF'\nhello\nEOF"],
            sudo=True,
            role='modify',
            summary='Write cloud-init user-data',
        )

    assert prompts == [
        'Approve this step? [y]es/[a]ll/[s]how/[N]o: ',
        'Approve this step? [y]es/[a]ll/[s]how/[N]o: ',
    ]
    joined = '\n'.join(messages)
    assert 'Full commands for step: Write cloud-init' in joined
    assert "sudo bash -c 'cat > /tmp/user-data <<'\"'\"'EOF'" in joined


def test_manager_run_uses_submit_execution_path(
    monkeypatch: MonkeyPatch,
) -> None:
    mgr = activate_manager(monkeypatch, yes_sudo=True, isatty=True)
    calls = []

    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append(cmd) or FakeProc(),
    )

    mgr.run(['virsh', 'dominfo', 'vm'], sudo=True, check=True, capture=True)
    assert calls == [
        ['sudo', '-n', 'true'],
        ['sudo', 'virsh', 'dominfo', 'vm'],
    ]


def test_confirm_sudo_scope_autoauthenticates_read_auth_with_autoapprove(
    monkeypatch: MonkeyPatch,
) -> None:
    mgr = activate_manager(
        monkeypatch,
        yes_sudo=False,
        isatty=True,
        auto_approve_readonly_sudo=True,
    )
    prompts = []
    messages: list[str] = []
    auth_cmds = []

    def fake_run(cmd, **kwargs: Any):  # type: ignore[no-untyped-def]
        auth_cmds.append(cmd)
        if cmd == ['sudo', '-n', 'true']:
            return FakeProc(returncode=1, stderr='sudo: a password is required')
        if cmd == ['sudo', '-v']:
            return FakeProc(returncode=0)
        raise AssertionError(cmd)

    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'y',
    )
    monkeypatch.setattr(
        'aivm.commands.log.opt',
        lambda **kwargs: FakeLog(messages, ('info', 'debug', 'trace')),
    )
    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)

    mgr.confirm_sudo_scope(
        purpose='Read nftables firewall status.',
        role='read',
        yes=False,
    )

    assert prompts == []
    assert auth_cmds == [['sudo', '-n', 'true'], ['sudo', '-v']]
    joined = '\n'.join(messages)
    assert 'Read nftables firewall status.' in joined
    assert 'Sudo authentication appears to be required' in joined
    assert (
        'Future read-only sudo commands are configured to auto-approve'
        in joined
    )


def test_confirm_sudo_scope_logs_preview_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    mgr = activate_manager(
        monkeypatch,
        yes_sudo=False,
        isatty=True,
        auto_approve_readonly_sudo=True,
    )
    messages: list[str] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        if cmd == ['sudo', '-n', 'true']:
            return FakeProc(returncode=1, stderr='sudo: a password is required')
        if cmd == ['sudo', '-v']:
            return FakeProc(returncode=0)
        raise AssertionError(cmd)

    monkeypatch.setattr(builtins, 'input', lambda prompt: 'y')
    monkeypatch.setattr(
        'aivm.commands.log.opt',
        lambda **kwargs: FakeLog(messages, ('info', 'debug', 'trace')),
    )
    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)

    mgr.confirm_sudo_scope(
        purpose='Inspect VM status.',
        role='read',
        yes=False,
        preview_cmds=[
            ['virsh', '-c', 'qemu:///system', 'dominfo', 'demo-vm'],
            ['nft', 'list', 'table', 'inet', 'aivm_fw'],
        ],
    )

    joined = '\n'.join(messages)
    assert 'Planned sudo commands:' in joined
    assert 'sudo virsh -c qemu:///system dominfo demo-vm' in joined
    assert 'sudo nft list table inet aivm_fw' in joined


def test_plan_preview_includes_summary_and_command(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=True, isatty=True)
    messages: list[str] = []

    monkeypatch.setattr(
        'aivm.commands.log.opt',
        lambda **kwargs: FakeLog(messages, ('info', 'debug')),
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Enable service'):
        mgr.submit(
            ['systemctl', 'enable', '--now', 'libvirtd'],
            sudo=True,
            role='modify',
            summary='Enable and start libvirtd service',
        )

    joined = '\n'.join(messages)
    assert '  1. Enable and start libvirtd service' in joined
    assert 'command: sudo systemctl enable --now libvirtd' in joined


def test_run_logs_use_stacklevel_to_attribute_caller(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=True, isatty=True)
    depths_seen: list[int] = []

    def _tracking_opt(**kwargs: Any) -> FakeLog:
        depths_seen.append(kwargs.get('depth', 0))
        return FakeLog([], ())

    monkeypatch.setattr('aivm.commands.log.opt', _tracking_opt)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with PlanScope(mgr, 'Enable service'):
        mgr.submit(
            ['systemctl', 'enable', '--now', 'libvirtd'],
            sudo=True,
            role='modify',
            summary='Enable and start libvirtd service',
        )

    # stacklevel threading should produce depth values > 0, meaning log
    # lines are attributed above the CommandManager internals
    assert len(depths_seen) > 0
    assert all(d > 0 for d in depths_seen)


def test_read_only_command_stays_read_inside_modify_intent(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False, isatty=False)
    calls = []

    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append(cmd) or FakeProc(),
    )

    mgr = CommandManager.current()
    with IntentScope(mgr, 'Create VM', role='modify'):
        with PlanScope(mgr, 'Inspect libvirt state'):
            mgr.submit(
                ['virsh', 'dominfo', 'vm'],
                sudo=True,
                role='read',
                check=False,
                summary='Inspect domain state',
            )

    assert calls == [
        ['sudo', '-n', 'true'],
        ['sudo', '-n', 'virsh', 'dominfo', 'vm'],
    ]


def test_plan_preview_labels_read_only_commands(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=True, isatty=True)
    messages: list[str] = []

    monkeypatch.setattr(
        'aivm.commands.log.opt',
        lambda **kwargs: FakeLog(messages, ('info', 'debug')),
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(),
    )

    mgr = CommandManager.current()
    with IntentScope(mgr, 'Inspect host', role='read'):
        with PlanScope(mgr, 'Read mount metadata'):
            mgr.submit(
                ['findmnt', '-n', '-o', 'SOURCE', '--target', '/tmp/demo'],
                sudo=True,
                role='read',
                check=False,
                summary='Inspect mount source',
            )

    joined = '\n'.join(messages)
    assert '  1. Inspect mount source' in joined
    assert (
        'command (read-only): sudo findmnt -n -o SOURCE --target /tmp/demo'
        in joined
    )


def test_noninteractive_sudo_plan_requires_yes(
    monkeypatch: MonkeyPatch,
) -> None:
    activate_manager(monkeypatch, yes_sudo=False)
    mgr = CommandManager.current()

    with pytest.raises(RuntimeError, match='Re-run with --yes or --yes-sudo'):
        with IntentScope(mgr, 'Prepare host', role='modify'):
            with PlanScope(mgr, 'Install packages'):
                mgr.submit(
                    ['apt-get', 'update'],
                    sudo=True,
                    role='modify',
                    summary='Refresh apt metadata',
                )


def test_confirm_file_update_requires_yes_noninteractive(
    monkeypatch: MonkeyPatch,
) -> None:
    mgr = activate_manager(monkeypatch, yes_sudo=False)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: False)
    with pytest.raises(RuntimeError, match='Re-run with --yes'):
        mgr.confirm_file_update(
            yes=False,
            path='/tmp/ssh-config',
            purpose='Update SSH entry',
        )


def test_confirm_file_update_aborts_on_negative_response(
    monkeypatch: MonkeyPatch,
) -> None:
    mgr = activate_manager(monkeypatch, yes_sudo=False)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr(builtins, 'input', lambda _: 'n')
    with pytest.raises(RuntimeError, match='Aborted by user'):
        mgr.confirm_file_update(
            yes=False,
            path='/tmp/ssh-config',
            purpose='Update SSH entry',
        )
