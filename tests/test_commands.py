"""Tests for CommandManager approval and probe-cache behavior."""

from __future__ import annotations

from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandError, CommandManager, Elided
from aivm.errors import (
    AIVMError,
    ApprovalUnavailableError,
    CommandNotExecutedError,
    SudoRequiredError,
    UserDeclinedError,
)
from tests.helpers import FakeProc, capture_logs, patch_command_runtime


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


def test_a_write_is_confirmed_whatever_binary_runs_it(
    monkeypatch: MonkeyPatch,
) -> None:
    """The write is the guard, not the command family or the privilege.

    Gating on ``virsh`` guarded ``undefine --remove-all-storage`` only by the
    coincidence that it shares a binary with ``setvcpus``, while an
    unprivileged command doing the same damage by another route was never
    guarded at all.
    """

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    prompts = patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(privilege_mode='never')
    CommandManager.activate(mgr)

    # unprivileged reads stay promptless
    mgr.run(
        ['virsh', '-c', 'qemu:///system', 'dominfo', 'vm'],
        sudo=False,
        role='read',
        check=False,
    )
    assert prompts == []

    # an unprivileged hypervisor mutation is confirmed
    mgr.run(
        ['virsh', '-c', 'qemu:///system', 'destroy', 'vm'],
        sudo=False,
        role='modify',
        summary='Destroy VM vm',
    )
    assert len(prompts) == 1

    # so is an unprivileged write that is not virsh at all, which the old
    # command-family rule let through
    mgr.run(
        ['ssh', 'vm', 'rm -rf /home/agent/work'],
        sudo=False,
        role='modify',
        summary='Remove guest work tree',
    )
    assert len(prompts) == 2


def test_declared_tool_bookkeeping_is_exempt(monkeypatch: MonkeyPatch) -> None:
    """aivm's own regenerable state does not ask permission to exist.

    The exemption is declared per call site, so forgetting it costs a prompt
    rather than costing the user their consent.
    """

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(0, 'ok', '')

    prompts = patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(privilege_mode='never')
    CommandManager.activate(mgr)

    mgr.run(
        ['mkdir', '-p', '/var/lib/libvirt/aivm/vm/images'],
        sudo=False,
        role='modify',
        ownership='tool',
    )
    assert prompts == []

    # the same command without the declaration is a user write
    mgr.run(
        ['mkdir', '-p', '/home/joncrall/code/thing'],
        sudo=False,
        role='modify',
    )
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


def test_failed_command_is_not_re_run_by_a_later_flush(
    monkeypatch: MonkeyPatch,
) -> None:
    """A command that raised must never be attempted again.

    A caught CommandError left the command queued, so the next flush -- from
    an unrelated later command -- re-ran it and re-raised its failure there.
    That surfaced as a totally different operation reporting an error it never
    issued, which is close to untraceable from a log.
    """
    attempts: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        attempts.append(list(cmd))
        if cmd[0] == 'failing':
            return FakeProc(1, '', 'boom')
        return FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)

    try:
        mgr.run(['failing', 'thing'], role='read', check=True, capture=True)
    except CommandError:
        pass

    result = mgr.run(['unrelated', 'thing'], role='read', check=True, capture=True)

    assert result.code == 0
    assert attempts == [['failing', 'thing'], ['unrelated', 'thing']], (
        'the failed command was re-run by the later flush'
    )


def test_failed_command_in_a_plan_is_not_re_run_by_a_later_flush(
    monkeypatch: MonkeyPatch,
) -> None:
    """Same invariant inside a step, where a cursor tracked progress instead."""
    attempts: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        attempts.append(list(cmd))
        if cmd[0] == 'failing':
            return FakeProc(1, '', 'boom')
        return FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)

    with mgr.step('Do a thing', why='exercise the plan queue'):
        try:
            mgr.run(['failing', 'thing'], role='read', check=True, capture=True)
        except CommandError:
            pass
        mgr.run(['unrelated', 'thing'], role='read', check=True, capture=True)

    assert attempts == [['failing', 'thing'], ['unrelated', 'thing']]


def test_attempt_reports_a_handled_failure_instead_of_raising(
    monkeypatch: MonkeyPatch,
) -> None:
    """Declaring that a step may fail replaces try/except in callers."""

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        return FakeProc(1, '', 'nope')

    patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)

    with mgr.attempt('Register the thing') as attempt:
        mgr.run(['failing', 'thing'], role='read', check=True, capture=True)

    assert attempt.failed
    assert not attempt.ok
    assert 'nope' in attempt.reason


def test_attempt_reports_success(monkeypatch: MonkeyPatch) -> None:
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    mgr = CommandManager(yes=True)

    with mgr.attempt('Register the thing') as attempt:
        result = mgr.run(['fine', 'thing'], role='read', check=True, capture=True)

    assert attempt.ok
    assert attempt.reason == ''
    assert result.stdout == 'ok'


def test_attempt_does_not_swallow_unexpected_errors(
    monkeypatch: MonkeyPatch,
) -> None:
    """Only the declared failure is an outcome; everything else is a bug."""
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    mgr = CommandManager(yes=True)

    with pytest.raises(ZeroDivisionError):
        with mgr.attempt('Register the thing'):
            1 / 0


def test_attempt_leaves_no_command_for_a_later_flush_to_re_run(
    monkeypatch: MonkeyPatch,
) -> None:
    """The whole point: a handled failure must not resurface elsewhere."""
    attempts: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        attempts.append(list(cmd))
        return FakeProc(1, '', 'nope') if cmd[0] == 'failing' else FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    mgr = CommandManager(yes=True)

    with mgr.attempt('Register the thing') as attempt:
        mgr.run(['failing', 'thing'], role='read', check=True, capture=True)
    assert attempt.failed

    mgr.run(['unrelated', 'thing'], role='read', check=True, capture=True)

    assert attempts == [['failing', 'thing'], ['unrelated', 'thing']]


def _recording_runner(
    monkeypatch: MonkeyPatch,
) -> list[list[str]]:
    """Fake runner where any 'failing' command fails and others succeed."""
    executed: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        executed.append(list(cmd))
        if cmd[0] == 'failing':
            return FakeProc(1, '', 'boom')
        return FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    return executed


def test_rereading_a_failed_loose_handle_runs_nothing_and_reraises(
    monkeypatch: MonkeyPatch,
) -> None:
    """Reading a result must never be a way to *cause* work.

    A failed handle stayed pending, so asking for its result again flushed the
    queue and executed whatever unrelated command was waiting there -- a
    state-changing one, in the case that motivated this.
    """
    executed = _recording_runner(monkeypatch)
    mgr = CommandManager(yes=True)

    handle = mgr.submit(['failing', 'thing'], role='read', check=True, capture=True)
    with pytest.raises(CommandError) as first:
        handle.result()

    mgr.submit(['unrelated', 'MUTATION'], role='modify', check=True, capture=True)

    with pytest.raises(CommandError) as second:
        handle.result()

    assert second.value is first.value, 'the original failure must be re-raised'
    assert executed == [['failing', 'thing']], (
        're-reading a failed handle executed a queued mutation'
    )
    assert handle.done()


def test_rereading_a_failed_plan_handle_runs_nothing_and_reraises(
    monkeypatch: MonkeyPatch,
) -> None:
    """Same invariant inside a step, which tracked progress with a cursor."""
    executed = _recording_runner(monkeypatch)
    mgr = CommandManager(yes=True)

    with mgr.step('Do a thing', why='exercise the plan queue'):
        handle = mgr.submit(
            ['failing', 'thing'], role='read', check=True, capture=True
        )
        with pytest.raises(CommandError) as first:
            handle.result()
        mgr.submit(
            ['unrelated', 'MUTATION'], role='modify', check=True, capture=True
        )
        with pytest.raises(CommandError) as second:
            handle.result()
        assert second.value is first.value
        assert executed == [['failing', 'thing']]


def test_rereading_a_failed_handle_with_an_empty_queue_reraises(
    monkeypatch: MonkeyPatch,
) -> None:
    """With nothing else queued this reported an unknown handle id instead.

    The original CommandError was lost outright, so the caller learned neither
    what failed nor why.
    """
    _recording_runner(monkeypatch)
    mgr = CommandManager(yes=True)

    handle = mgr.submit(['failing', 'thing'], role='read', check=True, capture=True)
    with pytest.raises(CommandError) as first:
        handle.result()
    with pytest.raises(CommandError) as second:
        handle.result()

    assert second.value is first.value


def test_aborted_plan_leaves_every_handle_terminal(
    monkeypatch: MonkeyPatch,
) -> None:
    """A handle must not outlive its plan still pending.

    Otherwise awaiting one reopens a step the manager already abandoned.
    """
    executed = _recording_runner(monkeypatch)
    mgr = CommandManager(yes=True)

    pending: list[Any] = []
    with pytest.raises(RuntimeError, match='caller gave up'):
        with mgr.step('Abandoned step'):
            pending.append(
                mgr.submit(['never', 'ran'], role='modify', summary='first')
            )
            pending.append(
                mgr.submit(['also', 'never'], role='modify', summary='second')
            )
            raise RuntimeError('caller gave up')

    assert executed == []
    for handle in pending:
        assert handle.done(), 'an unexecuted handle stayed pending'
        with pytest.raises(CommandNotExecutedError, match='aborted'):
            handle.result()
    assert executed == [], 'reading an abandoned handle executed something'


def test_every_terminal_handle_replays_instead_of_executing(
    monkeypatch: MonkeyPatch,
) -> None:
    """Repeated reads of any terminal handle must execute nothing."""
    executed = _recording_runner(monkeypatch)
    mgr = CommandManager(yes=True)

    good = mgr.submit(['fine', 'thing'], role='read', check=True, capture=True)
    assert good.result().stdout == 'ok'
    bad = mgr.submit(['failing', 'thing'], role='read', check=True, capture=True)
    with pytest.raises(CommandError):
        bad.result()

    aborted: list[Any] = []
    with pytest.raises(RuntimeError):
        with mgr.step('Abandoned'):
            aborted.append(mgr.submit(['never', 'ran'], role='modify'))
            raise RuntimeError('stop')

    baseline = list(executed)
    for _ in range(3):
        assert good.result().stdout == 'ok'
        with pytest.raises(CommandError):
            bad.result()
        with pytest.raises(CommandNotExecutedError):
            aborted[0].result()
    assert executed == baseline


def test_attempt_cannot_swallow_a_control_error(
    monkeypatch: MonkeyPatch,
) -> None:
    """Defense in depth: a broad `catch` must not absorb a refusal.

    `catch=AIVMError` is broad enough to cover an approval refusal by
    accident, and did -- turning "the user said no" into "the provider was
    unhelpful" and continuing with later mutations.
    """
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    mgr = CommandManager(yes=True)

    for control in (
        UserDeclinedError('Aborted by user.'),
        ApprovalUnavailableError('stdin is not interactive'),
        CommandNotExecutedError('never ran'),
        SudoRequiredError('sudo is forbidden'),
    ):
        with pytest.raises(type(control)):
            with mgr.attempt('Best effort', catch=AIVMError):
                raise control

    # An ordinary domain failure is still an outcome, not an error.
    with mgr.attempt('Best effort', catch=AIVMError) as attempt:
        raise AIVMError('the provider was unhelpful')
    assert attempt.failed


def test_declining_a_prompt_raises_a_control_error(
    monkeypatch: MonkeyPatch,
) -> None:
    """The refusal must be typed, or nothing downstream can recognize it."""
    prompts = patch_command_runtime(
        monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''), answer='n'
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    with pytest.raises(UserDeclinedError):
        mgr.run(['virsh', 'resume', 'vm'], sudo=True, role='modify')
    assert prompts


def test_noninteractive_approval_is_unavailable_not_declined(
    monkeypatch: MonkeyPatch,
) -> None:
    """Silence is not consent: absence of an answer stops the operation."""
    patch_command_runtime(
        monkeypatch,
        lambda cmd, **kw: FakeProc(0, 'ok', ''),
        isatty=False,
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    with pytest.raises(ApprovalUnavailableError):
        mgr.run(['virsh', 'resume', 'vm'], sudo=True, role='modify')


def test_marked_payload_logs_its_label_and_still_executes_in_full(
    monkeypatch: MonkeyPatch,
) -> None:
    """A declared payload is named in the log but sent whole to the process.

    The label is what makes the line readable; the value is what makes the
    command work. Eliding one must never elide the other.
    """
    executed: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        executed.append(list(cmd))
        return FakeProc(0, 'ok', '')

    patch_command_runtime(monkeypatch, fake_run)
    messages = capture_logs(
        monkeypatch, 'aivm.commands.log', levels=('info', 'warning', 'debug')
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    script = 'set -eu\n' + ('payload' * 200)
    mgr.run(
        ['ssh', 'agent@10.0.0.2', Elided(script, 'guest bootstrap script')],
        sudo=False,
        role='read',
    )

    run_lines = [m for m in messages if m.startswith('RUN')]
    assert run_lines == [
        'RUN: ssh agent@10.0.0.2 <<OMITTED guest bootstrap script>>'
    ]
    assert executed == [['ssh', 'agent@10.0.0.2', script]]
    # the shortening is announced rather than left for the reader to notice
    announcement = next(m for m in messages if 'OMITTED FROM' in m)
    assert 'guest bootstrap script' in announcement
    assert f'{len(script)} characters' in announcement


def test_unmarked_long_payload_admits_it_is_unmarked(
    monkeypatch: MonkeyPatch,
) -> None:
    """Length may say a value is unprintable; it may not say what the value is.

    Guessing from shape ("<remote command omitted>") states as fact something
    the renderer cannot know. Saying the argument is merely unmarked keeps the
    log honest and names the work that would fix it.
    """
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    messages = capture_logs(
        monkeypatch, 'aivm.commands.log', levels=('info', 'warning', 'debug')
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    script = 'payload' * 200
    mgr.run(['ssh', 'agent@10.0.0.2', script], sudo=False, role='read')

    run_line = next(m for m in messages if m.startswith('RUN'))
    assert run_line == 'RUN: ssh agent@10.0.0.2 <<OMITTED unmarked argument>>'
    assert 'payloadpayload' not in run_line
    # never asserts what the payload is, the way the old shape rules did
    assert 'remote command' not in run_line
    assert 'shell script' not in run_line
    # an unmarked payload is a gap in the code, so it is a warning naming the fix
    announcement = next(m for m in messages if 'OMITTED FROM' in m)
    assert 'UNMARKED' in announcement
    assert 'Elided(value, label)' in announcement


def test_ordinary_command_is_logged_verbatim(
    monkeypatch: MonkeyPatch,
) -> None:
    """Anything short enough to read prints in full, so it stays copy-pasteable.

    Teaching the equivalent libvirt invocation is the point of the log; a
    truncated command teaches nothing.
    """
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    messages = capture_logs(
        monkeypatch, 'aivm.commands.log', levels=('info', 'warning', 'debug')
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    cmd = [
        'virsh',
        '-c',
        'qemu:///system',
        'setvcpus',
        'aivm-2404',
        '30',
        '--maximum',
        '--config',
    ]
    mgr.run(cmd, sudo=False, role='read')

    assert 'RUN: ' + ' '.join(cmd) in messages


def test_only_an_unprivileged_read_is_held_back(
    monkeypatch: MonkeyPatch,
) -> None:
    """Changing state or spending privilege is announced; a plain read is not.

    A sudo read stays visible because the user may have been asked for a
    password to run it, and a prompt whose command never appears is worse
    than noise. Only a read that neither changes anything nor crosses a
    privilege boundary is deferred to -vv.
    """
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    info = capture_logs(monkeypatch, 'aivm.commands.log')
    mgr = CommandManager()
    CommandManager.activate(mgr)

    mgr.run(['virsh', 'dominfo', 'vm'], sudo=False, role='read')
    mgr.run(['qemu-img', 'info', '/disk.qcow2'], sudo=True, role='read')
    mgr.run(['virsh', 'setvcpus', 'vm', '8'], sudo=False, role='modify')

    shown = [m for m in info if m.startswith('RUN')]
    assert shown == [
        'RUN: sudo qemu-img info /disk.qcow2',
        'RUN: virsh setvcpus vm 8',
    ]


def test_reads_are_recoverable_at_debug(monkeypatch: MonkeyPatch) -> None:
    """Quiet must mean deferred, not discarded: -vv still shows every read."""
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    verbose = capture_logs(
        monkeypatch, 'aivm.commands.log', levels=('info', 'warning', 'debug')
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    mgr.run(['virsh', 'dominfo', 'vm'], sudo=False, role='read')

    assert 'RUN: virsh dominfo vm' in verbose


def test_an_unclassified_command_stays_loud(monkeypatch: MonkeyPatch) -> None:
    """Silence is opt-in. A command that declares nothing is not hidden.

    Role defaults to 'modify', so forgetting to classify a probe costs noise
    rather than costing the reader the record of what ran.
    """
    patch_command_runtime(monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''))
    info = capture_logs(monkeypatch, 'aivm.commands.log')
    mgr = CommandManager(yes=True)
    CommandManager.activate(mgr)

    mgr.run(['some-tool', '--do-a-thing'], sudo=False)

    assert 'RUN: some-tool --do-a-thing' in info


def test_a_read_that_escalates_nothing_stays_quiet_as_root(
    monkeypatch: MonkeyPatch,
) -> None:
    """sudo=True is an offer, not an event: as root nothing is escalated.

    Callers pass sudo=True speculatively under privilege_mode='as-needed'.
    Visibility tracks the privilege actually spent, so the same read that is
    announced for an unprivileged user is plumbing when already root.
    """
    patch_command_runtime(
        monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', ''), euid=0
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)
    probe = ['qemu-img', 'info', '/disk.qcow2']

    # capture_logs replaces the module logger, so each level is a separate run
    info = capture_logs(monkeypatch, 'aivm.commands.log', levels=('info',))
    mgr.run(probe, sudo=True, role='read')
    assert [m for m in info if m.startswith('RUN')] == []

    verbose = capture_logs(
        monkeypatch, 'aivm.commands.log', levels=('debug',)
    )
    mgr.run(probe, sudo=True, role='read')
    assert 'RUN: qemu-img info /disk.qcow2' in verbose


def test_handing_the_terminal_to_the_user_is_not_a_write(
    monkeypatch: MonkeyPatch,
) -> None:
    """An editor or shell needs no consent: the user is the one typing.

    Prompting here asks someone to confirm the command they just invoked.
    """
    prompts = patch_command_runtime(
        monkeypatch, lambda cmd, **kw: FakeProc(0, 'ok', '')
    )
    mgr = CommandManager()
    CommandManager.activate(mgr)

    mgr.run(
        ['vim', '/home/joncrall/.config/aivm/config.toml'],
        sudo=False,
        role='modify',
        user_driven=True,
        capture=False,
    )
    assert prompts == []

    # the exemption is declared, never inferred from capture=False
    mgr.run(
        ['vim', '/home/joncrall/.config/aivm/config.toml'],
        sudo=False,
        role='modify',
        capture=False,
    )
    assert len(prompts) == 1
