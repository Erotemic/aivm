"""Centralized command orchestration, logging, and approval handling.

This module is the long-term home for subprocess execution in ``aivm``.
It organizes command output around user-meaningful plans and intent
contexts while still preserving raw command visibility for deeper
debugging.

The main entry point is :class:`CommandManager`, which coordinates
command submission, grouped plan execution, and privileged-operation
approval prompts.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import sys
from contextvars import ContextVar
from dataclasses import dataclass, field
from sys import version_info
from typing import Literal, Sequence

if version_info >= (3, 11):
    from types import TracebackType
else:
    from types import TracebackType

from loguru import logger

from .errors import (
    AIVMError,
    ApprovalUnavailableError,
    CommandControlError,
    CommandNotExecutedError,
    SudoRequiredError,
    UserDeclinedError,
)
from .modes import (
    DEFAULT_PRIVILEGE_MODE,
    PrivilegeMode,
    normalize_privilege_mode,
)

log = logger

# TODO: The current command role model is too coarse.
# don't execute on this, this needs more thought. Current ideas written here.
#
# Right now roles mostly collapse into "read" vs "modify", but in practice
# there are at least two separate axes we care about:
#
# 1. privilege boundary
#    - unprivileged
#    - privileged / sudo
#
# 2. effect boundary
#    - read / inspect
#    - system write
#    - user-file write
#
# These should not be conflated. Some operations are unprivileged but still
# deserve explicit approval because they modify user-owned files (for example
# SSH config or other dotfiles). Other operations are privileged but read-only
# and may be safe to auto-approve in some contexts.
#
# Future design:
# - replace the coarse role model with a richer action / approval model
# - allow step-level approval policy to be explicit instead of only inferred
# - distinguish "touches user files" from "touches system state"
# - distinguish "requires sudo" from "is a write"

CommandRole = Literal['read', 'modify']

#: Whose state a write touches. ``user`` is anything the user would recognize
#: as theirs, including the guest; ``tool`` is aivm's own regenerable
#: bookkeeping. See "Command visibility and approval" in docs/source/design.rst
#: for the bar ``tool`` has to clear.
CommandOwnership = Literal['user', 'tool']


def shell_join(cmd: Sequence[str]) -> str:
    """Render a command sequence as a shell-escaped string.

    This is intended for logging and preview output rather than direct
    execution. Each element is converted to ``str`` and quoted with
    :func:`shlex.quote`.

    Args:
        cmd: Command tokens to render.

    Returns:
        A shell-escaped command line string.
    """
    return ' '.join(shlex.quote(str(c)) for c in cmd)


#: Length past which an *unmarked* argument is not printed in full. Crossing it
#: says only that the argument is too long to show: never what it contains.
#: Payloads worth naming are marked :class:`Elided` at the call site instead.
PREVIEW_ARG_MAX_LEN = 400


class Elided(str):
    """A command argument shown in previews as a label instead of its value.

    Execution is unaffected. This is a ``str`` subclass, so :func:`shell_join`
    and :mod:`subprocess` see the real payload; only preview rendering
    consults the label::

        Elided(script, 'virtiofs guard installer: script, conf, service, timer')

    Hiding is declared here, at the call site that knows what the payload is.
    The renderer never infers from an argument's shape or position what it
    holds, because a guess that reads as fact ("<remote command omitted>")
    teaches the user something the log does not actually know.

    The preview also carries the head of a SHA-256 of the value, which pins
    which content ran far better than a character count: two scripts of equal
    length are otherwise indistinguishable in a log.

    Digesting is unconditional, and safe because of an invariant that holds
    elsewhere: **secrets are never passed on a command line.** A private
    deploy key reaches the guest through ``input_text`` on stdin, and provider
    tokens are read from the environment, so no secret appears in ``spec.cmd``
    to be digested. Anything that does appear there is already printed in full
    by the ``raw command`` line at ``--verbose 2``, so withholding 32 bits of
    its hash would protect nothing -- verbosity is not a security boundary.

    The consequence for new code is the invariant, not the digest: if a value
    must not be logged, it must not be an argument. Put it in ``input_text``.

    The digest identifies; it never verifies. Eight hex characters is 32 bits
    and trivially collidable, so nothing may use it to decide two payloads are
    the same and skip a real check.

    Attributes:
        label: Short description rendered in place of the value.
        digest_hex: Leading SHA-256 hex characters of the value.
    """

    label: str
    digest_hex: str

    #: Enough to tell runs apart in a log; nowhere near enough to trust.
    DIGEST_CHARS = 8

    def __new__(cls, value: str, label: str) -> 'Elided':
        obj = super().__new__(cls, value)
        obj.label = label
        full = hashlib.sha256(value.encode('utf-8')).hexdigest()
        obj.digest_hex = full[: cls.DIGEST_CHARS]
        return obj


@dataclass(frozen=True)
class CommandResult:
    """Immutable result of one executed command.

    Attributes:
        code: Process exit status.
        stdout: Captured standard output text.
        stderr: Captured standard error text.
    """

    code: int
    stdout: str
    stderr: str


CommandState = Literal['pending', 'succeeded', 'failed', 'not-executed']


class CommandManagerInvariantError(CommandControlError):
    """Raised when the manager cannot say what happened to a command.

    Not knowing whether a command ran is never a recoverable outcome: the
    only safe response is to stop rather than guess or re-execute.
    """


class CommandError(AIVMError):
    """Error raised when a checked command finishes unsuccessfully.

    The exception retains both the original command and the normalized
    :class:`CommandResult` so callers can inspect exit status and any
    captured output.

    Attributes:
        cmd: The command that failed.
        result: The normalized result object for the failed command.
    """

    def __init__(self, cmd: Sequence[str] | str, result: CommandResult) -> None:
        self.cmd = cmd
        self.result = result
        rendered = cmd if isinstance(cmd, str) else shell_join(cmd)
        super().__init__(
            f'Command failed (code={result.code}):\n{rendered}\n{result.stderr}'.strip()
        )


class SudoUnavailableError(CommandError):
    """Raised when aivm cannot obtain the sudo credentials a command needs.

    This is a failure, not a refusal, so it is deliberately a
    :class:`CommandError` rather than a
    :class:`~aivm.errors.CommandControlError`. Nobody declined anything and
    no policy forbade it (:class:`~aivm.errors.SudoRequiredError` is that
    case): the host will not give *this account* credentials right now --
    no sudoers entry, a wrong password, or a non-interactive run with
    nothing cached. On a shared workstation that is the normal state of
    every non-administrator, so best-effort callers must be able to
    recover: a read-only probe that cannot escalate should report "I could
    not check" rather than abort the caller's whole operation.

    The message names what needed root, because ``sudo -v`` failing on its
    own tells the user nothing about which part of aivm wanted it.
    """

    def __init__(
        self,
        cmd: Sequence[str] | str,
        result: CommandResult,
        *,
        purpose: str = '',
    ) -> None:
        self.purpose = purpose
        super().__init__(cmd, result)
        detail = (result.stderr or result.stdout or '').strip()
        lines = ['aivm could not obtain sudo credentials on this host.']
        if purpose:
            lines.append(f'  Needed for: {purpose}')
        if detail:
            lines.append(f'  sudo said: {detail}')
        lines.append(
            '  If someone else administers this host, ask them to perform '
            'the privileged step (or to grant you sudo); otherwise re-run '
            'where you can authenticate.'
        )
        self.args = ('\n'.join(lines),)


@dataclass(frozen=True)
class IntentFrame:
    """One entry in the manager's intent stack.

    Intent frames describe *why* the caller is traversing a command tree.
    Visible frames are surfaced in breadcrumbs and plan previews to help a
    human understand the current operation at a glance.

    Attributes:
        title: Short human-readable title for this context.
        why: Optional longer explanation for the context.
        role: Default command role implied by this context.
        visible: If True, include this frame in rendered breadcrumbs.
    """

    title: str
    why: str = ''
    role: CommandRole = 'modify'
    visible: bool = True


@dataclass(frozen=True)
class CommandRequest:
    """Immutable description of one managed command request.

    A request is the single source of truth for preview and execution. It
    stores the command together with the execution, approval, and presentation
    metadata that :class:`CommandManager` needs. Requests returned by
    :meth:`CommandManager.request` are bound to that manager and can be
    previewed, submitted, or run directly.

    Attributes:
        cmd: Command tokens to execute.
        sudo: If True, execute through ``sudo`` when needed.
        role: Optional explicit command role. When omitted, the role is
            inferred from the surrounding intent context.
        ownership: Whose state a write touches.
        user_driven: True when the command hands the terminal to the user.
        check: If True, raise :class:`CommandError` on non-zero exit.
        capture: If True, capture stdout and stderr.
        text: If True, run the subprocess in text mode.
        input_text: Optional standard input text to send to the process.
        env: Optional process environment override.
        timeout: Optional timeout in seconds.
        summary: Short human-facing summary shown in previews.
        detail: Optional longer preview detail.

    ``CommandSpec`` remains as a compatibility alias.
    """

    cmd: Sequence[str]
    sudo: bool = False
    role: CommandRole | None = None
    ownership: CommandOwnership = 'user'
    user_driven: bool = False
    check: bool = True
    capture: bool = True
    text: bool = True
    input_text: str | None = None
    env: dict[str, str] | None = None
    timeout: float | None = None
    summary: str = ''
    detail: str = ''
    _manager: 'CommandManager | None' = field(
        default=None, repr=False, compare=False
    )

    def _bound_manager(self) -> 'CommandManager':
        manager = self._manager
        if manager is None:
            raise CommandManagerInvariantError(
                'This CommandRequest is not bound to a CommandManager. '
                'Create requests with mgr.request(...).'
            )
        return manager

    def preview(self) -> None:
        """Render this request without executing it."""
        self._bound_manager()._preview_request(self, _stacklevel=2)

    def submit(self, *, eager: bool = False) -> 'CommandExecution':
        """Submit this request and return its execution record."""
        return self._bound_manager()._submit_request(
            self, eager=eager, _stacklevel=2
        )

    def run(self) -> CommandResult:
        """Execute this request and return its result immediately."""
        manager = self._bound_manager()
        # Keep the long-standing manager entry point observable by existing
        # instrumentation. Every option still comes from this request.
        return manager.run(
            list(self.cmd),
            sudo=self.sudo,
            role=self.role,
            ownership=self.ownership,
            user_driven=self.user_driven,
            check=self.check,
            capture=self.capture,
            text=self.text,
            input_text=self.input_text,
            env=self.env,
            timeout=self.timeout,
            summary=self.summary,
            detail=self.detail,
        )


@dataclass
class CommandExecution:
    """Lifecycle record for one submitted :class:`CommandRequest`.

    Executions let callers defer work until a later flush, or force execution
    on demand by asking for the result. Once terminal, an execution answers
    from stored state forever: success replays its result, failure re-raises
    the original exception, and dry-run or abandoned work raises
    :class:`CommandNotExecutedError`.
    """

    manager: 'CommandManager'
    command_id: int
    _result: CommandResult | None = None
    _state: CommandState = 'pending'
    _error: BaseException | None = None

    def done(self) -> bool:
        """Return True once this execution has reached a terminal state."""
        return self._state != 'pending'

    def result(self, *, _stacklevel: int = 1) -> CommandResult:
        """Return the result, resolving this execution if still pending.

        Reading an already-terminal execution never causes more work. This
        invariant prevents a failed or abandoned execution from reopening its
        queue and running unrelated pending commands.
        """
        if self._state == 'pending':
            self.manager.flush_through(
                self.command_id, _stacklevel=_stacklevel + 1
            )
        if self._state == 'succeeded':
            assert self._result is not None
            return self._result
        if self._error is not None:
            raise self._error
        raise CommandManagerInvariantError(
            f'Command {self.command_id} is still pending after the flush that '
            'was supposed to resolve it. Refusing to flush again, because '
            'that would execute unrelated queued work.'
        )

    def _set_result(self, result: CommandResult) -> None:
        """Record a successful execution."""
        self._result = result
        self._state = 'succeeded'

    def _set_failure(self, error: BaseException) -> None:
        """Record an attempted execution that raised."""
        self._error = error
        self._state = 'failed'

    def _set_not_executed(self, reason: str) -> None:
        """Record that this execution will never run."""
        self._error = CommandNotExecutedError(reason)
        self._state = 'not-executed'

    @property
    def stdout(self) -> str:
        return self.result().stdout

    @property
    def stderr(self) -> str:
        return self.result().stderr

    @property
    def returncode(self) -> int:
        return self.result().code

    @property
    def code(self) -> int:
        return self.result().code


# Backward-compatible names for callers that imported the earlier API.
CommandSpec = CommandRequest
CommandHandle = CommandExecution


@dataclass
class PlannedCommand:
    """A request and execution record stored in a manager queue."""

    command_id: int
    request: CommandRequest
    execution: CommandExecution
    # Set immediately before execution, so it means attempted rather than
    # succeeded. A raised command must never remain eligible for a later flush.
    attempted: bool = False


@dataclass
class Attempt:
    """Outcome of a :meth:`CommandManager.attempt` block.

    Attributes:
        title: What was being attempted.
        error: The handled exception, or None when the block succeeded.
    """

    title: str
    error: BaseException | None = None

    @property
    def failed(self) -> bool:
        """Whether the attempt failed in a way the caller expected."""
        return self.error is not None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def reason(self) -> str:
        """The failure, phrased for a user, or '' when it succeeded."""
        return str(self.error) if self.error is not None else ''


class AttemptScope:
    """Class-based context manager for an expected, handled failure."""

    def __init__(
        self,
        title: str,
        *,
        why: str = '',
        catch: type[BaseException] | tuple[type[BaseException], ...] = (
            CommandError
        ),
    ) -> None:
        self.title = title
        self.why = why
        self.catch = catch
        self.record = Attempt(title=title)

    def __enter__(self) -> Attempt:
        log.debug(
            'Attempting: {}{}',
            self.title,
            f' ({self.why})' if self.why else '',
        )
        return self.record

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        if exc is None:
            log.debug('Attempt succeeded: {}', self.title)
            return False
        if isinstance(exc, CommandControlError):
            return False
        if isinstance(exc, self.catch):
            self.record.error = exc
            log.info(
                'Attempt failed but is handled by the caller: {}: {}',
                self.title,
                exc,
            )
            return True
        return False


@dataclass
class CommandPlan:
    """Ordered group of commands previewed and executed as one step.

    Plans are usually created indirectly through :class:`PlanScope`. They
    collect related commands, present a plan preview, optionally request
    approval, and then execute in order.

    Attributes:
        title: Human-facing title for the step.
        why: Optional explanation of the step's purpose.
        approval_scope: Optional label describing the approval boundary.
        commands: Commands in submission order.
        approved: True once this plan has cleared approval.
        approved_command_count: Number of commands present when approval was
            granted. Commands appended after that never went through the
            plan prompt and must be confirmed individually at execution.
        executed_upto: Highest command index already executed.
        closed: True once the plan lifecycle has ended.
        rendered_preview: True once the preview has been logged.
    """

    title: str
    why: str = ''
    approval_scope: str = ''
    commands: list[PlannedCommand] = field(default_factory=list)
    approved: bool = False
    approved_command_count: int = 0
    executed_upto: int = -1
    closed: bool = False
    rendered_preview: bool = False

    def add(self, item: PlannedCommand) -> None:
        """Append one planned command to this plan."""
        self.commands.append(item)

    def is_empty(self) -> bool:
        """Return True if this plan contains no commands."""
        return not self.commands


class IntentScope:
    """Context manager that temporarily pushes an intent frame.

    Use this to describe the current user-visible task while building up a
    command tree. Nested scopes form the breadcrumb shown in plan previews.
    """

    def __init__(
        self,
        manager: 'CommandManager',
        title: str,
        *,
        why: str = '',
        role: CommandRole = 'modify',
        visible: bool = True,
    ) -> None:
        self.manager = manager
        self.frame = IntentFrame(
            title=title, why=why, role=role, visible=visible
        )

    def __enter__(self) -> 'IntentScope':
        """Push this scope's intent frame onto the manager."""
        self.manager.push_intent(self.frame)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        """Pop this scope's frame from the manager on exit."""
        self.manager.pop_intent(self.frame)
        return False


class PlanScope:
    """Context manager that groups submitted commands into one plan.

    On successful exit, the collected plan is finalized, previewed, and
    flushed. If the block raises an exception, the plan is aborted instead.
    """

    def __init__(
        self,
        manager: 'CommandManager',
        title: str,
        *,
        why: str = '',
        approval_scope: str = '',
    ) -> None:
        self.manager = manager
        self.plan = CommandPlan(
            title=title,
            why=why,
            approval_scope=approval_scope,
        )

    def __enter__(self) -> CommandPlan:
        """Begin collecting commands into this scope's plan."""
        self.manager.begin_plan(self.plan)
        return self.plan

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        """Finish or abort the plan, then remove it from the manager."""
        try:
            if exc_type is None:
                self.manager.finish_plan(self.plan, _stacklevel=2)
            else:
                self.manager.abort_plan(self.plan)
        finally:
            self.manager.end_plan(self.plan)
        return False


class ApprovedActionScope:
    """Class-based approval scope for one compound state-changing action."""

    def __init__(
        self,
        manager: 'CommandManager',
        *,
        purpose: str,
        yes: bool = False,
    ) -> None:
        self.manager = manager
        self.purpose = purpose
        self.yes = yes
        self.previous_approval = False

    def __enter__(self) -> None:
        already_approved = (
            self.yes or self.manager.yes or self.manager._approve_all_remaining
        )
        if not already_approved:
            if not sys.stdin.isatty():
                raise ApprovalUnavailableError(
                    'This state-changing operation requires confirmation, '
                    'but stdin is not interactive. Re-run with --yes.'
                )
            log.opt(depth=0).info('About to perform a state-changing action:')
            log.opt(depth=0).info('  {}', self.purpose)
            ans = input('Continue? [y/N]: ').strip().lower()
            if ans not in {'y', 'yes'}:
                raise UserDeclinedError('Aborted by user.')
        self.previous_approval = self.manager._approve_all_remaining
        self.manager._approve_all_remaining = True
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        self.manager._approve_all_remaining = self.previous_approval
        return False


_CURRENT_MANAGER: ContextVar['CommandManager | None'] = ContextVar(
    'aivm_current_command_manager', default=None
)


class CommandManager:
    """Central authority for command submission, execution, and approval.

    A command manager organizes subprocess execution around human-readable
    intent scopes and plans. Commands may be submitted either into the
    current open plan or as loose commands. Plans can be previewed and
    approved as a unit before execution.

    Args:
        yes: If True, auto-approve operations that would otherwise prompt.
        yes_sudo: If True, auto-approve privileged sudo operations.
        auto_approve_readonly_sudo: If True, allow read-only sudo commands
            to proceed without prompting when possible.

    Example:
        >>> # Submit one loose command outside of any step.
        >>> from aivm.commands import *  # NOQA
        >>> py = sys.executable
        >>> mgr = CommandManager(yes=True)
        >>> h = mgr.submit(
        ...     [py, '-c', 'print("virsh dominfo demo-vm")'],
        ...     summary='Run one ad hoc inspection command',
        ... )
        >>> print(h.stdout.strip())
        virsh dominfo demo-vm

    Example:
        >>> # Group several "privileged" actions into one readable step.
        >>> from aivm.commands import *  # NOQA
        >>> py = sys.executable
        >>> mgr = CommandManager(yes=True)
        >>> with mgr.intent(title='User specified intent title (e.g. prepare host)', role='modify'):
        ...     with mgr.step(
        ...         title='User specified step title. e.g. install host dependencies',
        ...         why='User specified why. e.g. prepare the machine for VM lifecycle operations',
        ...     ):
        ...         h1 = mgr.submit(
        ...             [py, '-c', 'print("sudo apt-get update -y")'],
        ...             summary='User summary, e.g. Refresh apt metadata',
        ...         )
        ...         h2 = mgr.submit(
        ...             [py, '-c', 'print("sudo apt-get install -y qemu-system libvirt-daemon-system")'],
        ...             summary='User summary, e.g. Install virtualization packages',
        ...         )
        ...         h3 = mgr.submit(
        ...             [py, '-c', 'print("sudo systemctl enable --now libvirtd")'],
        ...             summary='User summary, e.g. Enable libvirtd service',
        ...         )

    Example:
        >>> # Discover something in one step, then use it in a later step.
        >>> from aivm.commands import *  # NOQA
        >>> py = sys.executable
        >>> mgr = CommandManager(yes=True)
        >>> with mgr.intent('configure guest access', role='modify'):
        ...     with mgr.step(
        ...         'discover VM address',
        ...         why='later commands need the current guest IP',
        ...     ):
        ...         ip = mgr.submit(
        ...             [py, '-c', 'print("10.0.0.42")'],
        ...             summary='Read cached VM IP',
        ...         )
        >>> addr = ip.stdout.strip()
        >>> with mgr.intent('configure guest access', role='modify'):
        ...     with mgr.step(
        ...         'test SSH command composition',
        ...         why='show how later commands can consume earlier output',
        ...     ):
        ...         cmd = mgr.submit(
        ...             [py, '-c', f'print("ssh agent@{addr} sudo systemctl status ssh")'],
        ...             summary='Show the SSH command that would be run',
        ...         )

    Example:
        >>> # Use output from an earlier command inside the same step when the
        >>> # later command depends on it.
        >>> from aivm.commands import *  # NOQA
        >>> py = sys.executable
        >>> mgr = CommandManager(yes=True)
        >>> with mgr.intent('reconcile attachment', role='modify'):
        ...     with mgr.step(
        ...         'inspect then repair bind target',
        ...         why='the repair command depends on the detected source',
        ...     ):
        ...         current = mgr.submit(
        ...             [py, '-c', 'print("/old/source")'],
        ...             summary='Inspect current bind source',
        ...         )
        ...         found = current.stdout.strip()
        ...         repair = mgr.submit(
        ...             [py, '-c', f'print("sudo mount --bind /new/source /srv/target  # replacing {found}")'],
        ...             summary='Replace stale bind source',
        ...         )

    Example:
        >>> # xdoctest: +IGNORE_WANT
        >>> from aivm.commands import *  # NOQA
        >>> import sys
        >>> mgr = CommandManager(yes=True)
        >>> with mgr.intent(title='inspect runtime', role='read'):
        ...     h3 = mgr.submit(
        ...         [sys.executable, '-c', 'print("alpha")'],
        ...         summary='emit alpha',
        ...     )
        ...     with mgr.step(title='collect facts', why='demonstrate the command lifecycle') as plan:
        ...         h1 = mgr.submit(
        ...             [sys.executable, '-c', 'print("alpha")'],
        ...             summary='emit alpha',
        ...         )
        ...         h2 = mgr.submit(
        ...             [sys.executable, '-c', 'print("beta")'],
        ...             summary='emit beta',
        ...         )
        ...         # The plan is executed after the context ends.
    """

    def intent(
        self,
        title: str,
        *,
        why: str = '',
        role: CommandRole = 'modify',
        visible: bool = True,
    ) -> IntentScope:
        """
        Context manager that temporarily pushes an intent frame.

        Use this to mark some high level intent.
        """
        return IntentScope(self, title, why=why, role=role, visible=visible)

    def attempt(
        self,
        title: str,
        *,
        why: str = '',
        catch: type[BaseException] | tuple[type[BaseException], ...] = (
            CommandError
        ),
    ) -> AttemptScope:
        """Run commands whose failure is an expected, handled outcome.

        Callers that can recover from a failure otherwise write their own
        ``try``/``except`` around manager calls, which states *how* they are
        coping rather than *what* they are doing, and leaves the manager
        believing an error is still live. This declares the intent instead:
        the block may fail, the failure is handled here, and execution
        continues with whatever the caller does next.

        The block's outcome is reported on the yielded :class:`Attempt`
        instead of propagating::

            with mgr.attempt('Register the deploy key') as registering:
                remote = provider.add_key(...)
            if registering.failed:
                hand_off_to_a_human(registering.reason)

        Logging says so too, so an ERROR line inside a handled attempt does
        not read as a fatal error to whoever is watching.

        Args:
            title: What is being attempted, in user-facing words.
            why: Optional longer explanation.
            catch: Exception types treated as an outcome rather than an
                error. Anything else propagates normally.
                :class:`~aivm.errors.CommandControlError` is never caught
                here, whatever this says.
        """
        return AttemptScope(title, why=why, catch=catch)

    def step(
        self,
        title: str,
        *,
        why: str = '',
        approval_scope: str = '',
    ) -> PlanScope:
        """
        Context manager that groups submitted commands into one plan

        Use this to group related commands.
        """
        # TODO: might want to rename this to StepScope
        return PlanScope(
            self,
            title,
            why=why,
            approval_scope=approval_scope,
        )

    @classmethod
    def current(cls) -> 'CommandManager':
        """Return the current context-local manager, creating one if needed."""
        current = _CURRENT_MANAGER.get()
        if current is None:
            current = cls()
            _CURRENT_MANAGER.set(current)
        return current

    @classmethod
    def activate(cls, manager: 'CommandManager') -> None:
        """Install ``manager`` as the current context-local manager."""
        _CURRENT_MANAGER.set(manager)

    @classmethod
    def reset_current(cls) -> None:
        """Clear the current context-local manager."""
        _CURRENT_MANAGER.set(None)

    def __init__(
        self,
        *,
        yes: bool = False,
        yes_sudo: bool = False,
        auto_approve_readonly_sudo: bool = True,
        privilege_mode: str = str(DEFAULT_PRIVILEGE_MODE),
        dry_run: bool = False,
    ) -> None:
        self.yes = yes
        self.yes_sudo = yes_sudo
        self.auto_approve_readonly_sudo = auto_approve_readonly_sudo
        # Dry-run is an execution policy, not a parallel command renderer.
        # Callers submit the same CommandRequest either way; this manager renders
        # it and resolves the execution without invoking a process.
        self.dry_run = bool(dry_run)
        # Under NEVER this manager refuses to execute any sudo command
        # (enforced in _execute_one and in confirm_sudo_scope) so no code
        # path can escalate silently; call sites consult aivm.privilege
        # helpers to pick sudo=False where an unprivileged path exists.
        # An unknown mode raises rather than defaulting: coercing it here
        # would silently pick the permissive option.
        self.privilege_mode: PrivilegeMode = normalize_privilege_mode(
            privilege_mode
        )
        self.intent_stack: list[IntentFrame] = []
        self.plan_stack: list[CommandPlan] = []
        self._next_command_id = 0
        self._approve_all_remaining = False
        self._loose_commands: list[PlannedCommand] = []
        self._sudo_authentication_required: bool | None = None
        # Sticky: set once an authentication attempt has actually failed.
        # Without it every later privileged step re-prompts an account that
        # has already been shown to have no usable sudo, turning one clear
        # failure into a run of identical ones.
        self._sudo_unavailable_result: CommandResult | None = None
        # Scratch space for modules to memoize read-only probe results
        # (e.g. domain XML) for the lifetime of this manager. Entries are
        # expected to be validated against ``mutation_generation`` so any
        # state-changing command conservatively invalidates them.
        self.probe_cache: dict[str, dict] = {}
        # Incremented every time a state-changing ('modify') command is
        # executed. Probe caches compare against this to decide staleness.
        # Invariant required of callers: state-changing commands must carry
        # role='modify' (directly or via their intent scope). Note that
        # _effective_role classifies unlabeled sudo+check=False commands as
        # reads, so tolerant mutations need an explicit role.
        self.mutation_generation = 0

    def push_intent(self, frame: IntentFrame) -> None:
        """Push one intent frame onto the active intent stack."""
        # TODO: probably a good public method, let the underlying scope handle it.
        self.intent_stack.append(frame)

    def pop_intent(self, frame: IntentFrame) -> None:
        """Remove ``frame`` from the active intent stack.

        The most recently pushed matching frame is removed. This tolerates
        mildly out-of-order cleanup to avoid leaking stale context.
        """
        # TODO: probably a good public method, let the underlying scope handle it.
        if self.intent_stack and self.intent_stack[-1] is frame:
            self.intent_stack.pop()
            return
        for idx in range(len(self.intent_stack) - 1, -1, -1):
            if self.intent_stack[idx] is frame:
                del self.intent_stack[idx]
                return

    def begin_plan(self, plan: CommandPlan) -> None:
        """Push an in-progress plan onto the plan stack."""
        # TODO: probably a good public method, let the underlying scope handle it.
        self.plan_stack.append(plan)

    def end_plan(self, plan: CommandPlan) -> None:
        """Remove ``plan`` from the active plan stack."""
        # TODO: probably a good public method, let the underlying scope handle it.
        if self.plan_stack and self.plan_stack[-1] is plan:
            self.plan_stack.pop()
            return
        for idx in range(len(self.plan_stack) - 1, -1, -1):
            if self.plan_stack[idx] is plan:
                del self.plan_stack[idx]
                return

    def _resolve_abandoned_plan_commands(self, plan: CommandPlan) -> None:
        """Resolve every command ``plan`` will never run.

        A handle that outlives its plan must still answer for itself:
        awaiting one cannot be allowed to reopen a step the manager
        abandoned.
        """
        for item in plan.commands:
            if not item.attempted and not item.execution.done():
                item.execution._set_not_executed(
                    f'Step {plan.title!r} was abandoned before this command '
                    f'ran: {self._preview_command(item.request)}'
                )

    def abort_plan(self, plan: CommandPlan) -> None:
        """Mark ``plan`` as closed without executing its commands."""
        # TODO: probably a good public method, let the underlying scope handle it.
        self._resolve_abandoned_plan_commands(plan)
        plan.closed = True

    def finish_plan(self, plan: CommandPlan, *, _stacklevel: int = 1) -> None:
        """Finalize, approve, and execute a plan.

        Empty plans are simply marked closed. Non-empty plans are previewed,
        approved if needed, then flushed in order. When approval is declined
        or a command raises mid-plan, the exception escapes *this* call, so
        the remaining commands are resolved here -- abort_plan only covers
        exceptions raised by the step body itself.
        """
        # TODO: probably a good public method, let the underlying scope handle it.
        if plan.is_empty():
            plan.closed = True
            return
        try:
            if self.dry_run:
                self._render_plan_preview(plan, _stacklevel=_stacklevel + 1)
                self._resolve_dry_run_commands(plan.commands)
            else:
                self._approve_plan_if_needed(plan, _stacklevel=_stacklevel + 1)
                self._flush_plan(plan, _stacklevel=_stacklevel + 1)
        finally:
            self._resolve_abandoned_plan_commands(plan)
            plan.closed = True

    def current_plan(self) -> CommandPlan | None:
        """Return the currently active innermost plan, if any."""
        return self.plan_stack[-1] if self.plan_stack else None

    def request(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: CommandOwnership = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandRequest:
        """Declare one managed command without previewing or executing it."""
        return CommandRequest(
            cmd=tuple(c if isinstance(c, Elided) else str(c) for c in cmd),
            sudo=sudo,
            role=role,
            ownership=ownership,
            user_driven=user_driven,
            check=check,
            capture=capture,
            text=text,
            input_text=input_text,
            env=dict(env) if env is not None else None,
            timeout=timeout,
            summary=summary.strip(),
            detail=detail.strip(),
            _manager=self,
        )

    def _submit_request(
        self,
        request: CommandRequest,
        *,
        eager: bool = False,
        _stacklevel: int = 1,
    ) -> CommandExecution:
        """Submit a previously declared request."""
        if request._manager not in {None, self}:
            raise CommandManagerInvariantError(
                'Cannot submit a CommandRequest through a different manager.'
            )
        execution = CommandExecution(
            manager=self, command_id=self._next_command_id
        )
        planned = PlannedCommand(
            command_id=self._next_command_id,
            request=request,
            execution=execution,
        )
        self._next_command_id += 1

        plan = self.current_plan()
        if plan is not None:
            plan.add(planned)
            if eager:
                self.flush_through(
                    planned.command_id, _stacklevel=_stacklevel + 1
                )
            return execution

        self._loose_commands.append(planned)
        if eager:
            self.flush_through(
                planned.command_id, _stacklevel=_stacklevel + 1
            )
        return execution

    def submit(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: CommandOwnership = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
        eager: bool = False,
        _stacklevel: int = 1,
    ) -> CommandExecution:
        """Compatibility shortcut for ``request(...).submit()``."""
        request = self.request(
            cmd,
            sudo=sudo,
            role=role,
            ownership=ownership,
            user_driven=user_driven,
            check=check,
            capture=capture,
            text=text,
            input_text=input_text,
            env=env,
            timeout=timeout,
            summary=summary,
            detail=detail,
        )
        return self._submit_request(
            request, eager=eager, _stacklevel=_stacklevel + 1
        )

    def run(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: CommandOwnership = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandResult:
        """Compatibility shortcut for ``request(...).run()``."""
        request = self.request(
            cmd,
            sudo=sudo,
            role=role,
            ownership=ownership,
            user_driven=user_driven,
            check=check,
            capture=capture,
            text=text,
            input_text=input_text,
            env=env,
            timeout=timeout,
            summary=summary,
            detail=detail,
        )
        return self._submit_request(
            request, eager=True, _stacklevel=2
        ).result(_stacklevel=2)

    def _preview_request(
        self, request: CommandRequest, *, _stacklevel: int = 1
    ) -> None:
        """Render a declared request without running it."""
        if request._manager not in {None, self}:
            raise CommandManagerInvariantError(
                'Cannot preview a CommandRequest through a different manager.'
            )
        local_log = log.opt(depth=_stacklevel)
        if request.summary:
            local_log.info('DRYRUN: {}', request.summary)
        else:
            local_log.info('DRYRUN: command would execute')
        preview_cmd, omissions = self._render_preview(request)
        role_label = self._effective_role(request)
        command_label = (
            'command (read-only)' if role_label == 'read' else 'command'
        )
        local_log.info('{}:\n{}', command_label, preview_cmd)
        self._announce_omissions(omissions, _stacklevel=_stacklevel)
        if request.detail:
            local_log.debug('detail: {}', request.detail)
        raw_cmd = self._raw_command(request)
        if raw_cmd != preview_cmd:
            local_log.debug('raw command:\n{}', raw_cmd)

    def preview_spec(
        self, spec: CommandRequest, *, _stacklevel: int = 1
    ) -> None:
        """Compatibility alias for :meth:`CommandRequest.preview`."""
        self._preview_request(spec, _stacklevel=_stacklevel + 1)

    def preview(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: CommandOwnership = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
        _stacklevel: int = 1,
    ) -> None:
        """Compatibility shortcut for ``request(...).preview()``."""
        request = self.request(
            cmd,
            sudo=sudo,
            role=role,
            ownership=ownership,
            user_driven=user_driven,
            check=check,
            capture=capture,
            text=text,
            input_text=input_text,
            env=env,
            timeout=timeout,
            summary=summary,
            detail=detail,
        )
        self._preview_request(request, _stacklevel=_stacklevel + 1)

    def replace_process(
        self,
        cmd: Sequence[str],
        *,
        role: CommandRole | None = None,
        env: dict[str, str] | None = None,
        summary: str = '',
        detail: str = '',
    ) -> None:
        """Replace this process, or only render the command during dry-run."""
        if self.current_plan() is not None:
            raise CommandManagerInvariantError(
                'Process replacement cannot occur inside an open command step.'
            )
        spec = self.request(
            cmd,
            role=role,
            user_driven=True,
            capture=False,
            env=env,
            summary=summary,
            detail=detail,
        )
        local_log = log.opt(depth=1)
        run_line, omissions = self._render_preview(spec)
        if spec.summary:
            local_log.info('{}{}', 'DRYRUN: ' if self.dry_run else '', spec.summary)
        label = 'DRYRUN (exec skipped):' if self.dry_run else 'RUN (exec, replaces this process):'
        local_log.info('{}\n{}', label, run_line)
        self._announce_omissions(omissions, _stacklevel=1)
        raw_line = self._raw_command(spec)
        if raw_line != run_line:
            local_log.debug('raw command:\n{}', raw_line)
        if self.dry_run:
            return
        argv = [str(part) for part in spec.cmd]
        try:
            if env is None:
                os.execvp(argv[0], argv)
            os.execvpe(argv[0], argv, env)
        except FileNotFoundError as ex:
            missing = ex.filename or (argv[0] if argv else '<empty command>')
            raise CommandError(
                argv, CommandResult(127, '', f'command not found: {missing}')
            ) from ex
        except PermissionError as ex:
            denied = ex.filename or (argv[0] if argv else '<empty command>')
            raise CommandError(
                argv,
                CommandResult(126, '', f'command is not executable: {denied}'),
            ) from ex
        raise CommandManagerInvariantError('os.exec returned without replacing the process')

    def _resolve_dry_run_commands(
        self, commands: Sequence[PlannedCommand]
    ) -> None:
        """Resolve pending commands as previewed without fabricating results."""
        for item in commands:
            if item.attempted or item.execution.done():
                continue
            item.attempted = True
            item.execution._set_not_executed(
                'Command was previewed but not executed because this is a dry run: '
                f'{self._preview_command(item.request)}'
            )

    def _preview_dry_run_loose_commands(
        self, *, through_command_id: int | None, _stacklevel: int
    ) -> None:
        """Render pending loose commands and resolve them without execution."""
        for item in self._loose_commands:
            if item.attempted:
                continue
            self.preview_spec(item.request, _stacklevel=_stacklevel + 1)
            self._resolve_dry_run_commands([item])
            if (
                through_command_id is not None
                and item.command_id >= through_command_id
            ):
                break

    def flush_through(self, command_id: int, *, _stacklevel: int = 1) -> None:
        """Flush execution through the specified command id.

        This executes all earlier pending commands needed to reach the
        requested command, whether it lives inside an active plan or in the
        loose-command queue.

        Args:
            command_id: Identifier of the last command that must be run.
        """
        # TODO: does this need to be public?
        # Only ever flush a queue that actually holds the requested command.
        if self.dry_run:
            for plan in reversed(self.plan_stack):
                if any(item.command_id == command_id for item in plan.commands):
                    self._render_plan_preview(plan, _stacklevel=_stacklevel + 1)
                    self._resolve_dry_run_commands(plan.commands)
                    return
            if any(item.command_id == command_id for item in self._loose_commands):
                self._preview_dry_run_loose_commands(
                    through_command_id=command_id,
                    _stacklevel=_stacklevel + 1,
                )
                return
            raise CommandManagerInvariantError(
                f'No queue holds command {command_id}, so the manager cannot preview it.'
            )
        # Only ever flush a queue that actually holds the requested command.
        # Substituting "whatever else is pending" is how re-reading a resolved
        # handle used to execute an unrelated command.
        for plan in reversed(self.plan_stack):
            if any(item.command_id == command_id for item in plan.commands):
                self._approve_plan_if_needed(plan, _stacklevel=_stacklevel + 1)
                self._flush_plan(
                    plan,
                    through_command_id=command_id,
                    _stacklevel=_stacklevel + 1,
                )
                return
        if any(item.command_id == command_id for item in self._loose_commands):
            self._flush_loose_commands(
                through_command_id=command_id, _stacklevel=_stacklevel + 1
            )
            return
        raise CommandManagerInvariantError(
            f'No queue holds command {command_id}, so the manager cannot say '
            'whether it ran. Refusing to execute anything else.'
        )

    def _normalize_role(self, role: str | None) -> CommandRole:
        """Normalize a role string to ``'read'`` or ``'modify'``."""
        mode = str(role or 'modify').strip().lower()
        if mode == 'read':
            return 'read'
        return 'modify'

    def _effective_role(self, spec: CommandRequest) -> CommandRole:
        """Infer the effective role for a command specification."""
        if spec.role is not None:
            return self._normalize_role(spec.role)
        if spec.sudo and not spec.check:
            return 'read'
        for frame in reversed(self.intent_stack):
            if frame.role in {'read', 'modify'}:
                return frame.role
        return 'modify'

    def render_breadcrumb(self) -> str:
        """Render the visible intent stack as a breadcrumb string."""
        parts = [f.title for f in self.intent_stack if f.visible and f.title]
        return ' > '.join(parts)

    def sudo_authentication_required(self) -> bool:
        """Return True when the current user likely needs sudo auth."""
        if os.geteuid() == 0:
            self._sudo_authentication_required = False
            return False
        if self.privilege_mode == PrivilegeMode.NEVER:
            # Never invoke sudo under NEVER, not even `sudo -n true`;
            # callers on this path are about to be rejected anyway.
            return True
        if self._sudo_authentication_required is not None:
            return self._sudo_authentication_required
        probe = subprocess.run(
            ['sudo', '-n', 'true'],
            capture_output=True,
            text=True,
        )
        self._sudo_authentication_required = probe.returncode != 0
        log.opt(depth=0).trace(
            'sudo auth probe returncode={} stderr={!r}',
            probe.returncode,
            (probe.stderr or '').strip(),
        )
        return self._sudo_authentication_required

    def sudo_escalation_possible(self) -> bool:
        """Return whether aivm could still obtain sudo in this invocation.

        Answers the capability question a caller needs *before* deciding
        whether a privileged step is worth starting, so a host account with
        no sudo is told what it cannot do instead of walking into a failed
        ``sudo -v``. It never prompts and never escalates.

        ``sudo -n true`` failing is not on its own a "no": an interactive
        run can still ask for a password. So the answer is False only when
        we already know escalation cannot succeed --- root-less under a
        no-sudo policy, an authentication attempt that already failed, or a
        non-interactive run with nothing cached and nobody to ask.
        """
        if os.geteuid() == 0:
            return True
        if self.privilege_mode == PrivilegeMode.NEVER:
            return False
        if self._sudo_unavailable_result is not None:
            return False
        if not self.sudo_authentication_required():
            return True
        return sys.stdin.isatty()

    def _readonly_sudo_policy_note(self) -> str:
        if self.auto_approve_readonly_sudo:
            return (
                'Future read-only sudo commands are configured to auto-approve '
                'once authentication is ready.'
            )
        return (
            'Future read-only sudo commands are configured to keep asking for '
            'approval unless you choose [a]ll or enable auto approval in config.'
        )

    def _render_sudo_prompt_context(
        self,
        *,
        purpose: str,
        role: CommandRole,
        auth_required: bool,
        preview_cmds: Sequence[Sequence[str]] | None = None,
    ) -> None:
        local_log = log.opt(depth=0)
        local_log.info(
            'About to request sudo for {} host operations:',
            'read-only' if role == 'read' else 'state-changing',
        )
        local_log.info('  {}', purpose)
        if preview_cmds:
            local_log.info('  Planned sudo commands:')
            for idx, cmd in enumerate(preview_cmds, start=1):
                rendered = shell_join(['sudo', *(str(part) for part in cmd)])
                local_log.info('    {}. sudo command:\n{}', idx, rendered)
        if auth_required:
            local_log.info(
                '  Sudo authentication appears to be required before the next command can run.'
            )
            local_log.info('  {}', self._readonly_sudo_policy_note())

    def _authenticate_sudo(self, *, purpose: str = '') -> None:
        """Refresh sudo credentials now so later commands do not surprise."""
        self._reject_sudo_if_forbidden(['sudo', '-v'], needs_sudo=True)
        if os.geteuid() == 0:
            self._sudo_authentication_required = False
            return
        if self._sudo_unavailable_result is not None:
            # Already proven impossible in this invocation. Re-running sudo
            # would re-prompt an account that cannot answer, once per
            # privileged step, burying the first clear explanation.
            raise SudoUnavailableError(
                ['sudo', '-v'], self._sudo_unavailable_result, purpose=purpose
            )
        cmd = ['sudo', '-v']
        if not sys.stdin.isatty():
            cmd = ['sudo', '-n', '-v']
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            res = CommandResult(
                proc.returncode,
                proc.stdout or '',
                proc.stderr or '',
            )
            # Remember it: this account cannot escalate in this invocation,
            # and re-asking once per privileged step only repeats the same
            # failure with less context each time.
            self._sudo_unavailable_result = res
            raise SudoUnavailableError(cmd, res, purpose=purpose)
        self._sudo_authentication_required = False

    def _reject_sudo_if_forbidden(
        self, cmd: Sequence[str] | str, *, needs_sudo: bool
    ) -> None:
        """Raise when a sudo command would run under ``privilege_mode=never``.

        This is the structural never-sudo guarantee: every execution path
        funnels through here, so a call site that forgot to consult the
        privilege helpers fails loudly instead of escalating. Note it keys
        on the command being run, not on the feature that requested it, so
        work that turns out to need no privileges is never refused.
        """
        if not needs_sudo or self.privilege_mode != PrivilegeMode.NEVER:
            return
        if os.geteuid() == 0:
            return
        raise SudoRequiredError(
            'Sudo is forbidden (behavior.privilege_mode = "never"), but this '
            'operation requested privileged host access:\n'
            f'  {shell_join(cmd) if not isinstance(cmd, str) else cmd}\n'
            'Run `aivm host permissions check` to see which host permissions '
            'are missing, or which features still require sudo. Set '
            'behavior.privilege_mode to '
            "'as-needed' to escalate only where it is required."
        )

    def confirm_sudo_scope(
        self,
        *,
        purpose: str,
        role: str = 'modify',
        yes: bool = False,
        preview_cmds: Sequence[Sequence[str]] | None = None,
    ) -> None:
        """Preflight sudo approval/authentication for an upcoming operation."""
        if os.geteuid() == 0:
            return
        self._reject_sudo_if_forbidden(
            preview_cmds[0] if preview_cmds else purpose, needs_sudo=True
        )
        eff_role = self._normalize_role(role)
        auth_required = self.sudo_authentication_required()
        auto_yes = (
            yes
            or self.yes
            or self.yes_sudo
            or self._approve_all_remaining
            or (eff_role == 'read' and self.auto_approve_readonly_sudo)
        )
        if auth_required:
            self._render_sudo_prompt_context(
                purpose=purpose,
                role=eff_role,
                auth_required=True,
                preview_cmds=preview_cmds,
            )
        if auto_yes:
            if auth_required:
                self._authenticate_sudo(purpose=purpose)
            return
        if not sys.stdin.isatty():
            raise ApprovalUnavailableError(
                'Privileged host operations require confirmation, but stdin is not interactive. '
                'Re-run with --yes or --yes-sudo.'
            )
        if not auth_required:
            self._render_sudo_prompt_context(
                purpose=purpose,
                role=eff_role,
                auth_required=False,
                preview_cmds=preview_cmds,
            )
        ans = input('Continue? [y]es/[a]ll/[N]o: ').strip().lower()
        if ans in {'a', 'all'}:
            self._approve_all_remaining = True
        elif ans not in {'y', 'yes'}:
            raise UserDeclinedError('Aborted by user.')
        if auth_required:
            self._authenticate_sudo(purpose=purpose)

    def approved_action(
        self,
        *,
        purpose: str,
        yes: bool = False,
    ) -> ApprovedActionScope:
        """Approve one compound action before any direct mutation occurs.

        Some operations combine direct Python filesystem changes with later
        subprocess mutations. This scope obtains approval up front and
        temporarily suppresses nested command prompts so declining can never
        happen after the direct portion has already changed state.
        """
        return ApprovedActionScope(self, purpose=purpose, yes=yes)

    def confirm_file_update(
        self,
        *,
        path: str | os.PathLike[str],
        purpose: str,
        yes: bool = False,
    ) -> None:
        """Confirm an update to a user-managed host file."""
        if yes or self.yes or self._approve_all_remaining:
            return
        if not sys.stdin.isatty():
            raise ApprovalUnavailableError(
                'External host file updates require confirmation, but stdin is not interactive. '
                'Re-run with --yes.'
            )
        local_log = log.opt(depth=0)
        local_log.info('About to update a host file not managed by aivm:')
        local_log.info('  {}', os.fspath(path))
        local_log.info('  {}', purpose)
        ans = input('Continue? [y/N]: ').strip().lower()
        if ans not in {'y', 'yes'}:
            raise UserDeclinedError('Aborted by user.')

    def _is_confirmable_write(self, spec: CommandRequest) -> bool:
        """Return True for a state change the user has to consent to.

        The write itself is the guard. This deliberately does not consult the
        command name: gating on ``virsh`` guarded ``undefine
        --remove-all-storage`` only by the coincidence that it shares a binary
        with ``setvcpus``, while an unprivileged command doing the same damage
        by another route was never guarded at all.

        Two exemptions, both declared by the call site and never inferred:
        ``ownership='tool'`` for aivm's own regenerable bookkeeping, and
        ``user_driven`` for commands that hand the terminal to the user. See
        docs/source/design.rst for the bar each must clear.
        """
        if self._effective_role(spec) != 'modify':
            return False
        if spec.user_driven:
            return False
        return spec.ownership != 'tool'

    def _command_needs_approval(self, spec: CommandRequest) -> bool:
        """Return True when ``spec`` must be confirmed before executing.

        Two independent triggers: the command changes state, or it escalates
        on the host. They overlap deliberately, so a write that also needs
        sudo is caught even if its effect was mis-declared -- but the user is
        asked exactly once, because approval is a property of the command
        rather than a toll per matching rule.
        """
        if os.geteuid() == 0:
            return False
        privileged = spec.sudo
        if not privileged and not self._is_confirmable_write(spec):
            return False
        if self.yes or self.yes_sudo or self._approve_all_remaining:
            return False
        if (
            privileged
            and self._effective_role(spec) == 'read'
            and self.auto_approve_readonly_sudo
        ):
            return False
        return True

    def _plan_needs_approval(self, plan: CommandPlan) -> bool:
        """Return True if any command in ``plan`` requires approval."""
        return any(
            self._command_needs_approval(item.request) for item in plan.commands
        )

    def _approve_plan_if_needed(
        self, plan: CommandPlan, *, _stacklevel: int = 1
    ) -> None:
        """Render and approve ``plan`` if approval has not already occurred."""
        if plan.approved:
            return
        for item in plan.commands:
            # Reject sudo work before any approval side effect (previews,
            # prompts, `sudo -n true` probes, `sudo -v`) can run.
            self._reject_sudo_if_forbidden(
                item.request.cmd, needs_sudo=item.request.sudo
            )
        self._render_plan_preview(plan, _stacklevel=_stacklevel + 1)
        readonly_autoapproved_sudo = [
            item
            for item in plan.commands
            if item.request.sudo
            and self._effective_role(item.request) == 'read'
            and self.auto_approve_readonly_sudo
        ]
        if (
            readonly_autoapproved_sudo
            and not self._plan_needs_approval(plan)
            and not (self.yes or self.yes_sudo or self._approve_all_remaining)
        ):
            if self.sudo_authentication_required():
                self._authenticate_sudo(purpose=plan.title)
            plan.approved = True
            plan.approved_command_count = len(plan.commands)
            return
        if not self._plan_needs_approval(plan):
            plan.approved = True
            plan.approved_command_count = len(plan.commands)
            return
        if not sys.stdin.isatty():
            raise ApprovalUnavailableError(
                'Privileged host operations require confirmation, but stdin is not interactive. '
                'Re-run with --yes or --yes-sudo.'
            )
        while True:
            ans = (
                input('Approve this step? [y]es/[a]ll/[s]how/[N]o: ')
                .strip()
                .lower()
            )
            if ans in {'s', 'show'}:
                self._render_plan_full_commands(
                    plan, _stacklevel=_stacklevel + 1
                )
                continue
            if ans in {'a', 'all'}:
                self._approve_all_remaining = True
                plan.approved = True
                plan.approved_command_count = len(plan.commands)
                return
            if ans in {'y', 'yes'}:
                plan.approved = True
                plan.approved_command_count = len(plan.commands)
                return
            raise UserDeclinedError('Aborted by user.')

    def _render_plan_preview(
        self, plan: CommandPlan, *, _stacklevel: int = 1
    ) -> None:
        """Log a concise preview of the commands contained in ``plan``."""
        if plan.rendered_preview:
            return
        breadcrumb = self.render_breadcrumb()
        local_log = log.opt(depth=_stacklevel)
        local_log.info('{}Step: {}', 'DRYRUN: ' if self.dry_run else '', plan.title)
        if breadcrumb:
            local_log.info('Context: {}', breadcrumb)
        if plan.why:
            local_log.info('Why: {}', plan.why)
        local_log.info('Planned commands: {}', len(plan.commands))
        for idx, item in enumerate(plan.commands, start=1):
            summary = item.request.summary or shell_join(item.request.cmd)
            role = self._effective_role(item.request)
            preview_cmd, omissions = self._render_preview(item.request)
            local_log.info('  {}. {}', idx, summary)
            command_label = (
                'command (read-only)' if role == 'read' else 'command'
            )
            local_log.info('     {}:\n{}', command_label, preview_cmd)
            self._announce_omissions(omissions, _stacklevel=_stacklevel)
            if item.request.detail:
                local_log.debug('     detail: {}', item.request.detail)
            raw_cmd = self._raw_command(item.request)
            if raw_cmd != preview_cmd:
                local_log.debug('     raw command:\n{}', raw_cmd)
            local_log.trace('     role={} capture={}', role, item.request.capture)
        plan.rendered_preview = True

    def _render_plan_full_commands(
        self, plan: CommandPlan, *, _stacklevel: int = 1
    ) -> None:
        """Log the full raw command lines for every item in ``plan``."""
        local_log = log.opt(depth=_stacklevel)
        local_log.info('Full commands for step: {}', plan.title)
        for idx, item in enumerate(plan.commands, start=1):
            local_log.info('  {}. full command:\n{}', idx, self._raw_command(item.request))

    def _confirm_loose_command(
        self, spec: CommandRequest, *, _stacklevel: int = 1
    ) -> None:
        """Confirm one approval-needing command outside a plan's approval.

        Sudo commands go through the full sudo scope confirmation
        (authentication included). Unprivileged state-changing libvirt
        commands get a plain confirmation prompt so the approval contract
        survives ``privilege_mode='never'``.
        """
        if os.geteuid() == 0:
            return
        if not spec.sudo and not self._command_needs_approval(spec):
            return
        role = self._effective_role(spec)
        purpose = spec.summary.strip()
        if not purpose:
            breadcrumb = self.render_breadcrumb().strip()
            if breadcrumb:
                purpose = breadcrumb
            else:
                purpose = (
                    'Run a privileged host command without an explicit step.'
                )
        if not spec.summary.strip():
            log.opt(depth=_stacklevel).info(
                '  This command is not grouped into an explicit step. '
                'Wrap related work in mgr.intent(...) / mgr.step(...) for clearer previews and fewer prompts.'
            )
        if spec.sudo:
            self.confirm_sudo_scope(
                yes=False,
                purpose=purpose,
                role=role,
                preview_cmds=[list(spec.cmd)],
            )
            return
        self._confirm_unprivileged_mutation(
            purpose=purpose, preview_cmds=[list(spec.cmd)]
        )

    def _confirm_unprivileged_mutation(
        self,
        *,
        purpose: str,
        preview_cmds: Sequence[Sequence[str]] | None = None,
    ) -> None:
        """Prompt for a state-changing hypervisor command that needs no sudo."""
        local_log = log.opt(depth=0)
        local_log.info(
            'About to run state-changing operations (no sudo needed):'
        )
        local_log.info('  {}', purpose)
        if preview_cmds:
            local_log.info('  Planned commands:')
            for idx, cmd in enumerate(preview_cmds, start=1):
                local_log.info(
                    '    {}. command:\n{}',
                    idx,
                    shell_join([str(p) for p in cmd]),
                )
        if not sys.stdin.isatty():
            raise ApprovalUnavailableError(
                'State-changing operations require confirmation, but stdin '
                'is not interactive. Re-run with --yes.'
            )
        ans = input('Continue? [y]es/[a]ll/[N]o: ').strip().lower()
        if ans in {'a', 'all'}:
            self._approve_all_remaining = True
        elif ans not in {'y', 'yes'}:
            raise UserDeclinedError('Aborted by user.')

    def _flush_plan(
        self,
        plan: CommandPlan,
        *,
        through_command_id: int | None = None,
        _stacklevel: int = 1,
    ) -> None:
        """Execute pending commands in ``plan`` in submission order.

        Iterates by index rather than over a snapshot because a command may be
        appended mid-flush (a sudo escalation fallback does exactly that), and
        skips anything already attempted rather than tracking a cursor.
        """
        idx = -1
        while idx + 1 < len(plan.commands):
            idx += 1
            item = plan.commands[idx]
            if item.attempted:
                continue
            if (
                plan.approved
                and idx >= plan.approved_command_count
                and (item.request.sudo or self._is_confirmable_write(item.request))
            ):
                # This command was appended after the step cleared approval
                # (e.g. a sudo escalation fallback), so the plan prompt never
                # covered it. Apply the same policy the plan approval would
                # have: confirm when approval is required, otherwise make
                # sure auto-approved read-only sudo is authenticated up
                # front so it cannot fail (or prompt) mid-plan.
                role = self._effective_role(item.request)
                if self._command_needs_approval(item.request):
                    self._confirm_loose_command(
                        item.request, _stacklevel=_stacklevel + 1
                    )
                elif (
                    item.request.sudo
                    and role == 'read'
                    and self.auto_approve_readonly_sudo
                    and not (
                        self.yes or self.yes_sudo or self._approve_all_remaining
                    )
                    and os.geteuid() != 0
                    and self.sudo_authentication_required()
                ):
                    self._authenticate_sudo()
            item.attempted = True
            try:
                res = self._execute_one(
                    item.request,
                    ordinal=(idx + 1, len(plan.commands)),
                    within_plan=True,
                    _stacklevel=_stacklevel + 1,
                )
            except BaseException as ex:
                item.execution._set_failure(ex)
                raise
            item.execution._set_result(res)
            plan.executed_upto = idx
            if (
                through_command_id is not None
                and item.command_id >= through_command_id
            ):
                break

    def _next_unattempted_loose(self) -> PlannedCommand | None:
        """Return the oldest loose command that has not been attempted."""
        for item in self._loose_commands:
            if not item.attempted:
                return item
        # Nothing left to do, so the queue can be released. Attempted items are
        # kept until here only so a partial flush can find its place again.
        self._loose_commands.clear()
        return None

    def _has_pending_loose(self) -> bool:
        return any(not item.attempted for item in self._loose_commands)

    def _flush_loose_commands(
        self,
        *,
        through_command_id: int | None = None,
        _stacklevel: int = 1,
    ) -> None:
        """Execute pending loose commands in FIFO order."""
        while True:
            item = self._next_unattempted_loose()
            if item is None:
                return
            item.attempted = True
            try:
                res = self._execute_one(
                    item.request, within_plan=False, _stacklevel=_stacklevel + 1
                )
            except BaseException as ex:
                item.execution._set_failure(ex)
                raise
            item.execution._set_result(res)
            if (
                through_command_id is not None
                and item.command_id >= through_command_id
            ):
                break

    def _raw_command(self, spec: CommandRequest) -> str:
        """Return the full shell-rendered command that would be executed."""
        cmd = list(spec.cmd)
        if spec.sudo and os.geteuid() != 0:
            cmd = ['sudo', *cmd] if sys.stdin.isatty() else ['sudo', '-n', *cmd]
        return shell_join(cmd)

    def _render_preview(self, spec: CommandRequest) -> tuple[str, list[str]]:
        """Return ``(preview, omissions)`` for ``spec``.

        Arguments render verbatim, so the line stays the command the user
        would have typed. Two things are not printed in full: an argument the
        call site marked :class:`Elided`, which renders as its label, and an
        unmarked argument past :data:`PREVIEW_ARG_MAX_LEN`, which says only
        that it is too long and asks to be marked.

        Nothing here infers what a payload is. An unmarked payload therefore
        reads as an unhelpful log line rather than a tidy one, which is the
        point: it names work still to do, the way an ungrouped command does.

        ``omissions`` describes anything left out, so the caller can say so
        out loud. A quietly shortened command is worse than a long one: the
        reader has no way to tell a faithful line from an abridged one.
        """
        cmd = list(spec.cmd)
        if spec.sudo and os.geteuid() != 0:
            cmd = ['sudo', *cmd] if sys.stdin.isatty() else ['sudo', '-n', *cmd]
        display_parts: list[str] = []
        omissions: list[str] = []
        for part in cmd:
            if isinstance(part, Elided):
                display_parts.append(f'<<OMITTED {part.label}>>')
                omissions.append(
                    f'{part.label} ({len(part)} characters, '
                    f'sha256:{part.digest_hex})'
                )
                continue
            text = str(part)
            if len(text) > PREVIEW_ARG_MAX_LEN:
                display_parts.append('<<OMITTED unmarked argument>>')
                omissions.append(
                    f'UNMARKED argument ({len(text)} characters). Mark it '
                    'Elided(value, label) at the call site to name it'
                )
                continue
            display_parts.append(shlex.quote(text))
        return ' '.join(display_parts), omissions

    def _preview_command(self, spec: CommandRequest) -> str:
        """Return only the rendered preview line for ``spec``."""
        return self._render_preview(spec)[0]

    def _announce_omissions(
        self,
        omissions: Sequence[str],
        *,
        quiet: bool = False,
        _stacklevel: int = 1,
    ) -> None:
        """Say plainly that the line above was not the whole command.

        An unmarked payload is logged as a warning because it is a gap in the
        code, not a deliberate choice; a marked one is expected and stays at
        info. Both name how to recover the literal text.

        The extra frame for this helper is added to ``_stacklevel`` so the
        notice is attributed to the call site that ran the command, next to
        the line it is talking about.

        ``quiet`` follows the command's own visibility. A notice that says
        "the command above" must never outlive the command above: an
        unprivileged read is held for ``--verbose 2``, so its omission notice
        is too, or the log shows a complaint about a line that is not there.
        """
        local_log = log.opt(depth=_stacklevel + 1)
        for description in omissions:
            if quiet:
                emit = local_log.debug
            else:
                emit = (
                    local_log.warning
                    if description.startswith('UNMARKED')
                    else local_log.info
                )
            emit(
                '  ^^ OMITTED FROM THE COMMAND ABOVE: {}. Re-run with -vv to '
                'log the literal command.',
                description,
            )

    def _execute_one(
        self,
        spec: CommandRequest,
        *,
        ordinal: tuple[int, int] | None = None,
        within_plan: bool = False,
        _stacklevel: int = 1,
    ) -> CommandResult:
        """Execute one command specification and normalize its result."""
        local_log = log.opt(depth=_stacklevel)
        self._reject_sudo_if_forbidden(spec.cmd, needs_sudo=spec.sudo)
        role = self._effective_role(spec)
        if role == 'modify':
            # Bump before running so probe caches are invalidated even if
            # the mutation fails partway through.
            self.mutation_generation += 1
        if not within_plan and (spec.sudo or self._is_confirmable_write(spec)):
            self._confirm_loose_command(spec, _stacklevel=_stacklevel + 1)
        # Whether privilege is actually spent, not merely offered: under
        # privilege_mode='as-needed' a caller passes sudo=True speculatively,
        # and as root no escalation happens at all.
        escalated = spec.sudo and os.geteuid() != 0
        cmd = list(spec.cmd)
        if escalated:
            cmd = ['sudo', *cmd] if sys.stdin.isatty() else ['sudo', '-n', *cmd]

        # Render what the user could have typed, minus payloads the call site
        # marked. The literal line stays reachable at DEBUG in this same run,
        # so following a log never requires re-running the command to read it.
        run_line, omissions = self._render_preview(spec)
        raw_line = shell_join(cmd)

        # POLICY (see CLAUDE.md, "`sudo` on the command line is always called
        # out"): the user is made aware of anything with the potential to
        # perform an unbounded privileged sudo op, even if we know what the
        # program being called is. Merely invoking sudo on the command line is
        # strong enough of a thing that it needs to be called out. Do not
        # reduce this to role alone -- a privileged read still prints, because
        # what is announced is the escalation, not the read.
        #
        # State changes are announced for the separate reason that they
        # altered the host. What is left for -vv is the remainder: a read that
        # escalates nothing, which is plumbing.
        #
        # Quiet is therefore declared, never inferred: a command is demoted
        # only where a call site says role='read' or runs inside a read intent
        # *and* no sudo was applied. An unclassified command defaults to
        # 'modify' and stays loud, so an unaudited path is heard, not skipped.
        quiet = role == 'read' and not escalated
        emit = local_log.debug if quiet else local_log.info
        if within_plan and ordinal is not None:
            current, total = ordinal
            emit('RUN [{}/{}]:\n{}', current, total, run_line)
        else:
            emit('RUN:\n{}', run_line)
        self._announce_omissions(
            omissions, quiet=quiet, _stacklevel=_stacklevel
        )
        if raw_line != run_line:
            local_log.debug('  raw command:\n{}', raw_line)

        try:
            proc = subprocess.run(
                cmd,
                input=spec.input_text if spec.input_text is not None else None,
                capture_output=spec.capture,
                text=spec.text,
                env=spec.env,
                timeout=spec.timeout,
            )
            res = CommandResult(
                proc.returncode,
                proc.stdout or '',
                proc.stderr or '',
            )
        except FileNotFoundError as ex:
            missing = ex.filename or (cmd[0] if cmd else '<empty command>')
            res = CommandResult(127, '', f'command not found: {missing}')
            local_log.warning('Command executable not found:\n{}', run_line)
            if spec.check:
                raise CommandError(cmd, res) from ex
            return res
        except PermissionError as ex:
            denied = ex.filename or (cmd[0] if cmd else '<empty command>')
            res = CommandResult(126, '', f'command is not executable: {denied}')
            local_log.warning(
                'Command executable is not permitted:\n{}', run_line
            )
            if spec.check:
                raise CommandError(cmd, res) from ex
            return res
        except subprocess.TimeoutExpired as ex:
            stdout = ex.stdout or ''
            stderr = ex.stderr or ''
            if not isinstance(stdout, str):
                stdout = stdout.decode(errors='replace')
            if not isinstance(stderr, str):
                stderr = stderr.decode(errors='replace')
            res = CommandResult(
                124, stdout, (stderr + '\ncommand timed out').strip()
            )
            local_log.warning(
                'Command timed out after {}s:\n{}',
                spec.timeout,
                run_line,
            )
            if spec.check:
                raise CommandError(cmd, res) from ex
            return res

        local_log.trace(
            'Command result code={} stdout_len={} stderr_len={}',
            res.code,
            len(res.stdout),
            len(res.stderr),
        )
        if spec.check and res.code != 0:
            local_log.error(
                'Command failed code={}:\n{}\nstderr={}\nstdout={}',
                res.code,
                run_line,
                res.stderr.strip(),
                res.stdout.strip(),
            )
            raise CommandError(cmd, res)
        return res
