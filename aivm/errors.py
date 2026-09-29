"""Project-specific exception types."""

from __future__ import annotations


class AIVMError(RuntimeError):
    """Base error for domain-level aivm failures."""


class MissingSSHIdentityError(AIVMError):
    """Raised when SSH identity configuration is required but missing."""


class VMNotRunningError(AIVMError):
    """Raised when an operation requires a VM that is currently stopped."""


class NoVMContextError(AIVMError):
    """Raised when the store names no single VM for this invocation.

    This is not "the config is wrong": the store parsed and resolved fine, it
    just does not point at exactly one VM here -- none are defined, or several
    match and nothing can disambiguate them non-interactively. Commands with a
    sensible VM-less view (``aivm status``) may catch this and render it; every
    other :class:`AIVMError` describes a broken config and must reach the user.
    """


class PrivilegeModeError(AIVMError):
    """Raised when ``behavior.privilege_mode`` names no known mode."""


class CommandControlError(AIVMError):
    """Base for decisions about *whether* a command may run.

    These are categorically different from the outcome of running one. A
    :class:`~aivm.commands.CommandError` says the user asked for something and
    it did not work; a control error says the user did not authorize it, or
    policy forbade it, or it never ran at all. Best-effort machinery routinely
    and correctly recovers from the former -- provider bureaucracy must never
    block credential preparation -- and must never recover from the latter,
    because continuing past one contradicts the user's own decision.

    :meth:`aivm.commands.CommandManager.attempt` re-raises every subclass
    unconditionally, even when the caller passes a broad ``catch``. A caller
    with a genuine recovery path may still catch a specific subclass outside
    an attempt block; generic recovery may not.
    """


class UserDeclinedError(CommandControlError):
    """Raised when the user answered no at an approval prompt."""


class ApprovalUnavailableError(CommandControlError):
    """Raised when approval is required but cannot be requested.

    Silence is not consent. A non-interactive run has nobody to ask, so the
    operation stops rather than proceeding on an assumption; ``--yes`` is how
    a caller grants approval up front.
    """


class CommandNotExecutedError(CommandControlError):
    """Raised when a command never ran and never will.

    Its plan was aborted, or execution was abandoned. The command reached a
    terminal state without an outcome, so any caller awaiting its result gets
    this rather than a stale, missing, or silently re-executed one.
    """


class SudoRequiredError(CommandControlError):
    """Raised when an operation needs sudo but ``privilege_mode='never'``.

    The message must tell the user which command or feature needed
    privileges and how to proceed (finish ``aivm host permissions setup``,
    disable the feature, or choose a privilege mode that may escalate).
    """
