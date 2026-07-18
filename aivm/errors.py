"""Project-specific exception types."""

from __future__ import annotations


class AIVMError(RuntimeError):
    """Base error for domain-level aivm failures."""


class MissingSSHIdentityError(AIVMError):
    """Raised when SSH identity configuration is required but missing."""


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


class SudoRequiredError(AIVMError):
    """Raised when an operation needs sudo but ``privilege_mode='never'``.

    The message must tell the user which command or feature needed
    privileges and how to proceed (finish ``aivm host permissions setup``,
    disable the feature, or choose a privilege mode that may escalate).
    """
