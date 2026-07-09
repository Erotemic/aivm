"""Project-specific exception types."""

from __future__ import annotations


class AIVMError(RuntimeError):
    """Base error for domain-level aivm failures."""


class MissingSSHIdentityError(AIVMError):
    """Raised when SSH identity configuration is required but missing."""


class PrivilegeModeError(AIVMError):
    """Raised when ``behavior.privilege_mode`` names no known mode."""


class SudoRequiredError(AIVMError):
    """Raised when an operation needs sudo but ``privilege_mode='never'``.

    The message must tell the user which command or feature needed
    privileges and how to proceed (finish ``aivm host sudoless setup``,
    disable the feature, or choose a privilege mode that may escalate).
    """
