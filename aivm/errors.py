"""Project-specific exception types."""

from __future__ import annotations


class AIVMError(RuntimeError):
    """Base error for domain-level aivm failures."""


class MissingSSHIdentityError(AIVMError):
    """Raised when SSH identity configuration is required but missing."""


class SudolessModeError(AIVMError):
    """Raised when an operation needs sudo but sudoless mode forbids it.

    The message must tell the user which feature needed privileges and how
    to proceed (finish sudoless setup, disable the feature, or switch
    ``behavior.privilege_mode`` back to ``'auto'``/``'sudo'``).
    """
