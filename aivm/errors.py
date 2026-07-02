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


class SessionRuntimeError(AIVMError):
    """Raised when a system-runtime-only feature is used on a session VM.

    The message must name the feature, say why the session runtime cannot
    provide it (no managed network / no root firewall / no host bind
    mounts), and point at the session-compatible alternative or at
    ``runtime.mode = 'system'``.
    """
