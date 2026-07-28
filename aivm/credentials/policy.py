"""Configuration policy owned by the VM credential feature.

This module exists so the credential feature reads its own setting instead of
having the shared CLI option surface push it in. Nothing outside this package
imports it, and no core module has to know the setting exists.

The policy only ever relaxes *directory mode* findings. Ownership, symlink,
file-type, and key-file permission checks are unconditional and live in
:mod:`aivm.credentials.keys`.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

from ..errors import AIVMError

CREDENTIAL_DIRECTORY_PERMISSION_POLICIES = ('warn', 'error', 'ignore')
DEFAULT_CREDENTIAL_DIRECTORY_PERMISSION_POLICY = 'warn'

# An explicit override set by a caller. Empty means "resolve from the store".
_POLICY_OVERRIDE: ContextVar[str] = ContextVar(
    'aivm_credential_directory_permission_policy', default=''
)


def normalize_credential_directory_permission_policy(value: object) -> str:
    """Validate a configured policy, rejecting anything unrecognized."""
    raw = (
        str(value or '').strip().lower()
        or DEFAULT_CREDENTIAL_DIRECTORY_PERMISSION_POLICY
    )
    if raw not in CREDENTIAL_DIRECTORY_PERMISSION_POLICIES:
        raise AIVMError(
            'Unknown behavior.credential_directory_permission_policy '
            f'{str(value)!r}. Valid values: '
            + ', '.join(CREDENTIAL_DIRECTORY_PERMISSION_POLICIES)
        )
    return raw


def set_credential_directory_permission_policy(value: object) -> Token[str]:
    """Override the configured policy for the current context."""
    return _POLICY_OVERRIDE.set(
        normalize_credential_directory_permission_policy(value)
    )


def reset_credential_directory_permission_policy(token: Token[str]) -> None:
    _POLICY_OVERRIDE.reset(token)


def credential_directory_permission_policy() -> str:
    """Resolve the active policy, preferring an explicit override.

    Resolution is lazy and happens only when a directory mode finding needs a
    verdict, so an unreadable store or an unrelated command never pays for it
    and a bad value here cannot break commands that touch no credentials.
    """
    override = _POLICY_OVERRIDE.get()
    if override:
        return override

    # Imported here so the credential package does not pull the service layer
    # into every module that merely wants a path helper.
    from ..config_store import load_store
    from ..services import active_cfg_path

    try:
        path = active_cfg_path()
        if not path.exists():
            return DEFAULT_CREDENTIAL_DIRECTORY_PERMISSION_POLICY
        reg = load_store(path)
    except Exception:
        # An unreadable store falls back to the default; a store that names an
        # unknown policy must not, so normalization stays outside the guard.
        return DEFAULT_CREDENTIAL_DIRECTORY_PERMISSION_POLICY
    return normalize_credential_directory_permission_policy(
        reg.behavior.credential_directory_permission_policy
    )
