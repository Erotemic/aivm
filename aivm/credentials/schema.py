"""Dependency-light schema constants for VM credential records."""

from __future__ import annotations

from typing import Literal, Protocol

from ..errors import AIVMError

CredentialKind = Literal['github-deploy-key', 'gitlab-deploy-key']
CredentialAccess = Literal['read', 'write']
CredentialState = Literal[
    'pending',
    'active',
    'revocation-pending',
    'abandon-pending',
]

CREDENTIAL_KIND_GITHUB_DEPLOY_KEY: CredentialKind = 'github-deploy-key'
CREDENTIAL_KIND_GITLAB_DEPLOY_KEY: CredentialKind = 'gitlab-deploy-key'

CREDENTIAL_ACCESS_READ: CredentialAccess = 'read'
CREDENTIAL_ACCESS_WRITE: CredentialAccess = 'write'

CREDENTIAL_STATE_PENDING: CredentialState = 'pending'
CREDENTIAL_STATE_ACTIVE: CredentialState = 'active'
CREDENTIAL_STATE_REVOCATION_PENDING: CredentialState = 'revocation-pending'
CREDENTIAL_STATE_ABANDON_PENDING: CredentialState = 'abandon-pending'

VALID_CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {
        CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
        CREDENTIAL_KIND_GITLAB_DEPLOY_KEY,
    }
)
VALID_CREDENTIAL_ACCESS: frozenset[str] = frozenset(
    {CREDENTIAL_ACCESS_READ, CREDENTIAL_ACCESS_WRITE}
)
VALID_CREDENTIAL_STATES: frozenset[str] = frozenset(
    {
        CREDENTIAL_STATE_PENDING,
        CREDENTIAL_STATE_ACTIVE,
        CREDENTIAL_STATE_REVOCATION_PENDING,
        CREDENTIAL_STATE_ABANDON_PENDING,
    }
)
CREDENTIAL_CLEANUP_STATES: frozenset[str] = frozenset(
    {
        CREDENTIAL_STATE_REVOCATION_PENDING,
        CREDENTIAL_STATE_ABANDON_PENDING,
    }
)


_CREDENTIAL_ACCESS_ALIASES: dict[str, CredentialAccess] = {
    'ro': CREDENTIAL_ACCESS_READ,
    'readonly': CREDENTIAL_ACCESS_READ,
    'read-only': CREDENTIAL_ACCESS_READ,
    'read_only': CREDENTIAL_ACCESS_READ,
    'rw': CREDENTIAL_ACCESS_WRITE,
    'readwrite': CREDENTIAL_ACCESS_WRITE,
    'read-write': CREDENTIAL_ACCESS_WRITE,
    'read_write': CREDENTIAL_ACCESS_WRITE,
}


def normalize_credential_access(value: object) -> CredentialAccess:
    """Normalize a requested access level, rejecting anything unrecognized.

    ``kwconf`` only warns when a programmatic call passes a value outside the
    declared ``Literal``, so this is the gate that keeps an unrecognized
    access level from reaching the provider as a silent grant.
    """
    raw = str(value or '').strip().lower()
    resolved = _CREDENTIAL_ACCESS_ALIASES.get(raw, raw)
    if resolved not in VALID_CREDENTIAL_ACCESS:
        allowed = ', '.join(sorted(VALID_CREDENTIAL_ACCESS))
        raise AIVMError(
            f'Unsupported credential access {str(value)!r}; '
            f'--access must be one of: {allowed}'
        )
    return (
        CREDENTIAL_ACCESS_WRITE
        if resolved == 'write'
        else (CREDENTIAL_ACCESS_READ)
    )


class _HasCredentialState(Protocol):
    @property
    def state(self) -> str: ...


def credential_is_guest_usable(entry: _HasCredentialState) -> bool:
    """Return whether an entry should remain in generated guest Git config."""
    return entry.state not in CREDENTIAL_CLEANUP_STATES


def credential_allows_vm_delete(entry: _HasCredentialState) -> bool:
    """Return whether provider revocation is complete enough for VM deletion."""
    return entry.state == CREDENTIAL_STATE_REVOCATION_PENDING
