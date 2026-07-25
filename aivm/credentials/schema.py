"""Dependency-light schema constants for VM credential records."""

from __future__ import annotations

from typing import Literal, Protocol

CredentialKind = Literal['github-deploy-key']
CredentialAccess = Literal['read', 'write']
CredentialState = Literal[
    'pending',
    'active',
    'revocation-pending',
    'abandon-pending',
]

CREDENTIAL_KIND_GITHUB_DEPLOY_KEY: CredentialKind = 'github-deploy-key'

CREDENTIAL_ACCESS_READ: CredentialAccess = 'read'
CREDENTIAL_ACCESS_WRITE: CredentialAccess = 'write'

CREDENTIAL_STATE_PENDING: CredentialState = 'pending'
CREDENTIAL_STATE_ACTIVE: CredentialState = 'active'
CREDENTIAL_STATE_REVOCATION_PENDING: CredentialState = 'revocation-pending'
CREDENTIAL_STATE_ABANDON_PENDING: CredentialState = 'abandon-pending'

VALID_CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {CREDENTIAL_KIND_GITHUB_DEPLOY_KEY}
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


class _HasCredentialState(Protocol):
    @property
    def state(self) -> str:
        ...


def credential_is_guest_usable(entry: _HasCredentialState) -> bool:
    """Return whether an entry should remain in generated guest Git config."""
    return entry.state not in CREDENTIAL_CLEANUP_STATES


def credential_allows_vm_delete(entry: _HasCredentialState) -> bool:
    """Return whether provider revocation is complete enough for VM deletion."""
    return entry.state == CREDENTIAL_STATE_REVOCATION_PENDING
