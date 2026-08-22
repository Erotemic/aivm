"""Credential backend naming and hierarchical preference resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .errors import AIVMError

CREDENTIAL_BACKEND_AUTO = 'auto'
CREDENTIAL_BACKEND_GUEST_KEY = 'guest-key'
CREDENTIAL_BACKEND_SSH_AGENT = 'ssh-agent'
DEFAULT_CREDENTIAL_BACKEND = CREDENTIAL_BACKEND_GUEST_KEY

CredentialBackend = Literal['guest-key', 'ssh-agent']
CredentialBackendSelection = Literal['auto', 'guest-key', 'ssh-agent']
CredentialBackendSource = Literal['explicit', 'vm', 'user', 'fallback']

_VALID_SELECTIONS = {
    CREDENTIAL_BACKEND_AUTO,
    CREDENTIAL_BACKEND_GUEST_KEY,
    CREDENTIAL_BACKEND_SSH_AGENT,
}


def normalize_credential_backend(value: object) -> CredentialBackendSelection:
    """Normalize one public backend selection without accepting vague aliases."""
    normalized = str(value or CREDENTIAL_BACKEND_AUTO).strip().lower()
    if normalized not in _VALID_SELECTIONS:
        allowed = ', '.join(sorted(_VALID_SELECTIONS))
        raise AIVMError(
            f'Unsupported credential backend {value!r}; expected one of: {allowed}.'
        )
    return cast(CredentialBackendSelection, normalized)


@dataclass(frozen=True)
class CredentialBackendResolution:
    """Resolved credential backend plus the preference layer that selected it."""

    backend: CredentialBackend
    source: CredentialBackendSource
    requested: CredentialBackendSelection
    vm_preference: CredentialBackendSelection
    user_preference: CredentialBackendSelection


def resolve_credential_backend(
    requested: object = CREDENTIAL_BACKEND_AUTO,
    *,
    vm_preference: object = CREDENTIAL_BACKEND_AUTO,
    user_preference: object = CREDENTIAL_BACKEND_AUTO,
) -> CredentialBackendResolution:
    """Resolve explicit -> VM -> user -> fallback credential backend selection."""
    requested_norm = normalize_credential_backend(requested)
    vm_norm = normalize_credential_backend(vm_preference)
    user_norm = normalize_credential_backend(user_preference)

    if requested_norm != CREDENTIAL_BACKEND_AUTO:
        return CredentialBackendResolution(
            backend=requested_norm,
            source='explicit',
            requested=requested_norm,
            vm_preference=vm_norm,
            user_preference=user_norm,
        )
    if vm_norm != CREDENTIAL_BACKEND_AUTO:
        return CredentialBackendResolution(
            backend=vm_norm,
            source='vm',
            requested=requested_norm,
            vm_preference=vm_norm,
            user_preference=user_norm,
        )
    if user_norm != CREDENTIAL_BACKEND_AUTO:
        return CredentialBackendResolution(
            backend=user_norm,
            source='user',
            requested=requested_norm,
            vm_preference=vm_norm,
            user_preference=user_norm,
        )
    return CredentialBackendResolution(
        backend=DEFAULT_CREDENTIAL_BACKEND,
        source='fallback',
        requested=requested_norm,
        vm_preference=vm_norm,
        user_preference=user_norm,
    )
