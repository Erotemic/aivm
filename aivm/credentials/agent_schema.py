"""Pure schema helpers for host-agent repository credentials."""

from __future__ import annotations

import hashlib
import re

from .models import GitRepository
from .validation import (
    CredentialValidationError,
    validate_repository_identity,
)

AGENT_CREDENTIAL_STATE_PENDING = 'pending'
AGENT_CREDENTIAL_STATE_ACTIVE = 'active'
AGENT_CREDENTIAL_STATE_REVOCATION_PENDING = 'revocation-pending'
VALID_AGENT_CREDENTIAL_STATES = frozenset(
    {
        AGENT_CREDENTIAL_STATE_PENDING,
        AGENT_CREDENTIAL_STATE_ACTIVE,
        AGENT_CREDENTIAL_STATE_REVOCATION_PENDING,
    }
)
_AGENT_CREDENTIAL_ID_RE = re.compile(r'^agent-git-[0-9a-f]{12}$')


def agent_credential_id(
    vm_name: str, canonical_repo: str, principal_id: str = ''
) -> str:
    """Return the disjoint id used by host-agent repository grants."""
    payload = (
        f'{str(vm_name).strip()}\0{str(principal_id).strip()}\0'
        f'{str(canonical_repo).strip()}'
    ).encode('utf-8')
    return 'agent-git-' + hashlib.sha256(payload).hexdigest()[:12]


def validate_agent_credential_id_format(value: str) -> str:
    text = str(value or '').strip()
    if not _AGENT_CREDENTIAL_ID_RE.fullmatch(text):
        raise CredentialValidationError(
            f'Invalid agent credential id {text!r}; expected '
            'agent-git-[0-9a-f]{12}.'
        )
    return text


def validate_agent_credential_identity(
    *,
    vm_name: str,
    cred_id: str,
    provider_host: str,
    owner: str,
    repository: str,
    principal_id: str = '',
) -> GitRepository:
    """Validate one host-agent credential's stable identity."""
    validated_id = validate_agent_credential_id_format(cred_id)
    repo = validate_repository_identity(provider_host, owner, repository)
    expected = agent_credential_id(vm_name, repo.canonical, principal_id)
    if validated_id != expected:
        raise CredentialValidationError(
            f'Agent credential id {validated_id!r} does not match VM '
            f'{vm_name!r} and repository {repo.display!r}; expected '
            f'{expected!r}.'
        )
    return repo
