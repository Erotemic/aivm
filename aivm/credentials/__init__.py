"""VM-scoped, host-managed credentials."""

from .models import GitRepository, ProviderDeployKey
from .resolve import parse_repository_url, resolve_repository
from .service import (
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
    select_credential,
)

__all__ = [
    'GitRepository',
    'ProviderDeployKey',
    'grant_repository_credential',
    'inspect_credential',
    'parse_repository_url',
    'resolve_repository',
    'revoke_repository_credential',
    'select_credential',
]
