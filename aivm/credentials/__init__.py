"""VM-scoped, host-managed credentials.

The lifecycle functions are imported lazily so config-store parsing can use the
credential validation helpers without creating a config-store/service cycle.
"""

from __future__ import annotations

from typing import Any

from .models import GitRepository, ProviderDeployKey

__all__ = [
    'GitRepository',
    'ProviderDeployKey',
    'abandon_repository_credential',
    'grant_repository_credential',
    'inspect_credential',
    'parse_repository_url',
    'resolve_repository',
    'revoke_repository_credential',
    'select_credential',
]


def __getattr__(name: str) -> Any:
    if name in {'parse_repository_url', 'resolve_repository'}:
        from . import resolve

        return getattr(resolve, name)
    if name in {
        'abandon_repository_credential',
        'grant_repository_credential',
        'inspect_credential',
        'revoke_repository_credential',
        'select_credential',
    }:
        from . import service

        return getattr(service, name)
    raise AttributeError(name)
