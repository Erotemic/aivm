"""VM-scoped, host-managed credentials.

The lifecycle functions are imported lazily so config-store parsing can use the
credential validation helpers without creating a config-store/service cycle.

Audit boundary
--------------

This package is optional: nothing here runs unless a user grants a VM access
to a repository. It is deliberately kept off the path of the core VM, network,
firewall, and privilege code so that a review of *those* never has to reason
about deploy keys. Core modules reference this package in exactly four places,
and that list is the thing to check when reviewing the boundary:

- ``config_store.models`` / ``config_store.parse`` import :mod:`.schema` and
  :mod:`.validation`. The store persists credential records, so it must
  validate them; both modules are pure and import nothing outward.
- ``cli.vm_lifecycle`` and ``vm.create`` import :mod:`.guards` -- and only
  :mod:`.guards` -- so a VM cannot be deleted or recreated out from under a
  live deploy key.
- ``cli.config.lint`` imports :mod:`.schema` and :mod:`.validation` to lint
  credential blocks in the store.
- ``cli.vm_creds`` is the feature's own command surface.

The shared CLI option surface (``cli._common``) must stay free of credential
imports. Settings this feature needs are resolved by :mod:`.policy` from the
store the running command bound, rather than pushed in by core.

Dependencies point inward only: modules here import ``commands``, ``config``,
``config_store``, ``errors``, ``host``, ``runtime``, and ``services``. No core
module imports credential lifecycle, key handling, or provider code.
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
