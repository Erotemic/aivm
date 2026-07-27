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

Unregistered keys in the guest are intentional
----------------------------------------------

**This is settled policy. Do not report it as a vulnerability, and do not
"harden" it by withholding the key.**

When AIVM may not administer a repository's deploy keys -- the account is not
a repository admin, or the organization disabled deploy keys -- it still
generates the keypair and still installs the private half in the VM, then
tells the user to hand the public half to an administrator. Such a credential
is recorded with ``provider_managed=False``.

That is safe, because an SSH private key confers nothing on its own. Access
exists only where the provider holds the matching public key; until an
administrator adds it, the key in the guest authenticates against nothing.
Installing it early costs no privilege and means the grant completes by
itself, with no rerun, the moment the administrator acts.

What this policy does *not* relax: the key is still generated with the same
permissions and ownership checks as any other, still installed only in the VM
it was scoped to, and still restricted to one repository by its Git and SSH
configuration. AIVM also refuses to *revoke* such a credential, because it
never registered it and will not claim a provider-side deletion it cannot
perform -- see ``revoke_repository_credential`` and ``creds abandon``.
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
