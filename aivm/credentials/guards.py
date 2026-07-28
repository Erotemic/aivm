"""Cross-cutting safety guards for destructive VM credential operations.

This is the single seam the VM lifecycle uses. Callers there should not need
credential states, host paths, or key handling -- a VM command asks whether it
may proceed and then asks for the leftovers to be cleaned up.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config_store import CredentialEntry, Store, find_credentials_for_vm
from ..errors import AIVMError
from .keys import remove_host_key
from .schema import credential_allows_vm_delete


def require_vm_credentials_released(
    store: Store,
    vm_name: str,
    *,
    action: str,
) -> list[CredentialEntry]:
    """Reject destructive VM operations while provider credentials are live."""
    credentials = find_credentials_for_vm(store, vm_name)
    blocking = [
        entry for entry in credentials if not credential_allows_vm_delete(entry)
    ]
    if blocking:
        lines = '\n'.join(
            '  - '
            f'{entry.provider_host}/{entry.owner}/{entry.repository} '
            f'({entry.access}, {entry.id})'
            for entry in blocking
        )
        raise AIVMError(
            f"VM '{vm_name}' still owns repository credentials and cannot be "
            f'{action}:\n{lines}\n'
            'Revoke them first with `aivm vm creds revoke ...`. '
            'AIVM will not silently orphan an active deploy key.'
        )
    return credentials


def discard_released_credential_material(
    credentials: Iterable[CredentialEntry],
) -> None:
    """Remove host key material left by credentials already revoked upstream.

    Only entries that :func:`require_vm_credentials_released` would let a VM
    deletion proceed on are touched, so this cannot erase key material for a
    deploy key that still exists at the provider.
    """
    for entry in credentials:
        if credential_allows_vm_delete(entry):
            remove_host_key(entry.vm_name, entry.id)
