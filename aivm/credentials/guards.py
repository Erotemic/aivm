"""Cross-cutting safety guards for destructive VM credential operations."""

from __future__ import annotations

from ..config_store import CredentialEntry, Store, find_credentials_for_vm
from ..errors import AIVMError
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
