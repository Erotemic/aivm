"""Credential ownership policy for shared machine stores."""

from __future__ import annotations

from ..config_store import CredentialEntry, Store, find_principal
from ..legacy.pre_0_6_0 import compatibility_surface
from ..errors import AIVMError


@compatibility_surface
def credential_principal_label(reg: Store, principal_id: str) -> str:
    """Return a stable human-readable credential owner label."""
    principal = str(principal_id or '').strip()
    if not principal:
        return 'legacy/unattributed'
    for item in reg.principals:
        if item.id == principal:
            return f'{item.host_user} -> {item.guest_user} ({principal})'
    return principal


@compatibility_surface
def validate_credential_principal(
    reg: Store, credential: CredentialEntry
) -> None:
    """Reject missing or dangling owners in machine stores."""
    if reg.store_kind != 'machine':
        return
    principal = str(credential.principal_id or '').strip()
    if not principal:
        raise AIVMError(
            f'Credential {credential.id!r} for VM {credential.vm_name!r} '
            'is missing principal_id.'
        )
    if (
        find_principal(
            reg,
            vm_name=credential.vm_name,
            principal_id=principal,
        )
        is None
    ):
        raise AIVMError(
            f'Credential {credential.id!r} for VM {credential.vm_name!r} '
            f'references unknown principal {principal!r}.'
        )


@compatibility_surface
def require_credential_owner(
    reg: Store,
    credential: CredentialEntry,
    *,
    current_principal_id: str,
) -> None:
    """Require the owning principal for secret-bearing credential operations.

    Unlike attachment metadata, a provider credential depends on private host
    key material and provider authentication held by the owner. A trusted host
    administrator may inspect global metadata, but must not revoke, abandon,
    repair, or install another principal's credential from the wrong login.
    """
    current = str(current_principal_id or '').strip()
    owner = str(credential.principal_id or '').strip()
    if not owner or owner == current:
        return
    label = credential_principal_label(reg, owner)
    raise AIVMError(
        'Credential belongs to another VM principal.\n'
        f'Owner: {label}\n'
        f'Credential: {credential.id}\n'
        f'Repository: {credential.provider_host}/{credential.owner}/'
        f'{credential.repository}\n'
        'Run the credential operation as the owning host user. Machine-wide '
        'administrative views expose metadata only; they do not borrow another '
        "user's private key or provider authentication context."
    )
