"""Attachment ownership policy for shared machine stores."""

from __future__ import annotations

from pathlib import Path

from ..config_scopes import ResolvedVMContext
from ..config_store import (
    ATTACHMENT_SYSTEM_OWNER,
    AttachmentEntry,
    Store,
    find_principal,
)
from ..errors import AIVMError
from ..scoped_store import resolve_store_scope

SYSTEM_ATTACHMENT_OWNER = ATTACHMENT_SYSTEM_OWNER
LEGACY_ATTACHMENT_OWNER = ''


def attachment_owner_for_context(
    context: ResolvedVMContext, store_path: Path
) -> str:
    """Return the owner recorded for new attachments in this store scope."""
    scope = resolve_store_scope(str(store_path))
    if not scope.is_machine:
        return LEGACY_ATTACHMENT_OWNER
    return context.principal.id


def attachment_owner_label(reg: Store, owner_principal_id: str) -> str:
    """Return a stable human-readable attachment owner label."""
    owner = str(owner_principal_id or '').strip()
    if not owner:
        return 'legacy/unattributed'
    if owner == SYSTEM_ATTACHMENT_OWNER:
        return 'system'
    for principal in reg.principals:
        if principal.id == owner:
            return f'{principal.host_user} -> {principal.guest_user} ({owner})'
    return owner


def require_attachment_mutation_permission(
    reg: Store,
    attachment: AttachmentEntry,
    *,
    current_principal_id: str,
    administrative_override: bool,
) -> None:
    """Require ownership, or an explicit trusted-host administrative override."""
    current = str(current_principal_id or '').strip()
    owner = str(attachment.owner_principal_id or '').strip()
    if not owner or owner == current:
        return
    if administrative_override:
        return
    label = attachment_owner_label(reg, owner)
    raise AIVMError(
        'Attachment is owned by another VM principal.\n'
        f'Owner: {label}\n'
        f'Host path: {attachment.host_path}\n'
        f'Guest destination: {attachment.guest_dst or "(default)"}\n'
        'Only the owner may update or detach it. A trusted host administrator '
        'may retry with --admin_override.'
    )


def validate_attachment_owner(reg: Store, attachment: AttachmentEntry) -> None:
    """Reject dangling owners in machine stores while accepting legacy input."""
    owner = str(attachment.owner_principal_id or '').strip()
    if reg.store_kind != 'machine' or not owner:
        return
    if owner == SYSTEM_ATTACHMENT_OWNER:
        return
    if find_principal(reg, vm_name=attachment.vm_name, principal_id=owner) is None:
        raise AIVMError(
            f'Attachment for VM {attachment.vm_name!r} references unknown '
            f'owner principal {owner!r}.'
        )
