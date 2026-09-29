"""Lookup and materialization helpers for the AIVM config store."""

from __future__ import annotations

import difflib
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from ..errors import AIVMError
from ..host_identity import HostIdentity
from .models import (
    AttachmentEntry,
    CredentialEntry,
    NetworkEntry,
    PrincipalEntry,
    Store,
    VMEntry,
)
from .parse import _norm_dir


def find_vm(reg: Store, vm_name: str) -> VMEntry | None:
    for rec in reg.vms:
        if rec.name == vm_name:
            return rec
    return None


def find_network(reg: Store, network_name: str) -> NetworkEntry | None:
    for rec in reg.networks:
        if rec.name == network_name:
            return rec
    return None


def find_principal(
    reg: Store, *, vm_name: str, principal_id: str
) -> PrincipalEntry | None:
    for item in reg.principals:
        if item.vm_name == vm_name and item.id == principal_id:
            return item
    return None


def find_principals_for_vm(reg: Store, vm_name: str) -> list[PrincipalEntry]:
    return sorted(
        (item for item in reg.principals if item.vm_name == vm_name),
        key=lambda item: (item.host_user, item.id),
    )


def find_principal_for_host(
    reg: Store, *, vm_name: str, host_user: str
) -> PrincipalEntry | None:
    matches = [
        item
        for item in reg.principals
        if item.vm_name == vm_name and item.host_user == host_user
    ]
    if len(matches) > 1:
        ids = ', '.join(sorted(item.id for item in matches))
        raise AIVMError(
            f'Multiple principals for host user {host_user!r} on VM '
            f'{vm_name!r}: {ids}. Repair the machine store before continuing.'
        )
    return matches[0] if matches else None


def find_principal_for_host_identity(
    reg: Store, *, vm_name: str, identity: HostIdentity
) -> PrincipalEntry | None:
    """Resolve a principal by kernel identity and fail on partial matches."""
    principals = find_principals_for_vm(reg, vm_name)
    exact = [
        item
        for item in principals
        if item.host_uid == identity.uid and item.host_user == identity.username
    ]
    if len(exact) > 1:
        ids = ', '.join(sorted(item.id for item in exact))
        raise AIVMError(
            f'Multiple access identities match uid {identity.uid} and host user '
            f'{identity.username!r} on VM {vm_name!r}: {ids}.'
        )
    if exact:
        return exact[0]

    uid_matches = [item for item in principals if item.host_uid == identity.uid]
    if uid_matches:
        details = ', '.join(
            f'{item.host_user!r} ({item.id})' for item in uid_matches
        )
        raise AIVMError(
            f'Invoking uid {identity.uid} now resolves to host user '
            f'{identity.username!r}, but the VM store records {details}. '
            'This looks like a host account rename. Repair the stored host '
            'username explicitly before continuing.'
        )

    name_matches = [
        item for item in principals if item.host_user == identity.username
    ]
    if name_matches:
        details = ', '.join(
            f'uid {item.host_uid} ({item.id})' for item in name_matches
        )
        raise AIVMError(
            f'Host user {identity.username!r} is running as uid {identity.uid}, '
            f'but the VM store records {details}. This looks like account '
            'recreation or UID reuse; refusing to select that identity.'
        )
    return None


#: Beyond this many known names, list a sample rather than the whole store.
_MAX_LISTED_NAMES = 10

#: Suggestions offered before falling back to listing everything.
_MAX_SUGGESTIONS = 3


def _near_misses(name: str, known: Sequence[str]) -> list[str]:
    """Return plausible intended names for ``name``, best first.

    Edit distance alone is not enough in either direction. A name that is a
    prefix of a longer one -- ``aivm-2404`` against ``aivm-2404-workstation``
    -- scores only about 0.6 because of the length gap, while unrelated short
    names in a uniformly-named store can clear that same bar on shared
    punctuation. Containment is checked first for the former, and the ratio
    cutoff is set high enough to exclude the latter.
    """
    lowered = name.lower()
    contained = [
        candidate
        for candidate in known
        if lowered
        and (lowered in candidate.lower() or candidate.lower() in lowered)
    ]
    close = difflib.get_close_matches(
        name, known, n=_MAX_SUGGESTIONS, cutoff=0.75
    )
    ordered = contained + [c for c in close if c not in contained]
    return ordered[:_MAX_SUGGESTIONS]


def unknown_name_message(
    kind: str, name: str, available: Sequence[str], *, empty_hint: str = ''
) -> str:
    """Build a 'no such thing, here is what exists' message.

    A bare "not found" leaves the user to guess whether they typo'd the name,
    are on a host whose store never had it, or are looking at the wrong config
    file entirely. Naming the near miss answers the first, and listing what is
    actually defined answers the other two.

    Args:
        kind: Singular noun for the thing, e.g. ``'VM'``.
        name: The name that was not found.
        available: Names that do exist, in any order.
        empty_hint: Advice appended when nothing at all is defined.

    Returns:
        A single-line message ending in a period.
    """
    known = sorted(available)
    parts = [f'{kind} not found in config store: {name!r}.']
    if not known:
        parts.append(f'No {kind}s are defined in this config store.')
        if empty_hint:
            parts.append(empty_hint)
        return ' '.join(parts)
    suggestions = _near_misses(name, known)
    if suggestions:
        quoted = [repr(match) for match in suggestions]
        if len(quoted) == 1:
            phrase = quoted[0]
        else:
            phrase = f'{", ".join(quoted[:-1])} or {quoted[-1]}'
        parts.append(f'Did you mean {phrase}?')
    shown = known[:_MAX_LISTED_NAMES]
    listed = ', '.join(shown)
    if len(known) > len(shown):
        listed += f' (+{len(known) - len(shown)} more)'
    parts.append(f'Known {kind}s: {listed}.')
    return ' '.join(parts)


def require_vm(reg: Store, vm_name: str) -> VMEntry:
    """Return the named VM entry, or raise naming what the store does have."""
    rec = find_vm(reg, vm_name)
    if rec is None:
        raise AIVMError(
            unknown_name_message(
                'VM',
                vm_name,
                [entry.name for entry in reg.vms],
                empty_hint='Run `aivm config init` to define one.',
            )
        )
    return rec


def require_network(reg: Store, network_name: str) -> NetworkEntry:
    """Return the named network entry, or raise naming the known networks."""
    rec = find_network(reg, network_name)
    if rec is None:
        raise AIVMError(
            unknown_name_message(
                'managed network',
                network_name,
                [entry.name for entry in reg.networks],
                empty_hint='Run `aivm config init` to define one.',
            )
        )
    return rec


def network_users(reg: Store, network_name: str) -> list[str]:
    return sorted(v.name for v in reg.vms if v.network_name == network_name)


def materialize_vm_cfg(reg: Store, vm_name: str) -> AgentVMConfig:
    """Build an effective VM config by joining VM entry + referenced network.

    VM records keep only a ``network_name`` pointer; network/firewall details
    live in ``[[networks]]``. This join step avoids stale duplicated network
    settings in VM entries and centralizes network edits.
    """
    vm = require_vm(reg, vm_name)
    net = find_network(reg, vm.network_name)
    if net is None:
        raise AIVMError(
            f"VM '{vm_name}' references unknown network '{vm.network_name}'. "
            'Define it under [[networks]].'
        )
    cfg = vm.cfg.expanded_paths()
    cfg.network = NetworkConfig(**asdict(net.network))
    cfg.firewall = FirewallConfig(**asdict(net.firewall))
    cfg.network.name = net.name
    return cfg


def _attachment_path_matches(
    candidates: Sequence[AttachmentEntry], host_path: str | Path
) -> list[AttachmentEntry]:
    """Match a stored attachment without requiring the source to exist.

    Lexical stored paths and aliases are authoritative for teardown. Filesystem
    canonicalization is only an additional strategy when both objects still
    exist; disappearance of the source must never make detach impossible.
    """
    norm = _norm_dir(host_path)
    exact = [item for item in candidates if item.host_path == norm]
    aliases = [
        item
        for item in candidates
        if item not in exact and norm in (item.host_lexical_paths or ())
    ]
    if exact or aliases:
        return exact + aliases

    try:
        target_resolved = str(Path(norm).resolve(strict=True))
    except OSError:
        return []
    resolved: list[AttachmentEntry] = []
    for item in candidates:
        try:
            stored_resolved = str(Path(item.host_path).resolve(strict=True))
        except OSError:
            continue
        if stored_resolved == target_resolved:
            resolved.append(item)
    return resolved


def _attachment_sort_key(item: AttachmentEntry) -> tuple[str, str, str, str]:
    return (
        item.owner_principal_id,
        item.vm_name,
        item.guest_dst,
        item.tag,
    )


def find_attachments(
    reg: Store,
    host_path: str | Path,
    *,
    owner_principal_id: str | None = None,
) -> list[AttachmentEntry]:
    """Return all attachment records matching a lexical path or saved alias."""
    candidates = [
        item
        for item in reg.attachments
        if (
            owner_principal_id is None
            or item.owner_principal_id == owner_principal_id
        )
    ]
    return sorted(
        _attachment_path_matches(candidates, host_path),
        key=_attachment_sort_key,
    )


def find_attachments_for_vm(
    reg: Store,
    vm_name: str,
    *,
    owner_principal_id: str | None = None,
) -> list[AttachmentEntry]:
    vm_name = str(vm_name).strip()
    return sorted(
        (
            att
            for att in reg.attachments
            if att.vm_name == vm_name
            and (
                owner_principal_id is None
                or att.owner_principal_id == owner_principal_id
            )
        ),
        key=lambda att: (
            att.owner_principal_id,
            att.host_path,
            att.guest_dst,
            att.tag,
        ),
    )


def find_attachment_for_vm(
    reg: Store,
    host_path: str | Path,
    vm_name: str,
    *,
    owner_principal_id: str | None = None,
) -> AttachmentEntry | None:
    """Locate one unambiguous VM attachment without requiring source access."""
    matches = [
        item
        for item in find_attachments(
            reg, host_path, owner_principal_id=owner_principal_id
        )
        if item.vm_name == vm_name
    ]
    if len(matches) > 1:
        details = '; '.join(
            f'owner={item.owner_principal_id or "legacy"}, '
            f'guest_dst={item.guest_dst or "(default)"}, tag={item.tag or "(none)"}'
            for item in matches
        )
        raise AIVMError(
            f'Multiple attachment records match {str(host_path)!r} on VM '
            f'{vm_name!r}: {details}. Select an owner or guest destination '
            'explicitly before detaching.'
        )
    return matches[0] if matches else None


def find_attachments_for_vm_path(
    reg: Store, host_path: str | Path, vm_name: str
) -> list[AttachmentEntry]:
    """Return every owner record matching one VM-local lexical path."""
    return [
        item
        for item in find_attachments(reg, host_path)
        if item.vm_name == vm_name
    ]


def find_attachment_by_guest_dst(
    reg: Store,
    *,
    vm_name: str,
    guest_dst: str,
    owner_principal_id: str | None = None,
) -> AttachmentEntry | None:
    """Locate one attachment by its machine-global guest destination."""
    target = str(guest_dst or '').strip()
    matches = [
        att
        for att in reg.attachments
        if att.vm_name == vm_name
        and att.guest_dst == target
        and (
            owner_principal_id is None
            or att.owner_principal_id == owner_principal_id
        )
    ]
    if len(matches) > 1:
        owners = ', '.join(
            sorted(att.owner_principal_id or '(legacy)' for att in matches)
        )
        raise AIVMError(
            f'Multiple attachments for VM {vm_name!r} use guest destination '
            f'{target!r}: {owners}.'
        )
    return matches[0] if matches else None


def find_attachment(
    reg: Store, host_path: str | Path
) -> AttachmentEntry | None:
    atts = sorted(
        find_attachments(reg, host_path),
        key=lambda att: (att.vm_name, att.guest_dst, att.tag),
    )
    return atts[0] if atts else None


def find_credentials_for_vm(
    reg: Store,
    vm_name: str,
    *,
    principal_id: str | None = None,
) -> list[CredentialEntry]:
    principal = (
        None if principal_id is None else str(principal_id or '').strip()
    )
    return sorted(
        (
            item
            for item in reg.credentials
            if item.vm_name == vm_name
            and (principal is None or item.principal_id == principal)
        ),
        key=lambda item: (item.principal_id, item.id),
    )


def find_credential(
    reg: Store,
    *,
    vm_name: str,
    credential_id: str,
    principal_id: str | None = None,
) -> CredentialEntry | None:
    principal = (
        None if principal_id is None else str(principal_id or '').strip()
    )
    matches = [
        item
        for item in reg.credentials
        if item.vm_name == vm_name
        and item.id == credential_id
        and (principal is None or item.principal_id == principal)
    ]
    if len(matches) > 1:
        raise AIVMError(
            f'Multiple credential records for VM {vm_name!r} use id '
            f'{credential_id!r}; select an owner principal explicitly.'
        )
    return matches[0] if matches else None
