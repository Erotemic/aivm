"""Lookup and materialization helpers for the AIVM config store."""

from __future__ import annotations

import difflib
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from ..errors import AIVMError
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
        if lowered and (lowered in candidate.lower() or candidate.lower() in lowered)
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


def find_attachments(
    reg: Store,
    host_path: str | Path,
    *,
    owner_principal_id: str | None = None,
) -> list[AttachmentEntry]:
    norm = _norm_dir(host_path)
    return [
        att
        for att in reg.attachments
        if att.host_path == norm
        and (
            owner_principal_id is None
            or att.owner_principal_id == owner_principal_id
        )
    ]


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
    """Locate an attachment for ``vm_name`` by host path.

    Match precedence:

    1. Exact lexical match against ``att.host_path``.
    2. Match against any of ``att.host_lexical_paths`` aliases.
    3. Match where ``resolve(input) == resolve(att.host_path)`` — handles the
       case where the user later attaches via the canonical path that an
       existing record was registered as a symlinked alias of (or vice
       versa). Resolving on every comparison would be slow on stores with
       many attachments; we only resolve when (1) and (2) miss.
    """
    norm = _norm_dir(host_path)
    candidates = [
        a
        for a in reg.attachments
        if a.vm_name == vm_name
        and (
            owner_principal_id is None
            or a.owner_principal_id == owner_principal_id
        )
    ]
    for att in candidates:
        if att.host_path == norm:
            return att
    for att in candidates:
        if norm in (att.host_lexical_paths or []):
            return att
    try:
        target_resolved = str(Path(norm).resolve())
    except OSError:
        return None
    for att in candidates:
        try:
            if str(Path(att.host_path).resolve()) == target_resolved:
                return att
        except OSError:
            continue
    return None



def find_attachments_for_vm_path(
    reg: Store, host_path: str | Path, vm_name: str
) -> list[AttachmentEntry]:
    """Return every owner's record matching one VM-local host path."""
    norm = _norm_dir(host_path)
    candidates = [att for att in reg.attachments if att.vm_name == vm_name]
    exact = [att for att in candidates if att.host_path == norm]
    aliases = [
        att
        for att in candidates
        if att not in exact and norm in (att.host_lexical_paths or [])
    ]
    if exact or aliases:
        return sorted(
            exact + aliases,
            key=lambda att: (att.owner_principal_id, att.guest_dst, att.tag),
        )
    try:
        target_resolved = str(Path(norm).resolve())
    except OSError:
        return []
    resolved: list[AttachmentEntry] = []
    for att in candidates:
        try:
            if str(Path(att.host_path).resolve()) == target_resolved:
                resolved.append(att)
        except OSError:
            continue
    return sorted(
        resolved,
        key=lambda att: (att.owner_principal_id, att.guest_dst, att.tag),
    )


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
    reg: Store, vm_name: str
) -> list[CredentialEntry]:
    return sorted(
        (item for item in reg.credentials if item.vm_name == vm_name),
        key=lambda item: item.id,
    )


def find_credential(
    reg: Store, *, vm_name: str, credential_id: str
) -> CredentialEntry | None:
    for item in reg.credentials:
        if item.vm_name == vm_name and item.id == credential_id:
            return item
    return None
