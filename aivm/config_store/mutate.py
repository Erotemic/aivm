"""Mutation helpers for the logical AIVM config store."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..legacy.pre_0_6_0 import compatibility_surface
from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from .models import (
    AttachmentEntry,
    CredentialEntry,
    NetworkEntry,
    PrincipalEntry,
    Store,
    VMEntry,
)
from .parse import _norm_dir


def upsert_vm(reg: Store, cfg: AgentVMConfig) -> None:
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)


@compatibility_surface
def upsert_vm_with_network(
    reg: Store, cfg: AgentVMConfig, *, network_name: str
) -> None:
    cfg = cfg.expanded_paths()
    name = cfg.vm.name
    net_name = str(network_name or '').strip()
    if not net_name:
        net_name = str(cfg.network.name or '').strip() or 'aivm-net'
    rec = VMEntry(name=name, network_name=net_name, cfg=cfg)
    existing = [v for v in reg.vms if v.name == name]
    if existing:
        i = reg.vms.index(existing[0])
        reg.vms[i] = rec
    else:
        reg.vms.append(rec)
    if reg.store_kind != 'machine':
        reg.active_vm = name


def upsert_network(
    reg: Store,
    *,
    network: NetworkConfig,
    firewall: FirewallConfig | None = None,
    name: str | None = None,
) -> None:
    net_name = str(name or network.name or '').strip()
    if not net_name:
        raise RuntimeError('network name must be non-empty')
    net = NetworkConfig(**asdict(network))
    net.name = net_name
    fw = (
        FirewallConfig(**asdict(firewall))
        if firewall is not None
        else FirewallConfig()
    )
    rec = NetworkEntry(name=net_name, network=net, firewall=fw)
    existing = [n for n in reg.networks if n.name == net_name]
    if existing:
        i = reg.networks.index(existing[0])
        reg.networks[i] = rec
    else:
        reg.networks.append(rec)


def remove_network(reg: Store, network_name: str) -> bool:
    existing = [n for n in reg.networks if n.name == network_name]
    if not existing:
        return False
    reg.networks = [n for n in reg.networks if n.name != network_name]
    return True


def remove_vm(
    reg: Store, vm_name: str, *, remove_attachments: bool = True
) -> bool:
    existing = [v for v in reg.vms if v.name == vm_name]
    if not existing:
        return False
    reg.vms = [v for v in reg.vms if v.name != vm_name]
    if remove_attachments:
        reg.attachments = [a for a in reg.attachments if a.vm_name != vm_name]
    reg.credentials = [c for c in reg.credentials if c.vm_name != vm_name]
    reg.principals = [p for p in reg.principals if p.vm_name != vm_name]
    if reg.active_vm == vm_name:
        reg.active_vm = reg.vms[0].name if reg.vms else ''
    return True


def upsert_attachment(
    reg: Store,
    *,
    host_path: str | Path,
    vm_name: str,
    owner_principal_id: str = '',
    mode: str = 'shared',
    access: str = 'rw',
    guest_dst: str = '',
    tag: str = '',
    state: str = 'active',
    source_dev: int = 0,
    source_ino: int = 0,
    host_lexical_paths: list[str] | tuple[str, ...] | None = None,
    host_lexical_path: str | None = None,
) -> None:
    """Insert or replace an attachment record.

    ``host_lexical_paths`` is the canonical list of lexical aliases (typed
    paths that resolve to ``host_path``). ``host_lexical_path`` (singular)
    is accepted for backwards compatibility with code written against the
    pre-schema-7 API but is deprecated and emits a warning.
    """
    paths: list[str] = []
    seen: set[str] = set()
    if host_lexical_paths:
        for p in host_lexical_paths:
            s = str(p).strip()
            if s and s not in seen:
                seen.add(s)
                paths.append(s)
    if host_lexical_path is not None:
        from loguru import logger as _log

        _log.warning(
            'upsert_attachment kwarg "host_lexical_path" is deprecated; '
            'pass "host_lexical_paths" instead.'
        )
        legacy = str(host_lexical_path).strip()
        if legacy and legacy not in seen:
            seen.add(legacy)
            paths.append(legacy)
    norm = _norm_dir(host_path)
    owner_principal_id = str(owner_principal_id or '').strip()
    existing = [
        a
        for a in reg.attachments
        if a.host_path == norm
        and a.vm_name == vm_name
        and a.owner_principal_id == owner_principal_id
    ]
    rec = AttachmentEntry(
        host_path=norm,
        vm_name=vm_name,
        owner_principal_id=owner_principal_id,
        mode=mode,
        access=access,
        guest_dst=guest_dst,
        tag=tag,
        state=state,
        source_dev=int(source_dev),
        source_ino=int(source_ino),
        host_lexical_paths=paths,
    )
    if existing:
        i = reg.attachments.index(existing[0])
        reg.attachments[i] = rec
    else:
        reg.attachments.append(rec)
    if owner_principal_id:
        reg.schema_version = max(reg.schema_version, 10)


def remove_attachment(
    reg: Store,
    *,
    host_path: str | Path,
    vm_name: str,
    owner_principal_id: str | None = None,
) -> bool:
    norm = _norm_dir(host_path)
    vm_name = str(vm_name).strip()
    owner = (
        None
        if owner_principal_id is None
        else str(owner_principal_id or '').strip()
    )
    orig_n = len(reg.attachments)
    reg.attachments = [
        a
        for a in reg.attachments
        if not (
            a.host_path == norm
            and a.vm_name == vm_name
            and (owner is None or a.owner_principal_id == owner)
        )
    ]
    return len(reg.attachments) != orig_n


def upsert_credential(reg: Store, credential: CredentialEntry) -> None:
    existing = [
        item
        for item in reg.credentials
        if item.vm_name == credential.vm_name
        and item.id == credential.id
        and item.principal_id == credential.principal_id
    ]
    if existing:
        reg.credentials[reg.credentials.index(existing[0])] = credential
    else:
        reg.credentials.append(credential)
    if credential.principal_id:
        reg.schema_version = max(reg.schema_version, 11)


def remove_credential(
    reg: Store,
    *,
    vm_name: str,
    credential_id: str,
    principal_id: str | None = None,
) -> bool:
    principal = (
        None if principal_id is None else str(principal_id or '').strip()
    )
    original = len(reg.credentials)
    reg.credentials = [
        item
        for item in reg.credentials
        if not (
            item.vm_name == vm_name
            and item.id == credential_id
            and (principal is None or item.principal_id == principal)
        )
    ]
    return len(reg.credentials) != original


def upsert_principal(reg: Store, principal: PrincipalEntry) -> None:
    """Insert or replace one VM principal by stable id."""
    existing = [item for item in reg.principals if item.id == principal.id]
    if existing:
        reg.principals[reg.principals.index(existing[0])] = principal
    else:
        reg.principals.append(principal)
    reg.schema_version = max(reg.schema_version, 9)


def remove_principal(reg: Store, *, vm_name: str, principal_id: str) -> bool:
    original = len(reg.principals)
    reg.principals = [
        item
        for item in reg.principals
        if not (item.vm_name == vm_name and item.id == principal_id)
    ]
    return len(reg.principals) != original
