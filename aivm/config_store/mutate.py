"""Mutation helpers for the logical AIVM config store."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from .models import AttachmentEntry, NetworkEntry, Store, VMEntry
from .parse import _norm_dir


def upsert_vm(reg: Store, cfg: AgentVMConfig) -> None:
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)


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
    if reg.active_vm == vm_name:
        reg.active_vm = reg.vms[0].name if reg.vms else ''
    return True


def upsert_attachment(
    reg: Store,
    *,
    host_path: str | Path,
    vm_name: str,
    mode: str = 'shared',
    access: str = 'rw',
    guest_dst: str = '',
    tag: str = '',
    host_lexical_path: str = '',
) -> None:
    norm = _norm_dir(host_path)
    existing = [
        a
        for a in reg.attachments
        if a.host_path == norm and a.vm_name == vm_name
    ]
    rec = AttachmentEntry(
        host_path=norm,
        vm_name=vm_name,
        mode=mode,
        access=access,
        guest_dst=guest_dst,
        tag=tag,
        host_lexical_path=host_lexical_path,
    )
    if existing:
        i = reg.attachments.index(existing[0])
        reg.attachments[i] = rec
    else:
        reg.attachments.append(rec)


def remove_attachment(
    reg: Store,
    *,
    host_path: str | Path,
    vm_name: str,
) -> bool:
    norm = _norm_dir(host_path)
    vm_name = str(vm_name).strip()
    orig_n = len(reg.attachments)
    reg.attachments = [
        a
        for a in reg.attachments
        if not (a.host_path == norm and a.vm_name == vm_name)
    ]
    return len(reg.attachments) != orig_n
