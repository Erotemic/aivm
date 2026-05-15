"""Lookup and materialization helpers for the AIVM config store."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from .models import AttachmentEntry, NetworkEntry, Store, VMEntry
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


def network_users(reg: Store, network_name: str) -> list[str]:
    return sorted(v.name for v in reg.vms if v.network_name == network_name)


def materialize_vm_cfg(reg: Store, vm_name: str) -> AgentVMConfig:
    """Build an effective VM config by joining VM entry + referenced network.

    VM records keep only a ``network_name`` pointer; network/firewall details
    live in ``[[networks]]``. This join step avoids stale duplicated network
    settings in VM entries and centralizes network edits.
    """
    vm = find_vm(reg, vm_name)
    if vm is None:
        raise RuntimeError(f'VM not found in config store: {vm_name}')
    net = find_network(reg, vm.network_name)
    if net is None:
        raise RuntimeError(
            f"VM '{vm_name}' references unknown network '{vm.network_name}'. "
            'Define it under [[networks]].'
        )
    cfg = vm.cfg.expanded_paths()
    cfg.network = NetworkConfig(**asdict(net.network))
    cfg.firewall = FirewallConfig(**asdict(net.firewall))
    cfg.network.name = net.name
    return cfg


def find_attachments(
    reg: Store, host_path: str | Path
) -> list[AttachmentEntry]:
    norm = _norm_dir(host_path)
    return [att for att in reg.attachments if att.host_path == norm]


def find_attachments_for_vm(reg: Store, vm_name: str) -> list[AttachmentEntry]:
    vm_name = str(vm_name).strip()
    return sorted(
        (att for att in reg.attachments if att.vm_name == vm_name),
        key=lambda att: (att.host_path, att.guest_dst, att.tag),
    )


def find_attachment_for_vm(
    reg: Store, host_path: str | Path, vm_name: str
) -> AttachmentEntry | None:
    norm = _norm_dir(host_path)
    for att in reg.attachments:
        if att.host_path == norm and att.vm_name == vm_name:
            return att
    return None


def find_attachment(
    reg: Store, host_path: str | Path
) -> AttachmentEntry | None:
    atts = sorted(
        find_attachments(reg, host_path),
        key=lambda att: (att.vm_name, att.guest_dst, att.tag),
    )
    return atts[0] if atts else None
