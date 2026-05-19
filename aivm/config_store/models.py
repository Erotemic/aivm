"""Logical desired-state models for the AIVM config store."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import AgentVMConfig, BehaviorConfig, FirewallConfig, NetworkConfig


@dataclass
class VMEntry:
    name: str
    network_name: str
    cfg: AgentVMConfig


@dataclass
class NetworkEntry:
    name: str
    network: NetworkConfig = field(default_factory=NetworkConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)


@dataclass
class AttachmentEntry:
    host_path: str
    vm_name: str
    mode: str = 'shared'
    access: str = 'rw'
    guest_dst: str = ''
    tag: str = ''
    host_lexical_path: str = ''


@dataclass
class Store:
    schema_version: int = 6
    active_vm: str = ''
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    defaults: AgentVMConfig | None = None
    networks: list[NetworkEntry] = field(default_factory=list)
    vms: list[VMEntry] = field(default_factory=list)
    attachments: list[AttachmentEntry] = field(default_factory=list)
