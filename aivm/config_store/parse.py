"""Parse TOML text into the logical AIVM config store model."""

from __future__ import annotations

import tomllib
from pathlib import Path

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from .models import AttachmentEntry, NetworkEntry, Store, VMEntry


def _norm_dir(path: str | Path) -> str:
    p = Path(path).expanduser()
    try:
        return str(p.resolve())
    except Exception:
        return str(p.absolute())


def _cfg_from_dict(raw: dict[str, object]) -> AgentVMConfig:
    cfg = AgentVMConfig()
    for section in (
        'vm',
        'network',
        'firewall',
        'image',
        'provision',
        'paths',
        'virtiofs',
    ):
        body = raw.get(section, None)
        if isinstance(body, dict):
            obj = getattr(cfg, section)
            for k, v in body.items():
                if hasattr(obj, str(k)):
                    setattr(obj, str(k), v)
    verbosity_val = raw.get('verbosity')
    if verbosity_val is not None:
        cfg.verbosity = int(verbosity_val)  # type: ignore
    return cfg


def parse_store_toml(text: str) -> Store:
    """Parse a canonical AIVM desired-state TOML document."""
    raw = tomllib.loads(text)
    reg = Store()
    reg.schema_version = int(raw.get('schema_version', 5))
    reg.active_vm = str(raw.get('active_vm', '')).strip()
    behavior_raw = raw.get('behavior', None)
    if isinstance(behavior_raw, dict):
        for k, v in behavior_raw.items():
            if hasattr(reg.behavior, k):
                setattr(reg.behavior, k, v)
    defaults_raw = raw.get('defaults', None)
    if isinstance(defaults_raw, dict):
        reg.defaults = _cfg_from_dict(defaults_raw).expanded_paths()

    for item in raw.get('networks', []):
        if not isinstance(item, dict):
            continue
        net = NetworkConfig()
        fw = FirewallConfig()
        net_raw = item.get('network', None)
        if isinstance(net_raw, dict):
            for k, v in net_raw.items():
                if hasattr(net, k):
                    setattr(net, k, v)
        fw_raw = item.get('firewall', None)
        if isinstance(fw_raw, dict):
            for k, v in fw_raw.items():
                if hasattr(fw, k):
                    setattr(fw, k, v)
        name = str(item.get('name', '')).strip()
        if not name:
            name = str(net.name or '').strip()
        if not name:
            continue
        net.name = name
        reg.networks.append(NetworkEntry(name=name, network=net, firewall=fw))

    for item in raw.get('vms', []):
        if not isinstance(item, dict):
            continue
        name = str(item.get('name', '')).strip()
        if not name:
            continue
        cfg = _cfg_from_dict(item).expanded_paths()
        cfg.vm.name = name
        network_name = str(item.get('network_name', '')).strip()
        if not network_name:
            network_name = str(cfg.network.name or '').strip()
        if not network_name:
            network_name = 'aivm-net'
        reg.vms.append(VMEntry(name=name, network_name=network_name, cfg=cfg))

    for item in raw.get('attachments', []):
        if not isinstance(item, dict):
            continue
        host_path = str(item.get('host_path', '')).strip()
        vm_name = str(item.get('vm_name', '')).strip()
        if not host_path or not vm_name:
            continue
        reg.attachments.append(
            AttachmentEntry(
                host_path=_norm_dir(host_path),
                vm_name=vm_name,
                mode=str(item.get('mode', 'shared') or 'shared'),
                access=str(item.get('access', 'rw') or 'rw'),
                guest_dst=str(item.get('guest_dst', '')).strip(),
                tag=str(item.get('tag', '')).strip(),
                host_lexical_path=str(
                    item.get('host_lexical_path', '')
                ).strip(),
            )
        )
    return reg
