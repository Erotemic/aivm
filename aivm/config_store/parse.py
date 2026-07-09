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


def _attachment_from_dict(
    item: dict[str, object], *, vm_name: str | None = None
) -> AttachmentEntry | None:
    """Parse one attachment record from either supported TOML shape.

    Legacy configs store attachments as top-level ``[[attachments]]`` records
    and must include ``vm_name``.  The future split-friendly schema stores
    attachments under the owning ``[[vms]]`` record as
    ``[[vms.attachments]]``; those records inherit the VM name from their
    parent.  The in-memory model remains flat for now so existing attachment
    and drift code continues to work unchanged.
    """
    host_path = str(item.get('host_path', '')).strip()
    inherited_vm_name = str(vm_name or '').strip()
    explicit_vm_name = str(item.get('vm_name', '')).strip()
    if (
        inherited_vm_name
        and explicit_vm_name
        and explicit_vm_name != inherited_vm_name
    ):
        raise ValueError(
            'nested VM attachment vm_name mismatch: '
            f'expected {inherited_vm_name!r}, got {explicit_vm_name!r}'
        )
    owner = inherited_vm_name or explicit_vm_name
    if not host_path or not owner:
        return None
    return AttachmentEntry(
        host_path=_norm_dir(host_path),
        vm_name=owner,
        mode=str(item.get('mode', 'shared') or 'shared'),
        access=str(item.get('access', 'rw') or 'rw'),
        guest_dst=str(item.get('guest_dst', '')).strip(),
        tag=str(item.get('tag', '')).strip(),
        host_lexical_paths=_parse_host_lexical_paths(item),
    )


def _parse_host_lexical_paths(item: dict) -> list[str]:
    """Read the lexical-alias list, accepting both new and legacy field names.

    The new schema (>= 7) stores ``host_lexical_paths`` as a TOML array. The
    legacy form ``host_lexical_path`` (a single string from schema 6 / earlier
    schema-6 attach records) is still accepted but produces a deprecation
    warning. If both keys are present the new list-form wins and the singular
    value is folded into it for forward-compat.
    """
    out: list[str] = []
    seen: set[str] = set()
    plural_raw = item.get('host_lexical_paths', None)
    if isinstance(plural_raw, (list, tuple)):
        for v in plural_raw:
            s = str(v).strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    legacy_raw = item.get('host_lexical_path', None)
    if legacy_raw is not None:
        legacy_str = str(legacy_raw).strip()
        if legacy_str:
            from loguru import logger as _log

            _log.warning(
                'Attachment field "host_lexical_path" is deprecated; '
                'use "host_lexical_paths = [...]" (schema 7+). '
                'Migrated value: {}',
                legacy_str,
            )
            if legacy_str not in seen:
                seen.add(legacy_str)
                out.append(legacy_str)
    return out


def parse_store_toml(text: str) -> Store:
    """Parse a canonical AIVM desired-state TOML document."""
    raw = tomllib.loads(text)
    reg = Store()
    parsed_schema_version = int(raw.get('schema_version', 5))
    reg.schema_version = parsed_schema_version
    reg.active_vm = str(raw.get('active_vm', '')).strip()
    # Legacy (schema_version < 6) stored mirror_shared_home_folders under
    # [behavior]. Newer schemas store it per-VM under [vms.vm]. Capture
    # the legacy value so we can lift it onto defaults.vm and each
    # [[vms]].vm below; do not preserve it on reg.behavior.
    legacy_mirror_home: bool | None = None
    behavior_raw = raw.get('behavior', None)
    if isinstance(behavior_raw, dict):
        for k, v in behavior_raw.items():
            if k == 'mirror_shared_home_folders':
                legacy_mirror_home = bool(v)
                continue
            if hasattr(reg.behavior, k):
                setattr(reg.behavior, k, v)
    defaults_raw = raw.get('defaults', None)
    if isinstance(defaults_raw, dict):
        reg.defaults = _cfg_from_dict(defaults_raw).expanded_paths()
        if legacy_mirror_home is not None:
            reg.defaults.vm.mirror_shared_home_folders = legacy_mirror_home
    elif legacy_mirror_home is not None:
        # No [defaults] section: synthesize one so the migrated value is
        # not silently dropped on round-trip.
        reg.defaults = AgentVMConfig()
        reg.defaults.vm.mirror_shared_home_folders = legacy_mirror_home

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
        if legacy_mirror_home is not None:
            # Honor the legacy [behavior] value unless the per-VM block
            # already overrides it. A schema_version<6 document cannot
            # have set the per-VM key intentionally, but a hand-edited
            # mixed file might; respect any explicit override.
            vm_block = item.get('vm', {})
            if not (
                isinstance(vm_block, dict)
                and 'mirror_shared_home_folders' in vm_block
            ):
                cfg.vm.mirror_shared_home_folders = legacy_mirror_home
        network_name = str(item.get('network_name', '')).strip()
        if not network_name:
            network_name = str(cfg.network.name or '').strip()
        if not network_name:
            network_name = 'aivm-net'
        reg.vms.append(VMEntry(name=name, network_name=network_name, cfg=cfg))

        for att_raw in item.get('attachments', []):
            if not isinstance(att_raw, dict):
                continue
            att = _attachment_from_dict(att_raw, vm_name=name)
            if att is not None:
                reg.attachments.append(att)

    for item in raw.get('attachments', []):
        if not isinstance(item, dict):
            continue
        att = _attachment_from_dict(item)
        if att is not None:
            reg.attachments.append(att)
    # If we migrated legacy fields, upgrade the on-disk schema_version so
    # the next write reflects the new layout.
    if legacy_mirror_home is not None:
        reg.schema_version = max(reg.schema_version, 6)
    # Schema 7 introduced host_lexical_paths (list). If any attachment was
    # parsed via the legacy singular form and the file's schema is below 7,
    # bump it so the next save uses the new shape.
    if reg.schema_version < 7 and any(
        att.host_lexical_paths for att in reg.attachments
    ):
        reg.schema_version = 7
    return reg
