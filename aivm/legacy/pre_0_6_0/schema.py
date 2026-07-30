"""Schema compatibility helpers for released pre-0.6 stores.

Everything here exists only to read documents written before AIVM 0.6:
the behavior-level ``mirror_shared_home_folders`` location (pre-schema-6)
and the singular ``host_lexical_path`` attachment field (pre-schema-7).
Deleting this module must only cost the ability to read those old
documents; parsing of current stores lives in :mod:`aivm.config_store.parse`.
"""

from __future__ import annotations

from typing import Mapping

from loguru import logger as log

from ...config import AgentVMConfig
from ...config_store.models import Store


def mirror_home_from_behavior(raw: Mapping[str, object]) -> bool | None:
    """Read the pre-schema-6 behavior-level mirror setting, if present."""
    behavior_raw = raw.get('behavior')
    if not isinstance(behavior_raw, dict):
        return None
    value = behavior_raw.get('mirror_shared_home_folders')
    if value is None:
        return None
    return bool(value)


def apply_mirror_home_to_defaults(
    reg: Store,
    mirror_home: bool | None,
) -> None:
    """Preserve the pre-schema-6 behavior-level mirror setting."""
    if mirror_home is None:
        return
    if reg.defaults is None:
        reg.defaults = AgentVMConfig()
    reg.defaults.vm.mirror_shared_home_folders = mirror_home


def apply_mirror_home_to_vm(
    cfg: AgentVMConfig,
    vm_raw: Mapping[str, object],
    mirror_home: bool | None,
) -> None:
    """Lift the pre-schema-6 mirror setting onto one effective VM."""
    if mirror_home is None:
        return
    vm_block = vm_raw.get('vm', {})
    if not (
        isinstance(vm_block, dict) and 'mirror_shared_home_folders' in vm_block
    ):
        cfg.vm.mirror_shared_home_folders = mirror_home


def parse_host_lexical_paths(item: Mapping[str, object]) -> list[str]:
    """Read schema-7 aliases while accepting the released singular field."""
    out: list[str] = []
    seen: set[str] = set()
    plural_raw = item.get('host_lexical_paths')
    if isinstance(plural_raw, (list, tuple)):
        for value in plural_raw:
            text = str(value).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)

    singular_raw = item.get('host_lexical_path')
    if singular_raw is not None:
        singular = str(singular_raw).strip()
        if singular:
            log.warning(
                'Attachment field "host_lexical_path" is deprecated; '
                'use "host_lexical_paths = [...]" (schema 7+). '
                'Migrated value: {}',
                singular,
            )
            if singular not in seen:
                out.append(singular)
    return out


def finalize_schema_version(
    reg: Store,
    *,
    parsed_schema_version: int,
    mirror_home: bool | None,
) -> None:
    """Record in-memory upgrades caused solely by pre-0.6 compatibility."""
    if mirror_home is not None:
        reg.schema_version = max(reg.schema_version, 6)
    if parsed_schema_version < 7 and any(
        attachment.host_lexical_paths for attachment in reg.attachments
    ):
        reg.schema_version = max(reg.schema_version, 7)
