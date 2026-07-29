"""Schema compatibility helpers for released pre-0.6 stores."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from loguru import logger as log

from ...config import AgentVMConfig
from ...config_store.models import Store

_VALID_STORE_KINDS = {'legacy', 'machine'}


@dataclass(frozen=True)
class ParsedHeaderCompatibility:
    """Compatibility state carried while parsing one store document."""

    parsed_schema_version: int
    mirror_shared_home_folders: bool | None


def parse_store_header(
    raw: Mapping[str, object],
    reg: Store,
) -> ParsedHeaderCompatibility:
    """Parse fields whose old and 0.6 locations differ."""
    schema_version_raw = raw.get('schema_version', 5)
    if not isinstance(schema_version_raw, (str, bytes, bytearray, int, float)):
        raise TypeError(
            'schema_version must be an integer-compatible scalar, '
            f'not {type(schema_version_raw).__name__}'
        )
    parsed_schema_version = int(schema_version_raw)
    reg.schema_version = parsed_schema_version
    store_kind = str(raw.get('store_kind', 'legacy') or 'legacy').strip()
    if store_kind not in _VALID_STORE_KINDS:
        allowed = ', '.join(sorted(_VALID_STORE_KINDS))
        raise ValueError(
            f'Invalid store_kind {store_kind!r}; expected one of: {allowed}'
        )
    reg.store_kind = store_kind
    reg.active_vm = str(raw.get('active_vm', '')).strip()

    mirror_home: bool | None = None
    behavior_raw = raw.get('behavior')
    if isinstance(behavior_raw, dict):
        for key, value in behavior_raw.items():
            if not isinstance(key, str):
                raise TypeError(
                    'behavior field names must be strings, '
                    f'not {type(key).__name__}'
                )
            if key == 'mirror_shared_home_folders':
                mirror_home = bool(value)
            elif hasattr(reg.behavior, key):
                setattr(reg.behavior, key, value)
    return ParsedHeaderCompatibility(
        parsed_schema_version=parsed_schema_version,
        mirror_shared_home_folders=mirror_home,
    )


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
    state: ParsedHeaderCompatibility,
) -> None:
    """Record in-memory upgrades caused solely by pre-0.6 compatibility."""
    if state.mirror_shared_home_folders is not None:
        reg.schema_version = max(reg.schema_version, 6)
    if state.parsed_schema_version < 7 and any(
        attachment.host_lexical_paths for attachment in reg.attachments
    ):
        reg.schema_version = max(reg.schema_version, 7)
