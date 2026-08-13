"""Explicit recovery for persistent source identity pins.

Persistent attachment paths are treated as names of approved filesystem
objects, not as authority by themselves.  The normal replay path therefore
refuses to follow a path whose pinned ``st_dev``/``st_ino`` pair changed.
This module provides the deliberate escape hatch: an operator can explicitly
trust the objects currently present at their saved paths and replace the pins.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...config import AgentVMConfig
from ...config_store import AttachmentEntry, Store, load_store, update_store
from ...errors import AIVMError
from ...fs_identity import directory_identity
from ..ownership import require_attachment_mutation_permission
from ..resolve import ATTACHMENT_MODE_PERSISTENT


@dataclass(frozen=True)
class PersistentSourceIdentityRefresh:
    """Result of explicitly trusting the current objects at saved paths."""

    refreshed: tuple[str, ...]
    unchanged: tuple[str, ...]
    unavailable: tuple[tuple[str, str], ...]
    skipped_foreign: tuple[str, ...]


def _active_persistent_records(reg: Store, vm_name: str) -> list[AttachmentEntry]:
    return [
        att
        for att in reg.attachments
        if att.vm_name == vm_name
        and str(att.mode or '').strip() == ATTACHMENT_MODE_PERSISTENT
        and str(att.state or 'active').strip() == 'active'
    ]


def _refresh_in_store(
    reg: Store,
    *,
    vm_name: str,
    current_principal_id: str,
    administrative_override: bool,
) -> PersistentSourceIdentityRefresh:
    refreshed: list[str] = []
    unchanged: list[str] = []
    unavailable: list[tuple[str, str]] = []
    skipped_foreign: list[str] = []

    for att in _active_persistent_records(reg, vm_name):
        try:
            require_attachment_mutation_permission(
                reg,
                att,
                current_principal_id=current_principal_id,
                administrative_override=administrative_override,
            )
        except AIVMError:
            skipped_foreign.append(att.host_path)
            continue

        try:
            identity = directory_identity(Path(att.host_path))
        except (OSError, ValueError) as ex:
            unavailable.append((att.host_path, str(ex)))
            continue

        current = (int(att.source_dev), int(att.source_ino))
        replacement = (identity.dev, identity.ino)
        if current == replacement:
            unchanged.append(att.host_path)
            continue

        # The no-symlink walk above happens inside the store transaction on
        # the mutating path, so the identity committed here is live evidence
        # from the authorization operation rather than a stale planning probe.
        att.source_dev = identity.dev
        att.source_ino = identity.ino
        refreshed.append(att.host_path)

    return PersistentSourceIdentityRefresh(
        refreshed=tuple(refreshed),
        unchanged=tuple(unchanged),
        unavailable=tuple(unavailable),
        skipped_foreign=tuple(skipped_foreign),
    )


def refresh_persistent_source_identities(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    current_principal_id: str,
    administrative_override: bool,
    dry_run: bool,
) -> PersistentSourceIdentityRefresh:
    """Trust and repin current source objects for authorized attachments.

    ``dry_run`` performs the same descriptor-pinned identity probes without
    mutating the store.  A real refresh recomputes every identity while the
    store update lock is held, which avoids treating pre-confirmation kernel
    state as timeless.
    """

    if dry_run:
        return _refresh_in_store(
            load_store(cfg_path),
            vm_name=cfg.vm.name,
            current_principal_id=current_principal_id,
            administrative_override=administrative_override,
        )

    result: PersistentSourceIdentityRefresh | None = None

    def mutate(reg: Store) -> None:
        nonlocal result
        result = _refresh_in_store(
            reg,
            vm_name=cfg.vm.name,
            current_principal_id=current_principal_id,
            administrative_override=administrative_override,
        )
        return None

    update_store(
        mutate,
        cfg_path,
        reason=(
            'Explicitly trust current host objects and refresh persistent '
            f'attachment source identities for VM {cfg.vm.name}.'
        ),
    )
    assert result is not None
    return result
