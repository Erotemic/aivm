"""Selection policy for released pre-0.6 stores."""

from __future__ import annotations

from pathlib import Path

from ...config_store.io import split_source_paths
from .paths import store_path


def store_exists(path: Path) -> bool:
    """Return whether a released monolithic or split store exists."""
    return bool(split_source_paths(path))


def selected_store_path(
    config_opt: str | None,
    *,
    machine_store_path: Path,
) -> Path | None:
    """Return the pre-0.6 store selected by released routing semantics.

    An explicit non-machine ``--config`` path always uses released semantics,
    even before the file exists.  An implicit selection returns the released
    default only when it already exists; otherwise the caller may initialize a
    new machine/profile installation.
    """
    if config_opt:
        explicit = Path(config_opt).expanduser().resolve()
        if explicit != machine_store_path:
            return explicit
        return None
    candidate = store_path().expanduser().resolve()
    return candidate if store_exists(candidate) else None
