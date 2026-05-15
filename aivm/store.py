"""Compatibility facade for AIVM's desired-state config store.

Historically this module contained the store data model, TOML codec, physical
single-file I/O, lookup helpers, and mutation helpers.  The implementation now
lives under :mod:`aivm.config_store` so config-layout work can change physical
storage without changing callers that import from ``aivm.store``.
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger as log

from .config_store import io as _io
from .config_store.io import (
    ConfigSource,
    LoadedStore,
    is_split_layout,
    load_config_document as _load_config_document,
    render_split_fragments,
    save_store_split as _save_store_split,
    format_existing_config as _format_existing_config,
    split_fragment_paths,
    split_source_paths,
)
from .config_store import paths as _paths
from .config_store.models import AttachmentEntry, NetworkEntry, Store, VMEntry
from .config_store.mutate import (
    remove_attachment,
    remove_network,
    remove_vm,
    upsert_attachment,
    upsert_network,
    upsert_vm,
    upsert_vm_with_network,
)
from .config_store.parse import _cfg_from_dict, _norm_dir, parse_store_toml
from .config_store.render import (
    _emit_toml_kv,
    _toml_escape,
    render_store_defaults_toml,
    render_store_networks_toml,
    render_store_root_toml,
    render_store_toml,
    render_store_vm_toml,
)
from .config_store.resolve import (
    find_attachment,
    find_attachment_for_vm,
    find_attachments,
    find_attachments_for_vm,
    find_network,
    find_vm,
    materialize_vm_cfg,
    network_users,
)


def _appdir(appname: str, kind: str) -> Path:
    """Compatibility wrapper for tests/callers that monkeypatch this hook."""
    return _paths._appdir(appname, kind)


def app_data_dir() -> Path:
    """User-writable application data directory for operational artifacts."""
    return _appdir('aivm', 'data')


def app_data_path(*parts: str) -> Path:
    """Return a path under the user-owned aivm data directory."""
    return app_data_dir().joinpath(*parts)


def persistent_host_state_dir(vm_name: str) -> Path:
    """User-owned host-side sync state for persistent attachments."""
    return app_data_path(vm_name, 'state')


def store_path() -> Path:
    return _appdir('aivm', 'config') / 'config.toml'


def load_config_document(path: Path | None = None) -> LoadedStore:
    """Load monolith or split config sources with source metadata.

    The facade supplies ``store_path()`` so historical monkeypatches of
    ``aivm.store._appdir`` continue to affect default path resolution.
    """
    return _load_config_document(path or store_path(), logger=log)


def load_store(path: Path | None = None) -> Store:
    """Load the current single-file config store.

    The facade supplies ``store_path()`` so historical monkeypatches of
    ``aivm.store._appdir`` continue to affect default path resolution.
    """
    return _io.load_store(path or store_path(), logger=log)


def save_store(
    reg: Store, path: Path | None = None, *, reason: str = ''
) -> Path:
    """Save the config store using the active physical layout."""
    return _io.save_store(reg, path or store_path(), reason=reason, logger=log)


def save_store_split(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    dry_run: bool = False,
) -> list[Path]:
    return _save_store_split(
        reg, path or store_path(), reason=reason, dry_run=dry_run, logger=log
    )


def format_existing_config(
    path: Path | None = None,
    *,
    backup: bool = True,
    dry_run: bool = False,
    force: bool = False,
) -> list[Path]:
    return _format_existing_config(
        path or store_path(),
        backup=backup,
        dry_run=dry_run,
        force=force,
        logger=log,
    )


__all__ = [
    'AttachmentEntry',
    'split_source_paths',
    'load_config_document',
    'is_split_layout',
    'LoadedStore',
    'ConfigSource',
    'NetworkEntry',
    'Store',
    'VMEntry',
    '_appdir',
    '_cfg_from_dict',
    '_emit_toml_kv',
    '_norm_dir',
    '_toml_escape',
    'app_data_dir',
    'app_data_path',
    'find_attachment',
    'find_attachment_for_vm',
    'find_attachments',
    'find_attachments_for_vm',
    'find_network',
    'find_vm',
    'load_store',
    'log',
    'materialize_vm_cfg',
    'network_users',
    'parse_store_toml',
    'persistent_host_state_dir',
    'remove_attachment',
    'remove_network',
    'remove_vm',
    'render_split_fragments',
    'save_store_split',
    'format_existing_config',
    'split_fragment_paths',
    'render_store_defaults_toml',
    'render_store_networks_toml',
    'render_store_root_toml',
    'render_store_vm_toml',
    'render_store_toml',
    'save_store',
    'store_path',
    'upsert_attachment',
    'upsert_network',
    'upsert_vm',
    'upsert_vm_with_network',
]
