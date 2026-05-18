"""Physical I/O for AIVM's desired-state config store.

This module currently supports two physical layouts that parse into the same
logical :class:`Store` model:

* legacy monolith: ``config.toml`` contains the whole document;
* split fragments: ``config.toml`` + ``defaults.toml`` + ``networks.toml``
  + ``vms/*.toml`` concatenate into the canonical document.

Split layouts can now be read and written.  Existing monolithic configs stay
supported, and `aivm config format` can canonicalize a monolith into fragments.
"""

from __future__ import annotations

import re
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from loguru import logger as log

from .models import Store
from .parse import parse_store_toml
from .paths import store_path
from .render import (
    render_store_defaults_toml,
    render_store_networks_toml,
    render_store_root_toml,
    render_store_toml,
    render_store_vm_toml,
)


@dataclass(frozen=True)
class ConfigSource:
    """One physical TOML fragment that contributed to a loaded document."""

    path: Path
    role: str


@dataclass
class LoadedStore:
    """A parsed store plus information about where it came from."""

    store: Store
    sources: list[ConfigSource] = field(default_factory=list)
    layout: str = 'monolith'
    source_text: str = ''
    vm_sources: dict[str, Path] = field(default_factory=dict)
    network_sources: dict[str, Path] = field(default_factory=dict)


def config_dir_from_path(path: Path | None = None) -> Path:
    """Return the config directory associated with a root config path."""
    fpath = path or store_path()
    return fpath.expanduser().resolve().parent


def split_source_paths(path: Path | None = None) -> list[ConfigSource]:
    """Return existing split/monolith config sources in load order.

    Load order is the concatenation contract:

    1. root ``config.toml``;
    2. sibling ``defaults.toml``;
    3. sibling ``networks.toml``;
    4. sorted sibling ``vms/*.toml``.
    """
    root = (path or store_path()).expanduser().resolve()
    cfg_dir = root.parent
    sources: list[ConfigSource] = []
    if root.exists():
        sources.append(ConfigSource(root, 'root'))
    defaults = cfg_dir / 'defaults.toml'
    if defaults.exists():
        sources.append(ConfigSource(defaults, 'defaults'))
    networks = cfg_dir / 'networks.toml'
    if networks.exists():
        sources.append(ConfigSource(networks, 'networks'))
    vms_dir = cfg_dir / 'vms'
    if vms_dir.exists():
        for vm_path in sorted(vms_dir.glob('*.toml')):
            if vm_path.is_file():
                sources.append(ConfigSource(vm_path, 'vm'))
    return sources


def is_split_layout(path: Path | None = None) -> bool:
    """Return True if split-layout fragments exist next to ``path``."""
    sources = split_source_paths(path)
    return any(src.role != 'root' for src in sources)


def _concat_sources(sources: Iterable[ConfigSource]) -> str:
    parts: list[str] = []
    for src in sources:
        text = src.path.read_text(encoding='utf-8')
        parts.append(f'\n# --- aivm config source: {src.path} ({src.role}) ---\n')
        parts.append(text.rstrip())
        parts.append('\n')
    return ''.join(parts).lstrip()


def _raw_names_from_text(text: str) -> tuple[list[str], list[str]]:
    raw = tomllib.loads(text) if text.strip() else {}
    vm_names: list[str] = []
    net_names: list[str] = []
    for item in raw.get('vms', []) or []:
        if isinstance(item, dict):
            name = str(item.get('name', '')).strip()
            if name:
                vm_names.append(name)
    for item in raw.get('networks', []) or []:
        if isinstance(item, dict):
            name = str(item.get('name', '')).strip()
            net = item.get('network', None)
            if not name and isinstance(net, dict):
                name = str(net.get('name', '')).strip()
            if name:
                net_names.append(name)
    return vm_names, net_names


def _record_source_names(
    src: ConfigSource,
    text: str,
    *,
    vm_sources: dict[str, Path],
    network_sources: dict[str, Path],
) -> None:
    vm_names, net_names = _raw_names_from_text(text)
    for name in vm_names:
        if name in vm_sources:
            raise ValueError(
                f"duplicate VM definition for {name!r}: "
                f'{vm_sources[name]} and {src.path}'
            )
        vm_sources[name] = src.path
    for name in net_names:
        if name in network_sources:
            raise ValueError(
                f"duplicate network definition for {name!r}: "
                f'{network_sources[name]} and {src.path}'
            )
        network_sources[name] = src.path


def load_config_document(
    path: Path | None = None, *, logger=log
) -> LoadedStore:
    """Load the logical AIVM config document from monolith or split files."""
    logger.trace(f'Start load config document {path}')
    fpath = (path or store_path()).expanduser().resolve()
    sources = split_source_paths(fpath)
    if not sources:
        logger.trace('Finish load config document: no sources, default store')
        return LoadedStore(store=Store(), sources=[], layout='missing')

    layout = 'split' if any(src.role != 'root' for src in sources) else 'monolith'
    vm_sources: dict[str, Path] = {}
    network_sources: dict[str, Path] = {}
    texts: list[str] = []
    for src in sources:
        text = src.path.read_text(encoding='utf-8')
        _record_source_names(
            src,
            text,
            vm_sources=vm_sources,
            network_sources=network_sources,
        )
        texts.append(text)

    source_text = _concat_sources(sources)
    reg = parse_store_toml(source_text)
    logger.trace(
        'Finish load config document layout={} sources={}',
        layout,
        len(sources),
    )
    return LoadedStore(
        store=reg,
        sources=sources,
        layout=layout,
        source_text=source_text,
        vm_sources=vm_sources,
        network_sources=network_sources,
    )


def load_store(path: Path | None = None, *, logger=log) -> Store:
    # FIXME: This is called very often and touches the disk.
    # We likely can do something more elegant here where a store is loaded once
    # (with a real architectural change, not just a functools.cache patch).
    return load_config_document(path, logger=logger).store



def _safe_fragment_stem(name: str) -> str:
    """Return a conservative filename stem for a config fragment."""
    stem = re.sub(r'[^A-Za-z0-9_.-]+', '_', name.strip())
    stem = stem.strip('._')
    if not stem:
        raise ValueError(f'Cannot derive config fragment filename from {name!r}')
    return stem


def split_fragment_paths(reg: Store, path: Path | None = None) -> dict[str, Path]:
    """Return target split-layout paths for the given logical store."""
    root = (path or store_path()).expanduser().resolve()
    cfg_dir = root.parent
    paths: dict[str, Path] = {
        'root': root,
        'defaults': cfg_dir / 'defaults.toml',
        'networks': cfg_dir / 'networks.toml',
    }
    vms_dir = cfg_dir / 'vms'
    used: set[str] = set()
    for vm in sorted(reg.vms, key=lambda v: v.name):
        stem = _safe_fragment_stem(vm.name)
        if stem in used:
            raise ValueError(
                f'Multiple VM names map to the same config fragment stem {stem!r}'
            )
        used.add(stem)
        paths[f'vm:{vm.name}'] = vms_dir / f'{stem}.toml'
    return paths


def _fragment_write_order(keys: Iterable[str]) -> list[str]:
    key_set = set(keys)
    ordered: list[str] = []
    for key in ('root', 'defaults', 'networks'):
        if key in key_set:
            ordered.append(key)
    ordered.extend(sorted(k for k in key_set if k.startswith('vm:')))
    ordered.extend(sorted(k for k in key_set if k not in set(ordered)))
    return ordered


def _validate_no_orphaned_attachments(reg: Store) -> None:
    vm_names = {vm.name for vm in reg.vms}
    orphaned = sorted(
        {att.vm_name for att in reg.attachments if att.vm_name not in vm_names}
    )
    if orphaned:
        names = ', '.join(orphaned)
        raise ValueError(
            'Cannot write split config with attachment records whose vm_name '
            f'does not match a configured VM: {names}'
        )


def render_split_fragments(reg: Store) -> dict[str, str]:
    """Render the logical store as concatenation-friendly TOML fragments."""
    _validate_no_orphaned_attachments(reg)
    fragments: dict[str, str] = {
        'root': render_store_root_toml(reg),
        'defaults': render_store_defaults_toml(reg),
        'networks': render_store_networks_toml(reg),
    }
    for vm in sorted(reg.vms, key=lambda v: v.name):
        fragments[f'vm:{vm.name}'] = render_store_vm_toml(reg, vm.name)
    return fragments


def _validate_split_fragments(fragments: dict[str, str]) -> None:
    """Validate that rendered fragments concatenate and parse."""
    pieces: list[str] = []
    for key in _fragment_write_order(fragments.keys()):
        text = fragments.get(key, '')
        pieces.append(text.rstrip())
        pieces.append('\n')
    parse_store_toml('\n'.join(pieces))


def save_store_split(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger=log,
    dry_run: bool = False,
) -> list[Path]:
    """Save a store as split config fragments.

    The physical files are a decomposition of the canonical desired-state
    document.  Concatenating root, networks, and sorted VM fragments yields TOML
    that parses as the same logical :class:`Store` shape.
    """
    target_paths = split_fragment_paths(reg, path)
    fragments = render_split_fragments(reg)
    _validate_split_fragments(fragments)

    ordered_keys = _fragment_write_order(fragments.keys())
    written: list[Path] = []
    root = target_paths['root']
    cfg_dir = root.parent
    vms_dir = cfg_dir / 'vms'
    logger.info('Writing split config store under {}', cfg_dir)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    if dry_run:
        return [target_paths[key] for key in ordered_keys]

    cfg_dir.mkdir(parents=True, exist_ok=True)
    vms_dir.mkdir(parents=True, exist_ok=True)

    for key in ordered_keys:
        text = fragments[key]
        fpath = target_paths[key]
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(text, encoding='utf-8')
        written.append(fpath)

    expected_vm_paths = {
        target_paths[key] for key in target_paths if key.startswith('vm:')
    }
    if vms_dir.exists():
        for old in sorted(vms_dir.glob('*.toml')):
            if old not in expected_vm_paths:
                old.unlink()
    return written


def save_store(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger=log,
) -> Path:
    fpath = (path or store_path()).expanduser().resolve()
    if is_split_layout(fpath):
        save_store_split(reg, fpath, reason=reason, logger=logger)
        return fpath
    fpath.parent.mkdir(parents=True, exist_ok=True)
    logger.info('Writing config store to {}', fpath)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    fpath.write_text(render_store_toml(reg), encoding='utf-8')
    return fpath


def format_existing_config(
    path: Path | None = None,
    *,
    backup: bool = True,
    dry_run: bool = False,
    force: bool = False,
    logger=log,
) -> list[Path]:
    """Format the current logical store into canonical split fragments.

    Existing monolithic configs are backed up before the root file is rewritten.
    Existing split layouts are rewritten in place, like a formatter.  ``force``
    is accepted for API compatibility but is not required.
    """
    root = (path or store_path()).expanduser().resolve()
    was_split = is_split_layout(root)
    loaded = load_config_document(root, logger=logger)
    reg = loaded.store
    fragments = render_split_fragments(reg)
    _validate_split_fragments(fragments)
    if dry_run:
        paths = split_fragment_paths(reg, root)
        return [paths[key] for key in _fragment_write_order(fragments.keys())]

    root.parent.mkdir(parents=True, exist_ok=True)
    if backup and root.exists() and not was_split:
        backup_path = root.with_suffix(root.suffix + '.bak')
        idx = 1
        while backup_path.exists():
            backup_path = root.with_suffix(root.suffix + f'.bak{idx}')
            idx += 1
        shutil.copy2(root, backup_path)
        logger.info('Backed up monolithic config to {}', backup_path)
    return save_store_split(
        reg, root, reason='Format config store into canonical split layout.', logger=logger
    )
