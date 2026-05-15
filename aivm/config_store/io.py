"""Physical I/O for AIVM's desired-state config store.

This module currently supports two physical layouts that parse into the same
logical :class:`Store` model:

* legacy monolith: ``config.toml`` contains the whole document;
* split fragments: ``config.toml`` + ``networks.toml`` + ``vms/*.toml``
  concatenate into the canonical document.

Writing split layouts is intentionally not implemented here yet.  Chunk 3 is
read-only split support; chunk 4 will add migration and split writes.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from loguru import logger as log

from .models import Store
from .parse import parse_store_toml
from .paths import store_path
from .render import render_store_toml


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
    2. sibling ``networks.toml``;
    3. sorted sibling ``vms/*.toml``.
    """
    root = (path or store_path()).expanduser().resolve()
    cfg_dir = root.parent
    sources: list[ConfigSource] = []
    if root.exists():
        sources.append(ConfigSource(root, 'root'))
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


def save_store(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger=log,
) -> Path:
    fpath = (path or store_path()).expanduser().resolve()
    if is_split_layout(fpath):
        raise RuntimeError(
            'Refusing to save split AIVM config layout with monolith writer. '
            'Split-layout read support is available, but split writes/migration '
            'belong to the next config refactor chunk.'
        )
    fpath.parent.mkdir(parents=True, exist_ok=True)
    logger.info('Writing config store to {}', fpath)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    fpath.write_text(render_store_toml(reg), encoding='utf-8')
    return fpath
