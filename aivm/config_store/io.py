"""Physical I/O for the current single-file AIVM config store."""

from __future__ import annotations

from pathlib import Path

from loguru import logger as log

from .models import Store
from .parse import parse_store_toml
from .paths import store_path
from .render import render_store_toml


def load_store(path: Path | None = None, *, logger=log) -> Store:
    # FIXME: This is called very often and touches the disk.
    # We likely can do something more elegant here where a store is loaded once
    # (with a real architectural change, not just a functools.cache patch).
    logger.trace(f'Start load store {path}')
    fpath = path or store_path()
    if not fpath.exists():
        logger.trace('Finish load store: does not exist, returning default')
        return Store()
    reg = parse_store_toml(fpath.read_text(encoding='utf-8'))
    logger.trace('Finish load store')
    return reg


def save_store(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger=log,
) -> Path:
    fpath = path or store_path()
    fpath.parent.mkdir(parents=True, exist_ok=True)
    logger.info('Writing config store to {}', fpath)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    fpath.write_text(render_store_toml(reg), encoding='utf-8')
    return fpath
