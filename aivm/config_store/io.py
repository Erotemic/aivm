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

import hashlib
import json
import os
import re
import shutil
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Iterable, Literal

from loguru import logger as log

from ..errors import AIVMError
from .fs_policy import (
    StoreFilesystemPolicy,
    apply_store_file_descriptor_policy,
    apply_store_file_policy,
    ensure_store_directory,
    exclusive_file_lock,
)
from .models import Store
from .parse import parse_store_toml
from ..legacy.pre_0_6_0 import compatibility_surface
from ..legacy.pre_0_6_0.paths import store_path
from .render import (
    render_store_defaults_toml,
    render_store_networks_toml,
    render_store_root_toml,
    render_store_toml,
    render_store_vm_toml,
)


class ConcurrentStoreUpdateError(AIVMError):
    """Raised when saving a Store loaded from an older on-disk revision.

    On a shared machine store this is the *expected* two-principals-editing
    collision, so it must render as a clean retry instruction, not a
    traceback.
    """


def _resolve_io_policy(
    root: Path, io_policy: StoreFilesystemPolicy | None
) -> StoreFilesystemPolicy | None:
    """Apply the configured machine-store policy when callers omit one."""
    if io_policy is not None:
        return io_policy
    # Lazy import avoids making the generic store layer depend on the machine
    # layout during module initialization.
    from ..machine_store import (
        current_machine_store_policy,
        is_machine_store_path,
    )

    if is_machine_store_path(root):
        return current_machine_store_policy()
    return None


def _lock_path(root: Path) -> Path:
    return root.parent / '.aivm-store.lock'


class _StoreLock:
    """Class-based scope for one store's configured advisory lock."""

    def __init__(
        self,
        root: Path,
        io_policy: StoreFilesystemPolicy | None = None,
    ) -> None:
        policy = io_policy or StoreFilesystemPolicy()
        lock_path = policy.lock_path or _lock_path(root)
        self.lock = exclusive_file_lock(lock_path, policy)

    def __enter__(self) -> None:
        self.lock.__enter__()
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return self.lock.__exit__(exc_type, exc, tb)


def _store_lock(
    root: Path, io_policy: StoreFilesystemPolicy | None = None
) -> _StoreLock:
    """Return the class-based lock scope for one config store."""
    return _StoreLock(root, io_policy)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_text(
    path: Path,
    text: str,
    io_policy: StoreFilesystemPolicy | None = None,
) -> None:
    """Atomically replace text while preserving explicit shared-store metadata."""
    policy = io_policy or StoreFilesystemPolicy()
    ensure_store_directory(path.parent, policy)
    if policy.reject_symlinks and path.is_symlink():
        raise RuntimeError(f'Refusing to replace symlinked store file: {path}')
    with tempfile.NamedTemporaryFile(
        'w',
        encoding='utf-8',
        dir=str(path.parent),
        prefix=f'.{path.name}.',
        delete=False,
    ) as file:
        file.write(text)
        file.flush()
        apply_store_file_descriptor_policy(file.fileno(), policy)
        os.fsync(file.fileno())
        tmp = Path(file.name)
    try:
        os.replace(tmp, path)
        apply_store_file_policy(path, policy)
        _fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def _store_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    sources = split_source_paths(root)
    if not sources:
        digest.update(b'<missing>')
        return digest.hexdigest()
    for src in sources:
        digest.update(src.role.encode('utf-8'))
        digest.update(b'\0')
        digest.update(str(src.path).encode('utf-8'))
        digest.update(b'\0')
        digest.update(src.path.read_bytes())
        digest.update(b'\0')
    return digest.hexdigest()


def _mark_loaded_store(reg: Store, root: Path) -> None:
    reg._source_path = str(root)
    reg._source_fingerprint = _store_fingerprint(root)


def _check_store_revision(reg: Store, root: Path) -> None:
    if reg._source_path != str(root) or not reg._source_fingerprint:
        return
    current = _store_fingerprint(root)
    if current != reg._source_fingerprint:
        raise ConcurrentStoreUpdateError(
            'The AIVM config store changed after it was loaded; refusing to '
            f'overwrite concurrent changes at {root}. Reload and retry.'
        )


def _transaction_dir(root: Path) -> Path:
    return root.parent / '.aivm-store-transaction'


def _safe_relative_path(raw: str) -> Path:
    rel = Path(raw)
    if rel.is_absolute() or '..' in rel.parts:
        raise RuntimeError(f'invalid config transaction path: {raw!r}')
    return rel


def _recover_split_transaction(
    root: Path, io_policy: StoreFilesystemPolicy | None = None
) -> None:
    """Complete an interrupted split-layout replacement before any read."""
    txn = _transaction_dir(root)
    meta_path = txn / 'metadata.json'
    if not txn.exists():
        return
    if not meta_path.is_file():
        raise RuntimeError(
            f'incomplete AIVM config transaction metadata: {txn}'
        )
    metadata = json.loads(meta_path.read_text(encoding='utf-8'))
    for raw in metadata.get('write', []):
        rel = _safe_relative_path(str(raw))
        staged = txn / 'new' / rel
        target = root.parent / rel
        if staged.exists():
            ensure_store_directory(target.parent, io_policy)
            os.replace(staged, target)
            apply_store_file_policy(target, io_policy)
            _fsync_dir(target.parent)
    for raw in metadata.get('delete', []):
        rel = _safe_relative_path(str(raw))
        target = root.parent / rel
        target.unlink(missing_ok=True)
        _fsync_dir(target.parent)
    shutil.rmtree(txn)
    _fsync_dir(root.parent)


def _stage_split_transaction(
    root: Path,
    target_paths: dict[str, Path],
    fragments: dict[str, str],
    io_policy: StoreFilesystemPolicy | None = None,
) -> None:
    cfg_dir = root.parent
    txn = _transaction_dir(root)
    ensure_store_directory(cfg_dir, io_policy)
    _recover_split_transaction(root, io_policy)
    temp_txn = Path(
        tempfile.mkdtemp(prefix='.aivm-store-transaction-', dir=str(cfg_dir))
    )
    ensure_store_directory(temp_txn, io_policy)
    try:
        write_rels: list[str] = []
        for key in _fragment_write_order(fragments.keys()):
            target = target_paths[key]
            rel = target.relative_to(cfg_dir)
            staged = temp_txn / 'new' / rel
            _atomic_write_text(staged, fragments[key], io_policy)
            write_rels.append(str(rel))
        expected_vm_paths = {
            target_paths[key] for key in target_paths if key.startswith('vm:')
        }
        vms_dir = cfg_dir / 'vms'
        delete_rels = (
            [
                str(old.relative_to(cfg_dir))
                for old in sorted(vms_dir.glob('*.toml'))
                if old not in expected_vm_paths
            ]
            if vms_dir.exists()
            else []
        )
        metadata = {
            'schema_version': 1,
            'write': write_rels,
            'delete': delete_rels,
        }
        _atomic_write_text(
            temp_txn / 'metadata.json',
            json.dumps(metadata, indent=2, sort_keys=True) + '\n',
            io_policy,
        )
        _fsync_dir(temp_txn)
        os.replace(temp_txn, txn)
        _fsync_dir(cfg_dir)
        _recover_split_transaction(root, io_policy)
    finally:
        if temp_txn.exists():
            shutil.rmtree(temp_txn, ignore_errors=True)


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


@compatibility_surface
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
        parts.append(
            f'\n# --- aivm config source: {src.path} ({src.role}) ---\n'
        )
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
                f'duplicate VM definition for {name!r}: '
                f'{vm_sources[name]} and {src.path}'
            )
        vm_sources[name] = src.path
    for name in net_names:
        if name in network_sources:
            raise ValueError(
                f'duplicate network definition for {name!r}: '
                f'{network_sources[name]} and {src.path}'
            )
        network_sources[name] = src.path


def _load_config_document_unlocked(
    path: Path | None = None, *, logger: Any = log
) -> LoadedStore:
    """Load the logical AIVM config document from monolith or split files."""
    logger.trace(f'Start load config document {path}')
    fpath = (path or store_path()).expanduser().resolve()
    sources = split_source_paths(fpath)
    if not sources:
        logger.trace('Finish load config document: no sources, default store')
        return LoadedStore(store=Store(), sources=[], layout='missing')

    layout = (
        'split' if any(src.role != 'root' for src in sources) else 'monolith'
    )
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


@compatibility_surface
def load_config_document(
    path: Path | None = None,
    *,
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
) -> LoadedStore:
    """Load one coherent store revision, recovering interrupted writes first."""
    fpath = (path or store_path()).expanduser().resolve()
    io_policy = _resolve_io_policy(fpath, io_policy)
    with _store_lock(fpath, io_policy):
        _recover_split_transaction(fpath, io_policy)
        loaded = _load_config_document_unlocked(fpath, logger=logger)
        _mark_loaded_store(loaded.store, fpath)
        return loaded


@compatibility_surface
def load_store(
    path: Path | None = None,
    *,
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
) -> Store:
    # FIXME: This is called very often and touches the disk.
    # We likely can do something more elegant here where a store is loaded once
    # (with a real architectural change, not just a functools.cache patch).
    return load_config_document(path, logger=logger, io_policy=io_policy).store


def _safe_fragment_stem(name: str) -> str:
    """Return a conservative filename stem for a config fragment."""
    stem = re.sub(r'[^A-Za-z0-9_.-]+', '_', name.strip())
    stem = stem.strip('._')
    if not stem:
        raise ValueError(
            f'Cannot derive config fragment filename from {name!r}'
        )
    return stem


def split_fragment_paths(
    reg: Store, path: Path | None = None
) -> dict[str, Path]:
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
    orphaned_credentials = sorted(
        {
            cred.vm_name
            for cred in reg.credentials
            if cred.vm_name not in vm_names
        }
    )
    if orphaned_credentials:
        names = ', '.join(orphaned_credentials)
        raise ValueError(
            'Cannot write split config with credential records whose vm_name '
            f'does not match a configured VM: {names}'
        )
    orphaned_principals = sorted(
        {
            principal.vm_name
            for principal in reg.principals
            if principal.vm_name not in vm_names
        }
    )
    if orphaned_principals:
        names = ', '.join(orphaned_principals)
        raise ValueError(
            'Cannot write split config with principal records whose vm_name '
            f'does not match a configured VM: {names}'
        )
    if reg.store_kind == 'machine':
        principal_keys = {(item.vm_name, item.id) for item in reg.principals}
        dangling_owners = sorted(
            {
                (att.vm_name, att.owner_principal_id)
                for att in reg.attachments
                if att.owner_principal_id
                and att.owner_principal_id != 'system'
                and (att.vm_name, att.owner_principal_id) not in principal_keys
            }
        )
        if dangling_owners:
            details = ', '.join(
                f'{vm}:{owner}' for vm, owner in dangling_owners
            )
            raise ValueError(
                'Cannot write machine config with attachment records that '
                f'reference unknown principals: {details}'
            )
        unattributed_credentials = sorted(
            {
                (cred.vm_name, cred.id)
                for cred in reg.credentials
                if not cred.principal_id
            }
        )
        if unattributed_credentials:
            details = ', '.join(
                f'{vm}:{cred_id}' for vm, cred_id in unattributed_credentials
            )
            raise ValueError(
                'Cannot write machine config with credential records that '
                f'are missing principal_id: {details}'
            )
        dangling_credential_principals = sorted(
            {
                (cred.vm_name, cred.principal_id)
                for cred in reg.credentials
                if (cred.vm_name, cred.principal_id) not in principal_keys
            }
        )
        if dangling_credential_principals:
            details = ', '.join(
                f'{vm}:{principal}'
                for vm, principal in dangling_credential_principals
            )
            raise ValueError(
                'Cannot write machine config with credential records that '
                f'reference unknown principals: {details}'
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


def _save_store_split_unlocked(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger: Any = log,
    dry_run: bool = False,
    io_policy: StoreFilesystemPolicy | None = None,
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
    logger.info('Writing split config store under {}', cfg_dir)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    if dry_run:
        return [target_paths[key] for key in ordered_keys]

    ensure_store_directory(cfg_dir, io_policy)
    _stage_split_transaction(root, target_paths, fragments, io_policy)
    written.extend(target_paths[key] for key in ordered_keys)
    _mark_loaded_store(reg, root)
    return written


def save_store_split(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger: Any = log,
    dry_run: bool = False,
    io_policy: StoreFilesystemPolicy | None = None,
) -> list[Path]:
    root = (path or store_path()).expanduser().resolve()
    io_policy = _resolve_io_policy(root, io_policy)
    with _store_lock(root, io_policy):
        _recover_split_transaction(root, io_policy)
        _check_store_revision(reg, root)
        return _save_store_split_unlocked(
            reg,
            root,
            reason=reason,
            logger=logger,
            dry_run=dry_run,
            io_policy=io_policy,
        )


def _save_store_unlocked(
    reg: Store,
    fpath: Path,
    *,
    reason: str = '',
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
    force_split: bool = False,
) -> Path:
    """Write a store while the caller holds the physical store lock."""
    if force_split or is_split_layout(fpath):
        _save_store_split_unlocked(
            reg,
            fpath,
            reason=reason,
            logger=logger,
            io_policy=io_policy,
        )
        return fpath
    ensure_store_directory(fpath.parent, io_policy)
    logger.info('Writing config store to {}', fpath)
    if reason.strip():
        logger.info('  Reason: {}', reason.strip())
    _atomic_write_text(fpath, render_store_toml(reg), io_policy)
    _mark_loaded_store(reg, fpath)
    return fpath


@compatibility_surface
def save_store(
    reg: Store,
    path: Path | None = None,
    *,
    reason: str = '',
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
) -> Path:
    fpath = (path or store_path()).expanduser().resolve()
    io_policy = _resolve_io_policy(fpath, io_policy)
    with _store_lock(fpath, io_policy):
        _recover_split_transaction(fpath, io_policy)
        _check_store_revision(reg, fpath)
        return _save_store_unlocked(
            reg,
            fpath,
            reason=reason,
            logger=logger,
            io_policy=io_policy,
        )


def update_store(
    mutate: Callable[[Store], Store | None],
    path: Path | None = None,
    *,
    reason: str = '',
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
    force_split: bool = False,
) -> Store:
    """Load, mutate, and save one store revision under a single lock.

    This is the safe primitive for read-modify-write operations on the future
    machine store.  Separate ``load_store`` / ``save_store`` calls still retain
    optimistic-concurrency protection, but callers that want concurrent edits
    to merge must express the mutation through this transaction boundary.
    """
    fpath = (path or store_path()).expanduser().resolve()
    io_policy = _resolve_io_policy(fpath, io_policy)
    with _store_lock(fpath, io_policy):
        _recover_split_transaction(fpath, io_policy)
        loaded = _load_config_document_unlocked(fpath, logger=logger)
        reg = loaded.store
        replacement = mutate(reg)
        if replacement is not None:
            reg = replacement
        if not isinstance(reg, Store):
            raise TypeError('Store mutator must return Store or None')
        _save_store_unlocked(
            reg,
            fpath,
            reason=reason,
            logger=logger,
            io_policy=io_policy,
            force_split=force_split,
        )
        return reg


def format_existing_config(
    path: Path | None = None,
    *,
    backup: bool = True,
    dry_run: bool = False,
    force: bool = False,
    logger: Any = log,
    io_policy: StoreFilesystemPolicy | None = None,
) -> list[Path]:
    """Format the current logical store into canonical split fragments.

    Existing monolithic configs are backed up before the root file is rewritten.
    Existing split layouts are rewritten in place, like a formatter.  ``force``
    is accepted for API compatibility but is not required.
    """
    root = (path or store_path()).expanduser().resolve()
    io_policy = _resolve_io_policy(root, io_policy)
    was_split = is_split_layout(root)
    loaded = load_config_document(root, logger=logger, io_policy=io_policy)
    reg = loaded.store
    fragments = render_split_fragments(reg)
    _validate_split_fragments(fragments)
    if dry_run:
        paths = split_fragment_paths(reg, root)
        return [paths[key] for key in _fragment_write_order(fragments.keys())]

    ensure_store_directory(root.parent, io_policy)
    if backup and root.exists() and not was_split:
        backup_path = root.with_suffix(root.suffix + '.bak')
        idx = 1
        while backup_path.exists():
            backup_path = root.with_suffix(root.suffix + f'.bak{idx}')
            idx += 1
        shutil.copy2(root, backup_path)
        apply_store_file_policy(backup_path, io_policy)
        logger.info('Backed up monolithic config to {}', backup_path)
    return save_store_split(
        reg,
        root,
        reason='Format config store into canonical split layout.',
        logger=logger,
        io_policy=io_policy,
    )
