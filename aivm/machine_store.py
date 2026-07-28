"""Machine-wide store layout, permissions, and resource locks.

This module establishes the physical contract needed before AIVM moves any
live configuration out of a user's XDG directories.  It is intentionally not
wired into normal config loading yet: version 0.6 first proves that group-safe
writes, recovery, and lock ordering work in isolation.
"""

from __future__ import annotations

import contextlib
import grp
import hashlib
import os
import re
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .config_store.fs_policy import (
    StoreFilesystemPolicy,
    ensure_store_directory,
    exclusive_file_lock,
)

MACHINE_STORE_ROOT_ENV = 'AIVM_MACHINE_STORE_ROOT'
DEFAULT_MACHINE_STORE_ROOT = Path('/var/lib/aivm')
DEFAULT_MACHINE_GROUP = 'aivm'

MACHINE_DIRECTORY_MODE = 0o2775
MACHINE_FILE_MODE = 0o664
BOOTSTRAP_DIRECTORY_MODE = 0o2750


class MachineStoreGroupError(RuntimeError):
    """Raised when the configured trusted host group does not exist."""


@dataclass(frozen=True)
class MachineStoreLayout:
    """Canonical paths owned by one host-wide AIVM installation."""

    root: Path
    config_path: Path
    locks_dir: Path
    vm_locks_dir: Path
    network_locks_dir: Path
    state_dir: Path
    bootstrap_dir: Path

    @classmethod
    def from_root(cls, root: Path) -> MachineStoreLayout:
        normalized = Path(os.path.abspath(os.fspath(root.expanduser())))
        locks = normalized / 'locks'
        return cls(
            root=normalized,
            config_path=normalized / 'config.toml',
            locks_dir=locks,
            vm_locks_dir=locks / 'vms',
            network_locks_dir=locks / 'networks',
            state_dir=normalized / 'state',
            bootstrap_dir=normalized / 'bootstrap',
        )

    @property
    def store_lock_path(self) -> Path:
        return self.locks_dir / 'store.lock'

    def vm_lock_path(self, vm_name: str) -> Path:
        return self.vm_locks_dir / f'{_resource_stem(vm_name)}.lock'

    def network_lock_path(self, network_name: str) -> Path:
        return self.network_locks_dir / f'{_resource_stem(network_name)}.lock'


def machine_store_layout(root: Path | None = None) -> MachineStoreLayout:
    """Resolve the machine-store layout without creating it."""
    if root is None:
        configured = os.environ.get(MACHINE_STORE_ROOT_ENV, '').strip()
        root = Path(configured) if configured else DEFAULT_MACHINE_STORE_ROOT
    return MachineStoreLayout.from_root(root)


def resolve_machine_group_gid(group_name: str = DEFAULT_MACHINE_GROUP) -> int:
    """Resolve the trusted host group used by the machine store."""
    try:
        return int(grp.getgrnam(group_name).gr_gid)
    except KeyError as ex:
        raise MachineStoreGroupError(
            f'Required host group {group_name!r} does not exist. '
            'Create it before initializing the shared machine store.'
        ) from ex


def machine_store_policy(
    layout: MachineStoreLayout | None = None,
    *,
    group_gid: int | None = None,
    group_name: str = DEFAULT_MACHINE_GROUP,
) -> StoreFilesystemPolicy:
    """Return group-safe filesystem rules for the global config store."""
    layout = layout or machine_store_layout()
    gid = resolve_machine_group_gid(group_name) if group_gid is None else group_gid
    return StoreFilesystemPolicy(
        managed_root=layout.root,
        directory_mode=MACHINE_DIRECTORY_MODE,
        file_mode=MACHINE_FILE_MODE,
        group_gid=gid,
        lock_path=layout.store_lock_path,
        reject_symlinks=True,
    )


def ensure_machine_store_layout(
    layout: MachineStoreLayout | None = None,
    *,
    group_gid: int | None = None,
    group_name: str = DEFAULT_MACHINE_GROUP,
) -> MachineStoreLayout:
    """Create the non-sensitive machine-store directories with stable modes."""
    layout = layout or machine_store_layout()
    policy = machine_store_policy(
        layout, group_gid=group_gid, group_name=group_name
    )
    for path in (
        layout.root,
        layout.locks_dir,
        layout.vm_locks_dir,
        layout.network_locks_dir,
        layout.state_dir,
    ):
        ensure_store_directory(path, policy)
    bootstrap_policy = StoreFilesystemPolicy(
        managed_root=layout.bootstrap_dir,
        directory_mode=BOOTSTRAP_DIRECTORY_MODE,
        file_mode=0o640,
        group_gid=policy.group_gid,
        reject_symlinks=True,
    )
    ensure_store_directory(layout.bootstrap_dir, bootstrap_policy)
    return layout


def _resource_stem(name: str) -> str:
    """Return a readable, collision-resistant lock filename stem."""
    clean = re.sub(r'[^A-Za-z0-9_.-]+', '_', name.strip()).strip('._')
    clean = clean[:48] or 'resource'
    digest = hashlib.sha256(name.encode('utf-8')).hexdigest()[:12]
    return f'{clean}-{digest}'


@dataclass(frozen=True, order=True)
class MachineLockSpec:
    """One lock in the global store -> network -> VM acquisition order."""

    rank: int
    name: str
    path: Path


def ordered_machine_locks(
    layout: MachineStoreLayout,
    *,
    include_store: bool = False,
    networks: Iterable[str] = (),
    vms: Iterable[str] = (),
) -> tuple[MachineLockSpec, ...]:
    """Build a deterministic, deduplicated resource lock sequence."""
    specs: set[MachineLockSpec] = set()
    if include_store:
        specs.add(MachineLockSpec(0, 'store', layout.store_lock_path))
    for name in networks:
        specs.add(
            MachineLockSpec(1, f'network:{name}', layout.network_lock_path(name))
        )
    for name in vms:
        specs.add(MachineLockSpec(2, f'vm:{name}', layout.vm_lock_path(name)))
    return tuple(sorted(specs))


@contextlib.contextmanager
def machine_resource_locks(
    layout: MachineStoreLayout,
    *,
    group_gid: int,
    include_store: bool = False,
    networks: Iterable[str] = (),
    vms: Iterable[str] = (),
) -> Iterator[tuple[MachineLockSpec, ...]]:
    """Acquire machine resource locks in the one supported global order."""
    policy = machine_store_policy(layout, group_gid=group_gid)
    specs = ordered_machine_locks(
        layout,
        include_store=include_store,
        networks=networks,
        vms=vms,
    )
    with ExitStack() as stack:
        for spec in specs:
            stack.enter_context(exclusive_file_lock(spec.path, policy))
        yield specs
