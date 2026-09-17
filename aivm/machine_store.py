"""Machine store layout, permissions, and resource locks.

This module establishes the physical contract for the active AIVM machine
store: group-safe writes, recovery, and globally ordered resource locks.

The store occupies one of two roots, chosen by
:func:`resolve_machine_store_root`: the host-wide group-owned root, or a
user-owned personal root for a host that never opted into trusted-group
membership. That choice changes the root path, the owning gid, and the
directory/file modes. It changes nothing else -- the documents, the lock
order, and every consumer of :class:`MachineStoreLayout` are identical,
because the layout is already a parameter throughout.
"""

from __future__ import annotations

import grp
import hashlib
import os
import re
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Iterable

from .config_store.fs_policy import (
    StoreFilesystemPolicy,
    ensure_store_directory,
    exclusive_file_lock,
)
from .config_store.paths import app_data_path
from .errors import AIVMError
from .host_identity import current_host_identity

MACHINE_STORE_ROOT_ENV = 'AIVM_MACHINE_STORE_ROOT'

# A subdirectory, not /var/lib/aivm itself. The store root is group-writable
# (MACHINE_DIRECTORY_MODE below), while /var/lib/aivm is the parent of the
# persistent-attachment replay state directory, which the root replay service
# will only consume from a chain no non-root account can write --
# ``_approved_state_directories_are_safe`` rejects any group- or
# world-writable bit on it and rewrites it back to root:root 0755. Pointing
# the store at that same directory makes the two subsystems overwrite each
# other's modes on every operation, and would let a store-group member
# replace the directory a root service reads.
DEFAULT_MACHINE_STORE_ROOT = Path('/var/lib/aivm/machine')

# Reuse the group every AIVM user already needs rather than inventing a second
# one. Reaching qemu:///system without sudo requires `libvirt` membership, so
# a dedicated `aivm` group gated a strict subset of what its members could
# already do -- it cost an extra groupadd, usermod, and re-login while
# `removing libvirt group root-equivalence` and hostile-user isolation are
# both explicit non-goals of the shared-machine release. Keeping one group
# also means a single-user host needs no migration when a second user
# arrives: they need libvirt membership regardless, and that now carries
# store access with it. Sites that do want a narrower group set
# ``AIVM_MACHINE_GROUP``; tightening later is a chgrp, not a data migration.
DEFAULT_MACHINE_GROUP = 'libvirt'
MACHINE_GROUP_ENV = 'AIVM_MACHINE_GROUP'

# Group-shared but not world-readable: the machine store carries VM documents
# that can include guest passwords, so access stops at the trusted group.
MACHINE_DIRECTORY_MODE = 0o2770
MACHINE_FILE_MODE = 0o660
BOOTSTRAP_DIRECTORY_MODE = 0o2750

# The same store, owned by one user instead of a group. Membership in the
# trusted group is a real privilege grant -- `libvirt` is root-equivalent, and
# `removing libvirt group root-equivalence` is an explicit non-goal -- so a
# single user who never opts into it still gets the whole 0.6 architecture,
# just rooted in their own data directory. Nothing here is a second store
# implementation: only the root path, the owning gid, and these modes differ,
# and every consumer already takes the layout as a parameter.
PERSONAL_DIRECTORY_MODE = 0o700
PERSONAL_FILE_MODE = 0o600
PERSONAL_BOOTSTRAP_DIRECTORY_MODE = 0o700


class MachineStoreGroupError(AIVMError):
    """Raised when the configured trusted host group does not exist.

    An :class:`AIVMError` so a fresh host (no ``aivm`` group, no store yet)
    gets the CLI's clean error rendering and setup guidance instead of a
    traceback from the first ``aivm status``/``aivm list``.
    """


class MachineStoreAccessError(AIVMError):
    """Raised when a shared store exists that this caller cannot reach.

    Falling back to a personal store here would be the one genuinely unsafe
    outcome of supporting both layouts: the host has already been set up to
    hold one authority, and a second private authority over the same libvirt
    domains is what invariant 1 of the shared-machine architecture forbids.
    Refusing is recoverable (join the group); silently forking is not.
    """


def personal_machine_store_root() -> Path:
    """Return the user-owned machine-store root for an unshared host."""
    return app_data_path('machine')


def machine_root_is_shared(path: Path) -> bool:
    """Return whether ``path`` belongs to the host-wide group-owned store.

    Subdirectories answer the same as their root. Migration transactions and
    lock namespaces build sublayouts, and every one of them must inherit the
    ownership of the store it lives in rather than being classified on its
    own name.
    """
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    shared = DEFAULT_MACHINE_STORE_ROOT
    return candidate == shared or shared in candidate.parents


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
    #: Whether this root is the host-wide group-owned store. Drives the
    #: owning gid and the directory/file modes, and nothing else: a personal
    #: store holds the same documents under the same names.
    shared: bool = True

    @classmethod
    def from_root(
        cls, root: Path, *, shared: bool | None = None
    ) -> MachineStoreLayout:
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
            shared=(
                machine_root_is_shared(normalized) if shared is None else shared
            ),
        )

    @property
    def store_lock_path(self) -> Path:
        return self.locks_dir / 'store.lock'

    def vm_lock_path(self, vm_name: str) -> Path:
        return self.vm_locks_dir / f'{_resource_stem(vm_name)}.lock'

    def network_lock_path(self, network_name: str) -> Path:
        return self.network_locks_dir / f'{_resource_stem(network_name)}.lock'

    def vm_state_dir(self, vm_name: str) -> Path:
        """Return machine-owned runtime state for one managed VM."""
        return self.state_dir / 'vms' / _resource_stem(vm_name)


def _directory_is_usable(path: Path) -> bool:
    """Return whether ``path`` is a real directory this caller can write."""
    if not path.is_dir() or path.is_symlink():
        return False
    return os.access(path, os.R_OK | os.W_OK | os.X_OK)


def candidate_machine_store_roots() -> tuple[Path, ...]:
    """Return every root a machine store may occupy, for diagnostics.

    Reporting commands need to describe both layouts without committing to
    one, so this never raises where :func:`resolve_machine_store_root` would.
    """
    configured = os.environ.get(MACHINE_STORE_ROOT_ENV, '').strip()
    if configured:
        return (Path(os.path.abspath(configured)),)
    return (DEFAULT_MACHINE_STORE_ROOT, personal_machine_store_root())


def resolve_machine_store_root() -> Path:
    """Choose between the shared and personal machine store roots.

    A host that has been set up for sharing always wins, because its records
    are the host's one authority. A host that has not is not made to opt into
    trusted-group membership merely to keep its own configuration: a user who
    never runs ``aivm host permissions setup`` gets an equivalent store under
    their own data directory, with no group and no privileged step anywhere.

    The refusal in the middle is deliberate. Falling back to a personal store
    while an unreadable shared one exists would hand this caller a second
    authority over domains the shared store already claims.
    """
    configured = os.environ.get(MACHINE_STORE_ROOT_ENV, '').strip()
    if configured:
        return Path(configured)
    shared = DEFAULT_MACHINE_STORE_ROOT
    if shared.is_dir() and not shared.is_symlink():
        if not _directory_is_usable(shared):
            group = current_machine_group_name()
            raise MachineStoreAccessError(
                f'This host has a shared AIVM machine store at {shared}, but '
                f'{current_host_identity().username!r} cannot write it. It is '
                f'owned by root and writable by the {group!r} group, which is '
                'the same membership that reaches qemu:///system without '
                'sudo.\n'
                f'  sudo usermod -aG {group} "$USER"   # then log out and in\n'
                'AIVM will not keep a second private store beside a shared '
                'one: both would claim the same libvirt domains.'
            )
        return shared
    return personal_machine_store_root()


def machine_store_layout(root: Path | None = None) -> MachineStoreLayout:
    """Resolve the machine-store layout without creating it."""
    if root is None:
        root = resolve_machine_store_root()
    return MachineStoreLayout.from_root(root)


def resolve_machine_group_gid(group_name: str = DEFAULT_MACHINE_GROUP) -> int:
    """Resolve the trusted host group used by the machine store."""
    try:
        return int(grp.getgrnam(group_name).gr_gid)
    except KeyError as ex:
        # The default group ships with libvirt, so its absence means libvirt
        # is not installed -- creating an empty group of the same name would
        # produce a group that grants no qemu:///system access and hide that.
        # Only a site-chosen group is ours to create. `aivm config init` is
        # not offered here either: it writes configuration and never touches
        # host groups, so it cannot clear this error.
        if group_name == DEFAULT_MACHINE_GROUP:
            raise MachineStoreGroupError(
                f'Required host group {group_name!r} does not exist. It is '
                'provided by libvirt, so install libvirt first (for example '
                '`sudo apt install libvirt-daemon-system`), then run `aivm '
                'host permissions setup`.'
            ) from ex
        raise MachineStoreGroupError(
            f'Required host group {group_name!r} does not exist. It is set by '
            f'{MACHINE_GROUP_ENV}. Create it, or unset that variable to use '
            f'the default {DEFAULT_MACHINE_GROUP!r} group: sudo groupadd '
            f'--system {group_name} && sudo usermod -aG {group_name} "$USER". '
            'Group membership applies at the next login.'
        ) from ex


def current_machine_group_name() -> str:
    """Return the trusted group configured for the shared machine store."""
    return (
        os.environ.get(MACHINE_GROUP_ENV, DEFAULT_MACHINE_GROUP).strip()
        or DEFAULT_MACHINE_GROUP
    )


def machine_group_exists(group_name: str | None = None) -> bool:
    """Return whether the configured trusted host group exists."""
    name = group_name or current_machine_group_name()
    try:
        grp.getgrnam(name)
    except KeyError:
        return False
    return True


def user_in_machine_group(
    user: str | None = None, *, group_name: str | None = None
) -> bool:
    """Return whether the current login has active trusted-group access."""
    name = group_name or current_machine_group_name()
    try:
        record = grp.getgrnam(name)
    except KeyError:
        return False
    selected = user or current_host_identity().username
    if selected in record.gr_mem:
        return True
    try:
        return int(record.gr_gid) in {int(gid) for gid in os.getgroups()}
    except OSError:
        return False


def machine_store_root_ready(
    layout: MachineStoreLayout | None = None,
) -> bool:
    """Return whether the caller can use the configured machine root."""
    layout = layout or machine_store_layout()
    return _directory_is_usable(layout.root)


def current_machine_group_gid(
    layout: MachineStoreLayout | None = None,
) -> int:
    """Resolve the owning gid for whichever store root is in use.

    Only the shared root is group-owned. A personal root and an explicit
    ``AIVM_MACHINE_STORE_ROOT`` sandbox both belong to the caller, so
    requiring a system group there would make an unshared host, an isolated
    test, and a local prototype all unnecessarily privileged.
    """
    layout = layout or machine_store_layout()
    if not layout.shared:
        return int(os.getgid())
    return resolve_machine_group_gid(current_machine_group_name())


def machine_store_policy(
    layout: MachineStoreLayout | None = None,
    *,
    group_gid: int | None = None,
    group_name: str = DEFAULT_MACHINE_GROUP,
) -> StoreFilesystemPolicy:
    """Return the filesystem rules for the selected config store root."""
    layout = layout or machine_store_layout()
    if group_gid is None:
        gid = (
            resolve_machine_group_gid(group_name)
            if layout.shared
            else int(os.getgid())
        )
    else:
        gid = group_gid
    return StoreFilesystemPolicy(
        managed_root=layout.root,
        directory_mode=(
            MACHINE_DIRECTORY_MODE if layout.shared else PERSONAL_DIRECTORY_MODE
        ),
        file_mode=MACHINE_FILE_MODE if layout.shared else PERSONAL_FILE_MODE,
        group_gid=gid,
        lock_path=layout.store_lock_path,
        reject_symlinks=True,
    )


def current_machine_store_policy(
    layout: MachineStoreLayout | None = None,
) -> StoreFilesystemPolicy:
    """Return the policy used by normal machine-store reads and writes."""
    layout = layout or machine_store_layout()
    return machine_store_policy(
        layout, group_gid=current_machine_group_gid(layout)
    )


def is_machine_store_path(path: Path) -> bool:
    """Return whether ``path`` is inside a machine root of either layout.

    Callers use this to classify a path they already hold, so it answers for
    every root a store may occupy rather than resolving the active one: the
    question stays answerable on a host whose shared root exists but is
    unreachable, where :func:`resolve_machine_store_root` deliberately fails.
    """
    candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
    for root in candidate_machine_store_roots():
        try:
            candidate.relative_to(Path(os.path.abspath(os.fspath(root))))
        except ValueError:
            continue
        return True
    return False


def _store_directory_error(
    layout: MachineStoreLayout, path: Path, ex: OSError
) -> AIVMError:
    """Explain a store directory this caller could not create or fix."""
    if not layout.shared:
        return AIVMError(
            f'Could not prepare your AIVM machine store at {path}: {ex}. '
            'This store is yours alone and needs no group or privileged '
            'step, so check that the path is writable.'
        )
    group = current_machine_group_name()
    return AIVMError(
        f'Could not prepare the shared AIVM machine store at {path}: {ex}.\n'
        f'It is owned by root and writable by the {group!r} group. Run `aivm '
        'host permissions setup`, or do it by hand:\n'
        f'  sudo install -d -o root -g root -m 0755 {layout.root.parent}\n'
        f'  sudo install -d -o root -g {group} -m 2770 {layout.root}\n'
        f'  sudo usermod -aG {group} "$USER"   # then log out and in'
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
        # Every caller of this function is answering a user's command, and a
        # store the caller cannot create is a condition the user can act on,
        # not an internal fault. Raising OSError here reaches the CLI as an
        # unhandled traceback; a symlink refusal stays a hard RuntimeError.
        try:
            ensure_store_directory(path, policy)
        except OSError as ex:
            raise _store_directory_error(layout, path, ex) from ex
    bootstrap_policy = StoreFilesystemPolicy(
        managed_root=layout.bootstrap_dir,
        directory_mode=(
            BOOTSTRAP_DIRECTORY_MODE
            if layout.shared
            else PERSONAL_BOOTSTRAP_DIRECTORY_MODE
        ),
        file_mode=0o640 if layout.shared else PERSONAL_FILE_MODE,
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
            MachineLockSpec(
                1, f'network:{name}', layout.network_lock_path(name)
            )
        )
    for name in vms:
        specs.add(MachineLockSpec(2, f'vm:{name}', layout.vm_lock_path(name)))
    return tuple(sorted(specs))


class MachineResourceLockScope:
    """Acquire machine resource locks in the one supported global order."""

    def __init__(
        self,
        layout: MachineStoreLayout,
        *,
        group_gid: int,
        include_store: bool = False,
        networks: Iterable[str] = (),
        vms: Iterable[str] = (),
    ) -> None:
        self.policy = machine_store_policy(layout, group_gid=group_gid)
        self.specs = ordered_machine_locks(
            layout,
            include_store=include_store,
            networks=networks,
            vms=vms,
        )
        self.stack = ExitStack()

    def __enter__(self) -> tuple[MachineLockSpec, ...]:
        self.stack.__enter__()
        try:
            for spec in self.specs:
                self.stack.enter_context(
                    exclusive_file_lock(spec.path, self.policy)
                )
        except BaseException:
            self.stack.close()
            raise
        return self.specs

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        return self.stack.__exit__(exc_type, exc, tb)


def machine_resource_locks(
    layout: MachineStoreLayout,
    *,
    group_gid: int,
    include_store: bool = False,
    networks: Iterable[str] = (),
    vms: Iterable[str] = (),
) -> MachineResourceLockScope:
    """Return a class-based ordered machine-resource lock scope."""
    return MachineResourceLockScope(
        layout,
        group_gid=group_gid,
        include_store=include_store,
        networks=networks,
        vms=vms,
    )
