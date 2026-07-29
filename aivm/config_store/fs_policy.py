"""Filesystem policy primitives for private and machine-wide stores.

The legacy AIVM store is private to one user and therefore relies on the
process umask.  A machine store is different: every trusted member of the
``aivm`` host group must be able to recover transactions and replace files
without silently changing their group or mode.  This module keeps those
filesystem rules explicit and injectable so tests never need to touch the real
``/var/lib/aivm`` tree.
"""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from types import TracebackType
from typing import Literal

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_HELD_LOCKS = threading.local()


def _process_lock(path: Path) -> threading.RLock:
    key = os.fspath(_absolute(path))
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.RLock())


def _held_locks() -> dict[str, int]:
    held = getattr(_HELD_LOCKS, 'paths', None)
    if held is None:
        held = {}
        _HELD_LOCKS.paths = held
    return held


@dataclass(frozen=True)
class StoreFilesystemPolicy:
    """Ownership and mode rules for one physical config store.

    ``None`` modes preserve the legacy behavior: directories and files are
    created subject only to the process umask.  Machine-store callers provide
    explicit modes, a group id, a managed root, and a central lock path.
    """

    managed_root: Path | None = None
    directory_mode: int | None = None
    file_mode: int | None = None
    group_gid: int | None = None
    lock_path: Path | None = None
    reject_symlinks: bool = False

    def with_lock_path(self, path: Path) -> StoreFilesystemPolicy:
        """Return the same policy routed through a particular lock file."""
        return replace(self, lock_path=path)


def _absolute(path: Path) -> Path:
    """Normalize a path lexically without resolving possibly hostile links."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _managed_chain(path: Path, policy: StoreFilesystemPolicy) -> list[Path]:
    target = _absolute(path)
    root = policy.managed_root
    if root is None:
        return [target]
    managed_root = _absolute(root)
    try:
        relative = target.relative_to(managed_root)
    except ValueError as ex:
        raise ValueError(
            f'Path {target} is outside managed store root {managed_root}'
        ) from ex
    chain = [managed_root]
    cursor = managed_root
    for part in relative.parts:
        cursor = cursor / part
        chain.append(cursor)
    return chain


def _reject_link(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise RuntimeError(f'Refusing to manage symlinked store path: {path}')


def _set_group(path: Path, group_gid: int | None) -> None:
    if group_gid is None:
        return
    current_gid = path.stat().st_gid
    if current_gid != group_gid:
        os.chown(path, -1, group_gid)


def ensure_store_directory(
    path: Path, policy: StoreFilesystemPolicy | None = None
) -> Path:
    """Create a store directory and enforce the configured metadata.

    When a managed root is present, every directory from that root through the
    target receives the policy.  Parent directories outside the managed root
    are never modified.
    """
    policy = policy or StoreFilesystemPolicy()
    chain = _managed_chain(path, policy)
    for current in chain:
        if policy.reject_symlinks:
            _reject_link(current)
        current.mkdir(parents=True, exist_ok=True)
        if policy.reject_symlinks:
            _reject_link(current)
        _set_group(current, policy.group_gid)
        if policy.directory_mode is not None:
            os.chmod(current, policy.directory_mode)
    return chain[-1]


def apply_store_file_policy(
    path: Path, policy: StoreFilesystemPolicy | None = None
) -> None:
    """Apply explicit file mode/group metadata after creation or replacement."""
    policy = policy or StoreFilesystemPolicy()
    if policy.reject_symlinks:
        _reject_link(path)
    _set_group(path, policy.group_gid)
    if policy.file_mode is not None:
        os.chmod(path, policy.file_mode)


def apply_store_file_descriptor_policy(
    fd: int, policy: StoreFilesystemPolicy | None = None
) -> None:
    """Apply explicit metadata to an open temporary or lock file."""
    policy = policy or StoreFilesystemPolicy()
    if policy.group_gid is not None:
        os.fchown(fd, -1, policy.group_gid)
    if policy.file_mode is not None:
        os.fchmod(fd, policy.file_mode)


class ExclusiveFileLock:
    """Process/thread-safe reentrant advisory file lock scope."""

    def __init__(
        self,
        path: Path,
        policy: StoreFilesystemPolicy | None = None,
    ) -> None:
        self.policy = policy or StoreFilesystemPolicy()
        self.lock_path = _absolute(path)
        self.key = os.fspath(self.lock_path)
        self.process_lock = _process_lock(self.lock_path)
        self.fd: int | None = None
        self.nested = False
        self.entered = False

    def __enter__(self) -> None:
        """Acquire the in-process lock and, for the outer scope, ``flock``."""
        if self.entered:
            raise RuntimeError('ExclusiveFileLock instances are single-use')
        self.entered = True
        self.process_lock.acquire()
        try:
            held = _held_locks()
            if self.key in held:
                held[self.key] += 1
                self.nested = True
                return None

            ensure_store_directory(self.lock_path.parent, self.policy)
            flags = os.O_RDWR | os.O_CREAT
            if self.policy.reject_symlinks and hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(
                self.lock_path,
                flags,
                self.policy.file_mode or 0o666,
            )
            try:
                apply_store_file_descriptor_policy(fd, self.policy)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except BaseException:
                os.close(fd)
                raise
            self.fd = fd
            held[self.key] = 1
            return None
        except BaseException:
            self.entered = False
            self.process_lock.release()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        """Release the nesting count or outer kernel and process locks."""
        try:
            held = _held_locks()
            if self.nested:
                held[self.key] -= 1
            else:
                held.pop(self.key, None)
                if self.fd is not None:
                    try:
                        fcntl.flock(self.fd, fcntl.LOCK_UN)
                    finally:
                        os.close(self.fd)
                        self.fd = None
        finally:
            self.entered = False
            self.process_lock.release()
        return False


def exclusive_file_lock(
    path: Path, policy: StoreFilesystemPolicy | None = None
) -> ExclusiveFileLock:
    """Return a class-based advisory file-lock context manager."""
    return ExclusiveFileLock(path, policy)
