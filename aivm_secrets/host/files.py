"""Host files that policy, credentials, trust anchors and audit depend on.

Every path is checked along its whole length, not only at its last
component. A file is opened by walking from ``/`` through directory
descriptors with ``O_NOFOLLOW``, so the object that was checked is the object
that is read: there is no window in which a component can be swapped for a
symlink. No secret is ever read from a guest-supplied path.

A directory on the way is trusted when no principal other than root or the
caller can rename what it contains:

* it is owned by root or by the caller;
* it is not world-writable, unless sticky (``/tmp``);
* it is not group-writable, unless sticky, root-owned (root's own
  delegation), or owned by the caller's private primary group.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path

from ..errors import SecretsError

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _unsafe(
    path: object, reason: str, code: str = 'unsafe_file'
) -> SecretsError:
    return SecretsError(code, detail=f'{path}: {reason}')


def _private_group(gid: int) -> bool:
    """True for a user-private group: the caller's primary, with no others."""
    try:
        me = pwd.getpwuid(os.getuid())
        members = set(grp.getgrgid(gid).gr_mem)
    except KeyError:
        return False
    return gid == me.pw_gid and members <= {me.pw_name}


def _check_directory(info: os.stat_result, shown: object) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise _unsafe(shown, 'not a directory')
    if info.st_uid not in (0, os.getuid()):
        raise _unsafe(shown, 'directory owned by another user')
    if info.st_mode & stat.S_ISVTX:
        return
    if info.st_mode & stat.S_IWOTH:
        raise _unsafe(shown, 'directory is world-writable')
    if (
        info.st_mode & stat.S_IWGRP
        and info.st_uid != 0
        and not _private_group(info.st_gid)
    ):
        raise _unsafe(shown, 'directory is group-writable')


def _open_parent(path: Path) -> tuple[int, str]:
    """Open the verified parent directory of ``path``; return (fd, leaf)."""
    text = os.fspath(path)
    if not os.path.isabs(text):
        raise _unsafe(path, 'path is not absolute')
    try:
        # Ancestor symlinks are resolved once, then every component of the
        # result is re-opened without following links and checked.
        parent = os.path.realpath(os.path.dirname(text))
        leaf = os.path.basename(text)
        if leaf in ('', '.', '..'):
            raise _unsafe(path, 'path has no final component')
        fd = os.open('/', _DIR_FLAGS)
        try:
            _check_directory(os.fstat(fd), '/')
            walked = ''
            for part in [item for item in parent.split('/') if item]:
                walked += '/' + part
                step = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = step
                _check_directory(os.fstat(fd), walked)
        except BaseException:
            os.close(fd)
            raise
        return fd, leaf
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot open') from None


def _check_file(info: os.stat_result, path: Path, *, role: str) -> None:
    """``role`` is ``private`` (secret), ``trusted`` (config) or ``program``."""
    if not stat.S_ISREG(info.st_mode):
        raise _unsafe(path, 'not a regular file')
    if role == 'private':
        if info.st_uid != os.getuid():
            raise _unsafe(path, 'not owned by the current user')
        if info.st_mode & 0o077:
            raise _unsafe(path, 'readable or writable by group/other')
    else:
        if info.st_uid not in (0, os.getuid()):
            raise _unsafe(path, 'owned by another user')
        if info.st_mode & stat.S_IWOTH:
            raise _unsafe(path, 'world-writable')
        if info.st_mode & stat.S_IWGRP and (
            role == 'trusted'
            or (info.st_uid != 0 and not _private_group(info.st_gid))
        ):
            raise _unsafe(path, 'group-writable')
    if role != 'program' and info.st_nlink != 1:
        raise _unsafe(path, 'has additional hard links')


def read_owned(path: Path, *, private: bool, limit: int = 65536) -> bytes:
    """Read a secret (``private``) or a trusted configuration file.

    Refuses symlinks, hard links, non-regular files, unsafe owners and modes,
    oversized content, and any unsafe directory on the way.
    """
    fd, leaf = _open_parent(Path(path))
    try:
        try:
            handle = os.open(
                leaf,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=fd,
            )
        except OSError as ex:
            raise _unsafe(path, ex.strerror or 'cannot open') from None
    finally:
        os.close(fd)
    try:
        # Judge the descriptor before anything is read from it: a FIFO or a
        # directory is refused here, not discovered by a failing read.
        _check_file(
            os.fstat(handle),
            Path(path),
            role='private' if private else 'trusted',
        )
        result = b''
        while len(result) <= limit:
            chunk = os.read(handle, limit + 1 - len(result))
            if not chunk:
                break
            result += chunk
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot read') from None
    finally:
        os.close(handle)
    if len(result) > limit:
        raise _unsafe(path, f'larger than {limit} bytes')
    return result


def verify_program(path: Path, untrusted: tuple[Path, ...] = ()) -> Path:
    """Require a trustworthy path to a resolver executable; return that path.

    The name may be a symlink (``/snap/bin/gh``), and programs that dispatch
    on ``argv[0]`` need to be run by that name, so the link is followed here
    one hop at a time rather than replaced by its target. Every hop must sit
    in a trusted directory and outside every ``untrusted`` root, and the
    final target must be a regular executable no other user can modify.
    Because each directory on the way is controlled only by root or the
    caller, the name cannot be redirected between this check and ``exec``.
    """
    first = current = Path(os.path.abspath(path))
    for _ in range(16):
        located = Path(os.path.realpath(current.parent)) / current.name
        _refuse_under(located, untrusted, 'credential resolver')
        fd, leaf = _open_parent(current)
        try:
            try:
                info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                target = (
                    os.readlink(leaf, dir_fd=fd)
                    if stat.S_ISLNK(info.st_mode)
                    else None
                )
            except OSError as ex:
                raise _unsafe(located, ex.strerror or 'cannot stat') from None
        finally:
            os.close(fd)
        if target is None:
            _check_file(info, located, role='program')
            if not info.st_mode & 0o111:
                raise _unsafe(located, 'not executable')
            return first
        if info.st_uid not in (0, os.getuid()):
            raise _unsafe(located, 'symlink owned by another user')
        current = Path(os.path.normpath(located.parent / target))
    raise _unsafe(first, 'too many levels of symbolic links')


def private_directory(path: Path) -> Path:
    """Create (or accept) a caller-owned ``0700`` directory on a safe path."""
    path = Path(path)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot create') from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise _unsafe(path, 'not a directory owned by the current user')
    if info.st_mode & 0o077:
        raise _unsafe(path, 'accessible by group/other')
    os.close(_open_parent(path / 'leaf')[0])
    return path


def write_new(path: Path, data: bytes) -> None:
    """Create a ``0600`` file that must not already exist."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot create') from None


def _refuse_under(resolved: Path, roots: tuple[Path, ...], what: str) -> None:
    for root in roots:
        if resolved.is_relative_to(Path(os.path.realpath(root))):
            raise SecretsError(
                'shared_source', detail=f'{what} {resolved} is under {root}'
            )


def outside(path: Path, roots: tuple[Path, ...], *, what: str) -> Path:
    """Refuse a host path that lies inside a guest-writable directory.

    ``roots`` are the directories the caller has declared untrusted -- for
    AIVM, the workspace being shared with the guest. A policy, credential or
    program found there is controlled by the party it is meant to constrain.
    """
    resolved = Path(os.path.realpath(Path(path).expanduser()))
    _refuse_under(resolved, roots, what)
    return resolved
