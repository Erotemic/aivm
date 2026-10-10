"""Host files that policy, credentials, trust anchors and audit depend on.

Two questions are asked of every path, and both are asked of the *whole*
path rather than of its last component or of its resolved destination:

**Could the guest have put this here?** ``untrusted`` roots are directories
the guest can write (for AIVM, the shared workspace). A path is refused if
any location visited while resolving it lies under one: the path as written,
every symbolic link followed on the way, and the place it finally leads.
Checking only the destination is not enough -- ``/shared/link/token`` with
``link -> /host/private`` resolves outside the workspace while the guest
still decides, at any moment, what it resolves to.

**Could another local user change it?** Every directory on the way must be
owned by root or the caller and writable by nobody else. World write is
refused unless the directory is sticky (``/tmp``). Group write is refused
unless the group is *provably* the caller's own: see :func:`_private_group`.
That proof is deliberately hard to obtain, because a group's member list
does not show the accounts whose *primary* group it is.

Resolution walks from ``/`` through held directory descriptors opened with
``O_NOFOLLOW``, following symbolic links itself, one component at a time. The
object that was checked is therefore the object that is used.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path

from ..errors import SecretsError

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_LINKS = 40
Roots = tuple[Path, ...]
NSSWITCH = Path('/etc/nsswitch.conf')
# Account databases whose every entry ``getpwall`` is known to return.
ENUMERABLE = frozenset({'files', 'systemd'})


def _unsafe(
    path: object, reason: str, code: str = 'unsafe_file'
) -> SecretsError:
    return SecretsError(code, detail=f'{path}: {reason}')


def _root_forms(roots: Roots) -> list[Path]:
    """Each untrusted root as written and as resolved: both name it."""
    forms: list[Path] = []
    for root in roots:
        for form in (os.path.abspath(root), os.path.realpath(root)):
            if Path(form) not in forms:
                forms.append(Path(form))
    return forms


def _refuse_under(location: str, forms: list[Path], what: str) -> None:
    place = Path(location)
    for root in forms:
        if place == root or root in place.parents:
            raise SecretsError(
                'shared_source', detail=f'{what} {location} is under {root}'
            )


def _accounts_enumerable() -> bool:
    """Whether listing the account database can be trusted to be complete.

    A directory service (``sss``, ``ldap``, ``winbind``, ...) usually does
    not enumerate, so an account sharing our group could exist unseen. Only
    local databases count, and anything unreadable or unrecognized is "no".
    """
    try:
        text = NSSWITCH.read_text(encoding='ascii')
    except (OSError, UnicodeError):
        return False
    for line in text.splitlines():
        entry = line.split('#', 1)[0].strip()
        if not entry.startswith('passwd:'):
            continue
        sources = [
            word
            for word in entry[len('passwd:') :].split()
            if not word.startswith('[')
        ]
        return bool(sources) and all(word in ENUMERABLE for word in sources)
    return False


def _private_group(gid: int) -> bool:
    """Whether nobody but the caller can act through group ``gid``.

    Group-writable paths are normal on hosts that give each user a private
    group and a ``0002`` umask, so refusing them outright would refuse the
    stock configuration. They are accepted only when all of this holds:

    * ``gid`` is the caller's primary group;
    * the group lists no member other than the caller;
    * no *other account* has it as its primary group -- membership that the
      group's own member list never shows; and
    * every account can be seen: the host's account database is local.

    Anything that cannot be established counts as shared.
    """
    try:
        me = pwd.getpwuid(os.getuid())
        if gid != me.pw_gid or not _accounts_enumerable():
            return False
        if any(name != me.pw_name for name in grp.getgrgid(gid).gr_mem):
            return False
        return not any(
            entry.pw_gid == gid and entry.pw_uid != me.pw_uid
            for entry in pwd.getpwall()
        )
    except (KeyError, OSError):
        return False


def _check_directory(info: os.stat_result, shown: object) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise _unsafe(shown, 'not a directory')
    if info.st_uid not in (0, os.getuid()):
        raise _unsafe(shown, 'directory owned by another user')
    if info.st_mode & stat.S_ISVTX:
        return
    if info.st_mode & stat.S_IWOTH:
        raise _unsafe(shown, 'directory is world-writable')
    if info.st_mode & stat.S_IWGRP and not _private_group(info.st_gid):
        raise _unsafe(
            shown,
            'directory is writable by a shared group '
            '(not provably yours alone; chmod g-w)',
        )


def _walk(
    path: Path, untrusted: Roots, what: str, *, follow_leaf: bool
) -> tuple[int, str, Path]:
    """Resolve ``path`` safely; return ``(parent fd, leaf name, location)``.

    The caller owns the returned descriptor. ``location`` is where the leaf
    really is, with every link resolved. With ``follow_leaf`` a final
    symbolic link is followed like any other; without it the link itself is
    returned, for a caller that will refuse to open one.
    """
    text = os.fspath(path)
    if not os.path.isabs(text):
        raise _unsafe(path, 'path is not absolute')
    forms = _root_forms(untrusted)
    pending = [part for part in text.split('/') if part and part != '.']
    if not pending:
        raise _unsafe(path, 'path has no final component')
    links = 0
    current = ''
    fd = os.open('/', _DIR_FLAGS)
    try:
        _check_directory(os.fstat(fd), '/')
        while True:
            part = pending.pop(0)
            if part == '..':
                step = os.open('..', os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = step
                current = os.path.dirname(current)
                _check_directory(os.fstat(fd), current or '/')
                if not pending:
                    raise _unsafe(path, 'path has no final component')
                continue
            candidate = f'{current}/{part}'
            # The location itself, before anything about it is believed.
            _refuse_under(candidate, forms, what)
            info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) and (pending or follow_leaf):
                links += 1
                if links > MAX_LINKS:
                    raise _unsafe(path, 'too many levels of symbolic links')
                if info.st_uid not in (0, os.getuid()):
                    raise _unsafe(candidate, 'symlink owned by another user')
                target = os.readlink(part, dir_fd=fd)
                if target.startswith('/'):
                    step = os.open('/', _DIR_FLAGS)
                    os.close(fd)
                    fd = step
                    current = ''
                pending = [
                    item for item in target.split('/') if item and item != '.'
                ] + pending
                if not pending:
                    raise _unsafe(path, 'path has no final component')
                continue
            if not pending:
                return fd, part, Path(candidate)
            # O_NOFOLLOW: a component swapped for a link since the stat
            # above fails here instead of being followed.
            step = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = step
            current = candidate
            _check_directory(os.fstat(fd), current)
    except OSError as ex:
        os.close(fd)
        raise _unsafe(path, ex.strerror or 'cannot open') from None
    except BaseException:
        os.close(fd)
        raise


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
        if info.st_mode & stat.S_IWGRP and not _private_group(info.st_gid):
            raise _unsafe(
                path,
                'writable by a shared group '
                '(not provably yours alone; chmod g-w)',
            )
    if role != 'program' and info.st_nlink != 1:
        raise _unsafe(path, 'has additional hard links')


def read_owned(
    path: Path,
    *,
    private: bool,
    limit: int = 65536,
    untrusted: Roots = (),
    what: str = 'file',
) -> bytes:
    """Read a secret (``private``) or a trusted configuration file.

    Refuses a final symlink, hard links, non-regular files, unsafe owners
    and modes, oversized content, any unsafe directory on the way, and any
    path that passes through an ``untrusted`` root.
    """
    fd, leaf, location = _walk(Path(path), untrusted, what, follow_leaf=False)
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
            location,
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


def verify_program(path: Path, untrusted: Roots = ()) -> Path:
    """Locate a resolver executable; return where it *really* is.

    The name may be a symbolic link (``/snap/bin/gh``). Every link followed
    and every directory passed must be trusted and outside every
    ``untrusted`` root, and the final target must be a regular executable
    nobody else can modify.

    The caller must execute the returned location, not the name it started
    from: a name is re-resolved at ``exec`` time, the returned location has
    no link left in it to redirect. A program that dispatches on
    ``argv[0]`` can still be given its original name as ``argv[0]``.
    """
    fd, leaf, location = _walk(
        Path(os.path.abspath(path)),
        untrusted,
        'credential resolver',
        follow_leaf=True,
    )
    try:
        try:
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        except OSError as ex:
            raise _unsafe(location, ex.strerror or 'cannot stat') from None
    finally:
        os.close(fd)
    _check_file(info, location, role='program')
    if not info.st_mode & 0o111:
        raise _unsafe(location, 'not executable')
    return location


def private_directory(path: Path, untrusted: Roots = ()) -> Path:
    """Create (or accept) a caller-owned ``0700`` directory on a safe path."""
    path = Path(path)
    # Before anything is created: a path through a guest-owned link must
    # not get a directory made wherever that link currently points.
    outside(path, untrusted, what='directory')
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot create') from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise _unsafe(path, 'not a directory owned by the current user')
    if info.st_mode & 0o077:
        raise _unsafe(path, 'accessible by group/other')
    # Verify the directory itself and everything above it, by resolving an
    # imaginary entry inside it.
    fd, _, _ = _walk_into(path, untrusted, 'directory')
    os.close(fd)
    return path


def _walk_into(
    path: Path, untrusted: Roots, what: str
) -> tuple[int, str, Path]:
    """Open ``path`` itself as a verified directory."""
    fd, leaf, location = _walk(
        Path(os.path.abspath(path)), untrusted, what, follow_leaf=False
    )
    try:
        step = os.open(leaf, _DIR_FLAGS, dir_fd=fd)
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot open') from None
    finally:
        os.close(fd)
    try:
        _check_directory(os.fstat(step), location)
    except BaseException:
        os.close(step)
        raise
    return step, leaf, location


def write_new(path: Path, data: bytes) -> None:
    """Create a ``0600`` file that must not already exist."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except OSError as ex:
        raise _unsafe(path, ex.strerror or 'cannot create') from None


def outside(path: Path, roots: Roots, *, what: str) -> Path:
    """Refuse a host path the guest could have placed or could redirect.

    Unlike :func:`read_owned` this makes no ownership judgement and does not
    require the path to exist: it answers only whether resolving ``path``
    visits an untrusted root. The path as written, each symbolic link on the
    way and the final destination are all checked. Returns the destination.
    """
    forms = _root_forms(roots)
    text = os.path.abspath(Path(path).expanduser())
    _refuse_under(text, forms, what)
    pending = [part for part in text.split('/') if part]
    current = ''
    links = 0
    while pending:
        part = pending.pop(0)
        if part == '..':
            current = os.path.dirname(current)
            continue
        candidate = f'{current}/{part}'
        _refuse_under(candidate, forms, what)
        try:
            target = os.readlink(candidate)
        except OSError:
            # Not a link, or not there: nothing further to follow here.
            current = candidate
            continue
        links += 1
        if links > MAX_LINKS:
            raise _unsafe(path, 'too many levels of symbolic links')
        if target.startswith('/'):
            current = ''
        pending = [
            item for item in target.split('/') if item and item != '.'
        ] + pending
    return Path(current or '/')
