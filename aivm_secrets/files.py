"""Principal-owned host files. No secret is read from a guest-supplied path."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import SecretsError


def read_owned(path: Path, *, private: bool, limit: int = 65536) -> bytes:
    """Reject final symlinks, hard links, wrong owners and unsafe permissions.

    Ancestor directories remain part of the trusted host configuration. This
    is not the descriptor-relative, whole-path policy planned for Rust.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            forbidden = 0o077 if private else 0o022
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & forbidden):
                raise SecretsError('unsafe_file')
            result = stream.read(limit + 1)
            if len(result) > limit:
                raise SecretsError('unsafe_file')
            return result
    except OSError:
        raise SecretsError('unsafe_file') from None


def private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise SecretsError('unsafe_file')
        return path
    except OSError:
        raise SecretsError('unsafe_file') from None


def write_new(path: Path, data: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except OSError:
        raise SecretsError('unsafe_file') from None
