"""Filesystem-object identities used to bind approval to opened objects."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FilesystemIdentity:
    dev: int
    ino: int


def _directory_flags() -> int:
    flags = getattr(os, 'O_PATH', os.O_RDONLY)
    flags |= getattr(os, 'O_DIRECTORY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0)
    return flags


def directory_identity(path: str | Path) -> FilesystemIdentity:
    """Identify one absolute directory through no-symlink component walking."""
    candidate = Path(os.fspath(path))
    if not candidate.is_absolute():
        raise ValueError(
            f'Directory identity path must be absolute: {candidate}'
        )
    parts = [part for part in candidate.parts if part not in {'', '/'}]
    if any(part in {'.', '..'} for part in parts):
        raise ValueError(f'Directory identity path is not lexical: {candidate}')

    flags = _directory_flags()
    current_fd = os.open('/', flags)
    try:
        for part in parts:
            next_fd = os.open(part, flags, dir_fd=current_fd)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_fd)
                raise NotADirectoryError(os.fspath(candidate))
            os.close(current_fd)
            current_fd = next_fd
        info = os.fstat(current_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError(os.fspath(candidate))
        return FilesystemIdentity(dev=int(info.st_dev), ino=int(info.st_ino))
    finally:
        os.close(current_fd)
