"""Shared utility re-exports and small filesystem/path helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from .commands import CommandError as CmdError
from .commands import CommandResult as CmdResult
from .commands import shell_join

# Re-export a few long-standing compatibility aliases used by tests/helpers.

__all__ = [
    'CmdError',
    'CmdResult',
    'shell_join',
    'which',
    'ensure_dir',
    'expand',
    'os',
    'sys',
]


def which(cmd: str) -> Optional[str]:
    from shutil import which as _which

    return _which(cmd)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))
