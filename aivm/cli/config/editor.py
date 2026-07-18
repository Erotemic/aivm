"""Shared editor selection and invocation helpers for config commands."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable

from ...commands import CommandManager
from ...errors import AIVMError
from ...util import which


def select_editor_command(
    *,
    editor: str = '',
    prefer_visual: bool = False,
    fallbacks: Iterable[str] = ('nano', 'vi'),
    required: bool = True,
) -> list[str] | None:
    """Resolve an editor without silently dropping into an unfriendly fallback."""
    order = ['VISUAL', 'EDITOR'] if prefer_visual else ['EDITOR', 'VISUAL']
    candidates = [
        str(editor or '').strip(),
        *(os.environ.get(key, '').strip() for key in order),
    ]
    editor_cmd = next((candidate for candidate in candidates if candidate), '')
    if not editor_cmd:
        for name in fallbacks:
            resolved = which(name)
            if resolved:
                editor_cmd = resolved
                break
    if not editor_cmd:
        if required:
            raise AIVMError('No editor found. Set $EDITOR or pass --editor.')
        return None
    return shlex.split(editor_cmd)


def edit_path(path: Path, command: list[str]) -> None:
    """Open ``path`` in an interactive editor command."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text('', encoding='utf-8')
    CommandManager.current().run(
        [*command, str(path)], sudo=False, check=True, capture=False
    )
