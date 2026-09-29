"""Small stdlib helpers for AIVM's user-owned XDG directories.

Historical provenance
---------------------
AIVM <= 0.5 used :func:`ubelt.Path.appdir` plus ``ensuredir`` for these
locations.  This module is a fresh, AIVM-owned implementation of the small
Linux/XDG behavior AIVM actually needs; no ubelt source was copied.  Keeping
that provenance here makes the dependency removal auditable without carrying a
large general-purpose utility dependency for two path lookups.
"""

from __future__ import annotations

import os
from pathlib import Path

_XDG_ENV_BY_KIND = {
    'config': ('XDG_CONFIG_HOME', '.config'),
    'data': ('XDG_DATA_HOME', '.local/share'),
    'cache': ('XDG_CACHE_HOME', '.cache'),
    'state': ('XDG_STATE_HOME', '.local/state'),
}


def user_app_dir(
    appname: str,
    kind: str,
    *,
    mode: int = 0o777,
    ensure: bool = True,
) -> Path:
    """Resolve an XDG user directory and optionally create it.

    Args:
        appname: Application directory name below the selected XDG root.
        kind: One of ``config``, ``data``, ``cache``, or ``state``.
        mode: Creation mode, subject to the process umask like ``Path.mkdir``.
        ensure: Create the directory and parents when true.
    """
    try:
        env_name, home_suffix = _XDG_ENV_BY_KIND[kind]
    except KeyError as ex:
        choices = ', '.join(sorted(_XDG_ENV_BY_KIND))
        raise KeyError(
            f'Unknown user app directory kind {kind!r}; choose {choices}'
        ) from ex

    configured_root = os.environ.get(env_name, '').strip()
    if configured_root:
        root = Path(configured_root).expanduser()
    else:
        root = Path.home() / home_suffix
    path = root / appname
    if ensure:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
    return path
