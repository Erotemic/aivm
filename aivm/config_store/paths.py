"""Filesystem locations used by the AIVM config store."""

from __future__ import annotations

from pathlib import Path

import ubelt as ub


def _appdir(appname: str, kind: str) -> Path:
    p = ub.Path.appdir(appname, type=kind).ensuredir()
    return Path(p)


def app_data_dir() -> Path:
    """User-writable application data directory for operational artifacts."""
    return _appdir('aivm', 'data')


def app_data_path(*parts: str) -> Path:
    """Return a path under the user-owned aivm data directory."""
    return app_data_dir().joinpath(*parts)


def persistent_host_state_dir(vm_name: str) -> Path:
    """User-owned host-side sync state for persistent attachments."""
    return app_data_path(vm_name, 'state')


def store_path() -> Path:
    return _appdir('aivm', 'config') / 'config.toml'
