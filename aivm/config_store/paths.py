"""Filesystem locations used by the AIVM config store."""

from __future__ import annotations

from pathlib import Path

from ..user_paths import user_app_dir


def _appdir(appname: str, kind: str, *, mode: int = 0o777) -> Path:
    return user_app_dir(appname, kind, mode=mode)


def app_data_dir() -> Path:
    """User-writable application data directory for operational artifacts."""
    return _appdir('aivm', 'data', mode=0o700)


def app_data_path(*parts: str) -> Path:
    """Return a path under the user-owned aivm data directory."""
    return app_data_dir().joinpath(*parts)
