"""Released pre-0.6 per-user filesystem locations."""

from __future__ import annotations

from pathlib import Path

from ...user_paths import user_app_dir


def store_path() -> Path:
    """Return the released per-user desired-state store path."""
    return user_app_dir('aivm', 'config') / 'config.toml'


def persistent_host_state_dir(vm_name: str) -> Path:
    """Return the released per-user persistent replay-state directory."""
    return user_app_dir('aivm', 'data', mode=0o700) / vm_name / 'state'
