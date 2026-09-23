"""Per-user path behavior retained for pre-0.6.0 stores."""

from __future__ import annotations

from pathlib import Path

from aivm.legacy.pre_0_6_0.paths import store_path


def test_pre_0_6_0_store_path_is_confined_to_test_xdg_root(
    isolated_user_state: dict[str, Path],
) -> None:
    expected = isolated_user_state['config'] / 'aivm' / 'config.toml'
    assert store_path() == expected
    assert store_path().parent.is_dir()
