"""Tests for AIVM-owned XDG path and terminal compatibility helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.config_store.paths import app_data_dir
from aivm.terminal import highlight_code
from aivm.user_paths import user_app_dir


def test_implicit_app_data_path_is_confined_to_test_xdg_root(
    isolated_user_state: dict[str, Path],
) -> None:
    assert app_data_dir() == isolated_user_state['data'] / 'aivm'
    assert app_data_dir().is_dir()


def test_user_app_dir_honors_xdg_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    custom = tmp_path / 'custom-config'
    monkeypatch.setenv('XDG_CONFIG_HOME', str(custom))

    path = user_app_dir('aivm', 'config')

    assert path == custom / 'aivm'
    assert path.is_dir()


def test_user_app_dir_rejects_unknown_kind() -> None:
    with pytest.raises(KeyError, match='Unknown user app directory kind'):
        user_app_dir('aivm', 'mystery')


def test_highlight_code_is_optional_and_preserves_content() -> None:
    text = 'echo hello\n'
    rendered = highlight_code(text, lexer_name='bash')
    assert 'echo' in rendered
    assert 'hello' in rendered
