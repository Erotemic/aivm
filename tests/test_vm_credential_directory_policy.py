"""Credential-directory permission policy tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.cli.config.lint import _lint_store_text
from aivm.config_store import Store, parse_store_toml, render_store_toml
from aivm.credentials.keys import host_credential_dir
from aivm.credentials.policy import (
    credential_directory_permission_policy,
    normalize_credential_directory_permission_policy,
    reset_credential_directory_permission_policy,
    set_credential_directory_permission_policy,
)
from aivm.errors import AIVMError
from aivm.services import bind_active_config_option


@pytest.fixture(autouse=True)
def _unbind_active_config() -> Iterator[None]:
    """Keep a store bound here from leaking into other test modules."""
    yield
    bind_active_config_option(None)


def test_credential_directory_permission_policy_values() -> None:
    assert normalize_credential_directory_permission_policy(None) == 'warn'
    assert normalize_credential_directory_permission_policy(' WARN ') == 'warn'
    assert normalize_credential_directory_permission_policy('error') == 'error'
    assert normalize_credential_directory_permission_policy('ignore') == 'ignore'
    with pytest.raises(AIVMError, match='Unknown behavior'):
        normalize_credential_directory_permission_policy('sometimes')


def test_policy_round_trip_and_lint() -> None:
    store = Store()
    store.behavior.credential_directory_permission_policy = 'error'
    text = render_store_toml(store)
    assert 'credential_directory_permission_policy = "error"' in text
    assert not _lint_store_text(text)
    parsed = parse_store_toml(text)
    assert parsed.behavior.credential_directory_permission_policy == 'error'


def _write_policy_store(tmp_path: Path, policy: str) -> Path:
    path = tmp_path / 'config.toml'
    path.write_text(
        'schema = 6\n\n[behavior]\n'
        f'credential_directory_permission_policy = "{policy}"\n'
    )
    return path


def test_policy_is_read_from_the_store_the_command_bound(tmp_path: Path) -> None:
    # Core pushes nothing: it publishes which store is active and the
    # credential feature resolves its own setting from it.
    bind_active_config_option(str(_write_policy_store(tmp_path, 'ignore')))

    assert credential_directory_permission_policy() == 'ignore'


def test_missing_store_falls_back_to_warn(tmp_path: Path) -> None:
    bind_active_config_option(str(tmp_path / 'missing.toml'))

    assert credential_directory_permission_policy() == 'warn'


def test_unknown_policy_in_store_is_an_error(tmp_path: Path) -> None:
    # A typo must not silently pick an enforcement level for the user.
    bind_active_config_option(str(_write_policy_store(tmp_path, 'sometimes')))

    with pytest.raises(AIVMError, match='Unknown behavior'):
        credential_directory_permission_policy()


@pytest.mark.parametrize('policy', ['warn', 'ignore'])
def test_non_strict_policies_allow_broad_vm_directory(
    monkeypatch: MonkeyPatch, tmp_path: Path, policy: str
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    path = host_credential_dir('vm-a', 'git-123456789abc')
    vm_dir = path.parent.parent
    vm_dir.mkdir(mode=0o775)
    vm_dir.chmod(0o775)
    token = set_credential_directory_permission_policy(policy)
    try:
        assert host_credential_dir('vm-a', 'git-123456789abc') == path
    finally:
        reset_credential_directory_permission_policy(token)


def test_error_policy_blocks_broad_vm_directory(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    path = host_credential_dir('vm-a', 'git-123456789abc')
    vm_dir = path.parent.parent
    vm_dir.mkdir(mode=0o775)
    vm_dir.chmod(0o775)
    token = set_credential_directory_permission_policy('error')
    try:
        with pytest.raises(AIVMError, match='broader than recommended'):
            host_credential_dir('vm-a', 'git-123456789abc')
    finally:
        reset_credential_directory_permission_policy(token)
