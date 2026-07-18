"""Regression tests for release-blocking CLI and config failures."""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from aivm.cli._common import _BaseCommand
from aivm.cli.host_permissions import (
    _adopt_one_tree,
    _adopt_safety_error,
    _adopt_script,
)
from aivm.config import VirtiofsConfig


@pytest.mark.parametrize(
    'args',
    [
        ['--help'],
        ['host', '--help'],
        ['host', 'permissions', 'setup', '--help'],
        ['vm', 'create', '--help'],
        ['status', '--help'],
    ],
)
def test_help_exits_successfully(args: list[str]) -> None:
    proc = subprocess.run(
        [sys.executable, '-m', 'aivm', *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert 'help' in (proc.stdout + proc.stderr).lower()


def test_never_sudo_flag_is_not_public() -> None:
    assert 'never_sudo' not in vars(_BaseCommand)


def test_fdguard_defaults_are_complete() -> None:
    cfg = VirtiofsConfig()
    assert cfg.fd_guard_threshold == 500_000
    assert cfg.fd_guard_emergency_threshold == 750_000
    assert cfg.fd_guard_interval_sec == 600


def test_adopt_e2e_imports_renamed_module() -> None:
    source = (Path(__file__).parent / 'e2e/test_adopt.py').read_text(
        encoding='utf-8'
    )
    assert 'aivm.cli.host_permissions' in source


def test_adopt_rejects_broad_system_roots() -> None:
    assert _adopt_safety_error(Path('/var/lib')) is not None
    assert _adopt_safety_error(Path('/var/lib/libvirt')) is not None


def test_adopt_script_prunes_mounts_and_symlinks(tmp_path: Path) -> None:
    tree = tmp_path / 'vm-storage'
    tree.mkdir()
    script = _adopt_script(tree)
    assert '/proc/self/mountinfo' in script
    assert 'followlinks=False' in script
    assert 'path.is_symlink()' in script


def test_adopt_restarts_stopped_vm_after_handoff_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tree = tmp_path / 'vm-storage'
    tree.mkdir()
    restarted: list[str] = []
    monkeypatch.setattr(
        'aivm.cli.host_permissions._get_vm_state',
        lambda name: (0, 'running', ''),
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.shutdown_vm', lambda cfg: None
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions._wait_for_vm_state', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions._start_vm', restarted.append
    )

    class FailingManager:
        def step(
            self, *args: object, **kwargs: object
        ) -> contextlib.AbstractContextManager[None]:
            return contextlib.nullcontext()

        def submit(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError('handoff failed')

    args = SimpleNamespace(dry_run=False, config=None)
    with pytest.raises(RuntimeError, match='handoff failed'):
        _adopt_one_tree(args, cast(Any, FailingManager()), tree, ['vm-a'])
    assert restarted == ['vm-a']
