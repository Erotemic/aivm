"""Shared pytest fixtures.

The vocabulary these fixtures are built from lives in :mod:`tests.helpers`;
this module only promotes the pieces that enough files want to receive by
name rather than import.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager
from tests.helpers import written_cfg


@pytest.fixture(autouse=True)
def _fresh_command_manager() -> None:
    """Drop any manager a previous test activated.

    The manager is context-global; without this, a test that activates a
    manager with a non-default privilege mode would leak it into later
    tests that rely on ``CommandManager.current()`` defaults.
    """
    CommandManager.reset_current()


@pytest.fixture
def cfg_path(tmp_path: Path) -> Path:
    """A saved single-VM config store, sandboxed under ``tmp_path``.

    This is the scaffolding a CLI test opens with: a ``test-vm`` owned by
    ``agent`` whose every path lives inside the sandbox, written to a
    ``config.toml`` the CLI can be pointed at with ``--config``.
    """
    return written_cfg(tmp_path)


@pytest.fixture(autouse=True)
def _pin_privilege_probe(monkeypatch: MonkeyPatch) -> None:
    """Pin the sudoless capability probe to "unavailable" by default.

    Most unit tests fake subprocess execution and assert on the classic
    sudo-prefixed command shapes. With the default ``privilege_mode='as-needed'``
    the first libvirt command would first submit a live
    ``virsh -c qemu:///system list --name`` capability probe, which those
    strict fakes reject. Pinning the probe to False makes 'as-needed'
    behave exactly like 'always' in tests; privilege-specific tests override this
    fixture explicitly.
    """
    monkeypatch.setattr(
        'aivm.privilege.libvirt_unprivileged_ok', lambda: False
    )
