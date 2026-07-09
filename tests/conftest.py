"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from pytest import MonkeyPatch

from aivm.commands import CommandManager


@pytest.fixture(autouse=True)
def _fresh_command_manager() -> None:
    """Drop any manager a previous test activated.

    The manager is context-global; without this, a test that activates a
    manager with a non-default privilege mode would leak it into later
    tests that rely on ``CommandManager.current()`` defaults.
    """
    CommandManager.reset_current()




@pytest.fixture(autouse=True)
def _pin_privilege_probe(monkeypatch: MonkeyPatch) -> None:
    """Pin the sudoless capability probe to "unavailable" by default.

    Most unit tests fake subprocess execution and assert on the classic
    sudo-prefixed command shapes. With the default ``privilege_mode='auto'``
    the first libvirt command would first submit a live
    ``virsh -c qemu:///system list --name`` capability probe, which those
    strict fakes reject. Pinning the probe to False makes 'auto' behave
    exactly like 'sudo' in tests; privilege-specific tests override this
    fixture explicitly.
    """
    monkeypatch.setattr(
        'aivm.privilege.libvirt_unprivileged_ok', lambda: False
    )
