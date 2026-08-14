"""Tests for narrow one-shot guest requirement provisioning."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from aivm.commands import Elided
from aivm.config import AgentVMConfig
from aivm.vm.provision import provision_guest_requirements
from tests.helpers import FakeCommandManager


def test_targeted_code_requirement_does_not_enable_unrelated_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    assert cfg.tools.code == 'off'
    assert cfg.tools.uv == 'latest'

    transport = SimpleNamespace(
        ssh_identity_file='/tmp/id_ed25519',
        ssh_target=lambda ip: f'agent@{ip}',
    )
    provision_mod = importlib.import_module('aivm.vm.provision')
    monkeypatch.setattr(
        provision_mod, 'guest_transport_from_effective_cfg', lambda cfg: transport
    )
    monkeypatch.setattr(
        provision_mod, 'require_ssh_identity', lambda path: '/tmp/id_ed25519'
    )
    manager = FakeCommandManager()
    monkeypatch.setattr(provision_mod.CommandManager, 'current', lambda: manager)

    provision_guest_requirements(
        cfg,
        '10.77.0.103',
        tools=('code',),
    )

    assert cfg.tools.code == 'off'
    assert len(manager.calls) == 1
    payload = manager.calls[0][-1]
    assert isinstance(payload, Elided)
    script = str(payload)
    assert 'packages.microsoft.com/repos/code' in script
    assert 'apt-get install -y code' in script
    assert 'astral.sh/uv' not in script
    assert 'rustup' not in script
    assert 'docker' not in script


def test_targeted_package_and_tool_share_one_install_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    transport = SimpleNamespace(
        ssh_identity_file='/tmp/id_ed25519',
        ssh_target=lambda ip: f'agent@{ip}',
    )
    provision_mod = importlib.import_module('aivm.vm.provision')
    monkeypatch.setattr(
        provision_mod, 'guest_transport_from_effective_cfg', lambda cfg: transport
    )
    monkeypatch.setattr(
        provision_mod, 'require_ssh_identity', lambda path: '/tmp/id_ed25519'
    )
    manager = FakeCommandManager()
    monkeypatch.setattr(provision_mod.CommandManager, 'current', lambda: manager)

    provision_guest_requirements(
        cfg,
        '10.77.0.103',
        packages=('tmux',),
        tools=('code',),
    )

    assert len(manager.calls) == 1
    script = str(manager.calls[0][-1])
    assert 'apt-get install -y tmux' in script
    assert 'apt-get install -y code' in script
