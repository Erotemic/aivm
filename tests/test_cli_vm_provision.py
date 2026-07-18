"""Tests for the ``aivm vm provision`` CLI override-argument behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.cli.vm_lifecycle import VMProvisionCLI
from aivm.config import AgentVMConfig


def _stub_cfg_loader(monkeypatch: pytest.MonkeyPatch, cfg: AgentVMConfig) -> None:
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.load_cfg', lambda *a, **k: cfg
    )
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.cfg_path',
        lambda *a, **k: Path('/tmp/aivm-test-config.toml'),
    )


def test_provision_with_positional_tools_enables_them_for_this_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    # Defaults under test: code is OFF by default; we expect the CLI to
    # flip it to "latest" for this run only.
    assert cfg.tools.code == 'off'

    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, AgentVMConfig] = {}

    def fake_provision(received: AgentVMConfig, *, dry_run: bool) -> None:
        captured['cfg'] = received

    monkeypatch.setattr('aivm.cli.vm_lifecycle.provision', fake_provision)

    rc = VMProvisionCLI.main(
        argv=False, config=str(cfg_path), tools=['code'], dry_run=True
    )
    assert rc == 0
    assert captured['cfg'].tools.code == 'latest'
    # Other tool defaults stay where they were.
    assert captured['cfg'].tools.uv == 'latest'
    assert captured['cfg'].tools.rust == 'off'


def test_provision_with_multiple_positional_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, AgentVMConfig] = {}

    def fake_provision(received: AgentVMConfig, *, dry_run: bool) -> None:
        captured['cfg'] = received

    monkeypatch.setattr('aivm.cli.vm_lifecycle.provision', fake_provision)

    rc = VMProvisionCLI.main(
        argv=False,
        config=str(cfg_path),
        tools=['code', 'rust'],
        dry_run=True,
    )
    assert rc == 0
    assert captured['cfg'].tools.code == 'latest'
    assert captured['cfg'].tools.rust == 'stable'


def test_provision_rejects_unknown_tool_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    called = {'n': 0}

    def fake_provision(*a: Any, **k: Any) -> None:  # pragma: no cover - should not run
        called['n'] += 1

    monkeypatch.setattr('aivm.cli.vm_lifecycle.provision', fake_provision)

    rc = VMProvisionCLI.main(
        argv=False,
        config=str(cfg_path),
        tools=['kubernetes'],
        dry_run=True,
    )
    assert rc == 2
    assert called['n'] == 0
