"""Tests for full versus named-target ``aivm vm provision`` behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aivm.cli.vm_lifecycle import VMProvisionCLI
from aivm.config import AgentVMConfig


def _stub_cfg_loader(
    monkeypatch: pytest.MonkeyPatch, cfg: AgentVMConfig
) -> None:
    monkeypatch.setattr('aivm.cli.vm_lifecycle.load_cfg', lambda *a, **k: cfg)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.cfg_path',
        lambda *a, **k: Path('/tmp/aivm-test-config.toml'),
    )


def test_provision_with_positional_tool_is_narrow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    assert cfg.tools.code == 'off'
    assert cfg.tools.uv == 'latest'

    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, Any] = {}

    def fake_requirements(
        received: AgentVMConfig,
        ip: str,
        *,
        packages=(),
        tools=(),
        dry_run: bool,
    ) -> None:
        captured.update(
            cfg=received,
            ip=ip,
            packages=tuple(packages),
            tools=tuple(tools),
            dry_run=dry_run,
        )

    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_requirements
    )
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision',
        lambda *a, **k: pytest.fail('named targets must not run full provision'),
    )

    rc = VMProvisionCLI.main(
        argv=False, config=str(cfg_path), tools=['code'], dry_run=True
    )
    assert rc == 0
    assert captured['cfg'] is cfg
    assert captured['ip'] == '0.0.0.0'
    assert captured['packages'] == ()
    assert captured['tools'] == ('code',)
    assert captured['dry_run'] is True
    # The narrow helper enables the requested tool on a copy, not in config.
    assert cfg.tools.code == 'off'
    assert cfg.tools.uv == 'latest'


def test_provision_with_multiple_positional_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, Any] = {}

    def fake_requirements(
        received: AgentVMConfig,
        ip: str,
        *,
        packages=(),
        tools=(),
        dry_run: bool,
    ) -> None:
        captured.update(packages=tuple(packages), tools=tuple(tools))

    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_requirements
    )

    rc = VMProvisionCLI.main(
        argv=False,
        config=str(cfg_path),
        tools=['code', 'rust'],
        dry_run=True,
    )
    assert rc == 0
    assert captured['packages'] == ()
    assert captured['tools'] == ('code', 'rust')


def test_provision_docker_maps_to_only_docker_packages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.provision.install_docker = False
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, Any] = {}

    def fake_requirements(
        received: AgentVMConfig,
        ip: str,
        *,
        packages=(),
        tools=(),
        dry_run: bool,
    ) -> None:
        captured.update(packages=tuple(packages), tools=tuple(tools))

    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_requirements
    )

    rc = VMProvisionCLI.main(
        argv=False, config=str(cfg_path), tools=['docker'], dry_run=True
    )
    assert rc == 0
    assert captured['packages'] == ('docker.io', 'docker-compose-v2')
    assert captured['tools'] == ()
    assert cfg.provision.install_docker is False


def test_provision_docker_can_mix_with_guest_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    captured: dict[str, Any] = {}

    def fake_requirements(
        received: AgentVMConfig,
        ip: str,
        *,
        packages=(),
        tools=(),
        dry_run: bool,
    ) -> None:
        captured.update(packages=tuple(packages), tools=tuple(tools))

    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_requirements
    )

    rc = VMProvisionCLI.main(
        argv=False,
        config=str(cfg_path),
        tools=['docker', 'rust'],
        dry_run=True,
    )
    assert rc == 0
    assert captured['packages'] == ('docker.io', 'docker-compose-v2')
    assert captured['tools'] == ('rust',)


def test_bare_provision_keeps_full_configured_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)
    captured: dict[str, Any] = {}

    def fake_provision(received: AgentVMConfig, *, dry_run: bool) -> None:
        captured.update(cfg=received, dry_run=dry_run)

    monkeypatch.setattr('aivm.cli.vm_lifecycle.provision', fake_provision)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements',
        lambda *a, **k: pytest.fail('bare provision must use full provision'),
    )

    rc = VMProvisionCLI.main(
        argv=False, config=str(cfg_path), tools=[], dry_run=True
    )
    assert rc == 0
    assert captured == {'cfg': cfg, 'dry_run': True}


def test_provision_rejects_unknown_tool_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg_path = tmp_path / 'config.toml'
    cfg_path.write_text('[vm]\nname = "vmx"\n', encoding='utf-8')
    _stub_cfg_loader(monkeypatch, cfg)

    called = {'n': 0}

    def fake_provision(*a: Any, **k: Any) -> None:
        called['n'] += 1

    monkeypatch.setattr('aivm.cli.vm_lifecycle.provision', fake_provision)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.provision_guest_requirements', fake_provision
    )

    rc = VMProvisionCLI.main(
        argv=False,
        config=str(cfg_path),
        tools=['kubernetes'],
        dry_run=True,
    )
    assert rc == 2
    assert called['n'] == 0
