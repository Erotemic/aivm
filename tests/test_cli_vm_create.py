"""Tests for VM create/destroy store behavior with defaults-driven init."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.cli import AgentVMModalCLI
from aivm.cli.vm import VMCreateCLI, VMDestroyCLI
from aivm.config import AgentVMConfig
from aivm.store import (
    Store,
    find_network,
    load_store,
    save_store,
    upsert_attachment,
    upsert_vm,
)


def test_vm_create_uses_defaults_and_adds_vm(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    store.defaults = defaults
    save_store(store, cfg_path)

    monkeypatch.setattr(
        'aivm.cli.vm._cfg_path', lambda p: cfg_path if p else cfg_path
    )
    monkeypatch.setattr(
        'aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None
    )
    monkeypatch.setattr('aivm.cli.vm.create_or_start_vm', lambda *a, **k: None)
    monkeypatch.setattr('aivm.cli.vm._host_mem_total_mb', lambda: 65536)
    monkeypatch.setattr('aivm.cli.vm._host_mem_available_mb', lambda: 32768)
    monkeypatch.setattr('aivm.cli.vm._host_cpu_count', lambda: 32)
    monkeypatch.setattr('aivm.cli.vm._host_free_disk_gb', lambda p: 512.0)
    rc = VMCreateCLI.main(
        argv=False, config=str(cfg_path), vm='new-vm', yes=True
    )
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.defaults is not None
    assert any(v.name == 'new-vm' for v in loaded.vms)


def test_vm_destroy_removes_vm_and_attachments(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'killme'
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=tmp_path / 'p',
        vm_name='killme',
        guest_dst='/tmp/p',
        tag='hostcode-p',
        force=True,
    )
    save_store(store, cfg_path)
    monkeypatch.setattr(
        'aivm.cli.vm._load_cfg_with_path',
        lambda *a, **k: (cfg, cfg_path),
    )
    monkeypatch.setattr(
        'aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None
    )
    monkeypatch.setattr('aivm.cli.vm.destroy_vm', lambda *a, **k: None)
    rc = VMDestroyCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    loaded = load_store(cfg_path)
    assert all(v.name != 'killme' for v in loaded.vms)
    assert all(a.vm_name != 'killme' for a in loaded.attachments)


def test_vm_destroy_accepts_positional_vm_name(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'from-positional'
    upsert_vm(store, cfg)
    save_store(store, cfg_path)

    captured: dict[str, str] = {}
    monkeypatch.setattr(
        'aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None
    )
    monkeypatch.setattr(
        'aivm.cli.vm.destroy_vm',
        lambda destroy_cfg, **kwargs: captured.setdefault(
            'vm_name', destroy_cfg.vm.name
        ),
    )
    rc = AgentVMModalCLI.main(
        argv=[
            'vm',
            'destroy',
            'from-positional',
            '--yes',
            '--dry_run',
            '--config',
            str(cfg_path),
        ],
        _noexit=True,
    )
    rc = 0 if rc is None else int(rc)
    assert rc == 0
    assert captured['vm_name'] == 'from-positional'


def test_vm_create_interactive_edit_overrides_defaults(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    defaults.network.name = 'aivm-net'
    store.defaults = defaults
    save_store(store, cfg_path)

    monkeypatch.setattr(
        'aivm.cli.vm._cfg_path', lambda p: cfg_path if p else cfg_path
    )
    monkeypatch.setattr('aivm.cli.vm.sys.stdin.isatty', lambda: True)
    answers = iter(
        [
            'e',
            'custom-vm',
            '',
            '2',
            '3072',
            '24',
            'custom-net',
            '10.90.0.0/24',
            '10.90.0.1',
            '10.90.0.100',
            '10.90.0.200',
            'y',
        ]
    )
    monkeypatch.setattr('builtins.input', lambda _: next(answers))
    monkeypatch.setattr(
        'aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None
    )
    monkeypatch.setattr('aivm.cli.vm.create_or_start_vm', lambda *a, **k: None)
    monkeypatch.setattr('aivm.cli.vm._host_mem_total_mb', lambda: 65536)
    monkeypatch.setattr('aivm.cli.vm._host_mem_available_mb', lambda: 32768)
    monkeypatch.setattr('aivm.cli.vm._host_cpu_count', lambda: 32)
    monkeypatch.setattr('aivm.cli.vm._host_free_disk_gb', lambda p: 512.0)

    rc = VMCreateCLI.main(argv=False, config=str(cfg_path), yes=False)
    assert rc == 0
    loaded = load_store(cfg_path)
    rec = next(v for v in loaded.vms if v.name == 'custom-vm')
    assert rec.cfg.vm.cpus == 2
    assert rec.cfg.vm.ram_mb == 3072
    assert rec.cfg.vm.disk_gb == 24
    assert rec.network_name == 'custom-net'
    net = find_network(loaded, 'custom-net')
    assert net is not None
    assert net.network.subnet_cidr == '10.90.0.0/24'


def test_vm_create_interactive_abort(monkeypatch, tmp_path: Path) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    store.defaults = AgentVMConfig()
    save_store(store, cfg_path)
    monkeypatch.setattr(
        'aivm.cli.vm._cfg_path', lambda p: cfg_path if p else cfg_path
    )
    monkeypatch.setattr('aivm.cli.vm.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: 'n')
    monkeypatch.setattr('aivm.cli.vm._host_mem_total_mb', lambda: 8192)
    monkeypatch.setattr('aivm.cli.vm._host_mem_available_mb', lambda: 4096)
    monkeypatch.setattr('aivm.cli.vm._host_cpu_count', lambda: 4)
    monkeypatch.setattr('aivm.cli.vm._host_free_disk_gb', lambda p: 100.0)
    with pytest.raises(RuntimeError, match='Aborted by user'):
        VMCreateCLI.main(argv=False, config=str(cfg_path), yes=False)


def test_vm_create_warns_when_requested_resources_look_too_high(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    defaults = AgentVMConfig()
    defaults.vm.name = 'warn-vm'
    defaults.vm.ram_mb = 1800
    defaults.vm.cpus = 2
    defaults.vm.disk_gb = 64
    defaults.paths.base_dir = str(tmp_path)
    store.defaults = defaults
    save_store(store, cfg_path)

    monkeypatch.setattr(
        'aivm.cli.vm._cfg_path', lambda p: cfg_path if p else cfg_path
    )
    monkeypatch.setattr(
        'aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None
    )
    monkeypatch.setattr('aivm.cli.vm.create_or_start_vm', lambda *a, **k: None)
    monkeypatch.setattr('aivm.cli.vm._host_mem_total_mb', lambda: 4096)
    monkeypatch.setattr('aivm.cli.vm._host_mem_available_mb', lambda: 2048)
    monkeypatch.setattr('aivm.cli.vm._host_cpu_count', lambda: 4)
    monkeypatch.setattr('aivm.cli.vm._host_free_disk_gb', lambda p: 20.0)
    warns: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm.log.warning',
        lambda *a, **k: warns.append((a, k)),
    )

    rc = VMCreateCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    assert len(warns) >= 2


def test_vm_create_errors_when_resources_physically_impossible(
    monkeypatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    defaults = AgentVMConfig()
    defaults.vm.name = 'impossible-vm'
    defaults.vm.ram_mb = 8192
    defaults.vm.cpus = 8
    store.defaults = defaults
    save_store(store, cfg_path)
    monkeypatch.setattr(
        'aivm.cli.vm._cfg_path', lambda p: cfg_path if p else cfg_path
    )
    monkeypatch.setattr('aivm.cli.vm._host_mem_total_mb', lambda: 4096)
    monkeypatch.setattr('aivm.cli.vm._host_mem_available_mb', lambda: 2048)
    monkeypatch.setattr('aivm.cli.vm._host_cpu_count', lambda: 2)
    with pytest.raises(RuntimeError, match='not feasible on this host'):
        VMCreateCLI.main(argv=False, config=str(cfg_path), yes=True)
