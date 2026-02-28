"""Tests for VM create/destroy store behavior with defaults-driven init."""

from __future__ import annotations

from pathlib import Path

from aivm.cli import AgentVMModalCLI
from aivm.cli.vm import VMCreateCLI, VMDestroyCLI
from aivm.config import AgentVMConfig
from aivm.store import Store, load_store, save_store, upsert_attachment, upsert_vm


def test_vm_create_uses_defaults_and_adds_vm(monkeypatch, tmp_path: Path) -> None:
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
    monkeypatch.setattr(
        'aivm.cli.vm.create_or_start_vm', lambda *a, **k: None
    )
    rc = VMCreateCLI.main(argv=False, config=str(cfg_path), vm='new-vm', yes=True)
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.defaults is not None
    assert any(v.name == 'new-vm' for v in loaded.vms)


def test_vm_destroy_removes_vm_and_attachments(monkeypatch, tmp_path: Path) -> None:
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
    monkeypatch.setattr('aivm.cli.vm._confirm_sudo_block', lambda **kwargs: None)
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
