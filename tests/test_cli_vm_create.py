"""Tests for VM create/delete store behavior with defaults-driven init."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.cli import AgentVMModalCLI
from aivm.cli.vm_lifecycle import VMCreateCLI, VMDeleteCLI
from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    find_network,
    load_store,
    save_store,
    upsert_attachment,
    upsert_vm,
)
from tests.helpers import noop, patch_ns, returns, write_store


@dataclass
class CreateOpsStub:
    """Handle over the stubbed ``vm create`` pipeline.

    ``cfg_path`` is the store the CLI is pointed at; ``override`` swaps a
    single ``aivm.vm.create_ops`` seam for a test that wants to inspect
    or vary it.
    """

    cfg_path: Path
    monkeypatch: MonkeyPatch

    def override(self, **seams: Any) -> None:
        for name, value in seams.items():
            self.monkeypatch.setattr(f'aivm.vm.create_ops.{name}', value)


@pytest.fixture
def stub_create_ops(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> CreateOpsStub:
    """Stub the create pipeline down to store bookkeeping.

    Installs the seven seams that every ``vm create`` test otherwise
    re-patches by hand: the config-path resolver plus the six
    ``create_ops`` side effects (network/firewall/VM provisioning, the
    host-dep install, and the two resource-check probes).  Returns a
    handle whose ``cfg_path`` is the store the CLI reads and whose
    ``override`` swaps any individual seam.
    """
    cfg_path = tmp_path / 'config.toml'
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.cfg_path',
        lambda p: cfg_path if p else cfg_path,
    )
    patch_ns(
        monkeypatch,
        'aivm.vm.create_ops',
        {
            'ensure_network': noop,
            'apply_firewall': noop,
            'create_or_start_vm': noop,
            'maybe_install_missing_host_deps': noop,
            'vm_resource_warning_lines': returns([]),
            'vm_resource_impossible_lines': returns([]),
        },
    )
    return CreateOpsStub(cfg_path=cfg_path, monkeypatch=monkeypatch)


def test_vm_create_summary_shows_password_login_default(tmp_path: Path) -> None:
    from aivm.vm.create_ops import _render_vm_create_summary

    cfg = AgentVMConfig()
    cfg.vm.allow_password_login = True
    text = _render_vm_create_summary(cfg, tmp_path / 'config.toml')
    assert 'vm.allow_password_login: true' in text
    assert 'enables password login on console and SSH' in text
    assert 'vm.password: (configured)' in text


def test_vm_create_interactive_edit_updates_password_login(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.vm.create_ops import _review_vm_create_overrides_interactive

    cfg = AgentVMConfig()
    cfg.vm.allow_password_login = False
    answers = iter([
        'e',  # edit values
        '',  # vm.name
        '',  # vm.user
        '',  # vm.cpus
        '',  # vm.ram_mb
        '',  # vm.disk_gb
        'y',  # vm.allow_password_login
        'debug-pass',  # vm.password
        '',  # network.name
        '',  # network.subnet_cidr
        '',  # network.gateway_ip
        '',  # network.dhcp_start
        '',  # network.dhcp_end
        'y',  # confirm
    ])
    monkeypatch.setattr('aivm.vm.create_ops.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: next(answers))
    out = _review_vm_create_overrides_interactive(cfg, tmp_path / 'config.toml')
    assert out.vm.allow_password_login is True
    assert out.vm.password == 'debug-pass'


def test_vm_create_uses_defaults_and_adds_vm(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    write_store(cfg_path, defaults=defaults)

    rc = VMCreateCLI.main(
        argv=False, config=str(cfg_path), vm='new-vm', yes=True
    )
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.defaults is not None
    assert any(v.name == 'new-vm' for v in loaded.vms)
    assert loaded.defaults.vm.name == 'template-vm'


def test_vm_create_falls_back_to_existing_vm_when_defaults_missing(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    tmpl = AgentVMConfig()
    tmpl.vm.name = 'template-existing'
    tmpl.vm.cpus = 6
    tmpl.vm.ram_mb = 12288
    tmpl.network.name = 'tmpl-net'
    write_store(cfg_path, tmpl, active_vm=tmpl.vm.name)

    rc = VMCreateCLI.main(
        argv=False, config=str(cfg_path), vm='demo-vm', yes=True
    )
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.defaults is None
    rec = next(v for v in loaded.vms if v.name == 'demo-vm')
    assert rec.cfg.vm.cpus == 6
    assert rec.cfg.vm.ram_mb == 12288
    assert rec.network_name == 'tmpl-net'


def test_vm_create_yes_preserves_existing_active_vm(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    existing = AgentVMConfig()
    existing.vm.name = 'current-default'
    write_store(
        cfg_path, existing, defaults=defaults, active_vm=existing.vm.name
    )

    rc = VMCreateCLI.main(
        argv=False,
        config=str(cfg_path),
        vm='new-vm',
        yes=True,
    )
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.active_vm == 'current-default'
    assert any(v.name == 'new-vm' for v in loaded.vms)


def test_vm_create_set_default_opt_in(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    existing = AgentVMConfig()
    existing.vm.name = 'current-default'
    write_store(
        cfg_path, existing, defaults=defaults, active_vm=existing.vm.name
    )

    rc = VMCreateCLI.main(
        argv=False,
        config=str(cfg_path),
        vm='new-vm',
        yes=True,
        set_default=True,
    )
    assert rc == 0
    loaded = load_store(cfg_path)
    assert loaded.active_vm == 'new-vm'


def test_vm_create_interactive_default_prompt_no_keeps_active(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    existing = AgentVMConfig()
    existing.vm.name = 'current-default'
    write_store(
        cfg_path, existing, defaults=defaults, active_vm=existing.vm.name
    )

    asked: list[str] = []
    stub_create_ops.override(
        _review_vm_create_overrides_interactive=lambda cfg, path: cfg,
        _prompt_set_created_vm_default=(
            lambda vm_name: asked.append(vm_name) or False
        ),
    )

    rc = VMCreateCLI.main(
        argv=False,
        config=str(cfg_path),
        vm='new-vm',
        yes=False,
    )
    assert rc == 0
    assert asked == ['new-vm']
    loaded = load_store(cfg_path)
    assert loaded.active_vm == 'current-default'


def test_vm_delete_removes_vm_and_attachments(
    monkeypatch: MonkeyPatch, tmp_path: Path
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
    )
    save_store(store, cfg_path)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.load_cfg_with_path',
        lambda *a, **k: (cfg, cfg_path),
    )
    monkeypatch.setattr('aivm.cli.vm_lifecycle.destroy_vm', lambda *a, **k: None)
    rc = VMDeleteCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    loaded = load_store(cfg_path)
    assert all(v.name != 'killme' for v in loaded.vms)
    assert all(a.vm_name != 'killme' for a in loaded.attachments)


def test_vm_delete_warns_when_network_becomes_unused(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'solo-vm'
    cfg.network.name = 'solo-net'
    upsert_vm(store, cfg)
    save_store(store, cfg_path)
    warns: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.load_cfg_with_path',
        lambda *a, **k: (cfg, cfg_path),
    )
    monkeypatch.setattr('aivm.cli.vm_lifecycle.destroy_vm', lambda *a, **k: None)
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.log.warning',
        lambda *a, **k: warns.append((a, k)),
    )
    rc = VMDeleteCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    assert any(
        "Network '{}'" in args[0] and args[1] == 'solo-net' for args, _ in warns
    )


def test_vm_delete_accepts_positional_vm_name(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg_path = tmp_path / 'config.toml'
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'from-positional'
    upsert_vm(store, cfg)
    save_store(store, cfg_path)

    captured: dict[str, str] = {}
    monkeypatch.setattr(
        'aivm.cli.vm_lifecycle.destroy_vm',
        lambda destroy_cfg, **kwargs: captured.setdefault(
            'vm_name', destroy_cfg.vm.name
        ),
    )
    rc = AgentVMModalCLI.main(
        argv=[
            'vm',
            'delete',
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
    monkeypatch: MonkeyPatch, stub_create_ops: CreateOpsStub
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    defaults.network.name = 'aivm-net'
    write_store(cfg_path, defaults=defaults)

    monkeypatch.setattr('aivm.vm.create_ops.sys.stdin.isatty', lambda: True)
    answers = iter(
        [
            'e',
            'custom-vm',
            '',
            '2',
            '3072',
            '24',
            'n',
            'custom-net',
            '10.90.0.0/24',
            '10.90.0.1',
            '10.90.0.100',
            '10.90.0.200',
            'y',
        ]
    )

    def fake_input(_prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            # Keep this test focused on interactive override flow even if
            # environment-dependent prompts (e.g. missing host deps) appear.
            return 'y'

    monkeypatch.setattr('builtins.input', fake_input)

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


def test_vm_create_interactive_abort(
    monkeypatch: MonkeyPatch, stub_create_ops: CreateOpsStub
) -> None:
    cfg_path = stub_create_ops.cfg_path
    write_store(cfg_path, defaults=AgentVMConfig())
    monkeypatch.setattr('aivm.vm.create_ops.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: 'n')
    with pytest.raises(RuntimeError, match='Aborted by user'):
        VMCreateCLI.main(argv=False, config=str(cfg_path), yes=False)


def test_vm_create_warns_when_requested_resources_look_too_high(
    monkeypatch: MonkeyPatch, stub_create_ops: CreateOpsStub
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'warn-vm'
    defaults.vm.ram_mb = 1800
    defaults.vm.cpus = 2
    defaults.vm.disk_gb = 64
    defaults.paths.base_dir = str(cfg_path.parent)
    write_store(cfg_path, defaults=defaults)

    stub_create_ops.override(
        vm_resource_warning_lines=returns(['warn1', 'warn2']),
    )
    warns: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.vm.create_ops.log.warning',
        lambda *a, **k: warns.append((a, k)),
    )

    rc = VMCreateCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    assert len(warns) >= 2


def test_vm_create_ensures_network_before_vm_create(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'net-first-vm'
    defaults.network.name = 'net-first'
    write_store(cfg_path, defaults=defaults)

    calls: list[str] = []
    stub_create_ops.override(
        ensure_network=lambda *a, **k: calls.append('ensure_network'),
        apply_firewall=lambda *a, **k: calls.append('apply_firewall'),
        create_or_start_vm=(
            lambda *a, **k: calls.append('create_or_start_vm')
        ),
    )
    rc = VMCreateCLI.main(argv=False, config=str(cfg_path), yes=True)
    assert rc == 0
    assert calls[:2] == ['ensure_network', 'apply_firewall']
    assert calls[-1] == 'create_or_start_vm'


def test_vm_create_errors_when_resources_physically_impossible(
    stub_create_ops: CreateOpsStub,
) -> None:
    cfg_path = stub_create_ops.cfg_path
    defaults = AgentVMConfig()
    defaults.vm.name = 'impossible-vm'
    defaults.vm.ram_mb = 8192
    defaults.vm.cpus = 8
    write_store(cfg_path, defaults=defaults)

    stub_create_ops.override(
        vm_resource_impossible_lines=returns(
            ['vm.cpus=8 exceeds host CPU count=2']
        ),
    )
    with pytest.raises(RuntimeError, match='not feasible on this host'):
        VMCreateCLI.main(argv=False, config=str(cfg_path), yes=True)


def test_vm_create_initial_persistent_share_uses_final_vm_name(
    stub_create_ops: CreateOpsStub, tmp_path: Path
) -> None:
    """Attached fresh-create resolves the initial share after VM-name edits."""
    from aivm.vm.create_ops import create_vm_from_defaults

    cfg_path = stub_create_ops.cfg_path
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    base_dir = tmp_path / 'libvirt-aivm'

    defaults = AgentVMConfig()
    defaults.vm.name = 'template-vm'
    defaults.paths.base_dir = str(base_dir)
    write_store(cfg_path, defaults=defaults)

    def fake_review(cfg: AgentVMConfig, path: Path) -> AgentVMConfig:
        cfg.vm.name = 'fresh-vm'
        return cfg

    prepared: list[tuple[str, bool]] = []
    created: list[tuple[AgentVMConfig, dict]] = []
    stub_create_ops.override(
        _review_vm_create_overrides_interactive=fake_review,
        _ensure_persistent_root_parent_dir=(
            lambda cfg, *, dry_run: prepared.append((cfg.vm.name, dry_run))
        ),
        create_or_start_vm=(
            lambda cfg, **kwargs: created.append((cfg, dict(kwargs)))
        ),
    )

    rc = create_vm_from_defaults(
        cfg_path,
        set_default=True,
        yes=False,
        initial_attachment_host_src=host_src,
        initial_attachment_mode='persistent',
    )

    assert rc == 0
    assert prepared == [('fresh-vm', False)]
    assert created
    created_cfg, kwargs = created[0]
    assert created_cfg.vm.name == 'fresh-vm'
    assert kwargs['share_source_dir'] == str(
        base_dir / 'fresh-vm' / 'persistent-root'
    )
    assert kwargs['share_tag'] == 'aivm-persistent-root'
