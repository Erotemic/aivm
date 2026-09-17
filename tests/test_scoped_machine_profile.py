"""Unit coverage for the activated machine/profile persistence split."""

from __future__ import annotations

import stat
import tomllib
from pathlib import Path

import pytest

from aivm.cli.config.init import initialize_config_defaults
from aivm.config import AgentVMConfig
from aivm.config_store import load_store, save_store, upsert_vm
from aivm.machine_store import machine_store_layout
from aivm.profile_store import (
    PROFILE_FILE_MODE,
    UserProfileStore,
    load_user_profile,
    profile_store_path,
    save_user_profile,
)
from aivm.scoped_store import resolve_store_scope
from aivm.services import load_vm_context_with_path
from aivm.vm.create_ops import create_vm_from_defaults


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _creator_defaults(tmp_path: Path) -> AgentVMConfig:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-shared-host'
    cfg.vm.user = 'alice-agent'
    cfg.paths.base_dir = str(tmp_path / 'libvirt-images')
    cfg.paths.state_dir = str(tmp_path / 'alice-state')
    cfg.paths.ssh_identity_file = str(tmp_path / 'alice-aivm-key')
    cfg.paths.ssh_pubkey_path = str(tmp_path / 'alice-aivm-key.pub')
    Path(cfg.paths.ssh_identity_file).write_text('PRIVATE-TEST\n')
    Path(cfg.paths.ssh_pubkey_path).write_text(
        'ssh-ed25519 AAAATEST alice@test\n', encoding='utf-8'
    )
    return cfg


def _initialize_machine_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AgentVMConfig:
    cfg = _creator_defaults(tmp_path)
    monkeypatch.setattr(
        'aivm.cli.config.init.default_vm_name', lambda: cfg.vm.name
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.domain_is_defined', lambda name: False
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults',
        lambda *args, **kwargs: cfg,
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.maybe_offer_create_ssh_identity',
        lambda *args, **kwargs: False,
    )
    rc = initialize_config_defaults(
        config_opt=None,
        yes=True,
        defaults=True,
        force=False,
        standalone_guidance=False,
    )
    assert rc == 0
    return cfg


def test_user_profile_roundtrip_is_private(tmp_path: Path) -> None:
    path = tmp_path / 'profile.toml'
    profile = UserProfileStore(
        active_vm='vm-a',
        ssh_identity_file='~/.ssh/id_aivm',
        ssh_pubkey_path='~/.ssh/id_aivm.pub',
        state_dir='~/.cache/aivm',
        default_guest_user='alice-agent',
    )
    profile.behavior.verbose = 3
    save_user_profile(profile, path)

    assert _mode(path) == PROFILE_FILE_MODE
    assert load_user_profile(path) == profile


def test_brand_new_init_splits_machine_and_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _initialize_machine_defaults(monkeypatch, tmp_path)
    layout = machine_store_layout()
    profile_path = profile_store_path()

    assert layout.config_path.exists()
    assert profile_path.exists()
    machine = load_store(layout.config_path)
    profile = load_user_profile(profile_path)

    assert machine.store_kind == 'machine'
    assert machine.schema_version == 9
    assert machine.defaults is not None
    assert machine.defaults.paths.base_dir == cfg.paths.base_dir
    # These values are deliberately absent from machine TOML and therefore
    # parse to ordinary dataclass defaults. Their authoritative values are in
    # the private profile.
    assert profile.ssh_identity_file == cfg.paths.ssh_identity_file
    assert profile.ssh_pubkey_path == cfg.paths.ssh_pubkey_path
    assert profile.state_dir == cfg.paths.state_dir
    assert profile.default_guest_user == 'alice-agent'

    root_raw = tomllib.loads(layout.config_path.read_text(encoding='utf-8'))
    defaults_raw = tomllib.loads(
        (layout.root / 'defaults.toml').read_text(encoding='utf-8')
    )
    assert root_raw == {'schema_version': 9, 'store_kind': 'machine'}
    assert 'user' not in defaults_raw['defaults']['vm']
    assert defaults_raw['defaults']['paths'] == {'base_dir': cfg.paths.base_dir}


def test_machine_create_persists_creator_and_resolves_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _initialize_machine_defaults(monkeypatch, tmp_path)
    layout = machine_store_layout()

    monkeypatch.setattr('aivm.scoped_store._current_host_user', lambda: 'alice')
    monkeypatch.setattr('aivm.scoped_store._current_host_uid', lambda: 1001)
    monkeypatch.setattr('aivm.scoped_store._current_host_gid', lambda: 1002)
    from aivm.host_identity import HostIdentity

    monkeypatch.setattr(
        'aivm.scoped_store.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1002, username='alice'),
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.vm_resource_warning_lines', lambda cfg: []
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.vm_resource_impossible_lines', lambda cfg: []
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.maybe_install_missing_host_deps',
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.ensure_network', lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.apply_firewall', lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_or_start_vm', lambda *args, **kwargs: None
    )
    # A libvirt boundary like the create above, and the subject of
    # tests/test_domain_authority.py. This test is about what the store
    # records, not about what gets written to the domain.
    monkeypatch.setattr(
        'aivm.vm.create_ops.stamp_domain_authority',
        lambda *args, **kwargs: None,
    )

    rc = create_vm_from_defaults(
        layout.config_path,
        set_default=True,
        yes=True,
        dry_run=False,
    )
    assert rc == 0

    machine = load_store(layout.config_path)
    assert [item.host_user for item in machine.principals] == ['alice']
    principal = machine.principals[0]
    assert principal.vm_name == cfg.vm.name
    assert principal.guest_user == 'alice-agent'
    assert principal.host_uid == 1001
    assert principal.host_gid == 1002
    assert principal.ssh_public_key == 'ssh-ed25519 AAAATEST alice@test'
    assert principal.state == 'active'

    profile = load_user_profile(profile_store_path())
    assert profile.active_vm == cfg.vm.name
    context, resolved_path = load_vm_context_with_path(None)
    assert resolved_path == layout.config_path
    assert context.principal.id == principal.id
    assert context.guest_user == 'alice-agent'
    assert context.profile.ssh_identity_file == cfg.paths.ssh_identity_file
    assert context.machine.vm.name == cfg.vm.name

    vm_raw = tomllib.loads(
        next((layout.root / 'vms').glob('*.toml')).read_text(encoding='utf-8')
    )['vms'][0]
    assert 'user' not in vm_raw['vm']
    assert vm_raw['paths'] == {'base_dir': cfg.paths.base_dir}
    assert vm_raw['principals'][0]['host_user'] == 'alice'


def test_profile_write_cannot_change_machine_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _initialize_machine_defaults(monkeypatch, tmp_path)
    layout = machine_store_layout()
    before = {
        path.relative_to(layout.root): path.read_bytes()
        for path in layout.root.rglob('*.toml')
    }
    profile = load_user_profile(profile_store_path())
    profile.active_vm = 'some-other-selection'
    profile.behavior.verbose = 4
    save_user_profile(profile, profile_store_path())
    after = {
        path.relative_to(layout.root): path.read_bytes()
        for path in layout.root.rglob('*.toml')
    }
    assert after == before


def test_existing_legacy_store_wins_until_explicit_migration(
    isolated_user_state: dict[str, Path],
) -> None:
    legacy_path = isolated_user_state['config'] / 'aivm' / 'config.toml'
    reg = load_store(legacy_path)
    cfg = AgentVMConfig()
    cfg.vm.name = 'legacy-vm'
    upsert_vm(reg, cfg)
    save_store(reg, legacy_path)

    scope = resolve_store_scope(None)
    assert scope.mode == 'legacy'
    assert scope.store_path == legacy_path.resolve()
    assert not machine_store_layout().config_path.exists()


def test_machine_store_without_current_principal_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _initialize_machine_defaults(monkeypatch, tmp_path)
    # Add a machine VM without adopting a principal to characterize the
    # boundary before automatic enrollment lands.
    layout = machine_store_layout()
    reg = load_store(layout.config_path)
    cfg = _creator_defaults(tmp_path)
    upsert_vm(reg, cfg)
    save_store(reg, layout.config_path)
    profile = load_user_profile(profile_store_path())
    profile.active_vm = cfg.vm.name
    save_user_profile(profile, profile_store_path())
    monkeypatch.setattr('aivm.scoped_store._current_host_user', lambda: 'bob')

    with pytest.raises(Exception, match='not enrolled'):
        load_vm_context_with_path(None)


def test_config_paths_and_edit_expose_private_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from aivm.cli.config.edit import _resolve_config_edit_target
    from aivm.cli.config.paths import ConfigPathsCLI

    cfg = _initialize_machine_defaults(monkeypatch, tmp_path)
    profile = load_user_profile(profile_store_path())
    profile.active_vm = cfg.vm.name
    save_user_profile(profile, profile_store_path())

    rc = ConfigPathsCLI.main(argv=False, target='config')
    assert rc == 0
    out = capsys.readouterr().out
    assert 'scope: machine' in out
    assert f'active_vm: {cfg.vm.name}' in out
    assert f'profile (file, exists): {profile_store_path()}' in out

    assert (
        _resolve_config_edit_target(
            config_opt=None,
            target='profile',
        )
        == profile_store_path()
    )


def test_machine_config_show_creates_machine_document_not_legacy(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from aivm.cli.config.show import ConfigShowCLI

    layout = machine_store_layout()
    assert not layout.config_path.exists()
    rc = ConfigShowCLI.main(argv=False)
    assert rc == 0
    assert load_store(layout.config_path).store_kind == 'machine'
    assert 'store_kind = "machine"' in layout.config_path.read_text()
    assert capsys.readouterr().out


def test_machine_store_lints_with_principals(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from aivm.cli.config.lint import _lint_store_text
    from aivm.config_store import load_config_document
    from aivm.scoped_store import current_principal_entry, save_scope_store

    cfg = _initialize_machine_defaults(monkeypatch, tmp_path)
    scope = resolve_store_scope(None)
    reg = load_store(scope.store_path)
    upsert_vm(reg, cfg)
    reg.principals.append(
        current_principal_entry(
            cfg,
            host_user='alice',
            host_uid=1001,
            host_gid=1002,
        )
    )
    save_scope_store(scope, reg, reason='lint fixture')
    loaded = load_config_document(scope.store_path)
    assert _lint_store_text(loaded.source_text) == []
