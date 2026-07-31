"""Read-only planning coverage for released-store migration."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable, cast

import pytest

from aivm.cli.config.migrate import ConfigMigratePlanCLI
from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    Store,
    save_store,
    upsert_attachment,
    upsert_credential,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.credentials.validation import credential_id
from aivm.legacy.pre_0_6_0.migration import (
    LegacyStoreSource,
    RuntimeInventory,
    build_migration_plan,
    collect_runtime_inventory,
    parse_legacy_source_spec,
)
from aivm.machine_store import MachineStoreLayout
from tests.helpers import FakeProc, activate_manager, command_recorder


def _as_object_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _as_object_dict_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    return [_as_object_dict(item) for item in value]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _public_key() -> str:
    return 'ssh-ed25519 ZmFrZS1taWdyYXRpb24ta2V5LWJsb2I= migration-test'


def _legacy_store(
    root: Path,
    *,
    host_user: str,
    vm_name: str = 'aivm-2404-shared',
    ram_mb: int = 8192,
) -> tuple[LegacyStoreSource, Path]:
    home = root / host_user
    key = home / '.ssh' / 'id_aivm_ed25519'
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text('private-test-material\n')
    key.with_suffix('.pub').write_text(_public_key() + '\n')

    cfg = AgentVMConfig().expanded_paths()
    cfg.vm.name = vm_name
    cfg.vm.user = f'{host_user}-agent'
    cfg.vm.ram_mb = ram_mb
    cfg.network.name = 'aivm-net'
    cfg.paths.ssh_identity_file = str(key)
    cfg.paths.ssh_pubkey_path = str(key.with_suffix('.pub'))
    cfg.paths.state_dir = str(home / '.local' / 'state' / 'aivm')

    reg = Store(schema_version=8, active_vm=vm_name)
    reg.defaults = cfg
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    upsert_attachment(
        reg,
        host_path=home / 'code' / 'project',
        vm_name=vm_name,
        # A released store spells this mode 'shared'; the live CLI now calls
        # it 'direct-virtiofs' and refuses the old name. Migration has to
        # carry the record across that rename.
        mode='shared',
        access='rw',
        guest_dst=f'/home/{host_user}-agent/code/project',
        tag=f'{host_user}-project',
    )
    legacy_cred_id = credential_id(vm_name, 'github.com/kitware/aivm')
    upsert_credential(
        reg,
        CredentialEntry(
            id=legacy_cred_id,
            vm_name=vm_name,
            provider_host='github.com',
            owner='Kitware',
            repository='aivm',
            provider_key_id='1234',
            provider_key_title='legacy migration fixture',
            key_fingerprint='SHA256:ZmFrZUZpbmdlcnByaW50',
            state='active',
        ),
    )

    store_path = home / '.config' / 'aivm' / 'config.toml'
    save_store(reg, store_path)
    data_root = home / '.local' / 'share' / 'aivm' / vm_name
    legacy_cred_dir = data_root / 'credentials' / legacy_cred_id
    legacy_cred_dir.mkdir(parents=True)
    (legacy_cred_dir / 'id_ed25519').write_text('private-test-material\n')
    legacy_state = data_root / 'state'
    legacy_state.mkdir(parents=True)
    (legacy_state / 'persistent-attachments.json').write_text('{}\n')
    source = LegacyStoreSource(
        path=store_path,
        host_user=host_user,
        host_uid=1001 if host_user == 'alice' else 1002,
        host_gid=1001 if host_user == 'alice' else 1002,
        home=home,
    )
    return source, store_path


def _runtime_for(
    vm_name: str = 'aivm-2404-shared',
) -> Callable[..., RuntimeInventory]:
    def collect(**kwargs: object) -> RuntimeInventory:
        del kwargs
        return RuntimeInventory(
            checked=True,
            domains=[vm_name, 'unmanaged-domain'],
            networks=['aivm-net', 'default'],
            unmanaged_domains=['unmanaged-domain'],
            unmanaged_networks=['default'],
        )

    return collect


def test_single_store_plan_attributes_user_owned_records_without_writes(
    tmp_path: Path,
) -> None:
    source, store_path = _legacy_store(tmp_path, host_user='alice')
    before = _sha256(store_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')

    plan = build_migration_plan(
        [source],
        layout=layout,
        runtime_collector=_runtime_for(),
    )

    assert not plan.blocked
    assert _sha256(store_path) == before
    assert not layout.root.exists()
    assert plan.machine['schema_version'] == 11
    assert plan.machine['store_kind'] == 'machine'

    principals = _as_object_dict_list(plan.machine['principals'])
    principal = principals[0]
    assert principal['host_user'] == 'alice'
    assert principal['guest_user'] == 'alice-agent'
    assert principal['public_key_present'] is True
    principal_id = str(principal['id'])

    attachments = _as_object_dict_list(plan.machine['attachments'])
    assert attachments[0]['owner_principal_id'] == principal_id
    # A released 'shared' record migrates to the mode's current name rather
    # than landing in the machine store under a spelling nothing accepts.
    assert attachments[0]['mode'] == 'direct-virtiofs'

    credentials = _as_object_dict_list(plan.machine['credentials'])
    assert credentials[0]['principal_id'] == principal_id
    assert credentials[0]['id'] != credential_id(
        'aivm-2404-shared', 'github.com/kitware/aivm'
    )
    assert credentials[0]['provider_key_id'] == '1234'

    assert plan.profiles[0]['active_vm'] == 'aivm-2404-shared'
    persistent_move = plan.persistent_state_moves[0]
    credential_move = plan.credential_material_moves[0]
    assert persistent_move['source_exists'] is True
    assert persistent_move['source_kind'] == 'directory'
    assert len(str(persistent_move['source_sha256'])) == 64
    assert credential_move['source_exists'] is True
    assert credential_move['source_kind'] == 'directory'
    assert len(str(credential_move['source_sha256'])) == 64
    assert credential_move['action'] == ('copy-and-retain-legacy-for-rollback')
    assert plan.runtime.unmanaged_domains == ['unmanaged-domain']


def test_multiple_released_stores_claiming_one_vm_blocks_silent_merge(
    tmp_path: Path,
) -> None:
    alice, _ = _legacy_store(tmp_path, host_user='alice', ram_mb=8192)
    bob, _ = _legacy_store(tmp_path, host_user='bob', ram_mb=16384)

    plan = build_migration_plan(
        [alice, bob],
        layout=MachineStoreLayout.from_root(tmp_path / 'machine'),
        check_runtime=False,
    )

    codes = {item.code for item in plan.conflicts}
    assert 'multiple-store-vm-claim' in codes
    issue = next(
        item
        for item in plan.conflicts
        if item.code == 'multiple-store-vm-claim'
    )
    fields = _as_object_dict(issue.details['differing_machine_fields'])
    field_lists: list[list[object]] = []
    for value in fields.values():
        assert isinstance(value, list)
        field_lists.append(cast(list[object], value))
    assert any('cfg.vm.ram_mb' in values for values in field_lists)
    assert plan.blocked


def test_profile_path_divergence_is_explicit_conflict(tmp_path: Path) -> None:
    source, store_path = _legacy_store(tmp_path, host_user='alice')
    from aivm.config_store import load_store

    reg = load_store(store_path)
    from copy import deepcopy

    second = deepcopy(reg.vms[0].cfg).expanded_paths()
    second.vm.name = 'aivm-2404-second'
    second.paths.ssh_identity_file = str(source.home / '.ssh' / 'other')
    second.paths.ssh_pubkey_path = str(source.home / '.ssh' / 'other.pub')
    Path(second.paths.ssh_pubkey_path).write_text(_public_key() + '\n')
    upsert_vm_with_network(reg, second, network_name=second.network.name)
    save_store(reg, store_path)

    plan = build_migration_plan(
        [source],
        layout=MachineStoreLayout.from_root(tmp_path / 'machine'),
        check_runtime=False,
    )

    assert 'profile-path-divergence' in {item.code for item in plan.conflicts}


def test_parse_source_spec_accepts_explicit_owner(tmp_path: Path) -> None:
    path = tmp_path / 'alice' / '.config' / 'aivm' / 'config.toml'
    source = parse_legacy_source_spec(f'alice={path}')
    assert source.host_user == 'alice'
    assert source.path == path.resolve()
    assert source.home.name == 'alice'


def test_cli_json_plan_is_strictly_non_mutating(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    current_user = os.environ.get('USER') or 'tester'
    source, store_path = _legacy_store(tmp_path, host_user=current_user)
    before_files = {
        item: _sha256(item)
        for item in store_path.parent.rglob('*')
        if item.is_file()
    }

    rc = ConfigMigratePlanCLI.main(
        argv=False,
        sources=[str(store_path)],
        output='json',
        no_runtime=True,
    )

    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report['mode'] == 'dry-run'
    assert report['status'] == 'ready'
    assert report['runtime']['checked'] is False
    after_files = {
        item: _sha256(item)
        for item in store_path.parent.rglob('*')
        if item.is_file()
    }
    assert after_files == before_files


def test_runtime_missing_domain_blocks_apply_readiness(tmp_path: Path) -> None:
    source, _ = _legacy_store(tmp_path, host_user='alice')

    def collect(**kwargs: object) -> RuntimeInventory:
        del kwargs
        return RuntimeInventory(
            checked=True,
            domains=[],
            networks=['aivm-net'],
            missing_domains=['aivm-2404-shared'],
        )

    plan = build_migration_plan(
        [source],
        layout=MachineStoreLayout.from_root(tmp_path / 'machine'),
        runtime_collector=collect,
    )

    assert 'runtime-domain-missing' in {item.code for item in plan.conflicts}


@pytest.mark.parametrize(
    ('libvirt_ok', 'expect_sudo'),
    [
        pytest.param(False, True, id='escalates_when_libvirt_needs_sudo'),
        pytest.param(True, False, id='stays_unprivileged_when_libvirt_reachable'),
    ],
)
def test_runtime_inventory_follows_the_libvirt_escalation_decision(
    monkeypatch: pytest.MonkeyPatch,
    libvirt_ok: bool,
    expect_sudo: bool,
) -> None:
    """Inventory escalation is privilege policy, not a migration option.

    Overrides the conftest probe pin, since the probe answer is the input
    under test here.
    """
    monkeypatch.setattr(
        'aivm.privilege.libvirt_without_sudo_ok', lambda: libvirt_ok
    )
    activate_manager(monkeypatch, yes_sudo=True)
    rec = command_recorder(monkeypatch, default=FakeProc(stdout='aivm-2404\n'))

    inventory = collect_runtime_inventory(
        managed_vms=['aivm-2404'], managed_networks=['aivm-net']
    )

    assert inventory.checked and not inventory.error
    assert rec.normalized == [
        ['virsh', 'list', '--all', '--name'],
        ['virsh', 'net-list', '--all', '--name'],
    ]
    assert [cmd[0] == 'sudo' for cmd in rec.calls] == [expect_sudo] * 2


def test_existing_machine_store_is_reported_as_merge_conflict(
    tmp_path: Path,
) -> None:
    source, _ = _legacy_store(tmp_path, host_user='alice')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    existing_cfg = AgentVMConfig().expanded_paths()
    existing_cfg.vm.name = 'existing-machine'
    existing = Store(schema_version=11, store_kind='machine')
    upsert_network(
        existing, network=existing_cfg.network, firewall=existing_cfg.firewall
    )
    upsert_vm_with_network(
        existing, existing_cfg, network_name=existing_cfg.network.name
    )
    save_store(existing, layout.config_path)

    plan = build_migration_plan([source], layout=layout, check_runtime=False)

    assert 'target-store-not-empty' in {item.code for item in plan.conflicts}


def test_frozen_monolith_and_split_produce_same_migration_records(
    tmp_path: Path,
) -> None:
    fixture_root = Path(__file__).parent / 'data' / 'released_v0_5'

    def copy_layout(name: str) -> Path:
        source = fixture_root / name
        target = tmp_path / name
        for source_file in source.rglob('*'):
            if source_file.is_file():
                target_file = target / source_file.relative_to(source)
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_bytes(source_file.read_bytes())
        return target / 'config.toml'

    plans = []
    for name in ('monolithic', 'split'):
        path = copy_layout(name)
        source = LegacyStoreSource(
            path=path,
            host_user='alice',
            host_uid=1001,
            host_gid=1001,
            home=tmp_path / 'alice',
        )
        plans.append(
            build_migration_plan(
                [source],
                layout=MachineStoreLayout.from_root(
                    tmp_path / f'machine-{name}'
                ),
                check_runtime=False,
            )
        )

    assert plans[0].machine == plans[1].machine
    assert plans[0].profiles == plans[1].profiles
    assert {item.code for item in plans[0].conflicts} == {
        item.code for item in plans[1].conflicts
    }


def test_missing_trusted_host_group_blocks_the_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plan must not report READY when apply cannot take its first step.

    Apply resolves the trusted group before any lock or write, so a host
    without it fails immediately. Drop the sandbox root the suite sets so the
    real group requirement applies, and deny the lookup the way a host that
    never ran ``aivm config init`` does.
    """
    import grp

    source, _ = _legacy_store(tmp_path, host_user='alice')
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)

    def _no_such_group(name: str) -> object:
        raise KeyError(name)

    monkeypatch.setattr(grp, 'getgrnam', _no_such_group)

    plan = build_migration_plan(
        [source],
        layout=MachineStoreLayout.from_root(tmp_path / 'machine'),
        check_runtime=False,
    )

    assert plan.blocked
    issue = next(
        item for item in plan.conflicts if item.code == 'machine-group-missing'
    )
    assert 'groupadd --system aivm' in issue.message
    # The remediation has to name a command that creates the group; `config
    # init` only writes configuration and would leave the caller stuck.
    assert 'aivm host permissions setup' in issue.message
    assert 'config init' not in issue.message
    assert 'Status: BLOCKED' in plan.render_text()
