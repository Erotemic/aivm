"""Resumable apply, verification, and rollback coverage."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import cast

import pytest

from aivm.commands import CommandManager, CommandResult
from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    Store,
    load_store,
    save_store,
    upsert_attachment,
    upsert_credential,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.credentials.validation import credential_id
from aivm.enrollment import BootstrapIdentity
from aivm.guestctl import restricted_bootstrap_authorized_key
from aivm.legacy.pre_0_6_0.migration import (
    LegacyStoreSource,
    MigrationPlan,
    build_migration_plan,
)
from aivm.legacy.pre_0_6_0.migration_apply import (
    GuestInstaller,
    MigrationApplyResult,
    MigrationExecutionError,
    _guest_install_script,
    apply_migration,
    install_bootstrap_through_legacy_access,
    latest_migration_id,
    load_migration_journal,
    migration_plan_sha256,
    migration_transaction_dir,
    rebuild_plan_from_journal,
    rollback_migration,
    verify_applied_migration,
)
from aivm.machine_store import MachineStoreLayout
from aivm.profile_store import load_user_profile


def _public_key() -> str:
    return 'ssh-ed25519 ZmFrZS1taWdyYXRpb24ta2V5LWJsb2I= migration-apply'


def _legacy_source(tmp_path: Path) -> tuple[LegacyStoreSource, str, Path, Path]:
    host_user = os.environ.get('USER') or 'tester'
    home = tmp_path / host_user
    key = home / '.ssh' / 'id_aivm_ed25519'
    key.parent.mkdir(parents=True)
    key.write_text('private-key\n')
    key.with_suffix('.pub').write_text(_public_key() + '\n')

    cfg = AgentVMConfig().expanded_paths()
    cfg.vm.name = 'aivm-migrate-test'
    cfg.vm.user = 'legacy-agent'
    cfg.network.name = 'aivm-net'
    cfg.paths.ssh_identity_file = str(key)
    cfg.paths.ssh_pubkey_path = str(key.with_suffix('.pub'))
    cfg.paths.state_dir = str(home / '.local' / 'state' / 'aivm')

    reg = Store(schema_version=8, active_vm=cfg.vm.name)
    reg.defaults = cfg
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    upsert_attachment(
        reg,
        host_path=home / 'code' / 'project',
        vm_name=cfg.vm.name,
        mode='shared',
        access='rw',
        guest_dst='/home/legacy-agent/code/project',
    )
    old_cred_id = credential_id(cfg.vm.name, 'github.com/kitware/aivm')
    upsert_credential(
        reg,
        CredentialEntry(
            id=old_cred_id,
            vm_name=cfg.vm.name,
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

    data_root = home / '.local' / 'share' / 'aivm' / cfg.vm.name
    credential_source = data_root / 'credentials' / old_cred_id
    credential_source.mkdir(parents=True)
    os.chmod(credential_source, 0o700)
    private_key = credential_source / 'id_ed25519'
    private_key.write_text('private-key\n')
    os.chmod(private_key, 0o600)
    (credential_source / 'id_ed25519.pub').write_text(_public_key() + '\n')
    persistent_source = data_root / 'state'
    persistent_source.mkdir(parents=True)
    (persistent_source / 'persistent-attachments.json').write_text('{}\n')

    source = LegacyStoreSource(
        path=store_path,
        host_user=host_user,
        host_uid=os.getuid(),
        host_gid=os.getgid(),
        home=home,
    )
    return source, cfg.vm.name, credential_source, persistent_source


def _runtime_ok(
    plan: MigrationPlan, layout: MachineStoreLayout
) -> dict[str, object]:
    del layout
    return {
        'status': 'passed',
        'domains': sorted(plan.legacy_vm_cfgs),
        'creator_ssh_verified': sorted(plan.legacy_vm_cfgs),
    }


def _guest_stub(calls: list[str]) -> GuestInstaller:
    def install(
        vm_name: str, cfg: AgentVMConfig, layout: MachineStoreLayout
    ) -> None:
        del cfg, layout
        calls.append(vm_name)

    return install


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_apply_is_verified_resumable_and_retains_legacy_inputs(
    tmp_path: Path,
) -> None:
    source, vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    before = _digest(source.path)
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    assert not plan.blocked
    guest_calls: list[str] = []

    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub(guest_calls),
        runtime_verifier=_runtime_ok,
    )

    assert result.journal.status == 'complete'
    assert result.journal.completed_steps[-1] == 'verified'
    assert guest_calls == [vm_name]
    assert _digest(source.path) == before
    assert credential_source.exists()
    assert persistent_source.exists()

    machine = load_store(layout.config_path)
    assert machine.store_kind == 'machine'
    assert machine.schema_version == 11
    assert machine.vms[0].name == vm_name
    assert machine.principals[0].guest_user == 'legacy-agent'

    profile_path = Path(str(plan.profiles[0]['path']))
    profile = load_user_profile(profile_path)
    assert profile.active_vm == vm_name

    credential_target = Path(str(plan.credential_material_moves[0]['target']))
    persistent_target = Path(str(plan.persistent_state_moves[0]['target']))
    assert credential_target.is_dir()
    assert persistent_target.is_dir()
    assert credential_target.stat().st_uid == credential_source.stat().st_uid
    assert credential_target.stat().st_gid == credential_source.stat().st_gid
    assert (credential_target.stat().st_mode & 0o7777) == 0o700
    assert (credential_target / 'id_ed25519').stat().st_mode & 0o7777 == 0o600
    # A caller-owned root is the personal layout, so machine state is private
    # to this user rather than group-shared. test_machine_store covers the
    # group-shared modes against an explicitly shared root.
    assert (persistent_target.stat().st_mode & 0o7777) == 0o700
    assert (
        persistent_target / 'persistent-attachments.json'
    ).stat().st_mode & 0o7777 == 0o600
    assert (result.transaction_dir.stat().st_mode & 0o7777) == 0o750
    assert (
        result.transaction_dir / 'state.json'
    ).stat().st_mode & 0o7777 == 0o640
    assert (
        result.transaction_dir / 'backups-private'
    ).stat().st_mode & 0o7777 == 0o700

    repeated = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub(guest_calls),
        runtime_verifier=_runtime_ok,
    )
    assert repeated.resumed
    assert repeated.journal.status == 'complete'
    assert guest_calls == [vm_name]


@pytest.mark.parametrize(
    ('source_name', 'failure_path', 'error'),
    [
        ('credential', 'target', PermissionError(13, 'permission denied')),
        ('persistent', 'target', OSError(errno.EIO, 'I/O error')),
        ('persistent', 'parent', PermissionError(13, 'permission denied')),
    ],
)
def test_missing_source_destination_inspection_errors_fail_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_name: str,
    failure_path: str,
    error: OSError,
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    selected_source = (
        credential_source if source_name == 'credential' else persistent_source
    )
    shutil.rmtree(selected_source)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    moves = (
        plan.credential_material_moves
        if source_name == 'credential'
        else plan.persistent_state_moves
    )
    target = Path(str(moves[0]['target']))
    failing = target if failure_path == 'target' else target.parent
    if source_name == 'persistent':
        ancestor = (
            target.parent if failure_path == 'target' else target.parent.parent
        )
        ancestor.mkdir(parents=True, exist_ok=True)
    profile_path = Path(str(plan.profiles[0]['path']))
    transaction = migration_transaction_dir(
        'migration-' + migration_plan_sha256(plan)[:16],
        layout,
    )
    real_lstat = os.lstat

    def failing_lstat(
        path: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
    ) -> os.stat_result:
        if Path(path) == failing:
            raise error
        return real_lstat(path, dir_fd=dir_fd)

    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.migration_apply.os.lstat', failing_lstat
    )
    with pytest.raises(
        MigrationExecutionError,
        match='Could not prove migration destination is absent',
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not transaction.exists()
    assert not layout.config_path.exists()
    assert not profile_path.exists()
    assert not target.exists()


def test_missing_source_dangling_destination_symlink_fails_before_writes(
    tmp_path: Path,
) -> None:
    source, _vm_name, _credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    shutil.rmtree(persistent_source)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    target = Path(str(plan.persistent_state_moves[0]['target']))
    target.parent.mkdir(parents=True)
    target.symlink_to(tmp_path / 'missing-target', target_is_directory=True)
    profile_path = Path(str(plan.profiles[0]['path']))

    with pytest.raises(
        MigrationExecutionError, match='destination is a symlink'
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert target.is_symlink()
    assert not layout.config_path.exists()
    assert not (layout.state_dir / 'migrations').exists()
    assert not profile_path.exists()


def test_missing_source_intermediate_symlink_fails_before_writes(
    tmp_path: Path,
) -> None:
    source, _vm_name, _credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    shutil.rmtree(persistent_source)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    outside = tmp_path / 'outside-state'
    outside.mkdir()
    layout.root.mkdir()
    layout.state_dir.symlink_to(outside, target_is_directory=True)
    target = Path(str(plan.persistent_state_moves[0]['target']))
    profile_path = Path(str(plan.profiles[0]['path']))

    with pytest.raises(
        MigrationExecutionError, match='intermediate component is a symlink'
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert layout.state_dir.is_symlink()
    assert list(outside.iterdir()) == []
    assert not layout.config_path.exists()
    assert not profile_path.exists()
    assert not target.exists()


@pytest.mark.parametrize(
    ('source_name', 'expected_message'),
    [
        ('credential', 'Credential material source changed after planning'),
        ('persistent', 'Persistent state source changed after planning'),
    ],
)
def test_apply_rejects_deleted_planned_data_source_before_writing(
    tmp_path: Path, source_name: str, expected_message: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    selected = (
        credential_source if source_name == 'credential' else persistent_source
    )
    shutil.rmtree(selected)

    with pytest.raises(MigrationExecutionError, match=expected_message):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not layout.root.exists()


@pytest.mark.parametrize(
    ('source_name', 'expected_message'),
    [
        ('credential', 'Credential material source changed after planning'),
        ('persistent', 'Persistent state source changed after planning'),
    ],
)
def test_apply_rejects_planned_data_source_replaced_by_symlink(
    tmp_path: Path, source_name: str, expected_message: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    selected = (
        credential_source if source_name == 'credential' else persistent_source
    )
    replacement = selected.with_name(selected.name + '-replacement')
    selected.rename(replacement)
    selected.symlink_to(replacement, target_is_directory=True)

    with pytest.raises(MigrationExecutionError, match=expected_message):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not layout.root.exists()


@pytest.mark.parametrize(
    ('source_name', 'expected_message'),
    [
        ('credential', 'Credential material source changed after planning'),
        ('persistent', 'Persistent state source changed after planning'),
    ],
)
def test_apply_rejects_new_data_source_absent_during_planning(
    tmp_path: Path, source_name: str, expected_message: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    selected = (
        credential_source if source_name == 'credential' else persistent_source
    )
    shutil.rmtree(selected)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    selected.mkdir(parents=True)
    (selected / 'appeared-after-review').write_text('new data\n')

    with pytest.raises(MigrationExecutionError, match=expected_message):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not layout.root.exists()


@pytest.mark.parametrize('source_name', ['credential', 'persistent'])
def test_apply_rejects_stale_destination_for_missing_reviewed_source(
    tmp_path: Path, source_name: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    selected = (
        credential_source if source_name == 'credential' else persistent_source
    )
    shutil.rmtree(selected)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    moves = (
        plan.credential_material_moves
        if source_name == 'credential'
        else plan.persistent_state_moves
    )
    target = Path(str(moves[0]['target']))
    target.mkdir(parents=True)
    (target / 'stale-material').write_text('not reviewed\n')

    with pytest.raises(
        MigrationExecutionError,
        match='destination exists even though its source was reviewed as missing',
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not layout.config_path.exists()
    assert not (layout.state_dir / 'migrations').exists()
    assert (target / 'stale-material').read_text() == 'not reviewed\n'


@pytest.mark.parametrize('source_name', ['credential', 'persistent'])
def test_verify_rejects_destination_created_for_missing_reviewed_source(
    tmp_path: Path, source_name: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    selected = (
        credential_source if source_name == 'credential' else persistent_source
    )
    shutil.rmtree(selected)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    moves = (
        plan.credential_material_moves
        if source_name == 'credential'
        else plan.persistent_state_moves
    )
    target = Path(str(moves[0]['target']))
    target.mkdir(parents=True)
    (target / 'stale-material').write_text('appeared after migration\n')

    with pytest.raises(
        MigrationExecutionError,
        match='destination exists even though its source was reviewed as missing',
    ):
        verify_applied_migration(
            result.journal.migration_id,
            layout=layout,
            runtime_verifier=_runtime_ok,
        )


@pytest.mark.parametrize(
    ('source_name', 'expected_message'),
    [
        ('credential', 'Credential material source changed after planning'),
        ('persistent', 'Persistent state source changed after planning'),
    ],
)
def test_apply_rejects_modified_planned_data_source_before_writing(
    tmp_path: Path, source_name: str, expected_message: str
) -> None:
    source, _vm_name, credential_source, persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    if source_name == 'credential':
        changed = credential_source / 'id_ed25519'
    else:
        changed = persistent_source / 'persistent-attachments.json'
    changed.write_text(changed.read_text(encoding='utf-8') + 'changed\n')

    with pytest.raises(MigrationExecutionError, match=expected_message):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not layout.root.exists()


def test_interrupted_apply_resumes_from_journal(tmp_path: Path) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    guest_calls: list[str] = []

    with pytest.raises(
        MigrationExecutionError, match='Injected migration interruption'
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_stub(guest_calls),
            runtime_verifier=_runtime_ok,
            fail_after_step='machine-store-written',
        )

    migration_id = latest_migration_id(layout=layout)
    failed = load_migration_journal(migration_id, layout=layout)
    assert failed.journal.status == 'failed'
    assert 'machine-store-written' in failed.journal.completed_steps

    rebuilt = rebuild_plan_from_journal(
        failed.journal,
        layout=layout,
        check_runtime=False,
    )
    assert not rebuilt.blocked
    resumed = apply_migration(
        rebuilt,
        layout=layout,
        guest_installer=_guest_stub(guest_calls),
        runtime_verifier=_runtime_ok,
    )
    assert resumed.resumed
    assert resumed.journal.status == 'complete'
    assert guest_calls == ['aivm-migrate-test']


def test_rollback_restores_pre_migration_paths(tmp_path: Path) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    before = _digest(source.path)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    profile_path = Path(str(plan.profiles[0]['path']))
    credential_target = Path(str(plan.credential_material_moves[0]['target']))
    persistent_target = Path(str(plan.persistent_state_moves[0]['target']))
    assert layout.config_path.exists()
    assert profile_path.exists()
    assert credential_target.exists()
    assert persistent_target.exists()

    rolled = rollback_migration(
        result.journal.migration_id,
        layout=layout,
    )

    assert rolled.journal.status == 'rolled-back'
    assert not layout.config_path.exists()
    assert not profile_path.exists()
    assert not credential_target.exists()
    assert not persistent_target.exists()
    assert source.path.exists()
    assert _digest(source.path) == before
    # The journal remains as durable evidence after rollback.
    assert rolled.transaction_dir.joinpath('state.json').exists()


def test_rollback_never_rewrites_evidence_only_inputs(tmp_path: Path) -> None:
    source, _vm_name, _cred, persistent_source = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    source.path.write_text(
        source.path.read_text(encoding='utf-8') + '\n# operator edit\n',
        encoding='utf-8',
    )
    persistent_file = persistent_source / 'persistent-attachments.json'
    persistent_file.write_text('{"operator": true}\n', encoding='utf-8')

    rolled = rollback_migration(result.journal.migration_id, layout=layout)

    assert rolled.journal.status == 'rolled-back'
    assert '# operator edit' in source.path.read_text(encoding='utf-8')
    assert persistent_file.read_text(encoding='utf-8') == '{"operator": true}\n'
    evidence = {
        item.role: item.disposition
        for item in rolled.journal.backups
        if item.role in {'legacy-store-input', 'persistent-input'}
    }
    assert evidence == {
        'legacy-store-input': 'evidence_only',
        'persistent-input': 'evidence_only',
    }


def test_rollback_refuses_changed_target_before_mutating_any_target(
    tmp_path: Path,
) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    persistent_target = Path(str(plan.persistent_state_moves[0]['target']))
    changed = persistent_target / 'concurrent-edit.txt'
    changed.write_text('do not overwrite\n', encoding='utf-8')

    with pytest.raises(
        MigrationExecutionError,
        match='changed after migration wrote it',
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    # Global preflight must discover the conflict before removing any other
    # machine/profile/credential target.
    assert layout.config_path.exists()
    assert changed.read_text(encoding='utf-8') == 'do not overwrite\n'
    failed = load_migration_journal(
        result.journal.migration_id,
        layout=layout,
    )
    assert failed.journal.status == 'rollback-failed'


def test_preexisting_private_target_uses_private_verified_backup(
    tmp_path: Path,
) -> None:
    source, _vm_name, credential_source, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    credential_target = Path(str(plan.credential_material_moves[0]['target']))
    shutil.copytree(
        credential_source, credential_target, copy_function=shutil.copy2
    )
    before = _digest(credential_target / 'id_ed25519')

    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )

    private_records = [
        item
        for item in result.journal.backups
        if item.role == 'private-credential-target'
    ]
    assert len(private_records) == 1
    private_backup = Path(private_records[0].backup)
    assert private_backup.is_dir()
    assert (private_backup.parent.stat().st_mode & 0o7777) == 0o700

    rollback_migration(result.journal.migration_id, layout=layout)
    assert credential_target.is_dir()
    assert _digest(credential_target / 'id_ed25519') == before


def _applied_migration_for_rollback(
    tmp_path: Path,
) -> tuple[MachineStoreLayout, MigrationPlan, MigrationApplyResult]:
    source, _vm_name, _credential_source, _persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    return layout, plan, result


def test_rollback_rejects_tampered_state_coordinates(tmp_path: Path) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    state_path = result.transaction_dir / 'state.json'
    payload = json.loads(state_path.read_text(encoding='utf-8'))
    outside = tmp_path / 'outside-do-not-touch'
    outside.write_text('safe\n', encoding='utf-8')
    payload['backups'][0]['original'] = str(outside)
    state_path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(state_path, 0o640)

    with pytest.raises(
        MigrationExecutionError, match='does not match protected state'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert outside.read_text(encoding='utf-8') == 'safe\n'
    assert layout.config_path.exists()


def test_rollback_rejects_group_writable_control_state(tmp_path: Path) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    state_path = result.transaction_dir / 'state.json'
    os.chmod(state_path, 0o660)

    with pytest.raises(MigrationExecutionError, match='group/other writable'):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert layout.config_path.exists()


def test_rollback_does_not_trust_journal_output_digest(tmp_path: Path) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    state_path = result.transaction_dir / 'state.json'
    payload = json.loads(state_path.read_text(encoding='utf-8'))
    selected = next(
        row for row in payload['backups'] if row.get('applied_existed') is True
    )
    selected['applied_sha256'] = '0' * 64
    state_path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(state_path, 0o640)

    with pytest.raises(
        MigrationExecutionError, match='output digest disagrees with protected'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert layout.config_path.exists()


def test_rollback_rejects_tampered_frozen_plan(tmp_path: Path) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    plan_path = result.transaction_dir / 'plan.json'
    payload = json.loads(plan_path.read_text(encoding='utf-8'))
    outside = tmp_path / 'outside-config.toml'
    payload['target_machine_store'] = str(outside)
    plan_path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(plan_path, 0o640)

    with pytest.raises(
        MigrationExecutionError, match='does not match its protected digest'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert not outside.exists()
    assert layout.config_path.exists()


def test_rollback_rejects_replaced_transaction_directory(
    tmp_path: Path,
) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    transaction = result.transaction_dir
    original = transaction.with_name(transaction.name + '-saved')
    transaction.rename(original)
    transaction.symlink_to(original, target_is_directory=True)

    with pytest.raises(
        MigrationExecutionError, match='symlinked migration transaction path'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert transaction.is_symlink()
    assert (original / 'state.json').exists()
    assert layout.config_path.exists()


def test_rollback_rejects_symlinked_transaction_parent(tmp_path: Path) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    migration_dir = result.transaction_dir.parent
    saved = migration_dir.with_name(migration_dir.name + '-saved')
    migration_dir.rename(saved)
    migration_dir.symlink_to(saved, target_is_directory=True)

    with pytest.raises(
        MigrationExecutionError, match='symlinked migration transaction path'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert migration_dir.is_symlink()
    assert (saved / result.transaction_dir.name / 'state.json').exists()
    assert layout.config_path.exists()


def test_rollback_rejects_symlinked_original_target(tmp_path: Path) -> None:
    layout, plan, result = _applied_migration_for_rollback(tmp_path)
    target = Path(str(plan.persistent_state_moves[0]['target']))
    saved = target.with_name(target.name + '-saved')
    target.rename(saved)
    outside = tmp_path / 'outside-original'
    outside.mkdir()
    marker = outside / 'marker'
    marker.write_text('safe\n', encoding='utf-8')
    target.symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        MigrationExecutionError, match='symlinked rollback target'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert marker.read_text(encoding='utf-8') == 'safe\n'
    assert target.is_symlink()
    assert saved.exists()
    assert layout.config_path.exists()


def test_rollback_rejects_journal_backup_path_substitution(
    tmp_path: Path,
) -> None:
    layout, _plan, result = _applied_migration_for_rollback(tmp_path)
    state_path = result.transaction_dir / 'state.json'
    payload = json.loads(state_path.read_text(encoding='utf-8'))
    outside = tmp_path / 'outside-backup'
    outside.write_text('safe\n', encoding='utf-8')
    payload['backups'][0]['backup'] = str(outside)
    state_path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(state_path, 0o640)

    with pytest.raises(
        MigrationExecutionError, match='metadata disagrees with protected state'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert outside.read_text(encoding='utf-8') == 'safe\n'
    assert layout.config_path.exists()


def test_rollback_rejects_symlinked_backup_path(tmp_path: Path) -> None:
    source, _vm_name, credential_source, _persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    credential_target = Path(str(plan.credential_material_moves[0]['target']))
    shutil.copytree(
        credential_source, credential_target, copy_function=shutil.copy2
    )
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    private_record = next(
        item
        for item in result.journal.backups
        if item.role == 'private-credential-target'
    )
    backup = Path(private_record.backup)
    saved = backup.with_name(backup.name + '-saved')
    backup.rename(saved)
    backup.symlink_to(saved, target_is_directory=True)

    with pytest.raises(
        MigrationExecutionError, match='symlinked migration backup'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert backup.is_symlink()
    assert credential_target.exists()
    assert layout.config_path.exists()


def test_rollback_rejects_modified_backup_contents(tmp_path: Path) -> None:
    source, _vm_name, credential_source, _persistent_source = _legacy_source(
        tmp_path
    )
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    credential_target = Path(str(plan.credential_material_moves[0]['target']))
    shutil.copytree(
        credential_source, credential_target, copy_function=shutil.copy2
    )
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    private_record = next(
        item
        for item in result.journal.backups
        if item.role == 'private-credential-target'
    )
    backup = Path(private_record.backup)
    (backup / 'id_ed25519').write_text(
        'attacker replacement\n', encoding='utf-8'
    )

    with pytest.raises(
        MigrationExecutionError, match='backup changed after creation'
    ):
        rollback_migration(result.journal.migration_id, layout=layout)

    assert credential_target.exists()
    assert layout.config_path.exists()


def test_verify_detects_source_mutation_after_apply(tmp_path: Path) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    result = apply_migration(
        plan,
        layout=layout,
        guest_installer=_guest_stub([]),
        runtime_verifier=_runtime_ok,
    )
    source.path.write_text(source.path.read_text() + '\n# changed\n')

    with pytest.raises(
        MigrationExecutionError, match='changed since the migration journal'
    ):
        verify_applied_migration(
            result.journal.migration_id,
            layout=layout,
            runtime_verifier=_runtime_ok,
        )


def test_migration_id_validation_rejects_malformed_values(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    for value in [
        'migration-',
        'migration-1234',
        'migration-0123456789abcdef0',
        'migration-0123456789abcdeg',
        '../migration-0123456789abcdef',
    ]:
        with pytest.raises(
            MigrationExecutionError, match='Invalid migration id'
        ):
            migration_transaction_dir(value, layout)


def test_apply_rejects_layout_different_from_reviewed_target(
    tmp_path: Path,
) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    reviewed_layout = MachineStoreLayout.from_root(
        tmp_path / 'reviewed-machine'
    )
    other_layout = MachineStoreLayout.from_root(tmp_path / 'other-machine')
    plan = build_migration_plan(
        [source], layout=reviewed_layout, check_runtime=False
    )

    with pytest.raises(MigrationExecutionError, match='does not match'):
        apply_migration(
            plan,
            layout=other_layout,
            guest_installer=_guest_stub([]),
            runtime_verifier=_runtime_ok,
        )

    assert not other_layout.config_path.exists()


def test_guest_bootstrap_script_is_forced_and_self_validating() -> None:
    public_key = _public_key()
    script = _guest_install_script(public_key)
    assert 'groupadd --system aivm-bootstrap' in script
    assert 'useradd --system --gid aivm-bootstrap' in script
    assert '/usr/local/sbin/aivm-guestctl' in script
    assert 'visudo -cf /etc/sudoers.d/aivm-bootstrap' in script
    restricted = restricted_bootstrap_authorized_key(public_key)
    assert 'no-agent-forwarding' in restricted
    assert 'no-port-forwarding' in restricted
    assert 'no-pty' in restricted
    assert 'command=' in restricted
    assert '--forced' in restricted
    assert 'base64 -d' in script


def test_default_guest_installer_uses_existing_creator_ssh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig().expanded_paths()
    cfg.vm.name = 'vm-existing'
    cfg.vm.user = 'legacy-agent'
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg.paths.ssh_pubkey_path = str(tmp_path / 'id_ed25519.pub')
    Path(cfg.paths.ssh_identity_file).write_text('private\n')
    Path(cfg.paths.ssh_pubkey_path).write_text(_public_key() + '\n')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    identity = BootstrapIdentity(
        directory=layout.bootstrap_dir / 'vm-existing',
        private_key=layout.bootstrap_dir / 'vm-existing' / 'id_ed25519',
        public_key_path=layout.bootstrap_dir / 'vm-existing' / 'id_ed25519.pub',
        known_hosts=layout.bootstrap_dir / 'vm-existing' / 'known_hosts',
        public_key=_public_key(),
        use_sudo=False,
    )
    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.migration_apply.ensure_bootstrap_identity',
        lambda vm_name, layout: identity,
    )
    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.migration_apply.require_ssh_identity',
        lambda path: str(path),
    )
    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.migration_apply.wait_for_ip',
        lambda cfg: '192.0.2.50',
    )
    captured: dict[str, object] = {}

    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self
        captured['cmd'] = cmd
        captured['input_text'] = kwargs.get('input_text', '')
        return CommandResult(0, '', '')

    monkeypatch.setattr(CommandManager, 'run', fake_run)
    install_bootstrap_through_legacy_access(cfg.vm.name, cfg, layout)

    raw_cmd = captured['cmd']
    assert isinstance(raw_cmd, list)
    cmd = cast(list[str], raw_cmd)
    assert cmd[0] == 'ssh'
    assert 'legacy-agent@192.0.2.50' in cmd
    assert cmd[-4:] == ['sudo', '-n', 'bash', '-s']
    assert '/usr/local/sbin/aivm-guestctl' in str(captured['input_text'])


def test_tree_digest_covers_a_file_the_caller_may_not_read(
    tmp_path: Path,
) -> None:
    """Apply must digest the bootstrap directory without reading the key.

    The bootstrap private key is root-owned 0600 by the machine-store
    contract -- trusted-group members never read it directly -- while apply
    runs unprivileged. Capturing outputs must therefore survive an unreadable
    member, and must still notice when it changes.
    """
    from aivm.legacy.pre_0_6_0.migration_apply import _tree_sha256

    tree = tmp_path / 'bootstrap'
    tree.mkdir()
    (tree / 'id_ed25519.pub').write_text('ssh-ed25519 AAAA pub\n')
    private = tree / 'id_ed25519'
    private.write_text('PRIVATE-A\n')
    os.chmod(private, 0o000)

    first = _tree_sha256(tree)

    # A different length behind the same unreadable mode still moves it.
    os.chmod(private, 0o600)
    private.write_text('PRIVATE-A-LONGER\n')
    os.chmod(private, 0o000)
    assert _tree_sha256(tree) != first

    # Becoming readable must not silently reuse the unreadable marker.
    os.chmod(private, 0o600)
    private.write_text('PRIVATE-A\n')
    readable = _tree_sha256(tree)
    os.chmod(private, 0o000)
    assert _tree_sha256(tree) != readable
