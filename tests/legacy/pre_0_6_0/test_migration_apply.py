"""Resumable apply, verification, and rollback coverage."""

from __future__ import annotations

import hashlib
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
from aivm.machine_store import MachineStoreLayout
from aivm.legacy.pre_0_6_0.migration import LegacyStoreSource, MigrationPlan, build_migration_plan
from aivm.legacy.pre_0_6_0.migration_apply import (
    GuestInstaller,
    MigrationExecutionError,
    apply_migration,
    latest_migration_id,
    load_migration_journal,
    migration_transaction_dir,
    rebuild_plan_from_journal,
    rollback_migration,
    _guest_install_script,
    install_bootstrap_through_legacy_access,
    verify_applied_migration,
)
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
    source, vm_name, credential_source, persistent_source = _legacy_source(tmp_path)
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
    assert (persistent_target.stat().st_mode & 0o7777) == 0o2775
    assert (
        persistent_target / 'persistent-attachments.json'
    ).stat().st_mode & 0o7777 == 0o664
    assert (result.transaction_dir.stat().st_mode & 0o7777) == 0o2775
    assert (
        result.transaction_dir / 'state.json'
    ).stat().st_mode & 0o7777 == 0o664
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


def test_interrupted_apply_resumes_from_journal(tmp_path: Path) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    guest_calls: list[str] = []

    with pytest.raises(MigrationExecutionError, match='Injected migration interruption'):
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
    credential_target = Path(
        str(plan.credential_material_moves[0]['target'])
    )
    shutil.copytree(credential_source, credential_target, copy_function=shutil.copy2)
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

    with pytest.raises(MigrationExecutionError, match='changed since the migration journal'):
        verify_applied_migration(
            result.journal.migration_id,
            layout=layout,
            runtime_verifier=_runtime_ok,
        )




def test_migration_id_validation_rejects_malformed_values(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    for value in [
        'migration-',
        'migration-1234',
        'migration-0123456789abcdef0',
        'migration-0123456789abcdeg',
        '../migration-0123456789abcdef',
    ]:
        with pytest.raises(MigrationExecutionError, match='Invalid migration id'):
            migration_transaction_dir(value, layout)


def test_apply_rejects_layout_different_from_reviewed_target(
    tmp_path: Path,
) -> None:
    source, _vm_name, _cred, _state = _legacy_source(tmp_path)
    reviewed_layout = MachineStoreLayout.from_root(tmp_path / 'reviewed-machine')
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
