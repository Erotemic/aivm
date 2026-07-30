"""Host-side bootstrap identity and principal reconciliation tests."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Literal

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    find_principal_for_host,
    load_store,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.enrollment import (
    EnrollmentReport,
    bootstrap_identity_paths,
    ensure_bootstrap_identity,
    normalized_guest_username,
    reconcile_current_principal,
)
from aivm.errors import AIVMError
from aivm.host_identity import HostIdentity
from aivm.machine_store import ensure_machine_store_layout, machine_store_layout
from aivm.profile_store import UserProfileStore, save_user_profile
from aivm.scoped_store import StoreScope, resolve_store_scope, save_scope_store
from tests.helpers import FakeProc, activate_manager, command_recorder


def _machine_with_profile(tmp_path: Path) -> tuple[AgentVMConfig, StoreScope]:
    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-shared-host'
    cfg.vm.user = 'creator-agent'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    reg = load_store(scope.store_path)
    reg.store_kind = 'machine'
    reg.schema_version = 9
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    save_scope_store(scope, reg, reason='test machine setup')

    ssh_dir = tmp_path / 'edward-home' / '.ssh'
    ssh_dir.mkdir(parents=True)
    private = ssh_dir / 'id_aivm_ed25519'
    public = ssh_dir / 'id_aivm_ed25519.pub'
    private.write_text('PRIVATE-TEST\n')
    public.write_text('ssh-ed25519 AAAAEDWARD edward@test\n')
    profile = UserProfileStore(
        active_vm=cfg.vm.name,
        ssh_identity_file=str(private),
        ssh_pubkey_path=str(public),
        state_dir=str(tmp_path / 'edward-state'),
        default_guest_user='edward-wang-agent',
    )
    assert scope.profile_path is not None
    save_user_profile(profile, scope.profile_path)
    return cfg, scope


def test_normalized_guest_username() -> None:
    assert normalized_guest_username('edward.wang') == 'edward-wang-agent'
    assert (
        normalized_guest_username('KHQ\\Alice.User') == 'khq-alice-user-agent'
    )
    assert len(normalized_guest_username('x' * 100)) <= 32


def test_bootstrap_identity_is_stable_and_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = machine_store_layout()
    ensure_machine_store_layout(layout, group_gid=os.getgid())
    activate_manager(monkeypatch, yes=True)

    def fake_run(
        cmd: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        argv = [str(part) for part in cmd]
        if argv[:2] == ['mkdir', '-p']:
            Path(argv[-1]).mkdir(parents=True, exist_ok=True)
        elif argv[:1] == ['chmod']:
            os.chmod(argv[-1], int(argv[1], 8))
        elif argv[:1] == ['ssh-keygen']:
            private = Path(argv[argv.index('-f') + 1])
            private.write_text('PRIVATE-BOOTSTRAP\n', encoding='utf-8')
            Path(str(private) + '.pub').write_text(
                'ssh-ed25519 AAAABOOTSTRAP aivm-bootstrap@test\n',
                encoding='utf-8',
            )
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    identity = ensure_bootstrap_identity('vm-shared', layout=layout)
    again = ensure_bootstrap_identity('vm-shared', layout=layout)

    assert again == identity
    assert identity.private_key.exists()
    assert identity.public_key_path.exists()
    assert identity.public_key.startswith('ssh-ed25519 ')
    assert stat.S_IMODE(identity.private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(identity.public_key_path.stat().st_mode) == 0o644


def test_reconcile_persists_pending_then_active_and_uses_two_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    identity = bootstrap_identity_paths(
        cfg.vm.name, layout=scope.machine_layout
    )
    identity.directory.mkdir(parents=True)
    identity.private_key.write_text('BOOTSTRAP-PRIVATE\n')
    identity.public_key_path.write_text(
        'ssh-ed25519 AAAABOOTSTRAP bootstrap@test\n'
    )
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(uid=1201, gid=1202, username='edward.wang'),
    )
    monkeypatch.setattr(
        'aivm.enrollment._resolve_enrollment_ip',
        lambda cfg, ip_override='': '10.77.0.119',
    )
    activate_manager(monkeypatch, yes=True)

    def route_ssh(cmd: list[str]) -> FakeProc:
        if 'aivm-bootstrap@10.77.0.119' in cmd:
            return FakeProc(0, '{"status":"ok"}\n', '')
        if 'edward-wang-agent@10.77.0.119' in cmd:
            return FakeProc(0, '', '')
        raise AssertionError(cmd)

    rec = command_recorder(monkeypatch, {'ssh': route_ssh})
    report = reconcile_current_principal(
        scope,
        vm_name=cfg.vm.name,
    )

    assert report.principal.state == 'active'
    assert report.principal.guest_user == 'edward-wang-agent'
    persisted = find_principal_for_host(
        load_store(scope.store_path),
        vm_name=cfg.vm.name,
        host_user='edward.wang',
    )
    assert persisted == report.principal
    assert rec.count('ssh') == 2
    bootstrap_cmd = rec.normalized[0]
    personal_cmd = rec.normalized[1]
    assert str(identity.private_key) in bootstrap_cmd
    assert 'aivm-bootstrap@10.77.0.119' in bootstrap_cmd
    assert 'edward-wang-agent@10.77.0.119' in personal_cmd
    personal_identity = tmp_path / 'edward-home' / '.ssh' / 'id_aivm_ed25519'
    assert str(personal_identity) in personal_cmd


def test_reconcile_keeps_pending_when_bootstrap_transport_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    identity = bootstrap_identity_paths(
        cfg.vm.name, layout=scope.machine_layout
    )
    identity.directory.mkdir(parents=True)
    identity.private_key.write_text('BOOTSTRAP-PRIVATE\n')
    identity.public_key_path.write_text(
        'ssh-ed25519 AAAABOOTSTRAP bootstrap@test\n'
    )
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(uid=1201, gid=1202, username='edward.wang'),
    )
    monkeypatch.setattr(
        'aivm.enrollment._resolve_enrollment_ip',
        lambda cfg, ip_override='': '10.77.0.119',
    )
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch, {'ssh': FakeProc(255, '', 'connection refused')}
    )

    with pytest.raises(Exception, match='Guest enrollment failed'):
        reconcile_current_principal(scope, vm_name=cfg.vm.name)

    persisted = find_principal_for_host(
        load_store(scope.store_path),
        vm_name=cfg.vm.name,
        host_user='edward.wang',
    )
    assert persisted is not None
    assert persisted.state == 'pending'


def test_reconcile_does_not_downgrade_active_identity_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Re-verifying a granted identity must not durably weaken it.

    Regression: reconcile persisted state='pending' before the first
    privileged command, so declining the prompt -- or an unreachable VM --
    left a previously active identity downgraded, which also weakens
    last-access accounting.
    """
    cfg, scope = _machine_with_profile(tmp_path)
    _record_existing_identity(scope, cfg)
    identity = bootstrap_identity_paths(
        cfg.vm.name, layout=scope.machine_layout
    )
    identity.directory.mkdir(parents=True)
    identity.private_key.write_text('BOOTSTRAP-PRIVATE\n')
    identity.public_key_path.write_text(
        'ssh-ed25519 AAAABOOTSTRAP bootstrap@test\n'
    )
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(uid=1201, gid=1202, username='edward.wang'),
    )
    monkeypatch.setattr(
        'aivm.enrollment._resolve_enrollment_ip',
        lambda cfg, ip_override='': '10.77.0.119',
    )
    activate_manager(monkeypatch, yes=True)
    command_recorder(
        monkeypatch, {'ssh': FakeProc(255, '', 'connection refused')}
    )

    with pytest.raises(Exception, match='Guest enrollment failed'):
        reconcile_current_principal(scope, vm_name=cfg.vm.name)

    persisted = find_principal_for_host(
        load_store(scope.store_path),
        vm_name=cfg.vm.name,
        host_user='edward.wang',
    )
    assert persisted is not None
    assert persisted.state == 'active'


def _record_existing_identity(
    scope: StoreScope,
    cfg: AgentVMConfig,
    *,
    key: str = 'ssh-ed25519 AAAAEDWARD original-comment',
    guest_user: str = 'edward-wang-agent',
) -> None:
    reg = load_store(scope.store_path)
    upsert_principal(
        reg,
        PrincipalEntry(
            id='principal-edward',
            vm_name=cfg.vm.name,
            host_user='edward.wang',
            host_uid=1201,
            host_gid=1202,
            guest_user=guest_user,
            ssh_public_key=key,
            state='active',
        ),
    )
    save_scope_store(scope, reg, reason='record existing identity')


def test_reconcile_rejects_key_material_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    _record_existing_identity(scope, cfg)
    assert scope.profile_path is not None
    profile = UserProfileStore(
        active_vm=cfg.vm.name,
        ssh_identity_file=str(tmp_path / 'id'),
        ssh_pubkey_path=str(tmp_path / 'id.pub'),
        state_dir=str(tmp_path / 'state'),
    )
    Path(profile.ssh_pubkey_path).write_text(
        'ssh-ed25519 AAAADIFFERENT new-comment\n', encoding='utf-8'
    )
    save_user_profile(profile, scope.profile_path)
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(1201, 1202, 'edward.wang'),
    )
    with pytest.raises(AIVMError, match='Key rotation is not supported'):
        reconcile_current_principal(scope, vm_name=cfg.vm.name, dry_run=True)


def test_reconcile_ignores_key_comment_only_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    _record_existing_identity(scope, cfg)
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(1201, 1202, 'edward.wang'),
    )
    report = reconcile_current_principal(
        scope, vm_name=cfg.vm.name, dry_run=True
    )
    assert report.principal.ssh_public_key.endswith('original-comment')


def test_reconcile_rejects_guest_account_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    _record_existing_identity(scope, cfg)
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(1201, 1202, 'edward.wang'),
    )
    with pytest.raises(AIVMError, match='Guest-account rotation'):
        reconcile_current_principal(
            scope,
            vm_name=cfg.vm.name,
            guest_user='new-account',
            dry_run=True,
        )


def test_reconcile_holds_identity_locks_through_guest_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, scope = _machine_with_profile(tmp_path)
    held = False

    class FakeLockScope:
        def __enter__(self) -> None:
            nonlocal held
            assert not held
            held = True

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: object,
        ) -> Literal[False]:
            del exc_type, exc, tb
            nonlocal held
            assert held
            held = False
            return False

    def fake_locks(*args: object, **kwargs: object) -> FakeLockScope:
        del args, kwargs
        return FakeLockScope()

    def fake_impl(
        call_scope: StoreScope,
        *,
        vm_name: str,
        guest_user: str = '',
        ip_override: str = '',
        dry_run: bool = False,
        enable_disabled: bool = False,
    ) -> EnrollmentReport:
        del guest_user, ip_override, enable_disabled
        assert call_scope is scope
        assert vm_name == cfg.vm.name
        assert dry_run is False
        assert held
        return EnrollmentReport(
            principal=PrincipalEntry(
                id='principal-test',
                vm_name=vm_name,
                host_user='tester',
                host_uid=1000,
                host_gid=1000,
                guest_user='tester-agent',
                state='active',
            ),
            ip='192.0.2.5',
            changed=True,
        )

    monkeypatch.setattr('aivm.enrollment.machine_resource_locks', fake_locks)
    monkeypatch.setattr(
        'aivm.enrollment._reconcile_current_principal_impl', fake_impl
    )

    report = reconcile_current_principal(scope, vm_name=cfg.vm.name)

    assert report.changed is True
    assert held is False
