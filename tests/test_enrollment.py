"""Host-side bootstrap identity and principal reconciliation tests."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.config_store import (
    find_principal_for_host,
    load_store,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.enrollment import (
    bootstrap_identity_paths,
    ensure_bootstrap_identity,
    normalized_guest_username,
    reconcile_current_principal,
)
from aivm.machine_store import ensure_machine_store_layout, machine_store_layout
from aivm.profile_store import UserProfileStore, save_user_profile
from aivm.scoped_store import resolve_store_scope, save_scope_store
from tests.helpers import FakeProc, activate_manager, command_recorder


def _machine_with_profile(tmp_path: Path) -> tuple[AgentVMConfig, object]:
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
        normalized_guest_username('KHQ\\Alice.User')
        == 'khq-alice-user-agent'
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
        'aivm.enrollment._current_host_identity',
        lambda: ('edward.wang', 1201, 1202),
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
        'aivm.enrollment._current_host_identity',
        lambda: ('edward.wang', 1201, 1202),
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
