"""CLI coverage for shared-machine principal access management."""

from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    load_store,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.profile_store import UserProfileStore, save_user_profile
from aivm.scoped_store import resolve_store_scope, save_scope_store
from tests.helpers import run_cli


def _write_machine_and_profile(tmp_path: Path) -> tuple[str, Path]:
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
    upsert_principal(
        reg,
        PrincipalEntry(
            id='principal-alice',
            vm_name=cfg.vm.name,
            host_user='alice',
            host_uid=1001,
            host_gid=1001,
            guest_user='alice-agent',
            ssh_public_key='ssh-ed25519 AAAAALICE alice@test',
            state='active',
        ),
    )
    save_scope_store(scope, reg, reason='test access CLI')

    ssh_dir = tmp_path / 'home' / '.ssh'
    ssh_dir.mkdir(parents=True)
    private = ssh_dir / 'id_aivm_ed25519'
    public = ssh_dir / 'id_aivm_ed25519.pub'
    private.write_text('PRIVATE\n', encoding='utf-8')
    public.write_text(
        'ssh-ed25519 AAAAEDWARD edward@test\n', encoding='utf-8'
    )
    assert scope.profile_path is not None
    save_user_profile(
        UserProfileStore(
            active_vm=cfg.vm.name,
            ssh_identity_file=str(private),
            ssh_pubkey_path=str(public),
            state_dir=str(tmp_path / 'state'),
            default_guest_user='edward-wang-agent',
        ),
        scope.profile_path,
    )
    return cfg.vm.name, scope.store_path


def test_vm_access_list_uses_machine_principals(
    tmp_path: Path, capsys: object
) -> None:
    vm_name, store_path = _write_machine_and_profile(tmp_path)

    rc = run_cli(
        [
            'vm',
            'access',
            'list',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert 'alice -> alice-agent' in output
    assert 'state=active' in output
    assert str(store_path) in output


def test_vm_access_reconcile_dry_run_derives_current_principal(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: object,
) -> None:
    vm_name, store_path = _write_machine_and_profile(tmp_path)
    monkeypatch.setattr(
        'aivm.enrollment._current_host_identity',
        lambda: ('edward.wang', 1201, 1202),
    )
    monkeypatch.setattr(
        'aivm.enrollment.get_ip_cached', lambda cfg: '10.77.0.119'
    )

    rc = run_cli(
        [
            'vm',
            'access',
            'reconcile',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
            '--dry-run',
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert 'Would enroll edward.wang as edward-wang-agent' in output
    assert 'state=pending' in output
