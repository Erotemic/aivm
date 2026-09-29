"""CLI coverage for shared-machine principal access management."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    load_store,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.host_identity import HostIdentity
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
    public.write_text('ssh-ed25519 AAAAEDWARD edward@test\n', encoding='utf-8')
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
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
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
    output = capsys.readouterr().out
    assert 'alice -> alice-agent' in output
    assert 'state=active' in output
    assert str(store_path) in output


def test_vm_access_reconcile_dry_run_derives_current_principal(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vm_name, store_path = _write_machine_and_profile(tmp_path)
    monkeypatch.setattr(
        'aivm.enrollment.current_host_identity',
        lambda: HostIdentity(uid=1201, gid=1202, username='edward.wang'),
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
    output = capsys.readouterr().out
    assert 'Would enroll edward.wang as edward-wang-agent' in output
    assert 'state=pending' in output


def test_vm_access_reconcile_enable_is_explicit(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_reconcile(scope: object, **kwargs: object) -> object:
        captured['scope'] = scope
        captured.update(kwargs)
        return SimpleNamespace(
            principal=SimpleNamespace(
                host_user='alice',
                guest_user='alice-agent',
                state='active',
            ),
            ip='10.77.0.10',
        )

    monkeypatch.setattr(
        'aivm.cli.vm_access.reconcile_current_principal', fake_reconcile
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
            '--enable',
        ]
    )

    assert rc == 0
    assert captured['enable_disabled'] is True
    assert 'Enrolled alice as alice-agent' in capsys.readouterr().out


def test_vm_access_disable_selector_defaults_to_caller(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_mutate(scope: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(
            principal=SimpleNamespace(
                host_user='alice',
                guest_user='alice-agent',
                id='principal-alice',
            ),
            ownership=SimpleNamespace(
                has_owned_records=False,
                attachment_count=0,
                credential_count=0,
            ),
        )

    monkeypatch.setattr(
        'aivm.cli.vm_access.mutate_access_identity', fake_mutate
    )
    rc = run_cli(
        [
            'vm',
            'access',
            'disable',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
            '--dry-run',
        ]
    )

    assert rc == 0
    assert captured['selector'] == ''


def test_vm_access_disable_dry_run_uses_lifecycle_service(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_mutate(scope: object, **kwargs: object) -> object:
        captured['scope'] = scope
        captured.update(kwargs)
        return SimpleNamespace(
            principal=SimpleNamespace(
                host_user='alice',
                guest_user='alice-agent',
                id='principal-alice',
            ),
            ownership=SimpleNamespace(
                has_owned_records=True,
                attachment_count=2,
                credential_count=1,
            ),
        )

    monkeypatch.setattr(
        'aivm.cli.vm_access.mutate_access_identity', fake_mutate
    )

    rc = run_cli(
        [
            'vm',
            'access',
            'disable',
            'alice',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
            '--dry-run',
        ]
    )

    assert rc == 0
    assert captured['action'] == 'disable'
    assert captured['dry_run'] is True
    output = capsys.readouterr().out
    assert 'Would disable access identity alice -> alice-agent' in output
    assert 'Owned records retained: 2 attachment(s), 1 credential(s).' in output


def test_vm_access_remove_dry_run_states_guest_home_retention(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    monkeypatch.setattr(
        'aivm.cli.vm_access.mutate_access_identity',
        lambda scope, **kwargs: SimpleNamespace(
            principal=SimpleNamespace(
                host_user='alice',
                guest_user='alice-agent',
                id='principal-alice',
            ),
            ownership=SimpleNamespace(
                has_owned_records=False,
                attachment_count=0,
                credential_count=0,
            ),
        ),
    )

    rc = run_cli(
        [
            'vm',
            'access',
            'remove',
            'alice',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
            '--dry-run',
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out
    assert 'Would remove access identity alice -> alice-agent' in output
    assert 'Guest home retained; no guest files were deleted.' in output


def test_vm_access_repair_host_identity_uses_lifecycle_service(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_repair(scope: object, **kwargs: object) -> object:
        captured['scope'] = scope
        captured.update(kwargs)
        return SimpleNamespace(
            changed=True,
            previous_host_user='alice',
            principal=SimpleNamespace(
                id='principal-alice',
                host_user='alice-renamed',
                host_uid=1001,
            ),
        )

    monkeypatch.setattr(
        'aivm.cli.vm_access.repair_current_host_identity', fake_repair
    )
    rc = run_cli(
        [
            'vm',
            'access',
            'repair_host_identity',
            '--vm',
            vm_name,
            '--config',
            str(store_path),
            '--dry-run',
        ]
    )

    assert rc == 0
    assert captured['vm_name'] == vm_name
    assert captured['dry_run'] is True
    assert (
        'Would repair access identity principal-alice'
        in capsys.readouterr().out
    )
