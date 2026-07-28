"""Operational lifecycle coverage for shared-machine access identities."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.access_control import mutate_access_identity
from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    PrincipalEntry,
    find_principal,
    load_store,
    upsert_attachment,
    upsert_credential,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.credentials.validation import credential_id
from aivm.errors import AIVMError
from aivm.profile_store import UserProfileStore, load_user_profile, save_user_profile
from aivm.scoped_store import StoreScope, resolve_store_scope, save_scope_store


def _machine_scope(
    tmp_path: Path, *, with_owned_records: bool = True
) -> tuple[StoreScope, str]:
    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-shared-host'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    reg = load_store(scope.store_path)
    reg.store_kind = 'machine'
    reg.schema_version = 11
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    for principal in (
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
        PrincipalEntry(
            id='principal-bob',
            vm_name=cfg.vm.name,
            host_user='bob',
            host_uid=1002,
            host_gid=1002,
            guest_user='bob-agent',
            ssh_public_key='ssh-ed25519 AAAABOB bob@test',
            state='active',
        ),
    ):
        upsert_principal(reg, principal)
    if with_owned_records:
        upsert_attachment(
            reg,
            host_path=tmp_path / 'alice-project',
            vm_name=cfg.vm.name,
            owner_principal_id='principal-alice',
            guest_dst='/work/alice-project',
            tag='alice-project',
        )
        upsert_credential(
            reg,
            CredentialEntry(
                id=credential_id(
                    cfg.vm.name, 'github.com/kitware/kwimage', 'principal-alice'
                ),
                vm_name=cfg.vm.name,
                principal_id='principal-alice',
                owner='Kitware',
                repository='kwimage',
                provider_key_title='aivm test key',
                key_fingerprint='SHA256:test',
                state='active',
            ),
        )
    save_scope_store(scope, reg, reason='test access lifecycle')
    assert scope.profile_path is not None
    save_user_profile(
        UserProfileStore(active_vm=cfg.vm.name), scope.profile_path
    )
    return scope, cfg.vm.name


def test_disable_preserves_owned_records_and_clears_current_profile(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path)
    monkeypatch.setattr('aivm.access_control.getpass.getuser', lambda: 'alice')
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: '10.0.0.11',
    )

    report = mutate_access_identity(
        scope,
        vm_name=vm_name,
        action='disable',
    )

    assert report.changed is True
    assert report.ownership.attachment_count == 1
    assert report.ownership.credential_count == 1
    loaded = load_store(scope.store_path)
    principal = find_principal(
        loaded, vm_name=vm_name, principal_id='principal-alice'
    )
    assert principal is not None
    assert principal.state == 'disabled'
    assert len(loaded.attachments) == 1
    assert len(loaded.credentials) == 1
    assert scope.profile_path is not None
    assert load_user_profile(scope.profile_path).active_vm == ''


def test_remove_refuses_owned_records_before_guest_mutation(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path)
    monkeypatch.setattr('aivm.access_control.getpass.getuser', lambda: 'alice')
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError('guest mutation must not run')
        ),
    )

    with pytest.raises(AIVMError, match='while it owns 1 attachment'):
        mutate_access_identity(
            scope,
            vm_name=vm_name,
            action='remove',
        )


def test_cross_user_remove_requires_explicit_admin_override(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    monkeypatch.setattr('aivm.access_control.getpass.getuser', lambda: 'alice')
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: '10.0.0.11',
    )

    with pytest.raises(AIVMError, match='--admin_override'):
        mutate_access_identity(
            scope,
            vm_name=vm_name,
            selector='bob',
            action='remove',
        )

    report = mutate_access_identity(
        scope,
        vm_name=vm_name,
        selector='bob',
        action='remove',
        administrative_override=True,
    )
    assert report.changed is True
    loaded = load_store(scope.store_path)
    assert find_principal(
        loaded, vm_name=vm_name, principal_id='principal-bob'
    ) is None
    assert find_principal(
        loaded, vm_name=vm_name, principal_id='principal-alice'
    ) is not None


def test_last_active_identity_requires_explicit_override(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    reg = load_store(scope.store_path)
    reg.principals = [
        item for item in reg.principals if item.id == 'principal-alice'
    ]
    save_scope_store(scope, reg, reason='leave one access identity')
    monkeypatch.setattr('aivm.access_control.getpass.getuser', lambda: 'alice')

    with pytest.raises(AIVMError, match='last active access identity'):
        mutate_access_identity(
            scope,
            vm_name=vm_name,
            action='disable',
            dry_run=True,
        )

    report = mutate_access_identity(
        scope,
        vm_name=vm_name,
        action='disable',
        allow_last_access=True,
        dry_run=True,
    )
    assert report.changed is True


def test_repeated_disable_is_idempotent_without_guest_transport(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from dataclasses import replace

    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    reg = load_store(scope.store_path)
    alice = find_principal(
        reg, vm_name=vm_name, principal_id='principal-alice'
    )
    assert alice is not None
    upsert_principal(reg, replace(alice, state='disabled'))
    save_scope_store(scope, reg, reason='pre-disable alice')
    monkeypatch.setattr('aivm.access_control.getpass.getuser', lambda: 'alice')
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError('already-disabled identity must not contact guest')
        ),
    )

    report = mutate_access_identity(
        scope,
        vm_name=vm_name,
        action='disable',
    )

    assert report.changed is False
    loaded = load_store(scope.store_path)
    current = find_principal(
        loaded, vm_name=vm_name, principal_id='principal-alice'
    )
    assert current is not None
    assert current.state == 'disabled'


def test_disable_guest_transport_uses_restricted_bootstrap_protocol(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    from aivm.access_control import _disable_guest_key

    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    reg = load_store(scope.store_path)
    principal = find_principal(
        reg, vm_name=vm_name, principal_id='principal-alice'
    )
    assert principal is not None
    captured: dict[str, object] = {}

    class FakeManager:
        def run(self, cmd: list[str], **kwargs: object) -> object:
            captured['cmd'] = cmd
            captured.update(kwargs)
            return SimpleNamespace(code=0, stdout='', stderr='')

    identity_dir = tmp_path / 'bootstrap'
    identity_dir.mkdir()
    private = identity_dir / 'id_ed25519'
    known_hosts = identity_dir / 'known_hosts'
    private.write_text('PRIVATE\n', encoding='utf-8')
    known_hosts.write_text('', encoding='utf-8')
    monkeypatch.setattr(
        'aivm.enrollment.require_bootstrap_identity',
        lambda *args, **kwargs: SimpleNamespace(
            private_key=private,
            known_hosts=known_hosts,
            use_sudo=False,
        ),
    )
    monkeypatch.setattr(
        'aivm.access_control._resolve_ip', lambda cfg, override: '10.0.0.11'
    )
    monkeypatch.setattr(
        'aivm.access_control.CommandManager.current', lambda: FakeManager()
    )

    ip = _disable_guest_key(
        scope,
        principal,
        reg=reg,
        ip_override='',
    )

    assert ip == '10.0.0.11'
    cmd = captured['cmd']
    assert isinstance(cmd, list)
    assert cmd[-2:] == ['aivm-bootstrap@10.0.0.11', 'disable-principal']
    payload = str(captured['input_text'])
    assert '"operation": "disable-principal"' in payload
    assert principal.ssh_public_key in payload
    assert captured['sudo'] is False
