"""Operational lifecycle coverage for shared-machine access identities."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from aivm.access_control import mutate_access_identity, repair_current_host_identity
from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    PrincipalEntry,
    Store,
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
from aivm.host_identity import HostIdentity
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
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )
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
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )
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
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )
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
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )

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


def test_repeated_disable_reconciles_guest_transport(
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
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )
    calls: list[str] = []
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: calls.append('disable') or '10.0.0.11',
    )

    report = mutate_access_identity(
        scope,
        vm_name=vm_name,
        action='disable',
    )

    assert report.changed is False
    assert calls == ['disable']
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


def test_simultaneous_disables_cannot_remove_last_access(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """The second serialized disable observes the first one's committed state."""
    import threading

    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    identities = {
        'disable-alice': HostIdentity(1001, 1001, 'alice'),
        'disable-bob': HostIdentity(1002, 1002, 'bob'),
    }
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: identities[threading.current_thread().name],
    )
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: '10.0.0.11',
    )
    start = threading.Barrier(3)
    outcomes: list[tuple[str, str]] = []

    def worker(selector: str) -> None:
        start.wait()
        try:
            mutate_access_identity(
                scope, vm_name=vm_name, selector=selector, action='disable'
            )
        except AIVMError as ex:
            outcomes.append((selector, str(ex)))
        else:
            outcomes.append((selector, 'ok'))

    threads = [
        threading.Thread(
            target=worker, args=('alice',), name='disable-alice'
        ),
        threading.Thread(target=worker, args=('bob',), name='disable-bob'),
    ]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert sorted(value for _, value in outcomes).count('ok') == 1
    assert sum('last active access identity' in value for _, value in outcomes) == 1
    loaded = load_store(scope.store_path)
    active = [p for p in loaded.principals if p.state == 'active']
    disabled = [p for p in loaded.principals if p.state == 'disabled']
    assert len(active) == 1
    assert len(disabled) == 1


def test_disable_retry_repairs_crash_after_guest_revocation(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=1001, username='alice'),
    )
    guest_calls: list[str] = []
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: guest_calls.append('disable') or '10.0.0.11',
    )
    from aivm import access_control as module

    real_save = module.save_scope_store
    failures = 1

    def fail_once(
        save_scope: StoreScope, save_reg: Store, *, reason: str
    ) -> None:
        nonlocal failures
        if failures:
            failures -= 1
            raise OSError('simulated store persistence interruption')
        real_save(save_scope, save_reg, reason=reason)

    monkeypatch.setattr(module, 'save_scope_store', fail_once)
    with pytest.raises(OSError, match='interruption'):
        mutate_access_identity(scope, vm_name=vm_name, action='disable')

    current = find_principal(
        load_store(scope.store_path),
        vm_name=vm_name,
        principal_id='principal-alice',
    )
    assert current is not None and current.state == 'active'

    report = mutate_access_identity(scope, vm_name=vm_name, action='disable')
    assert report.principal.state == 'disabled'
    assert guest_calls == ['disable', 'disable']


def test_host_account_rename_repair_preserves_stable_identity_and_ownership(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path, with_owned_records=True)
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=1001, gid=2001, username='alice-renamed'),
    )

    report = repair_current_host_identity(scope, vm_name=vm_name)

    assert report.changed is True
    assert report.previous_host_user == 'alice'
    assert report.principal.id == 'principal-alice'
    assert report.principal.host_user == 'alice-renamed'
    assert report.principal.host_uid == 1001
    assert report.principal.host_gid == 2001
    loaded = load_store(scope.store_path)
    repaired = find_principal(
        loaded, vm_name=vm_name, principal_id='principal-alice'
    )
    assert repaired == report.principal
    assert loaded.attachments[0].owner_principal_id == 'principal-alice'
    assert loaded.credentials[0].principal_id == 'principal-alice'


def test_host_identity_repair_refuses_account_recreation_or_uid_reuse(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    scope, vm_name = _machine_scope(tmp_path, with_owned_records=False)
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(uid=9001, gid=9001, username='alice'),
    )

    with pytest.raises(AIVMError, match='account recreation or UID reuse'):
        repair_current_host_identity(scope, vm_name=vm_name)
