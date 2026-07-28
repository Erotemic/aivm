"""Synthetic onboarding coverage for ``aivm config init`` create-or-join."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import NoReturn

import pytest

from aivm.cli.config.init import initialize_config_defaults
from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    find_principal_for_host,
    load_store,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.enrollment import EnrollmentReport
from aivm.errors import AIVMError
from aivm.profile_store import (
    UserProfileStore,
    load_user_profile,
    save_user_profile,
)
from aivm.scoped_store import (
    StoreScope,
    load_scope_store,
    resolve_store_scope,
    save_scope_store,
)

VM_NAME = 'aivm-2404-shared-host'
BOB_KEY = 'ssh-ed25519 AAAABOB bob@test'


def _managed_machine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    principal: PrincipalEntry | None = None,
) -> StoreScope:
    """Write one managed VM and Bob's private profile into isolated stores."""
    monkeypatch.setattr(
        'aivm.cli.config.init.default_vm_name', lambda: VM_NAME
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.domain_is_defined', lambda name: False
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.getpass.getuser', lambda: 'bob'
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.hydrate_ssh_identity_defaults',
        lambda cfg: False,
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.maybe_offer_create_ssh_identity',
        lambda *args, **kwargs: False,
    )

    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    cfg.vm.name = VM_NAME
    cfg.vm.user = 'creator-agent'
    cfg.vm.cpus = 12
    cfg.vm.ram_mb = 24576
    cfg.vm.disk_gb = 160
    cfg.paths.base_dir = str(tmp_path / 'machine-disks')
    reg = load_scope_store(scope)
    reg.defaults = deepcopy(cfg)
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    if principal is not None:
        upsert_principal(reg, principal)
    save_scope_store(scope, reg, reason='write managed join fixture')

    ssh_dir = tmp_path / 'bob-home' / '.ssh'
    ssh_dir.mkdir(parents=True)
    private = ssh_dir / 'id_aivm_ed25519'
    public = ssh_dir / 'id_aivm_ed25519.pub'
    private.write_text('PRIVATE\n', encoding='utf-8')
    public.write_text(BOB_KEY + '\n', encoding='utf-8')
    assert scope.profile_path is not None
    save_user_profile(
        UserProfileStore(
            ssh_identity_file=str(private),
            ssh_pubkey_path=str(public),
            state_dir=str(tmp_path / 'bob-state'),
        ),
        scope.profile_path,
    )
    return scope


def _fail_auto_defaults(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise AssertionError('join path must not generate machine defaults')


def _activate_bob(
    scope: StoreScope,
    *,
    vm_name: str,
    guest_user: str,
) -> EnrollmentReport:
    """Synthetic enrollment transport that mutates only Bob's principal."""
    reg = load_scope_store(scope)
    principal = PrincipalEntry(
        id='principal-bob',
        vm_name=vm_name,
        host_user='bob',
        host_uid=1201,
        host_gid=1202,
        guest_user=guest_user,
        ssh_public_key=BOB_KEY,
        state='active',
    )
    upsert_principal(reg, principal)
    save_scope_store(scope, reg, reason='activate synthetic Bob')
    return EnrollmentReport(
        principal=principal,
        ip='10.77.0.119',
        changed=True,
    )


def test_config_init_joins_exact_managed_machine_without_machine_rewrite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scope = _managed_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.reconcile_current_principal', _activate_bob
    )
    before = load_scope_store(scope)
    before_defaults = deepcopy(before.defaults)
    before_networks = deepcopy(before.networks)
    before_vms = deepcopy(before.vms)

    rc = initialize_config_defaults(
        config_opt=None,
        yes=True,
        defaults=False,
        force=False,
        standalone_guidance=True,
    )

    assert rc == 0
    after = load_scope_store(scope)
    assert after.defaults == before_defaults
    assert after.networks == before_networks
    assert after.vms == before_vms
    bob = find_principal_for_host(after, vm_name=VM_NAME, host_user='bob')
    assert bob is not None
    assert bob.guest_user == 'bob-agent'
    assert bob.state == 'active'
    assert scope.profile_path is not None
    profile = load_user_profile(scope.profile_path)
    assert profile.active_vm == VM_NAME
    assert profile.default_guest_user == 'bob-agent'
    output = capsys.readouterr().out
    assert 'Existing managed machine found' in output
    assert 'Joined managed machine: bob -> bob-agent (active)' in output
    assert 'No VM created' not in output


def test_config_init_repeat_is_idempotent_and_skips_enrollment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = PrincipalEntry(
        id='principal-bob',
        vm_name=VM_NAME,
        host_user='bob',
        host_uid=1201,
        host_gid=1202,
        guest_user='bob-agent',
        ssh_public_key=BOB_KEY,
        state='active',
    )
    scope = _managed_machine(monkeypatch, tmp_path, principal=existing)
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )

    def unexpected_reconcile(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise AssertionError('active matching principal must not be reconciled')

    monkeypatch.setattr(
        'aivm.cli.config.init.reconcile_current_principal',
        unexpected_reconcile,
    )

    rc = initialize_config_defaults(
        config_opt=None,
        yes=False,
        defaults=False,
        force=True,
        standalone_guidance=True,
    )

    assert rc == 0
    after = load_scope_store(scope)
    assert [p.id for p in after.principals] == ['principal-bob']
    assert scope.profile_path is not None
    assert load_user_profile(scope.profile_path).active_vm == VM_NAME
    output = capsys.readouterr().out
    assert 'Already enrolled and active' in output
    assert '--force does not overwrite machine configuration' in output


def test_config_init_records_pending_join_for_stopped_vm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scope = _managed_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )

    def pending_reconcile(
        scope: StoreScope,
        *,
        vm_name: str,
        guest_user: str,
    ) -> NoReturn:
        reg = load_scope_store(scope)
        upsert_principal(
            reg,
            PrincipalEntry(
                id='principal-bob',
                vm_name=vm_name,
                host_user='bob',
                host_uid=1201,
                host_gid=1202,
                guest_user=guest_user,
                ssh_public_key=BOB_KEY,
                state='pending',
            ),
        )
        save_scope_store(scope, reg, reason='record synthetic pending Bob')
        raise AIVMError('VM is not reachable')

    monkeypatch.setattr(
        'aivm.cli.config.init.reconcile_current_principal',
        pending_reconcile,
    )

    rc = initialize_config_defaults(
        config_opt=None,
        yes=True,
        defaults=False,
        force=False,
        standalone_guidance=True,
    )

    assert rc == 0
    assert scope.profile_path is not None
    assert load_user_profile(scope.profile_path).active_vm == VM_NAME
    pending = find_principal_for_host(
        load_store(scope.store_path), vm_name=VM_NAME, host_user='bob'
    )
    assert pending is not None and pending.state == 'pending'
    captured = capsys.readouterr()
    assert 'Enrollment is pending' in captured.err
    assert 'aivm vm access reconcile' in captured.out
    assert 'Joined managed machine' not in captured.out


def test_config_init_failed_verification_does_not_select_machine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scope = _managed_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )

    def failed_reconcile(
        scope: StoreScope,
        *,
        vm_name: str,
        guest_user: str,
    ) -> NoReturn:
        reg = load_scope_store(scope)
        upsert_principal(
            reg,
            PrincipalEntry(
                id='principal-bob',
                vm_name=vm_name,
                host_user='bob',
                host_uid=1201,
                host_gid=1202,
                guest_user=guest_user,
                ssh_public_key=BOB_KEY,
                state='error',
            ),
        )
        save_scope_store(scope, reg, reason='record synthetic failed Bob')
        raise AIVMError('personal SSH verification failed')

    monkeypatch.setattr(
        'aivm.cli.config.init.reconcile_current_principal', failed_reconcile
    )

    with pytest.raises(AIVMError, match='verification failed'):
        initialize_config_defaults(
            config_opt=None,
            yes=True,
            defaults=False,
            force=False,
            standalone_guidance=True,
        )

    assert scope.profile_path is not None
    assert load_user_profile(scope.profile_path).active_vm == ''
    failed = find_principal_for_host(
        load_scope_store(scope), vm_name=VM_NAME, host_user='bob'
    )
    assert failed is not None and failed.state == 'error'


def test_config_init_refuses_unmanaged_hostname_collision_even_with_yes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        'aivm.cli.config.init.default_vm_name', lambda: VM_NAME
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.domain_is_defined', lambda name: True
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )

    with pytest.raises(AIVMError, match='Refusing to adopt'):
        initialize_config_defaults(
            config_opt=None,
            yes=True,
            defaults=True,
            force=True,
            standalone_guidance=True,
        )


def test_config_init_join_requires_confirmation_noninteractive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _managed_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(
        'aivm.cli.config.init.auto_defaults', _fail_auto_defaults
    )
    monkeypatch.setattr(
        'aivm.cli.config.init.sys.stdin.isatty', lambda: False
    )

    with pytest.raises(AIVMError, match='requires confirmation'):
        initialize_config_defaults(
            config_opt=None,
            yes=False,
            defaults=False,
            force=False,
            standalone_guidance=True,
        )
