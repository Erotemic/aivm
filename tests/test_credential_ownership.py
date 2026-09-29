"""Principal-scoped repository credential tests for shared machines."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aivm.cli.vm_creds import VMCredsListCLI, VMCredsStatusCLI
from aivm.commands import CommandManager, CommandResult
from aivm.config import AgentVMConfig
from aivm.config_scopes import ResolvedVMContext, resolve_persisted_vm_context
from aivm.config_store import (
    CredentialEntry,
    PrincipalEntry,
    Store,
    find_credentials_for_vm,
    load_store,
    remove_principal,
    save_store_split,
    upsert_credential,
    upsert_principal,
    upsert_vm,
)
from aivm.credentials.models import GitRepository
from aivm.credentials.ownership import require_credential_owner
from aivm.credentials.service import _install_and_activate, select_credential
from aivm.credentials.validation import credential_id
from aivm.errors import AIVMError
from aivm.profile_store import UserProfileStore


def _principal(
    vm_name: str, host_user: str, principal_id: str
) -> PrincipalEntry:
    host_id = 1001 if host_user == 'alice' else 1002
    return PrincipalEntry(
        id=principal_id,
        vm_name=vm_name,
        host_user=host_user,
        host_uid=host_id,
        host_gid=host_id,
        guest_user=f'{host_user}-agent',
        state='active',
    )


def _machine_store(vm_name: str = 'vm-shared') -> Store:
    reg = Store(store_kind='machine', schema_version=11)
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    upsert_vm(reg, cfg)
    upsert_principal(reg, _principal(vm_name, 'alice', 'principal-alice'))
    upsert_principal(reg, _principal(vm_name, 'bob', 'principal-bob'))
    return reg


def _credential(
    *,
    vm_name: str = 'vm-shared',
    principal_id: str,
    repository: str = 'kwimage',
) -> CredentialEntry:
    repo = GitRepository('github.com', 'Kitware', repository)
    cred_id = credential_id(vm_name, repo.canonical, principal_id)
    return CredentialEntry(
        id=cred_id,
        vm_name=vm_name,
        principal_id=principal_id,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access='read',
        provider_key_id='1001' if principal_id.endswith('alice') else '1002',
        provider_key_title=f'aivm:test:{vm_name}:{repo.owner}/{repo.name}:{cred_id}',
        key_fingerprint=(
            'SHA256:YWxpY2U'
            if principal_id.endswith('alice')
            else 'SHA256:Ym9i'
        ),
        state='active',
    )


def _context_for(
    cfg: AgentVMConfig,
    principal: PrincipalEntry,
    tmp_path: Path,
) -> ResolvedVMContext:
    profile = UserProfileStore(
        active_vm=cfg.vm.name,
        ssh_identity_file=str(tmp_path / principal.host_user / 'id_aivm'),
        ssh_pubkey_path=str(tmp_path / principal.host_user / 'id_aivm.pub'),
        state_dir=str(tmp_path / principal.host_user / 'state'),
        default_guest_user=principal.guest_user,
    )
    return resolve_persisted_vm_context(
        cfg,
        principal_entry=principal,
        profile_store=profile,
    )


def test_two_principals_can_credential_the_same_repository(
    tmp_path: Path,
) -> None:
    reg = _machine_store()
    alice = _credential(principal_id='principal-alice')
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, alice)
    upsert_credential(reg, bob)

    assert alice.id != bob.id
    assert reg.schema_version == 11
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    loaded = load_store(path)

    assert find_credentials_for_vm(
        loaded, 'vm-shared', principal_id='principal-alice'
    ) == [alice]
    assert find_credentials_for_vm(
        loaded, 'vm-shared', principal_id='principal-bob'
    ) == [bob]


def test_machine_credentials_require_a_valid_principal(tmp_path: Path) -> None:
    missing_owner = _machine_store()
    upsert_credential(
        missing_owner,
        replace(_credential(principal_id='principal-alice'), principal_id=''),
    )
    with pytest.raises(ValueError, match='missing principal_id'):
        save_store_split(missing_owner, tmp_path / 'missing.toml')

    dangling_owner = _machine_store()
    upsert_credential(
        dangling_owner,
        replace(
            _credential(principal_id='principal-alice'),
            principal_id='principal-carol',
        ),
    )
    with pytest.raises(ValueError, match='unknown principals'):
        save_store_split(dangling_owner, tmp_path / 'dangling.toml')


def test_disabled_principal_preserves_provider_metadata(tmp_path: Path) -> None:
    reg = _machine_store()
    entry = _credential(principal_id='principal-alice')
    upsert_credential(reg, entry)
    alice = next(
        item for item in reg.principals if item.id == 'principal-alice'
    )
    upsert_principal(reg, replace(alice, state='disabled'))

    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    loaded = load_store(path)
    [persisted] = find_credentials_for_vm(
        loaded, 'vm-shared', principal_id='principal-alice'
    )
    assert persisted.provider_key_id == entry.provider_key_id
    assert persisted.key_fingerprint == entry.key_fingerprint

    assert remove_principal(
        loaded, vm_name='vm-shared', principal_id='principal-alice'
    )
    with pytest.raises(ValueError, match='unknown principals'):
        save_store_split(loaded, tmp_path / 'removed.toml')


def test_foreign_secret_operation_is_rejected() -> None:
    reg = _machine_store()
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, bob)

    with pytest.raises(AIVMError, match='another VM principal'):
        require_credential_owner(
            reg,
            bob,
            current_principal_id='principal-alice',
        )


def test_repository_selector_is_principal_scoped() -> None:
    reg = _machine_store()
    repo = GitRepository('github.com', 'Kitware', 'kwimage')
    alice = _credential(principal_id='principal-alice')
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, alice)
    upsert_credential(reg, bob)

    assert (
        select_credential(
            reg,
            vm_name='vm-shared',
            selector=repo.display,
            repo=repo,
            principal_id='principal-bob',
        )
        is bob
    )
    with pytest.raises(AIVMError, match='Multiple principal credentials'):
        select_credential(
            reg,
            vm_name='vm-shared',
            selector=repo.display,
            repo=repo,
            principal_id=None,
        )


def test_guest_reconciliation_receives_only_owner_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reg = _machine_store()
    alice = _credential(principal_id='principal-alice')
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, alice)
    upsert_credential(reg, bob)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    cfg.vm.user = 'alice-agent'
    private_key = tmp_path / 'alice-private-key'
    private_key.write_text('PRIVATE-ALICE\n', encoding='utf-8')
    observed: list[list[CredentialEntry]] = []

    monkeypatch.setattr(
        'aivm.credentials.service._resolve_ip_for_ssh_ops',
        lambda *args, **kwargs: '192.0.2.20',
    )
    monkeypatch.setattr(
        'aivm.credentials.service.keys.host_private_key_path',
        lambda *args, **kwargs: private_key,
    )

    def capture_reconcile(
        *args: Any,
        credentials: list[CredentialEntry],
        **kwargs: Any,
    ) -> None:
        observed.append(list(credentials))

    monkeypatch.setattr(
        'aivm.credentials.service.reconcile_guest_credentials',
        capture_reconcile,
    )
    monkeypatch.setattr(
        'aivm.credentials.service.verify_guest_repository',
        lambda *args, **kwargs: CommandResult(0, '', ''),
    )
    monkeypatch.setattr(
        'aivm.credentials.service._save_credential_store',
        lambda *args, **kwargs: None,
    )

    _install_and_activate(
        cfg,
        reg,
        tmp_path / 'config.toml',
        alice,
        GitRepository('github.com', 'Kitware', 'kwimage'),
        principal_id='principal-alice',
        manager=CommandManager(yes=True),
    )

    assert observed == [[alice]]
    assert all(item.principal_id == 'principal-alice' for item in observed[0])


def test_cli_defaults_to_current_principal_and_supports_metadata_view(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    reg = _machine_store()
    alice = _credential(principal_id='principal-alice')
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, alice)
    upsert_credential(reg, bob)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    cfg.vm.user = 'alice-agent'
    principal = next(
        item for item in reg.principals if item.id == 'principal-alice'
    )
    context = _context_for(cfg, principal, tmp_path)
    store_path = tmp_path / 'config.toml'

    monkeypatch.setattr(
        'aivm.cli.vm_creds._load_credential_context',
        lambda *args, **kwargs: (context, reg, store_path, 'principal-alice'),
    )

    assert VMCredsListCLI.main(argv=False, all_principals=False) == 0
    current = capsys.readouterr().out
    assert alice.id in current
    assert bob.id not in current

    assert VMCredsListCLI.main(argv=False, all_principals=True) == 0
    global_view = capsys.readouterr().out
    assert alice.id in global_view
    assert bob.id in global_view
    assert 'machine-wide metadata' in global_view


def test_foreign_status_is_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    reg = _machine_store()
    bob = _credential(principal_id='principal-bob')
    upsert_credential(reg, bob)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    cfg.vm.user = 'alice-agent'
    principal = next(
        item for item in reg.principals if item.id == 'principal-alice'
    )
    context = _context_for(cfg, principal, tmp_path)

    monkeypatch.setattr(
        'aivm.cli.vm_creds._load_credential_context',
        lambda *args, **kwargs: (
            context,
            reg,
            tmp_path / 'config.toml',
            'principal-alice',
        ),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_creds.inspect_credential',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError('foreign metadata view must not inspect secrets')
        ),
    )

    assert (
        VMCredsStatusCLI.main(
            argv=False,
            selector=bob.id,
            all_principals=True,
        )
        == 0
    )
    output = capsys.readouterr().out
    assert bob.id in output
    assert 'metadata only' in output
    assert 'bob -> bob-agent' in output
