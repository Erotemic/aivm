"""Credential frontend/backend selection and preference resolution."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    load_store,
    save_store,
    set_vm_credential_backend,
    upsert_vm,
)
from aivm.credential_backends import (
    DEFAULT_CREDENTIAL_BACKEND,
    resolve_credential_backend,
)
from aivm.errors import AIVMError
from aivm.profile_store import (
    PROFILE_SCHEMA_VERSION,
    UserProfileStore,
    parse_user_profile,
    render_user_profile,
)


def test_backend_resolution_precedence() -> None:
    assert DEFAULT_CREDENTIAL_BACKEND == 'guest-key'
    assert resolve_credential_backend().backend == 'guest-key'
    assert resolve_credential_backend().source == 'fallback'

    user = resolve_credential_backend(user_preference='ssh-agent')
    assert (user.backend, user.source) == ('ssh-agent', 'user')

    vm = resolve_credential_backend(
        vm_preference='guest-key', user_preference='ssh-agent'
    )
    assert (vm.backend, vm.source) == ('guest-key', 'vm')

    explicit = resolve_credential_backend(
        'ssh-agent',
        vm_preference='guest-key',
        user_preference='guest-key',
    )
    assert (explicit.backend, explicit.source) == ('ssh-agent', 'explicit')


def test_backend_names_reject_agent_shorthand() -> None:
    with pytest.raises(AIVMError, match='ssh-agent'):
        resolve_credential_backend('agent')


def test_user_profile_backend_roundtrip_and_schema_upgrade() -> None:
    old = parse_user_profile('schema_version = 1\nactive_vm = "vm-a"\n')
    assert old.schema_version == PROFILE_SCHEMA_VERSION
    assert old.credential_backend == 'auto'

    old.credential_backend = 'ssh-agent'
    rendered = render_user_profile(old)
    assert f'schema_version = {PROFILE_SCHEMA_VERSION}' in rendered
    assert 'credential_backend = "ssh-agent"' in rendered
    assert parse_user_profile(rendered).credential_backend == 'ssh-agent'


def test_vm_backend_preference_roundtrip_raises_machine_schema(tmp_path: Path) -> None:
    path = tmp_path / 'config.toml'
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.vm.credential_backend = 'ssh-agent'
    store = Store(store_kind='machine', schema_version=13)
    upsert_vm(store, cfg)
    assert store.schema_version == 14
    save_store(store, path)

    loaded = load_store(path)
    assert loaded.schema_version == 14
    assert loaded.vms[0].cfg.vm.credential_backend == 'ssh-agent'


def test_vm_backend_preference_mutator_supports_clear_to_auto() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    store = Store(store_kind='machine', schema_version=13)
    upsert_vm(store, cfg)

    assert set_vm_credential_backend(store, 'vm-a', 'ssh-agent') == 'ssh-agent'
    assert store.vms[0].cfg.vm.credential_backend == 'ssh-agent'
    assert store.schema_version == 14

    assert set_vm_credential_backend(store, 'vm-a', 'auto') == 'auto'
    assert store.vms[0].cfg.vm.credential_backend == 'auto'
    assert store.schema_version == 14


def _mixed_store() -> Store:
    from aivm.config_store import AgentCredentialEntry, CredentialEntry

    return Store(
        credentials=[
            CredentialEntry(
                id='git-guest-example',
                vm_name='vm-a',
                principal_id='principal-a',
                provider_host='github.com',
                owner='Example',
                repository='repo',
                access='write',
                key_fingerprint='SHA256:guest',
                state='active',
            )
        ],
        agent_credentials=[
            AgentCredentialEntry(
                id='agent-git-ssh-example',
                vm_name='vm-a',
                principal_id='principal-a',
                provider_host='github.com',
                owner='Example',
                repository='repo',
                access='write',
                key_fingerprint='SHA256:ssh-agent',
                state='active',
            )
        ],
    )


def test_unified_selector_resolves_exact_ids_across_backends() -> None:
    from aivm.cli.vm_creds import _resolve_existing_credential
    from aivm.commands import CommandManager

    store = _mixed_store()
    manager = CommandManager(yes=True)
    guest = _resolve_existing_credential(
        store,
        vm_name='vm-a',
        selector='git-guest-example',
        remote='origin',
        manager=manager,
        principal_id='principal-a',
    )
    ssh_agent = _resolve_existing_credential(
        store,
        vm_name='vm-a',
        selector='agent-git-ssh-example',
        remote='origin',
        manager=manager,
        principal_id='principal-a',
    )
    assert guest.backend == 'guest-key'
    assert ssh_agent.backend == 'ssh-agent'


def test_unified_selector_requires_disambiguation_for_same_repo() -> None:
    from aivm.cli.vm_creds import _resolve_existing_credential
    from aivm.commands import CommandManager

    store = _mixed_store()
    manager = CommandManager(yes=True)
    with pytest.raises(AIVMError, match='Multiple credentials match'):
        _resolve_existing_credential(
            store,
            vm_name='vm-a',
            selector='Example/repo',
            remote='origin',
            manager=manager,
            principal_id='principal-a',
        )
    selected = _resolve_existing_credential(
        store,
        vm_name='vm-a',
        selector='Example/repo',
        remote='origin',
        manager=manager,
        principal_id='principal-a',
        backend='ssh-agent',
    )
    assert selected.backend == 'ssh-agent'


def test_bulk_revoke_repo_selects_all_matching_backends() -> None:
    from aivm.cli.vm_creds import _bulk_revoke_matches
    from aivm.commands import CommandManager

    rows = _bulk_revoke_matches(
        _mixed_store(),
        vm_name='vm-a',
        principal_id='principal-a',
        selector='Example/repo',
        remote='origin',
        backend='auto',
        manager=CommandManager(yes=True),
    )
    assert [(row.backend, row.entry.id) for row in rows] == [
        ('guest-key', 'git-guest-example'),
        ('ssh-agent', 'agent-git-ssh-example'),
    ]

    ssh_only = _bulk_revoke_matches(
        _mixed_store(),
        vm_name='vm-a',
        principal_id='principal-a',
        selector='Example/repo',
        remote='origin',
        backend='ssh-agent',
        manager=CommandManager(yes=True),
    )
    assert [(row.backend, row.entry.id) for row in ssh_only] == [
        ('ssh-agent', 'agent-git-ssh-example')
    ]


def test_bulk_revoke_without_selector_is_principal_and_vm_scoped() -> None:
    from aivm.cli.vm_creds import _bulk_revoke_matches
    from aivm.commands import CommandManager
    from aivm.config_store import AgentCredentialEntry, CredentialEntry

    store = _mixed_store()
    store.credentials.extend(
        [
            CredentialEntry(
                id='git-other-repo',
                vm_name='vm-a',
                principal_id='principal-a',
                provider_host='github.com',
                owner='Example',
                repository='other',
                access='read',
                key_fingerprint='SHA256:other',
                state='active',
            ),
            CredentialEntry(
                id='git-other-principal',
                vm_name='vm-a',
                principal_id='principal-b',
                provider_host='github.com',
                owner='Example',
                repository='foreign',
                access='read',
                key_fingerprint='SHA256:foreign',
                state='active',
            ),
            CredentialEntry(
                id='git-other-vm',
                vm_name='vm-b',
                principal_id='principal-a',
                provider_host='github.com',
                owner='Example',
                repository='vm-b',
                access='read',
                key_fingerprint='SHA256:vm-b',
                state='active',
            ),
        ]
    )
    store.agent_credentials.append(
        AgentCredentialEntry(
            id='agent-git-other-principal',
            vm_name='vm-a',
            principal_id='principal-b',
            provider_host='github.com',
            owner='Example',
            repository='foreign-agent',
            access='read',
            key_fingerprint='SHA256:foreign-agent',
            state='active',
        )
    )

    rows = _bulk_revoke_matches(
        store,
        vm_name='vm-a',
        principal_id='principal-a',
        selector='',
        remote='origin',
        backend='auto',
        manager=CommandManager(yes=True),
    )
    assert {row.entry.id for row in rows} == {
        'git-guest-example',
        'git-other-repo',
        'agent-git-ssh-example',
    }


def test_bulk_revoke_rejects_exact_id_as_all_selector() -> None:
    from aivm.cli.vm_creds import _bulk_revoke_matches
    from aivm.commands import CommandManager

    with pytest.raises(AIVMError, match='selector names a repository'):
        _bulk_revoke_matches(
            _mixed_store(),
            vm_name='vm-a',
            principal_id='principal-a',
            selector='agent-git-ssh-example',
            remote='origin',
            backend='auto',
            manager=CommandManager(yes=True),
        )


def test_revoke_cli_all_flag_parses() -> None:
    from aivm.cli.vm_creds import VMCredsRevokeCLI

    args = VMCredsRevokeCLI.cli(argv=['--all', '--dry_run'])
    assert args.all is True
    assert args.selector == ''
    assert args.dry_run is True


def test_bulk_revoke_continues_after_domain_failure(monkeypatch, capsys) -> None:
    from aivm.cli import vm_creds

    store = _mixed_store()
    rows = [
        vm_creds._SelectedCredential('guest-key', store.credentials[0]),
        vm_creds._SelectedCredential('ssh-agent', store.agent_credentials[0]),
    ]
    context = SimpleNamespace(
        effective_cfg=SimpleNamespace(vm=SimpleNamespace(name='vm-a'))
    )
    attempted: list[str] = []

    monkeypatch.setattr(
        vm_creds,
        '_load_credential_context',
        lambda *args, **kwargs: (context, store, Path('/config.toml'), 'principal-a'),
    )
    monkeypatch.setattr(vm_creds, '_bulk_revoke_matches', lambda *args, **kwargs: rows)

    def fake_revoke(*, selected, **kwargs):
        attempted.append(selected.entry.id)
        if selected.backend == 'guest-key':
            raise AIVMError('provider unavailable')

    monkeypatch.setattr(vm_creds, '_revoke_selected_credential', fake_revoke)

    with pytest.raises(AIVMError, match='Bulk revoke completed with 1 failure'):
        vm_creds.VMCredsRevokeCLI.main(argv=False, all=True)

    assert attempted == ['git-guest-example', 'agent-git-ssh-example']
    output = capsys.readouterr().out
    assert 'Could not fully revoke credential git-guest-example' in output
    assert 'Revoked credential agent-git-ssh-example' in output


def test_preference_cli_sets_vm_scope_and_reports_effective(monkeypatch, capsys) -> None:
    from types import SimpleNamespace

    from aivm.cli import vm_creds

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    store = Store(store_kind='machine', schema_version=14)
    upsert_vm(store, cfg)
    context = SimpleNamespace(
        effective_cfg=SimpleNamespace(vm=SimpleNamespace(name='vm-a')),
        machine=SimpleNamespace(
            vm=SimpleNamespace(credential_backend='auto')
        ),
        profile=SimpleNamespace(credential_backend='ssh-agent'),
    )
    scope = SimpleNamespace(is_machine=True, profile_path=Path('/profile.toml'))
    saved: list[tuple[str, str]] = []

    monkeypatch.setattr(
        vm_creds,
        '_load_credential_context',
        lambda *args, **kwargs: (context, store, Path('/machine/config.toml'), 'p'),
    )
    monkeypatch.setattr(vm_creds, 'resolve_store_scope', lambda *_args: scope)
    monkeypatch.setattr(
        vm_creds,
        'save_scope_store',
        lambda _scope, _store, *, reason: saved.append((_scope.__class__.__name__, reason)),
    )

    assert vm_creds.VMCredsPreferenceCLI.main(
        argv=False, backend='guest-key', scope='vm'
    ) == 0
    assert store.vms[0].cfg.vm.credential_backend == 'guest-key'
    assert saved
    output = capsys.readouterr().out
    assert 'VM scope:  guest-key' in output
    assert 'User scope: ssh-agent' in output
    assert 'Effective: guest-key (vm)' in output


def test_preference_cli_sets_user_scope_and_auto_can_defer(monkeypatch, capsys) -> None:
    from types import SimpleNamespace

    from aivm.cli import vm_creds

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    store = Store(store_kind='machine', schema_version=14)
    upsert_vm(store, cfg)
    context = SimpleNamespace(
        effective_cfg=SimpleNamespace(vm=SimpleNamespace(name='vm-a')),
        machine=SimpleNamespace(
            vm=SimpleNamespace(credential_backend='auto')
        ),
        profile=SimpleNamespace(credential_backend='guest-key'),
    )
    profile = UserProfileStore(credential_backend='guest-key')
    scope = SimpleNamespace(is_machine=True, profile_path=Path('/profile.toml'))
    saved: list[str] = []

    monkeypatch.setattr(
        vm_creds,
        '_load_credential_context',
        lambda *args, **kwargs: (context, store, Path('/machine/config.toml'), 'p'),
    )
    monkeypatch.setattr(vm_creds, 'resolve_store_scope', lambda *_args: scope)
    monkeypatch.setattr(vm_creds, 'load_scope_profile', lambda _scope: profile)
    monkeypatch.setattr(
        vm_creds,
        'save_user_profile',
        lambda current, _path: saved.append(current.credential_backend),
    )

    assert vm_creds.VMCredsPreferenceCLI.main(
        argv=False, backend='ssh-agent', scope='user'
    ) == 0
    assert profile.credential_backend == 'ssh-agent'
    assert saved == ['ssh-agent']
    output = capsys.readouterr().out
    assert 'User scope: ssh-agent' in output
    assert 'Effective: ssh-agent (user)' in output

    saved.clear()
    assert vm_creds.VMCredsPreferenceCLI.main(
        argv=False, backend='auto', scope='user'
    ) == 0
    assert profile.credential_backend == 'auto'
    assert saved == ['auto']
    output = capsys.readouterr().out
    assert 'Effective: guest-key (fallback)' in output


def test_public_vm_cli_exposes_one_credentials_frontend() -> None:
    from aivm.cli.vm import VMModalCLI
    from aivm.cli.vm_creds import VMCredsModalCLI

    assert VMModalCLI.creds is VMCredsModalCLI
    assert not hasattr(VMModalCLI, 'agent_creds')
    assert VMCredsModalCLI.preference is not None
    assert VMCredsModalCLI.doctor is not None
