"""Credential frontend/backend selection and preference resolution."""

from __future__ import annotations

from pathlib import Path

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
