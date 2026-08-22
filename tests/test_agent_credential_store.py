"""Config-store coverage for the independent ssh-agent credential collection."""

from __future__ import annotations

from aivm.config import AgentVMConfig
from aivm.config_store.models import (
    AgentCredentialEntry,
    CredentialEntry,
    Store,
    VMEntry,
)
from aivm.config_store.mutate import remove_vm
from aivm.config_store.parse import parse_store_toml
from aivm.config_store.render import render_store_toml
from aivm.credentials.agent_schema import agent_credential_id
from aivm.credentials.models import GitRepository
from aivm.credentials.schema import CREDENTIAL_KIND_GITHUB_DEPLOY_KEY
from aivm.credentials.validation import credential_id


def _store_with_both_credential_systems() -> Store:
    vm_name = 'vm-a'
    principal = 'principal-a'
    repo = GitRepository('github.com', 'Kitware', 'alpha')
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    guest = CredentialEntry(
        id=credential_id(vm_name, repo.canonical, principal),
        vm_name=vm_name,
        principal_id=principal,
        kind=CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access='read',
        provider_key_id='101',
        provider_key_title='guest-key',
        key_fingerprint='SHA256:Z3Vlc3Q',
        state='active',
    )
    agent = AgentCredentialEntry(
        id=agent_credential_id(vm_name, repo.canonical, principal),
        vm_name=vm_name,
        principal_id=principal,
        kind=CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access='write',
        provider_key_id='202',
        provider_key_title='ssh-agent-key',
        key_fingerprint='SHA256:YWdlbnQ',
        state='active',
    )
    return Store(
        schema_version=12,
        store_kind='machine',
        vms=[VMEntry(name=vm_name, network_name='aivm-net', cfg=cfg)],
        credentials=[guest],
        agent_credentials=[agent],
    )


def test_agent_credentials_round_trip_as_sibling_collection() -> None:
    store = _store_with_both_credential_systems()
    text = render_store_toml(store, attachment_style='nested')
    assert '[[vms.credentials]]' in text
    assert '[[vms.agent_credentials]]' in text
    parsed = parse_store_toml(text)
    assert parsed.schema_version == 12
    assert parsed.credentials == store.credentials
    assert parsed.agent_credentials == store.agent_credentials
    assert parsed.credentials[0].id.startswith('git-')
    assert parsed.agent_credentials[0].id.startswith('agent-git-')


def test_remove_vm_removes_both_independent_metadata_collections() -> None:
    store = _store_with_both_credential_systems()
    assert remove_vm(store, 'vm-a')
    assert store.credentials == []
    assert store.agent_credentials == []
