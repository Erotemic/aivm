"""Machine-impact summaries for shared and legacy stores."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    PrincipalEntry,
    Store,
    save_store,
    upsert_attachment,
    upsert_credential,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from aivm.credentials.validation import credential_id
from aivm.operational_scope import (
    announce_vm_machine_impact,
    network_machine_impact,
    vm_machine_impact,
)
from aivm.scoped_store import resolve_store_scope, save_scope_store


def _machine_inventory(tmp_path: Path) -> tuple[Path, str, str]:
    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404-shared-host'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    reg = Store(schema_version=11, store_kind='machine')
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    for host_user in ('alice', 'bob'):
        principal_id = f'principal-{host_user}'
        upsert_principal(
            reg,
            PrincipalEntry(
                id=principal_id,
                vm_name=cfg.vm.name,
                host_user=host_user,
                host_uid=1001 if host_user == 'alice' else 1002,
                host_gid=1001 if host_user == 'alice' else 1002,
                guest_user=f'{host_user}-agent',
                state='active',
            ),
        )
    upsert_attachment(
        reg,
        host_path=tmp_path / 'project',
        vm_name=cfg.vm.name,
        owner_principal_id='principal-alice',
        guest_dst='/work/project',
        tag='project',
    )
    upsert_credential(
        reg,
        CredentialEntry(
            id=credential_id(
                cfg.vm.name,
                'github.com/kitware/kwimage',
                'principal-bob',
            ),
            vm_name=cfg.vm.name,
            principal_id='principal-bob',
            owner='Kitware',
            repository='kwimage',
            provider_key_title='test',
            key_fingerprint='SHA256:test',
            state='active',
        ),
    )
    save_scope_store(scope, reg, reason='test machine impact')
    return scope.store_path, cfg.vm.name, cfg.network.name


def test_vm_and_network_machine_impact_counts_inventory(tmp_path: Path) -> None:
    store_path, vm_name, network_name = _machine_inventory(tmp_path)

    vm_impact = vm_machine_impact(store_path, vm_name)
    assert vm_impact is not None
    assert vm_impact.vm_count == 1
    assert vm_impact.identity_count == 2
    assert vm_impact.attachment_count == 1
    assert vm_impact.credential_count == 1

    network_impact = network_machine_impact(store_path, network_name)
    assert network_impact == vm_impact


def test_machine_impact_output_names_trust_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store_path, vm_name, _ = _machine_inventory(tmp_path)

    announce_vm_machine_impact(store_path, vm_name, action='restart')

    output = capsys.readouterr().out
    assert "Machine-wide action: restart VM 'aivm-2404-shared-host'" in output
    assert '2 access identity record(s)' in output
    assert 'trust_mode=trusted-host-users' in output


def test_legacy_store_has_no_machine_impact_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / 'legacy.toml'
    save_store(Store(), path, reason='test legacy impact')

    assert vm_machine_impact(path, 'legacy-vm') is None
    announce_vm_machine_impact(path, 'legacy-vm', action='restart')
    assert capsys.readouterr().out == ''
