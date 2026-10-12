"""Prove the host-derived VM identity changes on replacement or owner change."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import PrincipalEntry, Store, VMEntry
from aivm.secrets_identity_vm import resolve_managed_identity
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.vm_model import subject
from aivm_secrets.identity.vm_runner import evaluate
from tests.helpers import resolved_test_context

UUID_A = '123e4567-e89b-12d3-a456-426614174000'
UUID_B = '123e4567-e89b-12d3-a456-426614174001'


def sample():
    return {'schema': 1, 'store': 'a' * 64, 'vm': 'lab',
            'domain_uuid': UUID_A, 'principal': 'principal-a',
            'host_uid': 1000, 'guest_user': 'lab-agent'}


def test_pure_subject_is_closed_and_instance_specific():
    binding = sample()
    first = subject(binding)
    assert first.startswith('vm-') and len(first) == 67
    assert evaluate(binding) == {'ok': True, 'subject': first}
    for key, changed in (
        ('store', 'b' * 64), ('vm', 'lab2'), ('domain_uuid', UUID_B),
        ('principal', 'principal-b'), ('host_uid', 1001),
        ('guest_user', 'lab-agent2'),
    ):
        assert subject(dict(binding, **{key: changed})) != first
    for invalid in (
        dict(binding, extra='x'),
        dict(binding, schema=True),
        dict(binding, host_uid=True),
        dict(binding, domain_uuid=UUID_A.upper()),
        dict(binding, store='xyz'),
    ):
        assert evaluate(invalid) == {'ok': False, 'code': 'invalid_capability'}


def test_authoritative_store_context_and_domain_uuid(tmp_path, monkeypatch):
    cfg = AgentVMConfig()
    cfg.vm.name = 'lab'
    cfg.vm.user = 'lab-agent'
    monkeypatch.setattr('aivm.secrets_identity_vm.os.getuid', lambda: 1201)
    context = resolved_test_context(cfg, principal_id='principal-a',
                                    guest_user='lab-agent', host_uid=1201)
    path = tmp_path / 'machine.json'
    path.write_text('{}')
    reg = Store(store_kind='machine',
                vms=[VMEntry('lab', 'default', cfg)],
                principals=[PrincipalEntry(id='principal-a', vm_name='lab',
                                           host_user='host', host_uid=1201,
                                           host_gid=os.getgid(),
                                           guest_user='lab-agent', state='active')])
    monkeypatch.setattr('aivm.secrets_identity_vm.load_store', lambda _: reg)
    a = resolve_managed_identity(context, path, uuid_reader=lambda _: UUID_A)
    b = resolve_managed_identity(context, path, uuid_reader=lambda _: UUID_B)
    assert a.subject != b.subject
    assert a.uuid == UUID_A and a.principal_id == 'principal-a'
    reg.principals[0].state = 'disabled'
    with pytest.raises(SecretsError) as ex:
        resolve_managed_identity(context, path, uuid_reader=lambda _: UUID_A)
    assert ex.value.code == 'wrong_owner'
    reg.principals[0].state = 'active'
    reg.store_kind = 'legacy'
    with pytest.raises(SecretsError):
        resolve_managed_identity(context, path, uuid_reader=lambda _: UUID_A)


def test_aivm_host_binding_matches_all_python_reference_vectors():
    """Independent AIVM stdlib adapter may not drift from reference contract."""
    from aivm.secrets_identity_vm import _vm_subject
    vectors = (Path(__file__).parent / 'secrets_vectors' /
               'identity-managed-vm-v1.jsonl')
    for line in vectors.read_text().splitlines():
        case = json.loads(line)
        if case['expected_result']['ok']:
            assert _vm_subject(case['input']) == case['expected_result']['subject']
