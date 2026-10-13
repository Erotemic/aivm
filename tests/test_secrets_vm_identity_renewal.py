"""Managed-VM renewal uses authenticated CSR exchange plus a host CAS."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.commands import CommandResult
from aivm.secrets_identity_transport import enroll_managed_vm
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority, create_csr, inspect_csr
from tests.test_secrets_vm_enrollment_transport import fixture_context, UUID


def setup(tmp_path, monkeypatch, *, enroll_first=True):
    import aivm.secrets_identity_transport as module
    context, bound, store = fixture_context(tmp_path)
    key, csr = tmp_path / 'client.key', tmp_path / 'client.csr'
    fp = create_csr(private_key=key, request_file=csr)
    root = tmp_path / 'authority'
    authority = IdentityAuthority.initialize(root, issuer='aivm.test',
                                             audience='aivm-secrets.identity')
    old = (authority.enroll(subject=bound.subject, csr=csr.read_bytes(),
                            approve_fingerprint=fp) if enroll_first else None)
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_text('pinned host key')
    monkeypatch.setattr(module, 'resolve_store_scope', lambda _: SimpleNamespace(
        is_machine=True, machine_layout='layout'))
    monkeypatch.setattr(module, 'require_bootstrap_identity', lambda *a, **kw:
                        SimpleNamespace(private_key=tmp_path / 'boot.key',
                                        known_hosts=known_hosts, use_sudo=False))
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_identity_action', lambda manager, *, action,
                        extra=None, **kw: authority.status() if action=='status'
                        else authority.revoke(extra[-1]))
    monkeypatch.setattr(module, '_isolated_enroll', lambda manager, **kw:
                        authority.renew_client(subject=kw['subject'],csr=kw['csr'],
                            approve_fingerprint=inspect_csr(kw['csr']),
                            expected_epoch=kw['renewal'][0],
                            expected_thumbprint=kw['renewal'][1]))
    monkeypatch.setattr(module, '_public_client', lambda manager, **kw:
                        authority.public_client(kw['subject']))
    calls=[]
    def run(cmd, **kwargs):
        calls.append((cmd,kwargs))
        if cmd[-1]=='identity-csr':
            nonce=json.loads(kwargs['input_text'])['nonce']
            assert 'StrictHostKeyChecking=yes' in cmd
            return CommandResult(0,json.dumps({
                'status':'ok','operation':'identity-csr','nonce':nonce,
                'guest_user':bound.guest_user,'uid':bound.host_uid,
                'csr':csr.read_text()}),'')
        assert 'client.pem.new' in cmd[-1]
        return CommandResult(0,'','')
    monkeypatch.setattr(module.CommandManager,'current',lambda:SimpleNamespace(run=run))
    return module,context,bound,store,authority,root,old,calls


def test_managed_renewal_uses_authenticated_channel_and_cas(tmp_path,monkeypatch):
    module,ctx,bound,store,authority,root,old,calls=setup(tmp_path,monkeypatch)
    new=enroll_managed_vm(context=ctx,store=store,ip='10.0.0.2',
        authority_root=root,renew=True,uuid_reader=lambda _:UUID)
    assert new['subject']==bound.subject
    assert new['epoch']==old['epoch']+1
    assert new['certificate_sha256']!=old['certificate_sha256']
    assert len(calls)==2
    assert 'BEGIN PRIVATE KEY' not in str(calls)


def test_managed_renewal_denies_missing_enrollment_before_ssh(tmp_path,monkeypatch):
    module,ctx,bound,store,authority,root,old,calls=setup(
        tmp_path,monkeypatch,enroll_first=False)
    with pytest.raises(SecretsError) as exc:
        enroll_managed_vm(context=ctx,store=store,ip='10.0.0.2',
            authority_root=root,renew=True,uuid_reader=lambda _:UUID)
    assert exc.value.code=='revoked'
    assert calls==[]


def test_concurrent_replacement_fences_stale_renewal(tmp_path,monkeypatch):
    module,ctx,bound,store,authority,root,old,calls=setup(tmp_path,monkeypatch)
    original=module._isolated_enroll
    csr=(tmp_path/'client.csr').read_bytes()
    def concurrent(manager,**kwargs):
        authority.enroll(subject=bound.subject,csr=csr,
            approve_fingerprint=inspect_csr(csr),replace=True)
        return original(manager,**kwargs)
    monkeypatch.setattr(module,'_isolated_enroll',concurrent)
    with pytest.raises(SecretsError) as exc:
        enroll_managed_vm(context=ctx,store=store,ip='10.0.0.2',
            authority_root=root,renew=True,uuid_reader=lambda _:UUID)
    assert exc.value.code=='revoked'
    assert authority.status()['subjects'][bound.subject]['epoch']==old['epoch']+1
    assert len(calls)==1  # no public certificate was installed


def test_renewal_flag_does_not_combine_with_replace(tmp_path,monkeypatch):
    _,ctx,_,store,_,root,_,calls=setup(tmp_path,monkeypatch)
    with pytest.raises(SecretsError):
        enroll_managed_vm(context=ctx,store=store,ip='10.0.0.2',
            authority_root=root,replace=True,renew=True,uuid_reader=lambda _:UUID)
    assert calls==[]


def test_managed_vm_cli_exposes_separate_explicit_renewal_command():
    from aivm.cli.vm import VMModalCLI
    from aivm.cli.vm_identity import VMIdentityRenewCLI
    assert VMModalCLI.identity_renew is VMIdentityRenewCLI


def test_failed_renewal_delivery_revokes_new_epoch_not_old(tmp_path,monkeypatch):
    import aivm.secrets_identity_transport as module
    module,ctx,bound,store,authority,root,old,calls=setup(tmp_path,monkeypatch)
    csr=(tmp_path/'client.csr').read_bytes()
    monkeypatch.setattr(module.CommandManager,'current',lambda:SimpleNamespace(
        run=lambda cmd, **kw: CommandResult(0,json.dumps({
                'status':'ok','operation':'identity-csr',
                'nonce':json.loads(kw['input_text'])['nonce'],
                'guest_user':bound.guest_user,'uid':bound.host_uid,
                'csr':csr.decode()}),'') if cmd[-1]=='identity-csr'
            else CommandResult(1,'','delivery failed')))
    with pytest.raises(SecretsError):
        enroll_managed_vm(context=ctx,store=store,ip='10.0.0.2',
            authority_root=root,renew=True,uuid_reader=lambda _:UUID)
    row=authority.status()['subjects'][bound.subject]
    assert row['active'] is False
    assert row['epoch']==old['epoch']+2  # renewed epoch, then revoke
    assert row['certificate_sha256'] != old['certificate_sha256']
