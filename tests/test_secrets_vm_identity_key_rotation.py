"""VM identity-key replacement crosses only existing authenticated boundaries."""
from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.commands import CommandResult
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority, create_csr, inspect_csr
from tests.test_secrets_vm_enrollment_transport import fixture_context, UUID


def fake_vm(tmp_path, monkeypatch):
    import aivm.secrets_identity_transport as module
    context, bound, store = fixture_context(tmp_path)
    root = tmp_path/'authority'
    authority = IdentityAuthority.initialize(root, issuer='aivm.test',
        audience='aivm-secrets.identity')
    old_key, old_csr = tmp_path/'old.key',tmp_path/'old.csr'
    old_fp = create_csr(private_key=old_key,request_file=old_csr)
    old = authority.enroll(subject=bound.subject,csr=old_csr.read_bytes(),
                            approve_fingerprint=old_fp)
    next_key, next_csr = tmp_path/'next.key',tmp_path/'next.csr'
    next_fp = create_csr(private_key=next_key,request_file=next_csr)
    known_hosts=tmp_path/'known_hosts'; known_hosts.write_text('pinned host key')
    monkeypatch.setattr(module, 'resolve_store_scope', lambda _: SimpleNamespace(
        is_machine=True,machine_layout='layout'))
    monkeypatch.setattr(module,'require_bootstrap_identity',lambda *a,**kw:
        SimpleNamespace(private_key=tmp_path/'bootstrap.key',
                        known_hosts=known_hosts,use_sudo=False))
    monkeypatch.setattr(module,'resolve_managed_identity',lambda *a,**kw:bound)
    monkeypatch.setattr(module,'guest_writable_roots',lambda _:())
    monkeypatch.setattr(module,'_identity_action',lambda manager,*,action,
        extra=None,**kw: authority.status() if action=='status'
        else authority.revoke_if_current(
            subject=extra[1],expected_epoch=int(extra[3]),
            expected_thumbprint=extra[5]))
    actions=[]
    def isolated(manager,**kw):
        actions.append(kw)
        assert kw.get('rotate_key') is True
        assert kw['renewal']==(old['epoch'],old['certificate_sha256'])
        return authority.rotate_client_key(
            subject=kw['subject'],csr=kw['csr'],
            approve_fingerprint=inspect_csr(kw['csr']),
            expected_epoch=kw['renewal'][0],
            expected_thumbprint=kw['renewal'][1])
    monkeypatch.setattr(module,'_isolated_enroll',isolated)
    monkeypatch.setattr(module,'_public_client',lambda manager,**kw:
        authority.public_client(kw['subject']))
    calls=[]
    def run(cmd,**kw):
        calls.append((cmd,kw))
        if cmd[-1]=='identity-key-rotate-csr':
            req=json.loads(kw['input_text'])
            assert req['operation']=='identity-key-rotate-csr'
            assert 'StrictHostKeyChecking=yes' in cmd
            return CommandResult(0,json.dumps({
                'status':'ok','operation':'identity-key-rotate-csr',
                'guest_user':bound.guest_user,'uid':bound.host_uid,
                'nonce':req['nonce'],'csr':next_csr.read_text()}),'')
        if cmd[-1]=='identity-csr':
            pytest.fail('must use explicit rotating bootstrap operation')
        assert 'client.rotate.key' in cmd[-1]
        assert 'cmp -s' in cmd[-1]
        assert 'client.key.new' in cmd[-1]
        return CommandResult(0,'','')
    monkeypatch.setattr(module.CommandManager,'current',lambda:SimpleNamespace(run=run))
    return module,context,bound,store,authority,root,old,calls,actions,next_csr


def test_managed_rotation_uses_forced_ssh_and_no_raw_broker_socket(tmp_path,monkeypatch):
    m,c,b,store,a,root,old,calls,actions,csr=fake_vm(tmp_path,monkeypatch)
    result=m.enroll_managed_vm(context=c,store=store,ip='10.0.0.2',
        authority_root=root,renew=True,rotate_key=True,uuid_reader=lambda _:UUID)
    assert result['epoch']==old['epoch']+1
    assert result['certificate_sha256']!=old['certificate_sha256']
    assert len(calls)==2
    assert len(actions)==1
    assert 'BEGIN PRIVATE KEY' not in str(calls)


def test_rekey_install_failure_revokes_new_identity(tmp_path,monkeypatch):
    m,c,b,store,a,root,old,calls,actions,csr=fake_vm(tmp_path,monkeypatch)
    mgr=m.CommandManager.current()
    original=mgr.run
    def fail(cmd,**kw):
        if cmd[-1]!='identity-key-rotate-csr':
            return CommandResult(1,'','install rejected')
        return original(cmd,**kw)
    monkeypatch.setattr(m.CommandManager,'current',lambda:SimpleNamespace(run=fail))
    with pytest.raises(SecretsError) as exc:
        m.enroll_managed_vm(context=c,store=store,ip='10.0.0.2',
            authority_root=root,renew=True,rotate_key=True,uuid_reader=lambda _:UUID)
    row=a.status()['subjects'][b.subject]
    assert row['active'] is False
    assert row['epoch']==old['epoch']+2


def test_rotation_requires_renew_mode_without_guest_command(tmp_path,monkeypatch):
    m,c,b,store,a,root,old,calls,actions,csr=fake_vm(tmp_path,monkeypatch)
    with pytest.raises(SecretsError):
        m.enroll_managed_vm(context=c,store=store,ip='10.0.0.2',
            authority_root=root,rotate_key=True,uuid_reader=lambda _:UUID)
    assert not calls


def test_cli_registers_explicit_key_rotation():
    from aivm.cli.vm import VMModalCLI
    from aivm.cli.vm_identity import VMIdentityRotateKeyCLI
    assert VMModalCLI.identity_rotate_key is VMIdentityRotateKeyCLI


def _install_trial(tmp_path, *, corrupt=False):
    import aivm.secrets_identity_transport as module
    home=tmp_path/'home'
    directory=home/'.config'/'aivm'/'identity'
    directory.mkdir(parents=True)
    authority=IdentityAuthority.initialize(tmp_path/'authority',
        issuer='aivm.test',audience='aivm-secrets.identity')
    old_fp=create_csr(private_key=directory/'client.key',
        request_file=directory/'client.csr')
    old=authority.enroll(subject='guest',csr=(directory/'client.csr').read_bytes(),
                         approve_fingerprint=old_fp)
    (directory/'client.pem').write_bytes(Path(old['certificate']).read_bytes())
    cand_fp=create_csr(private_key=directory/'client.rotate.key',
        request_file=directory/'client.rotate.csr')
    new=authority.rotate_client_key(subject='guest',
        csr=(directory/'client.rotate.csr').read_bytes(),
        approve_fingerprint=cand_fp,expected_epoch=old['epoch'],
        expected_thumbprint=old['certificate_sha256'])
    public=authority.public_client('guest')
    if corrupt:
        # Replace staging key AFTER the host signed its CSR.
        (directory/'client.rotate.key').unlink()
        (directory/'client.rotate.csr').unlink()
        create_csr(private_key=directory/'client.rotate.key',
            request_file=directory/'client.rotate.csr')
    stdin=public['certificate_pem_b64']+'\n'+public['ca_pem_b64']+'\n'
    before=(directory/'client.key').read_bytes()
    done=subprocess.run(['/bin/sh','-c',module._guest_install_script(rotate_key=True)],
        input=stdin,text=True,capture_output=True,timeout=20,
        env={'HOME':str(home),'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    return directory,done,before,public,new


def test_real_shell_installs_matching_new_private_key(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (Encoding,PublicFormat)
    directory,done,previous,public,new=_install_trial(tmp_path)
    assert done.returncode==0,done.stderr
    assert (directory/'client.key').read_bytes()!=previous
    assert not (directory/'client.rotate.key').exists()
    assert not (directory/'client.rotate.csr').exists()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key=load_pem_private_key((directory/'client.key').read_bytes(),None)
    cert=x509.load_pem_x509_certificate((directory/'client.pem').read_bytes())
    actual=key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    expected=cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    assert actual==expected


def test_real_shell_denies_mismatched_staged_key_before_activation(tmp_path):
    directory,done,previous,public,new=_install_trial(tmp_path,corrupt=True)
    assert done.returncode!=0
    assert (directory/'client.key').read_bytes()==previous
    assert (directory/'client.rotate.key').exists()


def test_public_client_failure_also_revokes_exact_new_epoch(tmp_path, monkeypatch):
    m,c,b,store,a,root,old,calls,actions,csr=fake_vm(tmp_path,monkeypatch)
    monkeypatch.setattr(m,'_public_client',lambda *x,**k:
        (_ for _ in ()).throw(SecretsError('guest_setup')))
    with pytest.raises(SecretsError):
        m.enroll_managed_vm(context=c,store=store,ip='10.0.0.2',
            authority_root=root,renew=True,rotate_key=True,uuid_reader=lambda _:UUID)
    row=a.status()['subjects'][b.subject]
    assert row['active'] is False
    assert row['epoch']==old['epoch']+2
