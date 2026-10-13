"""VM identity-key replacement crosses only existing authenticated boundaries."""
from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aivm.commands import CommandResult
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.identity.enrollment import IdentityAuthority
from tests.helpers import activate_manager
from tests.test_secrets_vm_enrollment_transport import (
    UUID,
    ScriptedManager,
    certificate_thumbprint_of,
    fixture_context,
    guarded_revoke,
    managed_world,
    spki,
)


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
        else guarded_revoke(authority,extra))
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
    monkeypatch.setattr(module.CommandManager,'current',lambda:ScriptedManager(run))
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
    monkeypatch.setattr(m.CommandManager,'current',lambda:ScriptedManager(fail))
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
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    directory,done,previous,public,new=_install_trial(tmp_path)
    assert done.returncode==0,done.stderr
    assert (directory/'client.key').read_bytes()!=previous
    assert not (directory/'client.rotate.key').exists()
    assert not (directory/'client.rotate.csr').exists()
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )
    key=load_pem_private_key((directory/'client.key').read_bytes(),None)
    cert=x509.load_pem_x509_certificate((directory/'client.pem').read_bytes())
    actual=key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    expected=cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    assert actual==expected
    # The cached request moved with the key: a later renewal that replays
    # client.csr presents the active key, not the one rotation retired.
    assert spki(directory/'client.csr')==actual


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


def _plain_install(tmp_path: Path, *, same_key: bool,
                   remove_key: bool = False) -> tuple[Path, Any, bytes]:
    """Install a renewed certificate with the non-rotating script."""
    import aivm.secrets_identity_transport as module
    home=tmp_path/'home'
    directory=home/'.config'/'aivm'/'identity'
    directory.mkdir(parents=True)
    authority=IdentityAuthority.initialize(tmp_path/'authority',
        issuer='aivm.test',audience='aivm-secrets.identity')
    fp=create_csr(private_key=directory/'client.key',
                  request_file=directory/'client.csr')
    old=authority.enroll(subject='guest',csr=(directory/'client.csr').read_bytes(),
                         approve_fingerprint=fp)
    (directory/'client.pem').write_bytes(Path(old['certificate']).read_bytes())
    if same_key:
        authority.renew_client(subject='guest',
            csr=(directory/'client.csr').read_bytes(),approve_fingerprint=fp,
            expected_epoch=old['epoch'],expected_thumbprint=old['certificate_sha256'])
        public=authority.public_client('guest')
    else:
        # A valid certificate from the same CA, for some other key (say a
        # rotated-away one). Issued to another subject, so this does not
        # depend on whether the host would renew a different key.
        other=tmp_path/'other.csr'
        create_csr(private_key=tmp_path/'other.key',request_file=other)
        authority.enroll(subject='other',csr=other.read_bytes(),
                         approve_fingerprint=inspect_csr(other.read_bytes()))
        public=authority.public_client('other')
    before=(directory/'client.pem').read_bytes()
    if remove_key:
        (directory/'client.key').unlink()
    done=subprocess.run(['/bin/sh','-c',module._guest_install_script(rotate_key=False)],
        input=public['certificate_pem_b64']+'\n'+public['ca_pem_b64']+'\n',
        text=True,capture_output=True,timeout=20,
        env={'HOME':str(home),'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    return directory,done,before


def test_real_shell_plain_install_refuses_a_certificate_for_another_key(tmp_path: Path) -> None:
    directory,done,before=_plain_install(tmp_path,same_key=False)
    assert done.returncode!=0
    assert (directory/'client.pem').read_bytes()==before
    assert not list(directory.glob('.identity-check.*'))


def test_real_shell_plain_install_accepts_a_certificate_for_its_key(tmp_path: Path) -> None:
    directory,done,before=_plain_install(tmp_path,same_key=True)
    assert done.returncode==0,done.stderr
    assert (directory/'client.pem').read_bytes()!=before
    assert spki(directory/'client.pem')==spki(directory/'client.key')
    assert not list(directory.glob('.identity-check.*'))


def test_real_shell_plain_install_requires_an_installed_key(tmp_path: Path) -> None:
    directory,done,before=_plain_install(tmp_path,same_key=True,remove_key=True)
    assert done.returncode!=0
    assert (directory/'client.pem').read_bytes()==before


@pytest.mark.skipif(not Path('/usr/bin/openssl').exists(),
                    reason='the guest helper runs /usr/bin/openssl')
@pytest.mark.parametrize('helper', [
    pytest.param('current', id='current-helper'),
    # Guests keep their forced helper until an explicit upgrade, and the
    # old one replays client.csr verbatim. With the stale client.csr below,
    # only the host-delivered CSR refresh makes renewal present the active
    # key: turn that refresh into a no-op and this case fails.
    pytest.param('legacy', id='legacy-helper'),
])
def test_enroll_rotate_renew_keeps_guest_key_csr_and_certificate_consistent(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, helper: str) -> None:
    """B1: renewal after rotation must certify the active key, not the old one.

    Real guest helper code and openssl, the real install scripts under
    /bin/sh, and the real isolated authority; only ssh and virsh are faked.
    The guest then rotated under the *original* activation script, which
    removed the staged files but left client.csr holding the retired key's
    request -- the state of every existing guest that ever rotated.
    """
    world=managed_world(tmp_path,monkeypatch,helper=helper)
    activate_manager(monkeypatch,yes=True)
    directory=world.identity_dir

    def consistent() -> bytes:
        key=spki(directory/'client.key')
        assert spki(directory/'client.csr')==key
        assert spki(directory/'client.pem')==key
        row=world.row()
        assert row is not None and row['active'] is True
        assert row['certificate_sha256']==certificate_thumbprint_of(
            directory/'client.pem')
        # No scratch or staged file is left behind.
        assert not list(directory.glob('client.*.*'))
        assert not list(directory.glob('.*'))
        return key

    enrolled=world.enroll()
    first=consistent()
    retired_request=(directory/'client.csr').read_bytes()
    rotated=world.enroll(renew=True,rotate_key=True)
    second=consistent()
    assert second!=first
    # What the original activation script left behind.
    (directory/'client.csr').write_bytes(retired_request)
    assert spki(directory/'client.csr')==first
    renewed=world.enroll(renew=True)
    assert consistent()==second
    assert (enrolled['epoch'],rotated['epoch'],renewed['epoch'])==(0,1,2)
    assert len({enrolled['certificate_sha256'],rotated['certificate_sha256'],
                renewed['certificate_sha256']})==3
