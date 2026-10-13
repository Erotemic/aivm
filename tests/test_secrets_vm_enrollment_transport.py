"""Authenticated bootstrap CSR, bound-only session, and fail-closed paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.commands import CommandResult
from aivm.config import AgentVMConfig
from aivm.secrets_identity_transport import enroll_managed_vm, run_bound_secrets_ssh
from aivm.secrets_identity_vm import ManagedIdentity
from aivm.secrets_transport import BrokerSession
from aivm.services import PreparedSession
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from tests.helpers import resolved_test_context

UUID = '123e4567-e89b-12d3-a456-426614174000'


def fixture_context(tmp_path):
    cfg = AgentVMConfig()
    cfg.vm.name, cfg.vm.user = 'lab', 'lab-agent'
    key = tmp_path / 'login.key'
    key.write_text('synthetic SSH identity')
    cfg.paths.ssh_identity_file = str(key)
    cfg.paths.state_dir = str(tmp_path / 'state')
    context = resolved_test_context(cfg, principal_id='principal-a',
                                    guest_user='lab-agent', host_uid=1201)
    bound = ManagedIdentity(subject='vm-' + 'a' * 64, vm='lab', uuid=UUID,
                            principal_id='principal-a', guest_user='lab-agent',
                            host_uid=1201)
    store = tmp_path / 'store.json'
    store.write_text('{}')
    return context, bound, store


def test_forced_csr_enrolls_only_host_selected_subject(tmp_path, monkeypatch):
    import aivm.secrets_identity_transport as module
    context, bound, store = fixture_context(tmp_path)
    csr_key, csr_file = tmp_path / 'guest.key', tmp_path / 'guest.csr'
    create_csr(private_key=csr_key, request_file=csr_file)
    authority_root = tmp_path / 'authority'
    IdentityAuthority.initialize(authority_root, issuer='aivm.test',
                                 audience='aivm-secrets.identity')
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_text('pinned host key')
    bootstrap = SimpleNamespace(private_key=tmp_path / 'bootstrap.key',
                                known_hosts=known_hosts, use_sudo=False)
    monkeypatch.setattr(module, 'resolve_store_scope', lambda _: SimpleNamespace(
        is_machine=True, machine_layout='layout'))
    monkeypatch.setattr(module, 'require_bootstrap_identity', lambda *a, **kw: bootstrap)
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_isolated_enroll', lambda manager, **kw:
                        IdentityAuthority(authority_root).enroll(
                            subject=kw['subject'], csr=kw['csr'],
                            approve_fingerprint=inspect_csr(kw['csr']),
                            replace=kw['replace']))
    monkeypatch.setattr(module, '_public_client', lambda manager, **kw:
                        IdentityAuthority(authority_root).public_client(kw['subject']))
    def operator(manager, *, action, root, extra=None, **kw):
        if action == 'status':
            return IdentityAuthority(authority_root).status()
        if action == 'revoke-if-current':
            return IdentityAuthority(authority_root).revoke_if_current(
                subject=extra[1], expected_epoch=int(extra[3]),
                expected_thumbprint=extra[5])
        raise AssertionError(action)
    monkeypatch.setattr(module, '_identity_action', operator)
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[-1] == 'identity-csr':
            nonce = json.loads(kwargs['input_text'])['nonce']
            assert '-F' in cmd and '/dev/null' in cmd
            assert 'StrictHostKeyChecking=yes' in cmd
            return CommandResult(0, json.dumps({
                'status': 'ok', 'operation': 'identity-csr', 'nonce': nonce,
                'guest_user': 'lab-agent', 'uid': 1201,
                'csr': csr_file.read_text(),
            }), '')
        assert 'client.pem.new' in cmd[-1]
        assert 'BEGIN CERTIFICATE' not in str(cmd)
        return CommandResult(0, '', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: SimpleNamespace(
        run=fake_run))
    result = enroll_managed_vm(context=context, store=store, ip='10.0.0.2',
                               authority_root=authority_root,
                               uuid_reader=lambda _: UUID)
    assert result['subject'] == bound.subject
    assert IdentityAuthority(authority_root).status()['subjects'][bound.subject]['active']
    assert len(calls) == 2
    assert b'PRIVATE KEY' not in calls[1][1]['input_text'].encode()


def test_bootstrap_nonce_mismatch_does_not_issue_certificate(tmp_path, monkeypatch):
    import aivm.secrets_identity_transport as module
    context, bound, store = fixture_context(tmp_path)
    authority_root = tmp_path / 'authority'
    IdentityAuthority.initialize(authority_root, issuer='aivm.test',
                                 audience='aivm-secrets.identity')
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_text('pinned')
    monkeypatch.setattr(module, 'resolve_store_scope', lambda _: SimpleNamespace(
        is_machine=True, machine_layout='layout'))
    monkeypatch.setattr(module, 'require_bootstrap_identity', lambda *a, **kw:
                        SimpleNamespace(private_key=tmp_path / 'boot.key',
                                        known_hosts=known_hosts, use_sudo=False))
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_identity_action', lambda *a, **kw:
                        IdentityAuthority(authority_root).status())
    monkeypatch.setattr(module.CommandManager, 'current', lambda: SimpleNamespace(
        run=lambda *a, **kw: CommandResult(0, json.dumps({
            'status': 'ok', 'operation': 'identity-csr', 'nonce': 'f' * 32,
            'guest_user': 'lab-agent', 'uid': 1201, 'csr': 'forged'}), '')))
    with pytest.raises(SecretsError):
        enroll_managed_vm(context=context, store=store, ip='10.0.0.2',
                          authority_root=authority_root,
                          uuid_reader=lambda _: UUID)
    assert IdentityAuthority(authority_root).status()['subjects'] == {}


def test_bound_session_forwards_no_unbound_socket_and_revokes(tmp_path, monkeypatch):
    import aivm.secrets_identity_transport as module
    import aivm.secrets_transport as transport
    context, bound, store = fixture_context(tmp_path)
    workspace = tmp_path / 'project'
    workspace.mkdir()
    session = PreparedSession(
        context=context, cfg_path=store, reg_path=store, host_src=workspace,
        attachment_mode='persistent', share_source_dir=str(workspace),
        share_tag='hostcode', share_guest_dst='/home/lab-agent/code/project',
        ip='10.0.0.2', meta_path=None,
    )
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    (private / 'broker.sock').write_text('dummy')
    cap = private / 'capability'
    cap.write_text('aivs1.INNER_ONLY')
    cap.chmod(0o600)
    client = tmp_path / 'guest.py'
    client.write_text('#!/usr/bin/env python3\n')
    broker_info = BrokerSession(
        channel='a' * 32, socket=private / 'broker.sock',
        capability_file=cap, client=client, audit=private / 'audit',
        service='github', operations=('pr.view',), client_aliases=('gh',),
        writes='deny', lifetime_seconds=600,
    )
    events = []
    class FakeBroker:
        audit_head = ''
        def announce(self):
            return broker_info
        def stop(self):
            events.append('stop broker')
    class FakeBridge:
        def stop(self):
            events.append('stop bridge')
    def fake_run(cmd, **kwargs):
        events.append(('ssh', cmd))
        if '-R' in cmd:
            mapping = cmd[cmd.index('-R') + 1]
            assert mapping.endswith('/identity.sock')
            assert 'broker.sock' not in mapping
            assert 'AIVM_SECRETS_IDENTITY_MODE=mtls-v1' in str(cmd[-1])
            assert 'ForwardAgent=no' in cmd
        if 'input_text' in kwargs:
            assert kwargs['input_text'].startswith('JWT_ONLY\n')
        return CommandResult(0, '', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: SimpleNamespace(
        run=fake_run))
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_public_client', lambda *a, **kw:
                        {'subject': bound.subject, 'certificate_sha256': 'synthetic'})
    def issue(*a, **kwargs):
        kwargs['output'].write_text('JWT_ONLY')
        kwargs['output'].chmod(0o600)
    monkeypatch.setattr(module, '_isolated_issue', issue)
    monkeypatch.setattr(module, '_bridge_process', lambda *a, **kw: FakeBridge())
    monkeypatch.setattr(transport.BrokerProcess, 'start', lambda *a, **kw: FakeBroker())
    result = run_bound_secrets_ssh(
        session, ['ssh', 'lab-agent@10.0.0.2', 'exec $SHELL -l'],
        policy_path=tmp_path / 'policy.json', identity_root=tmp_path / 'authority',
        uuid_reader=lambda _: UUID,
    )
    assert result.code == 0
    assert events.index('stop bridge') < events.index('stop broker')
    assert not (private / 'bound.jwt').exists()
    assert sum(1 for event in events if isinstance(event, tuple) and '-R' in event[1]) == 1


def test_failed_guest_install_revokes_new_identity(tmp_path, monkeypatch):
    """A certificate cannot remain active if delivery to the VM fails."""
    import aivm.secrets_identity_transport as module
    context, bound, store = fixture_context(tmp_path)
    csr_key, csr_file = tmp_path / 'guest.key', tmp_path / 'guest.csr'
    create_csr(private_key=csr_key, request_file=csr_file)
    authority_root = tmp_path / 'authority'
    IdentityAuthority.initialize(authority_root, issuer='aivm.test',
                                 audience='aivm-secrets.identity')
    pinned = tmp_path / 'known_hosts'
    pinned.write_text('pinned SSH host key')
    monkeypatch.setattr(module, 'resolve_store_scope', lambda _: SimpleNamespace(
        is_machine=True, machine_layout='layout'))
    monkeypatch.setattr(module, 'require_bootstrap_identity', lambda *a, **kw:
                        SimpleNamespace(private_key=tmp_path / 'bootstrap.key',
                                        known_hosts=pinned, use_sudo=False))
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_isolated_enroll', lambda manager, **kw:
                        IdentityAuthority(authority_root).enroll(
                            subject=kw['subject'], csr=kw['csr'],
                            approve_fingerprint=inspect_csr(kw['csr']),
                            replace=kw['replace']))
    monkeypatch.setattr(module, '_public_client', lambda manager, **kw:
                        IdentityAuthority(authority_root).public_client(kw['subject']))
    def operator(manager, *, action, root, extra=None, **kw):
        if action == 'status':
            return IdentityAuthority(authority_root).status()
        if action == 'revoke-if-current':
            return IdentityAuthority(authority_root).revoke_if_current(
                subject=extra[1], expected_epoch=int(extra[3]),
                expected_thumbprint=extra[5])
        raise AssertionError(action)
    monkeypatch.setattr(module, '_identity_action', operator)
    def fake_run(cmd, **kwargs):
        if cmd[-1] == 'identity-csr':
            nonce = json.loads(kwargs['input_text'])['nonce']
            return CommandResult(0, json.dumps({
                'status': 'ok', 'operation': 'identity-csr', 'nonce': nonce,
                'guest_user': 'lab-agent', 'uid': 1201,
                'csr': csr_file.read_text()}), '')
        return CommandResult(1, 'guest failure; no secrets', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: SimpleNamespace(
        run=fake_run))
    with pytest.raises(SecretsError) as exc:
        enroll_managed_vm(context=context, store=store, ip='10.0.0.2',
                          authority_root=authority_root,
                          uuid_reader=lambda _: UUID)
    assert exc.value.code == 'guest_setup'
    assert IdentityAuthority(authority_root).status()['subjects'][bound.subject]['active'] is False


def test_isolated_ca_enrollment_uses_only_trusted_interpreter(tmp_path, monkeypatch):
    """The AIVM process does not directly execute host CA signing code."""
    import aivm.secrets_identity_transport as module
    from aivm_secrets.identity.enrollment import IdentityAuthority
    root = tmp_path / 'authority'
    authority = IdentityAuthority.initialize(root, issuer='aivm.test',
                                            audience='aivm-secrets.identity')
    observed = []
    class Manager:
        def run(self, cmd, **kwargs):
            observed.append((cmd, kwargs))
            assert '-I' in cmd
            assert '-m' in cmd and 'aivm_secrets' in cmd
            if 'enroll' in cmd:
                assert '--untrusted-root' in cmd
            assert kwargs['env'].get('PYTHONPATH') is None
            assert kwargs['env'].get('SSLKEYLOGFILE') is None
            csr_idx = cmd.index('--csr') + 1
            assert Path(cmd[csr_idx]).read_bytes() == b'SYNTHETIC PUBLIC CSR'
            if 'inspect-csr' in cmd:
                return CommandResult(0, json.dumps({
                    'key_fingerprint': '0' * 64}), '')
            return CommandResult(0, json.dumps({
                'subject': 'vm-' + 'a' * 64,
                'certificate_sha256': 'synthetic', 'epoch': 1,
                'not_after': 9999999999,
            }), '')
    reply = module._isolated_enroll(Manager(), authority_root=authority.root,
              subject='vm-' + 'a' * 64, csr=b'SYNTHETIC PUBLIC CSR',
              replace=False, untrusted=(tmp_path / 'shared',))
    assert reply['epoch'] == 1
    assert len(observed) == 2
    assert list(root.glob('.csr-*')) == []


@pytest.mark.parametrize('bridge_raises', [False, True])
def test_guest_setup_failure_shuts_down_both_host_services(tmp_path, monkeypatch, bridge_raises):
    """Even during partial installation, the bridge cannot survive its broker."""
    import aivm.secrets_identity_transport as module
    import aivm.secrets_transport as transport
    context, bound, store = fixture_context(tmp_path)
    workspace = tmp_path / 'project'
    workspace.mkdir()
    session = PreparedSession(
        context=context, cfg_path=store, reg_path=store, host_src=workspace,
        attachment_mode='persistent', share_source_dir=str(workspace),
        share_tag='hostcode', share_guest_dst='/home/lab-agent/code/project',
        ip='10.0.0.2', meta_path=None,
    )
    secure = tmp_path / 'secure'
    secure.mkdir(mode=0o700)
    cap = secure / 'capability'
    cap.write_text('aivs1.SYNTHETIC')
    cap.chmod(0o600)
    guest_client = secure / 'client.py'
    guest_client.write_text('# synthetic guest script')
    info = BrokerSession(
        channel='a' * 32, socket=secure / 'broker.sock', capability_file=cap,
        client=guest_client, audit=secure / 'audit', service='sample',
        operations=('read',), client_aliases=(), writes='deny',
        lifetime_seconds=600,
    )
    events = []
    class Broker:
        def announce(self): return info
        def stop(self): events.append('broker')
    class Bridge:
        def stop(self):
            events.append('bridge')
            if bridge_raises:
                raise RuntimeError('bridge shutdown fault')
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_public_client', lambda *a, **kw:
                        {'subject': bound.subject, 'certificate_sha256': 'synthetic'})
    monkeypatch.setattr(transport.BrokerProcess, 'start', lambda *a, **kw: Broker())
    def issue(manager, **kwargs):
        kwargs['output'].write_text('JWT_ONLY')
        kwargs['output'].chmod(0o600)
    monkeypatch.setattr(module, '_isolated_issue', issue)
    monkeypatch.setattr(module, '_bridge_process', lambda *a, **kw: Bridge())
    def fake_run(cmd, **kwargs):
        # Refuse the initial guest setup. Cleanup is best effort.
        return CommandResult(1, 'never echo secrets', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: SimpleNamespace(
        run=fake_run))
    with pytest.raises(RuntimeError if bridge_raises else SecretsError) as exc:
        run_bound_secrets_ssh(session,
            ['ssh', 'lab-agent@10.0.0.2', 'exec $SHELL -l'],
            policy_path=tmp_path / 'policy', identity_root=secure,
            uuid_reader=lambda _: UUID)
    if not bridge_raises:
        assert exc.value.code == 'guest_setup'
    assert events == ['bridge', 'broker']
    assert not (secure / 'bound.jwt').exists()


def test_bound_oauth_uses_managed_subject_and_only_host_paths(tmp_path, monkeypatch):
    """OAuth account selection is host-derived, never guest-supplied."""
    import aivm.secrets_identity_transport as module
    import aivm.secrets_transport as transport
    context, bound, store = fixture_context(tmp_path)
    workspace = tmp_path / 'project'
    workspace.mkdir()
    session = PreparedSession(
        context=context, cfg_path=store, reg_path=store, host_src=workspace,
        attachment_mode='persistent', share_source_dir=str(workspace),
        share_tag='hostcode', share_guest_dst='/home/lab-agent/code/project',
        ip='10.0.0.2', meta_path=None,
    )
    vault = tmp_path / 'vault'
    profile = tmp_path / 'provider.json'
    seen = []
    class ReachedBroker(Exception):
        pass
    def stop_at_broker(manager, argv):
        seen.append(argv)
        raise ReachedBroker()
    monkeypatch.setattr(module, 'resolve_managed_identity', lambda *a, **kw: bound)
    monkeypatch.setattr(module, 'guest_writable_roots', lambda _: ())
    monkeypatch.setattr(module, '_public_client', lambda *a, **kw:
                        {'subject': bound.subject, 'certificate_sha256': 'synthetic'})
    monkeypatch.setattr(module.CommandManager, 'current', lambda:
                        SimpleNamespace(run=lambda *a, **kw: None))
    monkeypatch.setattr(transport, 'interpreter_flags', lambda: ['-I'])
    monkeypatch.setattr(transport.BrokerProcess, 'start', stop_at_broker)
    with pytest.raises(ReachedBroker):
        run_bound_secrets_ssh(
            session, ['ssh', 'lab-agent@10.0.0.2', 'exec $SHELL -l'],
            policy_path=tmp_path / 'readonly-policy.json',
            identity_root=tmp_path / 'authority',
            oauth_vault=vault, oauth_provider_config=profile,
            uuid_reader=lambda _: UUID,
        )
    assert len(seen) == 1
    cmd = seen[0]
    assert cmd[cmd.index('--oauth-subject') + 1] == bound.subject
    assert cmd[cmd.index('--oauth-vault') + 1] == str(vault)
    assert cmd[cmd.index('--oauth-provider-config') + 1] == str(profile)
    assert '--token-file' not in cmd and '--token-stdin' not in cmd
    assert '--writes' in cmd and cmd[cmd.index('--writes') + 1] == 'deny'

    # Invalid source combinations fail before any broker is started.
    with pytest.raises(SecretsError) as wrong:
        run_bound_secrets_ssh(
            session, ['ssh', 'lab-agent@10.0.0.2', 'exec $SHELL -l'],
            policy_path=tmp_path / 'readonly-policy.json',
            identity_root=tmp_path / 'authority', token_file=tmp_path / 'token',
            oauth_vault=vault, oauth_provider_config=profile,
        )
    assert wrong.value.code == 'invalid_policy'
