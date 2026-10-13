"""Authenticated bootstrap CSR, bound-only session, and fail-closed paths.

The later tests run enrollment against :func:`managed_world`: a real machine
store, a real identity authority reached only through its isolated child
processes, and a guest that is a local directory behind :class:`FakeVMHost`,
which fakes nothing but the process boundary.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Sequence

import pytest

from aivm.commands import CommandManager, CommandResult
from aivm.config import AgentVMConfig
from aivm.errors import UserDeclinedError
from aivm.rc.guest import guestctl
from aivm.secrets_identity_transport import (
    enroll_managed_vm,
    run_bound_secrets_ssh,
)
from aivm.secrets_identity_vm import ManagedIdentity, resolve_managed_identity
from aivm.secrets_transport import BrokerSession
from aivm.services import PreparedSession
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.identity.enrollment import IdentityAuthority
from tests.helpers import (
    FakeProc,
    activate_manager,
    capture_logs,
    resolved_test_context,
)

UUID = '123e4567-e89b-12d3-a456-426614174000'


class ScriptedManager(CommandManager):
    """A real ``CommandManager`` whose external commands ``script`` answers.

    Keeps the manager's own control flow -- ``attempt`` and its refusal
    handling -- and replaces only execution, like ``FakeCommandManager``,
    but also hands ``script`` the keyword arguments (``input_text``) these
    tests read.
    """

    def __init__(self, script: Callable[..., CommandResult]) -> None:
        super().__init__(yes=True)
        self._script = script

    def run(self, cmd: Sequence[str], **kwargs: Any) -> CommandResult:  # type: ignore[override]
        return self._script(list(cmd), **kwargs)


def option(argv: Sequence[str], name: str) -> str:
    """The value of the one ``--name=value`` word in an identity argv."""
    prefix = f'--{name}='
    (value,) = [word[len(prefix):] for word in argv if word.startswith(prefix)]
    return value


def guarded_revoke(authority: IdentityAuthority,
                   extra: Sequence[str] | None) -> dict[str, Any]:
    """Apply a ``revoke-if-current`` argv to an in-process authority."""
    assert extra is not None
    return authority.revoke_if_current(
        subject=option(extra, 'subject'),
        expected_epoch=int(option(extra, 'expected-epoch')),
        expected_thumbprint=option(extra, 'expected-certificate-sha256'))


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
            return guarded_revoke(IdentityAuthority(authority_root), extra)
        raise AssertionError(action)
    monkeypatch.setattr(module, '_identity_action', operator)
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        assert '-F' in cmd and '/dev/null' in cmd
        assert 'StrictHostKeyChecking=yes' in cmd
        if cmd[-1] == 'identity-csr':
            nonce = json.loads(kwargs['input_text'])['nonce']
            return CommandResult(0, json.dumps({
                'status': 'ok', 'operation': 'identity-csr', 'nonce': nonce,
                'guest_user': 'lab-agent', 'uid': 1201,
                'csr': csr_file.read_text(),
            }), '')
        assert 'BEGIN CERTIFICATE' not in str(cmd)
        return CommandResult(0, '', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: ScriptedManager(
        fake_run))
    result = enroll_managed_vm(context=context, store=store, ip='10.0.0.2',
                               authority_root=authority_root,
                               uuid_reader=lambda _: UUID)
    assert result['subject'] == bound.subject
    assert IdentityAuthority(authority_root).status()['subjects'][bound.subject]['active']
    # Re-sign the cached CSR, fetch it over the forced channel, install.
    refresh, fetch, install = calls
    assert 'openssl req -new -key client.key' in refresh[0][-1]
    assert fetch[0][-1] == 'identity-csr'
    assert 'client.pem.new' in install[0][-1]
    assert b'PRIVATE KEY' not in install[1]['input_text'].encode()


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
    monkeypatch.setattr(module.CommandManager, 'current', lambda: ScriptedManager(
        lambda *a, **kw: CommandResult(0, json.dumps({
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
            return guarded_revoke(IdentityAuthority(authority_root), extra)
        raise AssertionError(action)
    monkeypatch.setattr(module, '_identity_action', operator)
    def fake_run(cmd, **kwargs):
        if cmd[-1] == 'identity-csr':
            nonce = json.loads(kwargs['input_text'])['nonce']
            return CommandResult(0, json.dumps({
                'status': 'ok', 'operation': 'identity-csr', 'nonce': nonce,
                'guest_user': 'lab-agent', 'uid': 1201,
                'csr': csr_file.read_text()}), '')
        if 'client.pem.new' in cmd[-1]:
            return CommandResult(1, 'guest failure; no secrets', '')
        return CommandResult(0, '', '')
    monkeypatch.setattr(module.CommandManager, 'current', lambda: ScriptedManager(
        fake_run))
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


# ---------------------------------------------------------------------------
# A real managed VM whose guest is a local directory
# ---------------------------------------------------------------------------

GUEST_USER = 'lab-agent'
VM_IP = '10.0.0.2'
PINNED = '10.0.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinnedHostKeyForTests\n'
Hook = Callable[[Callable[[], Any]], Any]


class FakeVMHost:
    """``subprocess.run`` for one managed VM whose guest is a local directory.

    Only the process boundary is fake. ``virsh domuuid`` answers a fixed
    domain UUID and ``sudo -n true`` reports cached credentials, because
    this host has no live libvirt domain and must not escalate. ``ssh``
    plays the guest locally: a principal-account command runs under
    ``/bin/sh`` with the guest's ``HOME``; a forced-bootstrap request runs
    the guest helper's own ``prepare_guest_identity_csr``, whose ``runuser``
    commands run here as the test user. The identity-service child
    processes, ``openssl`` and every shell script run for real.

    ``hooks`` maps a step -- ``refresh``, ``bootstrap``, ``install`` or an
    identity action such as ``enroll`` -- to ``hook(proceed)``, which may
    run the real step (``proceed()``) and then replace its result.
    ``helper='legacy'`` answers ``identity-csr`` the way the forced helper
    did before it re-signed the CSR: by replaying ``client.csr`` verbatim.
    """

    def __init__(self, real_run: Callable[..., Any], *, home: Path,
                 helper: str = 'current') -> None:
        self._real_run = real_run
        self.home = home
        self.helper = helper
        self.commands: list[list[str]] = []
        self.hooks: dict[str, Hook] = {}

    @property
    def identity_dir(self) -> Path:
        return self.home / '.config' / 'aivm' / 'identity'

    def ssh_commands(self) -> list[list[str]]:
        return [_unprivileged(argv) for argv in self.commands
                if _unprivileged(argv)[:1] == ['ssh']]

    def ran(self, step: str) -> bool:
        return any(_step_name(_unprivileged(argv)) == step
                   for argv in self.commands)

    def __call__(self, cmd: Sequence[Any], **kwargs: Any) -> Any:
        argv = [str(part) for part in cmd]
        self.commands.append(argv)
        bare = _unprivileged(argv)
        if bare == ['true']:
            return FakeProc(0)
        if bare[:1] == ['virsh'] and bare[-2:] == ['domuuid', 'lab']:
            return FakeProc(0, UUID + '\n')
        if bare[:4] == ['/usr/sbin/runuser', '-u', GUEST_USER, '--']:
            return self._real_run(bare[4:], **kwargs)
        step = _step_name(bare)
        if bare[:1] == [sys.executable]:
            return self._step(step, lambda: self._real_run(bare, **kwargs))
        if bare[:1] == ['ssh']:
            return self._step(step, lambda: self._guest(bare, kwargs.get('input')))
        raise AssertionError(f'unexpected command: {argv!r}')

    def _step(self, step: str, proceed: Callable[[], Any]) -> Any:
        hook = self.hooks.get(step)
        return proceed() if hook is None else hook(proceed)

    def _guest(self, argv: list[str], payload: str | None) -> FakeProc:
        target, remote = argv[-2], argv[-1]
        if target.startswith('aivm-bootstrap@'):
            return self._forced_helper(remote, payload or '')
        assert target == f'{GUEST_USER}@{VM_IP}', target
        done = self._real_run(
            ['/bin/sh', '-c', remote], input=payload, capture_output=True,
            text=True, timeout=60,
            env={'HOME': str(self.home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        return FakeProc(done.returncode, done.stdout, done.stderr)

    def _forced_helper(self, operation: str, payload: str) -> FakeProc:
        request = guestctl.GuestIdentityCSRRequest.from_json(payload)
        assert request.operation == operation
        cached = self.identity_dir / 'client.csr'
        if (self.helper == 'legacy' and operation == 'identity-csr' and
                (self.identity_dir / 'client.key').is_file() and cached.is_file()):
            report: dict[str, object] = {
                'status': 'ok', 'operation': operation, 'nonce': request.nonce,
                'guest_user': request.guest_user, 'uid': request.uid,
                'csr': cached.read_text()}
        else:
            try:
                report = guestctl.prepare_guest_identity_csr(request)
            except guestctl.GuestEnrollmentError as ex:
                return FakeProc(2, '', json.dumps({'status': 'error',
                                                   'error': str(ex)}))
        return FakeProc(0, json.dumps(report, sort_keys=True) + '\n')


def _unprivileged(argv: list[str]) -> list[str]:
    if argv[:2] == ['sudo', '-n']:
        return argv[2:]
    return argv[1:] if argv[:1] == ['sudo'] else argv


def _step_name(argv: list[str]) -> str:
    if argv[:1] == [sys.executable] and 'identity' in argv:
        return argv[argv.index('identity') + 1]
    if argv[:1] == ['ssh']:
        if argv[-2].startswith('aivm-bootstrap@'):
            return 'bootstrap'
        return 'install' if 'client.pem.new' in argv[-1] else 'refresh'
    return ''


@dataclass
class ManagedWorld:
    context: Any
    store: Path
    authority_root: Path
    known_hosts: Path
    host: FakeVMHost

    @property
    def identity_dir(self) -> Path:
        return self.host.identity_dir

    @property
    def subject(self) -> str:
        return resolve_managed_identity(
            self.context, self.store, uuid_reader=lambda _: UUID).subject

    def row(self) -> dict[str, Any] | None:
        status = IdentityAuthority(self.authority_root).status()
        return status['subjects'].get(self.subject)

    def active(self) -> bool | None:
        """Whether the subject's enrollment is active; None if never enrolled."""
        row = self.row()
        return None if row is None else bool(row['active'])

    def enroll(self, **kwargs: Any) -> dict[str, Any]:
        return enroll_managed_vm(context=self.context, store=self.store, ip=VM_IP,
                                 authority_root=self.authority_root, **kwargs)


def managed_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *,
                  helper: str = 'current') -> ManagedWorld:
    """A real 0.6 machine store, identity authority and local guest home.

    The store, the principal (this test process's own host identity), the
    bootstrap identity files and the authority are all real and on disk; the
    managed VM is :class:`FakeVMHost` at ``aivm.commands.subprocess.run``.
    """
    import subprocess

    from aivm.config_store import (
        PrincipalEntry,
        load_store,
        upsert_network,
        upsert_principal,
        upsert_vm_with_network,
    )
    from aivm.enrollment import bootstrap_identity_paths
    from aivm.host_identity import current_host_identity
    from aivm.profile_store import UserProfileStore, save_user_profile
    from aivm.scoped_store import resolve_store_scope, save_scope_store
    from aivm.services import load_vm_context_with_path
    from aivm.vm.paths import _paths

    scope = resolve_store_scope(None)
    assert scope.is_machine and scope.machine_layout is not None
    # Everything below writes the store and profile that the environment
    # selects. tests/conftest.py points those into tmp_path; anywhere else
    # (run without that fixture) they could be the developer's real
    # /var/lib/aivm/machine or ~/.config/aivm, so refuse before any write.
    sandbox = tmp_path.resolve()
    for written in (scope.store_path, scope.machine_layout.root, scope.profile_path):
        assert written is not None and Path(written).resolve().is_relative_to(
            sandbox), f'managed_world would write outside the test sandbox: {written}'
    me = current_host_identity()
    cfg = AgentVMConfig()
    cfg.vm.name, cfg.vm.user = 'lab', GUEST_USER
    reg = load_store(scope.store_path)
    reg.store_kind = 'machine'
    reg.schema_version = 11
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    upsert_principal(reg, PrincipalEntry(
        id='principal-a', vm_name='lab', host_user=me.username,
        host_uid=me.uid, host_gid=me.gid, guest_user=GUEST_USER,
        ssh_public_key='ssh-ed25519 AAAAOWNER owner@test', state='active'))
    save_scope_store(scope, reg, reason='test managed identity VM')
    login = tmp_path / 'login.key'
    login.write_text('synthetic SSH identity')
    assert scope.profile_path is not None
    save_user_profile(UserProfileStore(
        active_vm='lab', ssh_identity_file=str(login),
        state_dir=str(tmp_path / 'state'), default_guest_user=GUEST_USER),
        scope.profile_path)
    bootstrap = bootstrap_identity_paths('lab', layout=scope.machine_layout)
    bootstrap.directory.mkdir(parents=True, mode=0o700)
    bootstrap.private_key.write_text('synthetic bootstrap key')
    bootstrap.public_key_path.write_text('ssh-ed25519 AAAABOOT aivm-bootstrap@lab\n')
    bootstrap.known_hosts.write_text(PINNED)
    context, store = load_vm_context_with_path(
        None, vm_opt='lab', hydrate_runtime_defaults=False,
        persist_runtime_defaults=False)
    ip_file = _paths(context.effective_cfg)['ip_file']
    ip_file.parent.mkdir(parents=True, exist_ok=True)
    ip_file.write_text(VM_IP + '\n')
    authority_root = tmp_path / 'authority'
    IdentityAuthority.initialize(authority_root, issuer='aivm.test',
                                 audience='aivm-secrets.identity')
    home = tmp_path / 'guest-home'
    home.mkdir()
    # The guest's account database: only the principal's guest account.
    real_getpwnam = guestctl.pwd.getpwnam
    monkeypatch.setattr(guestctl.pwd, 'getpwnam', lambda name: SimpleNamespace(
        pw_uid=me.uid, pw_dir=str(home)) if name == GUEST_USER else real_getpwnam(name))
    host = FakeVMHost(subprocess.run, home=home, helper=helper)
    monkeypatch.setattr('aivm.commands.subprocess.run', host)
    return ManagedWorld(context=context, store=store,
                        authority_root=authority_root,
                        known_hosts=bootstrap.known_hosts, host=host)


def spki(path: Path) -> bytes:
    """DER SubjectPublicKeyInfo of a PEM private key, CSR or certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )
    data = path.read_bytes()
    if b'PRIVATE KEY' in data:
        key: Any = load_pem_private_key(data, None).public_key()
    elif b'CERTIFICATE REQUEST' in data:
        key = x509.load_pem_x509_csr(data).public_key()
    else:
        key = x509.load_pem_x509_certificate(data).public_key()
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def certificate_thumbprint_of(path: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from aivm_secrets.identity.token import certificate_thumbprint
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return certificate_thumbprint(cert.public_bytes(Encoding.DER))


# ---------------------------------------------------------------------------
# Enrollment against the managed-VM world
# ---------------------------------------------------------------------------


def test_every_identity_ssh_is_pinned_to_the_vm_host_key(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Principal SSH trusts the VM's pinned key, never ambient known_hosts."""
    world = managed_world(tmp_path, monkeypatch)
    activate_manager(monkeypatch, yes=True)
    world.enroll()
    world.enroll(renew=True)
    world.enroll(renew=True, rotate_key=True)
    steps = [_step_name(argv) for argv in world.host.ssh_commands()]
    assert steps == ['refresh', 'bootstrap', 'install',
                     'refresh', 'bootstrap', 'install',
                     'bootstrap', 'install']
    for argv in world.host.ssh_commands():
        assert f'UserKnownHostsFile={world.known_hosts}' in argv
        assert 'StrictHostKeyChecking=yes' in argv
        assert argv[1:3] == ['-F', '/dev/null']


@pytest.mark.parametrize('pin', [
    pytest.param('', id='empty'),
    pytest.param(None, id='missing'),
])
def test_unpinned_vm_host_key_refuses_before_any_ssh(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pin: str | None) -> None:
    world = managed_world(tmp_path, monkeypatch)
    if pin is None:
        world.known_hosts.unlink()
    else:
        world.known_hosts.write_text(pin)
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    assert exc.value.code == 'guest_setup'
    assert 'not pinned' in exc.value.detail
    assert world.host.ssh_commands() == []
    assert world.row() is None


@pytest.mark.skipif(os.getuid() == 0, reason='root reads a mode-000 file')
def test_root_only_pin_on_a_shared_store_keeps_strict_host_checking(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A group member who cannot read root's pin is still never TOFU."""
    import grp

    from aivm.scoped_store import resolve_store_scope

    world = managed_world(tmp_path, monkeypatch)
    layout = resolve_store_scope(str(world.store)).machine_layout
    assert layout is not None
    # Classify the sandbox store as the host-wide shared one, where the
    # bootstrap material -- the pinned known_hosts included -- is root's,
    # with this test user's own group as its trusted machine group.
    monkeypatch.setattr('aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', layout.root)
    monkeypatch.setenv('AIVM_MACHINE_GROUP', grp.getgrgid(os.getgid()).gr_name)
    world.known_hosts.chmod(0)
    messages = capture_logs(monkeypatch, 'aivm.secrets_identity_transport.log')
    activate_manager(monkeypatch, yes=True)
    try:
        world.enroll()
    finally:
        world.known_hosts.chmod(0o600)
    refresh, bootstrap, install = world.host.ssh_commands()
    for argv in (refresh, install):
        assert not any(part.startswith('UserKnownHostsFile=') for part in argv)
        assert 'StrictHostKeyChecking=yes' in argv
    # Root -- through sudo -- still reads the pin for the bootstrap channel.
    assert f'UserKnownHostsFile={world.known_hosts}' in bootstrap
    assert any(argv[:2] == ['sudo', '-n'] and argv[2] == 'ssh'
               for argv in world.host.commands)
    assert any('root-only' in message for message in messages)
    assert world.active() is True


def test_unreadable_pin_on_a_personal_store_refuses(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.getuid() == 0:
        pytest.skip('root reads a mode-000 file')
    world = managed_world(tmp_path, monkeypatch)
    world.known_hosts.chmod(0)
    activate_manager(monkeypatch, yes=True)
    try:
        with pytest.raises(SecretsError) as exc:
            world.enroll()
    finally:
        world.known_hosts.chmod(0o600)
    assert exc.value.code == 'unsafe_file'
    assert world.host.ssh_commands() == []


def test_failed_csr_refresh_issues_nothing_and_names_the_repair(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['refresh'] = lambda proceed: FakeProc(
        255, '', 'Host key verification failed.')
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    assert exc.value.code == 'guest_setup'
    assert 'aivm vm access reconcile' in exc.value.detail
    assert not world.host.ran('bootstrap')
    assert world.row() is None


@pytest.mark.parametrize('status, detail', [
    pytest.param(255, 'aivm vm access reconcile', id='ssh-channel-failed'),
    pytest.param(2, 'guest helper upgrade may be required', id='old-helper'),
])
def test_failed_forced_bootstrap_issues_nothing_and_says_why(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int,
        detail: str) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['bootstrap'] = lambda proceed: FakeProc(status, '', '')
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    assert exc.value.code == 'guest_setup'
    assert detail in exc.value.detail
    assert world.row() is None


def test_failed_install_revokes_exactly_the_issued_certificate(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['install'] = lambda proceed: FakeProc(1, '', 'rejected')
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    assert exc.value.code == 'guest_setup'
    assert 'guest certificate install failed' in exc.value.detail
    row = world.row()
    assert row is not None and row['active'] is False and row['epoch'] == 1
    assert world.host.ran('revoke-if-current')


def _decline(proceed: Callable[[], Any]) -> Any:
    # No post-issuance step prompts today (each is ownership='tool'), so the
    # refusal is raised where the manager raises a declined prompt: at the
    # moment the command would have run.
    raise UserDeclinedError('Aborted by user.')


def _interrupt(proceed: Callable[[], Any]) -> Any:
    raise KeyboardInterrupt()


def _run_logged_command(world: ManagedWorld, messages: list[str]) -> None:
    """Run the manual command a warning named, exactly as printed."""
    command = messages[-1].split('revoke it with: ', 1)[1]
    world.host.hooks.clear()
    done = world.host(shlex.split(command), capture_output=True, text=True,
                      timeout=60)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize('refuse', [
    pytest.param(_decline, id='declined'),
    pytest.param(_interrupt, id='interrupted'),
])
def test_refusal_after_issuance_runs_nothing_more_and_names_the_undo(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refuse: Hook) -> None:
    world = managed_world(tmp_path, monkeypatch)
    raised: list[BaseException] = []

    def refusing(proceed: Callable[[], Any]) -> Any:
        try:
            return refuse(proceed)
        except BaseException as ex:
            raised.append(ex)
            raise

    world.host.hooks['install'] = refusing
    warnings = capture_logs(monkeypatch, 'aivm.secrets_identity_transport.log',
                            levels=('warning',))
    activate_manager(monkeypatch, yes=True)
    with pytest.raises((UserDeclinedError, KeyboardInterrupt)) as exc:
        world.enroll()
    assert exc.value is raised[0]  # the refusal itself, never a SecretsError
    assert _step_name(_unprivileged(world.host.commands[-1])) == 'install'
    assert not world.host.ran('revoke-if-current')
    row = world.row()
    assert row is not None and row['active'] is True
    assert 'revoke-if-current' in warnings[-1]
    assert f"--expected-epoch={row['epoch']}" in warnings[-1]
    _run_logged_command(world, warnings)
    assert world.active() is False


def test_declined_undo_propagates_the_refusal_not_a_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['install'] = lambda proceed: FakeProc(1, '', 'rejected')
    world.host.hooks['revoke-if-current'] = _decline
    warnings = capture_logs(monkeypatch, 'aivm.secrets_identity_transport.log',
                            levels=('warning',))
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(UserDeclinedError):
        world.enroll()
    row = world.row()
    assert row is not None and row['active'] is True
    _run_logged_command(world, warnings)
    assert world.active() is False


def test_failed_undo_names_the_exact_revocation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['install'] = lambda proceed: FakeProc(1, '', 'rejected')
    world.host.hooks['revoke-if-current'] = lambda proceed: FakeProc(
        1, '', 'aivm-secrets: Host file ownership, permissions, or type is unsafe.')
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    assert exc.value.code == 'guest_setup'
    row = world.row()
    assert row is not None and row['active'] is True
    _run_logged_command(world, [exc.value.detail])
    assert world.active() is False


def _commit_then_time_out(proceed: Callable[[], Any]) -> Any:
    assert proceed().returncode == 0
    return FakeProc(124, '', 'command timed out')


def _commit_then_garble(proceed: Callable[[], Any]) -> Any:
    assert proceed().returncode == 0
    return FakeProc(0, '{"truncated', '')


def _refuse_without_commit(proceed: Callable[[], Any]) -> Any:
    return FakeProc(1, '', 'aivm-secrets: Operation is outside the granted authority.')


@pytest.mark.parametrize('issuance, committed', [
    pytest.param(_commit_then_time_out, True, id='timeout-after-commit'),
    pytest.param(_commit_then_garble, True, id='malformed-reply-after-commit'),
    pytest.param(_refuse_without_commit, False, id='refused'),
])
def test_lost_issuance_reply_reports_what_the_registry_now_holds(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issuance: Hook, committed: bool) -> None:
    """MISSING-8: an issuance that "failed" may still have committed."""
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['enroll'] = issuance
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    # Never revoked blindly: the advance could be another operator's.
    assert not world.host.ran('revoke-if-current')
    assert not world.host.ran('install')
    row = world.row()
    if not committed:
        assert exc.value.code == 'guest_setup'
        assert row is None
        return
    assert exc.value.code == 'outcome_unknown'
    assert row is not None and row['active'] is True
    subject = resolve_managed_identity(world.context, world.store,
                                       uuid_reader=lambda _: UUID).subject
    for fact in (subject, 'epoch %d' % row['epoch'], row['certificate_sha256']):
        assert fact in exc.value.detail
    _run_logged_command(world, [exc.value.detail])
    assert world.active() is False


def _text(done: Any) -> str:
    out = done.stdout
    return out.decode('ascii') if isinstance(out, bytes) else str(out)


def test_competing_renewal_is_reported_without_blaming_or_revoking_it(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A renewal that loses its compare-and-swap leaves the winner alone.

    The real issuing child refuses with exit status 1, which cannot prove
    that nothing was committed, so the registry is re-read. The operator is
    told what the registry now holds without being told, falsely, that no
    guest received it, and nothing is revoked.
    """
    world = managed_world(tmp_path, monkeypatch)
    activate_manager(monkeypatch, yes=True)
    world.enroll()
    before = world.row()
    assert before is not None
    world.host.commands.clear()

    def competitor_first(proceed: Callable[[], Any]) -> Any:
        # Another operator renews this subject during our CSR round trip.
        csr = (world.identity_dir / 'client.csr').read_bytes()
        IdentityAuthority(world.authority_root).renew_client(
            subject=world.subject, csr=csr, approve_fingerprint=inspect_csr(csr),
            expected_epoch=before['epoch'],
            expected_thumbprint=before['certificate_sha256'])
        return proceed()

    world.host.hooks['renew-client'] = competitor_first
    with pytest.raises(SecretsError) as exc:
        world.enroll(renew=True)
    row = world.row()
    assert row is not None and row['active'] is True
    assert row['epoch'] == before['epoch'] + 1
    assert exc.value.code == 'outcome_unknown'
    assert row['certificate_sha256'] in exc.value.detail
    assert 'another operator' in exc.value.detail
    assert 'no guest' not in exc.value.detail
    assert not world.host.ran('revoke-if-current')
    assert not world.host.ran('install')


def test_lost_issuance_is_seen_after_the_subject_row_restarted(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Epochs restart at 0 for a re-created row: compare certificates.

    This command reads the subject revoked at epoch 5. Before it issues, the
    row is removed (pruned, forgotten or erased by a CA rollover), so the
    issuance it then loses is epoch 0 -- below the epoch it observed.
    """
    world = managed_world(tmp_path, monkeypatch)
    reads: list[Any] = []

    def revoked_at_epoch_five_then_removed(proceed: Callable[[], Any]) -> Any:
        done = proceed()
        reads.append(done)
        if len(reads) > 1:
            return done
        status = json.loads(_text(done))
        assert world.subject not in status['subjects']
        status['subjects'][world.subject] = {
            'epoch': 5, 'active': False, 'certificate_sha256': 'R' * 43,
            'not_after': 1}
        return FakeProc(0, json.dumps(status), '')

    world.host.hooks['status'] = revoked_at_epoch_five_then_removed
    world.host.hooks['enroll'] = _commit_then_time_out
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    row = world.row()
    assert row is not None and row['active'] is True and row['epoch'] == 0
    assert exc.value.code == 'outcome_unknown'
    assert row['certificate_sha256'] in exc.value.detail
    assert not world.host.ran('revoke-if-current')
    _run_logged_command(world, [exc.value.detail])
    assert world.active() is False


def _commit_then_interrupt(proceed: Callable[[], Any]) -> Any:
    # Ctrl-C reaches the issuing child too, after it committed.
    assert proceed().returncode == 0
    raise KeyboardInterrupt()


def test_interrupt_during_issuance_runs_nothing_more_and_says_how_to_check(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = managed_world(tmp_path, monkeypatch)
    activate_manager(monkeypatch, yes=True)
    world.enroll()
    before = world.row()
    assert before is not None
    world.host.commands.clear()
    world.host.hooks['enroll'] = _commit_then_interrupt
    warnings = capture_logs(monkeypatch, 'aivm.secrets_identity_transport.log',
                            levels=('warning',))
    with pytest.raises(KeyboardInterrupt):
        world.enroll(replace=True)
    # Nothing ran after the interrupted child -- not even a registry read.
    assert _step_name(_unprivileged(world.host.commands[-1])) == 'enroll'
    issued = world.row()
    assert issued is not None and issued['active'] is True
    assert issued['epoch'] == before['epoch'] + 1
    message = warnings[-1]
    assert (f"other than epoch {before['epoch']} "
            f"(certificate {before['certificate_sha256']})") in message
    # Follow the warning: read the registry, then fence what it shows.
    world.host.hooks.clear()
    shown = world.host(shlex.split(message.split('`')[1]), capture_output=True,
                       text=True, timeout=60)
    now = json.loads(_text(shown))['subjects'][world.subject]
    command = message.split('revoke it with: ', 1)[1].replace(
        'EPOCH', str(now['epoch'])).replace(
        'CERTIFICATE_SHA256', now['certificate_sha256'])
    done = world.host(shlex.split(command), capture_output=True, text=True,
                      timeout=60)
    assert done.returncode == 0, done.stderr
    assert world.active() is False


def _issue_a_dash_thumbprint(world: ManagedWorld) -> Hook:
    """Issuing-step hook whose certificate's thumbprint begins with '-'.

    Base64url thumbprints do that about once in 64 certificates. Issue for
    real, then keep re-issuing in-process for the same CSR until one does,
    and reply with that certificate, which the registry then holds.
    """
    def hook(proceed: Callable[[], Any]) -> Any:
        done = proceed()
        assert done.returncode == 0, done.stderr
        record = json.loads(_text(done))
        csr = (world.identity_dir / 'client.csr').read_bytes()
        authority = IdentityAuthority(world.authority_root)
        for _ in range(4096):
            if record['certificate_sha256'].startswith('-'):
                return FakeProc(0, json.dumps(record), '')
            record = authority.enroll(subject=world.subject, csr=csr,
                                      approve_fingerprint=inspect_csr(csr),
                                      replace=True)
        pytest.fail("no certificate thumbprint began with '-'")
    return hook


@pytest.mark.parametrize('undo', ['automatic', 'manual'])
def test_a_thumbprint_beginning_with_a_dash_is_still_revocable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, undo: str) -> None:
    """The guarded revocation's argv must parse for every thumbprint."""
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['enroll'] = _issue_a_dash_thumbprint(world)
    world.host.hooks['install'] = lambda proceed: FakeProc(1, '', 'rejected')
    if undo == 'manual':
        world.host.hooks['revoke-if-current'] = lambda proceed: FakeProc(
            1, '', 'aivm-secrets: Host file ownership, permissions, or type is unsafe.')
    activate_manager(monkeypatch, yes=True)
    with pytest.raises(SecretsError) as exc:
        world.enroll()
    row = world.row()
    assert row is not None and row['certificate_sha256'].startswith('-')
    if undo == 'manual':
        assert row['active'] is True
        _run_logged_command(world, [exc.value.detail])
    assert world.active() is False


@pytest.mark.parametrize('rotate_key', [
    pytest.param(False, id='renew'),
    pytest.param(True, id='rotate-key'),
])
def test_renewal_of_a_certificate_whose_thumbprint_begins_with_a_dash(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rotate_key: bool) -> None:
    world = managed_world(tmp_path, monkeypatch)
    world.host.hooks['enroll'] = _issue_a_dash_thumbprint(world)
    activate_manager(monkeypatch, yes=True)
    enrolled = world.enroll()
    assert enrolled['certificate_sha256'].startswith('-')
    world.host.hooks.clear()
    renewed = world.enroll(renew=True, rotate_key=rotate_key)
    assert renewed['epoch'] == enrolled['epoch'] + 1
    row = world.row()
    assert row is not None and row['active'] is True
    assert row['certificate_sha256'] == renewed['certificate_sha256']
