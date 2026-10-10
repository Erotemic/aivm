import os

import pytest

from aivm.commands import CommandResult
from aivm.config import AgentVMConfig
from aivm.services import PreparedSession
from aivm_secrets.errors import SecretsError
from tests.helpers import resolved_test_context
from tests.secrets_helpers import FakeProvider, TOKEN, write_policy_file


def session_fixture(tmp_path):
    cfg = AgentVMConfig()
    cfg.vm.name = 'test-vm'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = str(tmp_path / 'identity')
    cfg.paths.state_dir = str(tmp_path / 'state')
    context = resolved_test_context(cfg, principal_id='principal-test', guest_user='agent',
                                    host_uid=os.getuid())
    source = tmp_path / 'project'
    source.mkdir()
    return PreparedSession(context=context, cfg_path=tmp_path / 'config.toml',
                           host_src=source, attachment_mode='persistent',
                           share_source_dir=str(source), share_tag='hostcode',
                           share_guest_dst='/home/agent/code/project', ip='10.0.0.2',
                           reg_path=tmp_path / 'config.toml', meta_path=None)


def test_foreground_adapter_carries_only_ciphertext_and_revokes(tmp_path, monkeypatch):
    from aivm.secrets_transport import run_secrets_ssh
    from aivm_secrets.broker import Broker
    from aivm_secrets.guest import exchange

    session = session_fixture(tmp_path)
    policy_path = write_policy_file(tmp_path / 'policy.json')
    provider = FakeProvider()
    brokers = []
    def create(*args, **kwargs):
        instance = Broker(*args, **kwargs, provider=provider)
        brokers.append(instance)
        return instance
    monkeypatch.setattr('aivm_secrets.broker.Broker', create)
    monkeypatch.setattr('aivm_secrets.sources.credential_from_gh', lambda: TOKEN)
    calls = []
    class Manager:
        def run(self, cmd, **kwargs):
            calls.append((cmd, kwargs))
            assert TOKEN not in ' '.join(cmd)
            assert TOKEN not in str(kwargs.get('input_text', ''))
            if '-R' in cmd:
                forwarding = cmd[cmd.index('-R') + 1]
                host_socket = forwarding.split(':', 1)[1]
                reply = exchange(host_socket, brokers[0].capability,
                                 {'operation': 'pr.view', 'repository': 'TauCetiProject/TauCeti', 'pr': 13861})
                assert reply['ok']
                assert 'ControlPath=none' in cmd and 'ExitOnForwardFailure=yes' in cmd
                assert 'StrictHostKeyChecking=yes' in cmd
                assert '-F' in cmd and '/dev/null' in cmd
            return CommandResult(0, '', '')
    monkeypatch.setattr('aivm.secrets_transport.CommandManager.current', lambda: Manager())
    result = run_secrets_ssh(session, ['ssh', '-t', '-i', '/identity', 'agent@10.0.0.2',
                                       'cd /home/agent/code/project && exec $SHELL -l'],
                             policy_path=policy_path)
    assert result.code == 0 and len(provider.calls) == 1
    ciphertext = next(kwargs['input_text'] for _, kwargs in calls
                      if str(kwargs.get('input_text', '')).startswith('aivs1.'))
    assert all(ciphertext not in ' '.join(cmd) for cmd, _ in calls)
    assert brokers[0].capability == ''
    assert brokers[0].handle(b'{}')['error']['code'] == 'revoked'
    assert any('rm -f' in cmd[-1] for cmd, _ in calls)


def test_adapter_rejects_shared_policy_before_credential_access(tmp_path, monkeypatch):
    from aivm.secrets_transport import run_secrets_ssh
    session = session_fixture(tmp_path)
    path = write_policy_file(session.host_src / 'policy.json')
    monkeypatch.setattr('aivm_secrets.sources.credential_from_gh', lambda: pytest.fail('credential read'))
    with pytest.raises(SecretsError) as exc:
        run_secrets_ssh(session, [], policy_path=path)
    assert exc.value.code == 'shared_source'


def test_adapter_refuses_cross_principal_secrets(tmp_path, monkeypatch):
    from dataclasses import replace
    from aivm.secrets_transport import run_secrets_ssh
    session = session_fixture(tmp_path)
    session = replace(session, context=replace(session.context,
                       principal=replace(session.context.principal, host_uid=os.getuid() + 1)))
    monkeypatch.setattr('aivm_secrets.sources.credential_from_gh', lambda: pytest.fail('credential read'))
    with pytest.raises(SecretsError) as exc:
        run_secrets_ssh(session, [], policy_path=tmp_path / 'missing')
    assert exc.value.code == 'wrong_owner'


def test_cli_secret_options_without_policy_do_not_prepare_vm(monkeypatch):
    from aivm.cli.vm_connect import VMSSHCLI
    monkeypatch.setattr('aivm.cli.vm_connect._prepare_foreground_session',
                        lambda args: pytest.fail('VM prepared'))
    assert VMSSHCLI.main(argv=False, secrets_token_file='token', yes=True) == 1
    assert VMSSHCLI.main(argv=False, secrets_allow_writes=True, yes=True) == 1


@pytest.mark.parametrize('failing_stage', [1, 2, 3])
def test_failed_guest_setup_revokes_without_exposing_guest_echo(tmp_path, monkeypatch, failing_stage):
    from aivm.secrets_transport import run_secrets_ssh
    from aivm_secrets.broker import Broker
    session = session_fixture(tmp_path)
    path = write_policy_file(tmp_path / 'policy.json')
    brokers = []
    def create(*args, **kwargs):
        instance = Broker(*args, **kwargs, provider=FakeProvider())
        brokers.append(instance)
        return instance
    monkeypatch.setattr('aivm_secrets.broker.Broker', create)
    monkeypatch.setattr('aivm_secrets.sources.credential_from_gh', lambda: TOKEN)
    class Manager:
        calls = 0
        def run(self, cmd, **kwargs):
            self.calls += 1
            if self.calls == failing_stage:
                return CommandResult(1, TOKEN, str(kwargs.get('input_text', '')))
            return CommandResult(0, '', '')
    manager = Manager()
    monkeypatch.setattr('aivm.secrets_transport.CommandManager.current', lambda: manager)
    with pytest.raises(SecretsError) as exc:
        run_secrets_ssh(session, ['ssh', 'agent@10.0.0.2', 'exec $SHELL -l'], policy_path=path)
    assert exc.value.code == 'guest_setup' and TOKEN not in str(exc.value)
    assert brokers[0].capability == ''
    assert brokers[0].handle(b'{}')['error']['code'] == 'revoked'


def test_generic_service_ssh_adapter_does_not_install_gh_shim(tmp_path, monkeypatch):
    """Schema 2 can obtain a host credential from a non-GitHub resolver."""
    from aivm.secrets_transport import run_secrets_ssh
    from aivm_secrets.broker import Broker
    from aivm_secrets.guest import exchange
    from aivm_secrets.wire import dumps

    session = session_fixture(tmp_path)
    policy = {
        'schema': 2, 'adapter': 'https', 'service': 'service-test',
        'host': 'api.example.org', 'authentication': 'bearer',
        'credential_source': {'kind': 'command', 'argv': ['mytool', 'auth', 'token']},
        'operations': [{'name': 'account.read', 'method': 'GET', 'path': '/v1/me'}],
    }
    path = tmp_path / 'generic-policy.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(dumps(policy))

    class Provider:
        def __init__(self):
            self.calls = []
        def execute(self, route, token):
            self.calls.append((route, token))
            return {'account': 'example'}

    provider = Provider()
    brokers = []
    def create(*args, **kwargs):
        instance = Broker(*args, **kwargs, provider=provider)
        brokers.append(instance)
        return instance
    monkeypatch.setattr('aivm_secrets.broker.Broker', create)
    monkeypatch.setattr('aivm_secrets.sources.resolve_source', lambda source: TOKEN)
    monkeypatch.setattr('aivm.secrets_transport.shutil.which', lambda binary: '/usr/bin/mytool')

    class Manager:
        def run(self, cmd, **kwargs):
            assert TOKEN not in ' '.join(cmd) and TOKEN not in str(kwargs.get('input_text', ''))
            if '-R' in cmd:
                host_socket = cmd[cmd.index('-R') + 1].split(':', 1)[1]
                assert exchange(host_socket, brokers[0].capability,
                                {'operation': 'account.read', 'arguments': {}})['ok']
                assert 'AIVM_SECRETS_CLIENT=' in cmd[-1]
                assert '/aivm-secrets' in cmd[-1]
                assert '/gh;' not in cmd[-1]
            return CommandResult(0, '', '')

    monkeypatch.setattr('aivm.secrets_transport.CommandManager.current', lambda: Manager())
    result = run_secrets_ssh(session, ['ssh', 'agent@10.0.0.2', 'exec $SHELL -l'],
                             policy_path=path)
    assert result.code == 0
    assert len(provider.calls) == 1 and provider.calls[0][1] == TOKEN
    assert brokers[0].capability == ''


def test_generic_source_executable_must_not_reside_in_shared_tree(tmp_path, monkeypatch):
    from aivm.secrets_transport import run_secrets_ssh
    from aivm_secrets.wire import dumps
    session = session_fixture(tmp_path)
    resolver = session.host_src / 'resolver'
    resolver.write_text('#!/bin/sh\n')
    resolver.chmod(0o700)
    path = tmp_path / 'policy.json'
    policy = {
        'schema': 2, 'adapter': 'https', 'service': 'source-check',
        'host': 'api.example.org', 'authentication': 'bearer',
        'credential_source': {'kind': 'command', 'argv': [str(resolver)]},
        'operations': [{'name': 'read', 'method': 'GET', 'path': '/v1/ok'}],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(dumps(policy))
    monkeypatch.setattr('aivm_secrets.sources.resolve_source',
                        lambda source: pytest.fail('host resolver executed'))
    with pytest.raises(SecretsError) as ex:
        run_secrets_ssh(session, ['ssh', 'agent@10.0.0.2', 'exec $SHELL -l'],
                        policy_path=path)
    assert ex.value.code == 'shared_source'
