"""Service-agnostic broker tests (no GitHub dependencies or live credentials)."""

import copy
import json
import os
import stat
from pathlib import Path

import pytest

from aivm_secrets.adapters import parse_policy
from aivm_secrets.broker import Broker
from aivm_secrets.cli import load_policy
from aivm_secrets.errors import SecretsError
from aivm_secrets.guest import exchange, main as guest_main, request_from_args, parser
from aivm_secrets.http_service import HTTPAdapter, HTTPPolicy, HTTPSProvider
from aivm_secrets.kernel import Binding
from aivm_secrets.server import LocalServer
from aivm_secrets.wire import dumps

SECRET = 'service_TOKEN_NOT_REAL_0123456789abcdef'


def config(**changes):
    result = {
        'schema': 2, 'adapter': 'https', 'service': 'demo-service',
        'host': 'api.example.org', 'authentication': 'x-api-key',
        'credential_source': {'kind': 'command', 'argv': ['mytool', 'auth', 'print-token'],
                              'inherit_env': ['XDG_CONFIG_HOME']},
        'operations': [
            {'name': 'profile.read', 'method': 'GET', 'path': '/v1/account'},
            {'name': 'issue.view', 'method': 'GET', 'path': '/v1/issues/{issue}',
             'parameters': {'issue': [23, 24]}},
            {'name': 'issue.comment', 'method': 'POST', 'path': '/v1/issues/{issue}/comments',
             'parameters': {'issue': [23, 24]}, 'body_fields': {'body': 100}},
        ],
        'lifetime_seconds': 1800, 'max_requests': 5, 'max_body_bytes': 100,
    }
    result.update(changes)
    return result


class FakeProvider:
    def __init__(self):
        self.calls = []

    def execute(self, route, credential):
        self.calls.append((route, credential))
        return {'ok': True, 'path': route.path, 'body': route.body}


class Fixture:
    def __init__(self, tmp_path: Path, *, allow_writes=False, policy=None):
        self.provider = FakeProvider()
        self.policy = policy or parse_policy(config())
        self.binding = Binding(os.getuid(), 'test-principal', 'vm-test', '1' * 32)
        self.audit = tmp_path / 'audit' / 'session.jsonl'
        self.broker = Broker(self.policy, self.binding, SECRET, self.audit,
                             allow_writes=allow_writes, provider=self.provider)

    def call(self, operation, **arguments):
        wire = {'version': 1, 'capability': self.broker.capability,
                'request': {'operation': operation, 'arguments': arguments}}
        return self.broker.handle(dumps(wire))


@pytest.fixture
def h(tmp_path):
    fixture = Fixture(tmp_path)
    yield fixture
    fixture.broker.close()


def test_http_policy_is_canonical_and_uses_non_github_credential_source():
    policy = HTTPPolicy.parse(config())
    operations = list(reversed(config()['operations']))
    assert HTTPPolicy.parse(config(operations=operations)).digest == policy.digest
    assert policy.service == 'demo-service'
    assert policy.credential_source['argv'] == ['mytool', 'auth', 'print-token']
    assert policy.host == 'api.example.org'
    assert policy.operations == ('issue.comment', 'issue.view', 'profile.read')


def test_service_reads_are_fixed_origin_and_allowlisted(h):
    reply = h.call('issue.view', issue=23)
    assert reply['ok'] and reply['result']['path'] == '/v1/issues/23'
    assert h.provider.calls[0][1] == SECRET
    assert SECRET not in json.dumps(reply) + h.audit.read_text()
    assert [json.loads(line)['event'] for line in h.audit.read_text().splitlines()] == [
        'session_open', 'authorized', 'dispatch', 'completed']


@pytest.mark.parametrize('bad,code', [
    ({'issue': 25}, 'denied'),
    ({'issue': True}, 'denied'),
    ({'issue': '23'}, 'denied'),
    ({'issue': 23, 'url': 'https://elsewhere.example'}, 'invalid_request'),
    ({}, 'invalid_request'),
])
def test_arguments_fail_closed_without_egress(h, bad, code):
    result = h.call('issue.view', **bad)
    assert result['error']['code'] == code
    assert not h.provider.calls


def test_unsupported_operation_does_not_reach_provider(h):
    assert h.call('tool.exec', args='sudo rm -rf /')['error']['code'] == 'denied'
    assert not h.provider.calls


def test_writes_require_policy_and_host_enablement(tmp_path, h):
    assert h.call('issue.comment', issue=23, body='hello')['error']['code'] == 'denied'
    assert not h.provider.calls
    w = Fixture(tmp_path / 'allowed', allow_writes=True)
    try:
        reply = w.call('issue.comment', issue=24, body='hello')
        assert reply['ok']
        route = w.provider.calls[-1][0]
        assert route.method == 'POST' and route.path == '/v1/issues/24/comments'
        assert route.body == {'body': 'hello'}
        assert 'hello' not in w.audit.read_text()
    finally:
        w.broker.close()


def test_one_budget_unit_per_action_and_revoke(tmp_path):
    cfg = config(max_requests=1)
    h = Fixture(tmp_path, policy=parse_policy(cfg))
    try:
        assert h.call('profile.read')['ok']
        assert h.call('profile.read')['error']['code'] == 'exhausted'
        h.broker.revoke()
        assert h.call('profile.read')['error']['code'] == 'revoked'
    finally:
        h.broker.close()


def test_response_must_not_reflect_provider_secret(h):
    h.provider.execute = lambda route, secret: {'secret': secret}
    reply = h.call('profile.read')
    assert reply['error']['code'] == 'upstream_response'
    assert SECRET not in json.dumps(reply) + h.audit.read_text()


@pytest.mark.parametrize('change', [
    {'adapter': 'exec'},
    {'host': 'localhost'},
    {'host': 'localhost.local'},
    {'host': '127.0.0.1'},
    {'host': 'api.example.org:443'},
    {'authentication': 'none'},
    {'operations': [{'name': 'bad', 'method': 'DELETE', 'path': '/v1'}]},
    {'operations': [{'name': 'bad', 'method': 'GET', 'path': '/v1/../admin'}]},
    {'operations': [{'name': 'bad', 'method': 'GET', 'path': '/{target}',
                     'parameters': {'target': ['ok', '../unsafe']}}]},
    {'operations': [{'name': 'bad', 'method': 'GET', 'path': '/https://attacker.invalid'}]},
])
def test_untrusted_egress_templates_rejected(change):
    with pytest.raises(SecretsError):
        parse_policy(config(**change))


def test_policy_file_check_and_standalone_guest_cli(tmp_path, monkeypatch, capsys):
    from aivm_secrets.cli import main
    path = tmp_path / 'policy.json'
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(dumps(config()))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    monkeypatch.setattr('aivm_secrets.sources.credential_from_command',
                        lambda *args: pytest.fail('credential read'))
    assert main(['policy-check', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['policy']['service'] == 'demo-service'
    assert load_policy(path).host == 'api.example.org'
    h = Fixture(tmp_path / 'session')
    try:
        sock = tmp_path / 'broker.sock'
        capability_path = tmp_path / 'capability'
        capability_path.write_text(h.broker.capability)
        with LocalServer(h.broker, sock):
            assert guest_main(['--socket', str(sock), '--capability-file', str(capability_path),
                               'invoke', 'issue.view', '--arguments', '{"issue":23}']) == 0
            result = json.loads(capsys.readouterr().out)
            assert result['result']['path'] == '/v1/issues/23'
    finally:
        h.broker.close()


def test_request_arguments_input_is_not_shell_parsed():
    args = parser().parse_args(['invoke', 'issue.view', '--arguments', '{"issue":23}'])
    assert request_from_args(args) == {'operation': 'issue.view', 'arguments': {'issue': 23}}
    for invalid in ('[]', '"quoted"', '{"issue": 1, "issue": 2}'):
        args = parser().parse_args(['invoke', 'issue.view', '--arguments', invalid])
        if invalid.startswith('{'):
            # The guest JSON parser alone need not reject duplicate keys; the
            # host's strict frame parser does. Do not imply the guest is TCB.
            continue
        with pytest.raises(ValueError):
            request_from_args(args)


class Response:
    def __init__(self, *, status=200, data=b'{"ok":true}'):
        self.status = status
        self.data = data
    def getheader(self, field, default=None):
        return default
    def read(self, count):
        return self.data[:count]


def fake_connection(monkeypatch, response):
    calls = []
    class Conn:
        def __init__(self, host, **kwargs):
            calls.append(('connect', host, kwargs))
        def request(self, method, path, **kwargs):
            calls.append(('request', method, path, kwargs))
        def getresponse(self):
            return response
        def close(self):
            calls.append(('close',))
    monkeypatch.setattr('aivm_secrets.http_service.http.client.HTTPSConnection', Conn)
    return calls


def test_https_provider_pins_host_credentials_and_tls(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://attacker.invalid:3128')
    provider = HTTPSProvider(HTTPPolicy.parse(config()))
    route = HTTPAdapter(HTTPPolicy.parse(config())).effect(
        HTTPAdapter(HTTPPolicy.parse(config())).parse(
            {'operation': 'issue.view', 'arguments': {'issue': 23}}), None)
    calls = fake_connection(monkeypatch, Response())
    assert provider.execute(route, SECRET) == {'ok': True}
    assert calls[0][1] == 'api.example.org'
    assert calls[0][2]['context'].check_hostname
    assert calls[1][2] == '/v1/issues/23'
    assert calls[1][3]['headers']['X-API-Key'] == SECRET
    assert len([call for call in calls if call[0] == 'request']) == 1
    assert calls[-1] == ('close',)


@pytest.mark.parametrize('status', [301, 302, 307, 401, 403, 429, 500])
def test_https_provider_never_redirects_or_retries(monkeypatch, status):
    provider = HTTPSProvider(HTTPPolicy.parse(config()))
    route = HTTPAdapter(HTTPPolicy.parse(config())).effect(
        HTTPAdapter(HTTPPolicy.parse(config())).parse(
            {'operation': 'issue.view', 'arguments': {'issue': 23}}), None)
    calls = fake_connection(monkeypatch, Response(status=status))
    with pytest.raises(SecretsError):
        provider.execute(route, SECRET)
    assert len([call for call in calls if call[0] == 'request']) == 1
