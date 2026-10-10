import json
import os
import socket
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from aivm_secrets.cli import main
from aivm_secrets.core import Route
from aivm_secrets.errors import SecretsError
from aivm_secrets.files import read_owned
from aivm_secrets.guest import exchange, main as guest_main
from aivm_secrets.provider import GitHubProvider, HOST, MAX_RESPONSE
from aivm_secrets.server import LocalServer
from aivm_secrets.sources import credential_from_file, credential_from_gh
from aivm_secrets.wire import read_frame
from tests.secrets_helpers import Harness, TOKEN, write_policy_file


def test_real_unix_socket_and_standalone_guest_client(tmp_path, capsys):
    h = Harness(tmp_path)
    try:
        with tempfile.TemporaryDirectory(prefix='as-test-') as directory:
            path = Path(directory) / 'broker.sock'
            capfile = Path(directory) / 'capability'
            capfile.write_text(h.broker.capability)
            with LocalServer(h.broker, path):
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                assert guest_main(['--socket', str(path), '--capability-file', str(capfile),
                                   'pr', 'view', '13861', '--repo', 'TauCetiProject/TauCeti']) == 0
                output = capsys.readouterr().out
                assert json.loads(output)['result']['number'] == 13861
                assert TOKEN not in output and h.broker.capability not in output
            assert not path.exists()
    finally:
        h.broker.close()


def test_real_socket_wrong_capability_and_malformed_request(tmp_path):
    h = Harness(tmp_path)
    try:
        with tempfile.TemporaryDirectory(prefix='as-test-') as directory:
            path = Path(directory) / 'b.sock'
            with LocalServer(h.broker, path):
                response = exchange(str(path), 'invalid',
                                    {'operation': 'pr.view', 'repository': 'TauCetiProject/TauCeti', 'pr': 13861})
                assert response['error']['code'] == 'invalid_capability'
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(path))
                    client.sendall(b'{"version":1,"version":1}\n')
                    assert json.loads(read_frame(client))['error']['code'] == 'invalid_request'
                assert not h.provider.calls
    finally:
        h.broker.close()


def test_concurrent_requests_cannot_exceed_session_budget(tmp_path):
    h = Harness(tmp_path, max_requests=3)
    request = {'operation': 'pr.view', 'repository': 'TauCetiProject/TauCeti', 'pr': 13861}
    try:
        with tempfile.TemporaryDirectory(prefix='as-test-') as directory:
            path = Path(directory) / 'b.sock'
            with LocalServer(h.broker, path):
                with ThreadPoolExecutor(max_workers=6) as pool:
                    replies = list(pool.map(lambda _: exchange(str(path), h.broker.capability, request), range(6)))
            assert sum(reply['ok'] for reply in replies) == 3
            assert len(h.provider.calls) == 3
    finally:
        h.broker.close()


def test_existing_socket_path_is_not_unlinked(tmp_path):
    h = Harness(tmp_path)
    try:
        with tempfile.TemporaryDirectory(prefix='as-test-') as directory:
            path = Path(directory) / 'b.sock'
            path.write_text('must survive')
            with pytest.raises(SecretsError):
                with LocalServer(h.broker, path):
                    pass
            assert path.read_text() == 'must survive'
    finally:
        h.broker.close()


def test_wire_absolute_deadline_and_size():
    left, right = socket.socketpair()
    try:
        right.sendall(b'not-finished')
        with pytest.raises(SecretsError):
            read_frame(left, timeout=0.02)
        right.sendall(b'x' * 20)
        with pytest.raises(SecretsError):
            read_frame(left, limit=8)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize('data', [b'{}\n{}\n', b'{}'])
def test_wire_denies_pipelining_and_incomplete_frames(data):
    left, right = socket.socketpair()
    try:
        right.sendall(data)
        right.shutdown(socket.SHUT_WR)
        with pytest.raises(SecretsError):
            read_frame(left)
    finally:
        left.close()
        right.close()


def test_policy_check_does_not_acquire_credential(tmp_path, monkeypatch, capsys):
    path = write_policy_file(tmp_path / 'policy.json')
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    monkeypatch.setattr('aivm_secrets.cli.credential_from_gh', lambda: pytest.fail('credential read'))
    assert main(['policy-check', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['policy']['repository'] == 'taucetiproject/tauceti'


@pytest.mark.parametrize('arguments', [
    ['api', '/user'], ['pr', 'merge', '1', '--repo', 'x/y'],
    ['pr', 'view', '1', '--repo', 'x/y', '--web'],
    ['pr', 'comment', '1', '--repo', 'x/y'],
])
def test_client_has_no_stock_gh_or_shell_fallback(arguments):
    with pytest.raises(SystemExit) as exc:
        guest_main(arguments)
    assert exc.value.code == 2


def test_private_token_file_checks(tmp_path):
    path = tmp_path / 'token'
    path.write_text(TOKEN + '\n')
    path.chmod(0o600)
    assert credential_from_file(path) == TOKEN
    path.chmod(0o644)
    with pytest.raises(SecretsError):
        credential_from_file(path)
    path.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(SecretsError):
        credential_from_file(link)
    hard = tmp_path / 'hard'
    os.link(path, hard)
    with pytest.raises(SecretsError):
        credential_from_file(path)


def test_policy_file_rejects_group_writes(tmp_path):
    path = tmp_path / 'policy'
    path.write_text('{}')
    path.chmod(0o664)
    with pytest.raises(SecretsError):
        read_owned(path, private=False)


def test_fifo_and_oversized_file_are_rejected_without_blocking(tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo, 0o600)
    with pytest.raises(SecretsError):
        read_owned(fifo, private=True)
    large = tmp_path / 'large'
    large.write_bytes(b'x' * 11)
    large.chmod(0o600)
    with pytest.raises(SecretsError):
        read_owned(large, private=True, limit=10)


def test_gh_source_is_fixed_command_and_never_logs_output(monkeypatch, capsys):
    from types import SimpleNamespace
    seen = []
    monkeypatch.setenv('GH_DEBUG', 'api')
    monkeypatch.setattr('aivm_secrets.sources.shutil.which', lambda name: '/usr/bin/gh')
    def run(cmd, **kwargs):
        seen.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout=TOKEN + '\n', stderr='')
    monkeypatch.setattr('aivm_secrets.sources.subprocess.run', run)
    assert credential_from_gh() == TOKEN
    assert seen[0][0] == ['/usr/bin/gh', 'auth', 'token', '--hostname', 'github.com']
    assert 'GH_DEBUG' not in seen[0][1]['env']
    assert not capsys.readouterr().out


class FakeResponse:
    status = 200
    data = b'{"ok":true}'
    encoding = 'identity'
    def getheader(self, name, default=None):
        return self.encoding if name == 'Content-Encoding' else default
    def read(self, count):
        return self.data[:count]


def fake_https(monkeypatch, response):
    seen = []
    class Connection:
        def __init__(self, host, **kwargs):
            seen.append(('connect', host, kwargs))
        def request(self, method, path, **kwargs):
            seen.append(('request', method, path, kwargs))
        def getresponse(self):
            return response
        def close(self):
            seen.append(('close',))
    monkeypatch.setattr('aivm_secrets.provider.http.client.HTTPSConnection', Connection)
    return seen


def test_egress_uses_fixed_verified_tls_origin_not_proxy_environment(monkeypatch):
    import ssl
    monkeypatch.setenv('HTTPS_PROXY', 'http://attacker.invalid:8888')
    seen = fake_https(monkeypatch, FakeResponse())
    assert GitHubProvider().execute(Route('GET', '/repos/x/y/pulls/1'), TOKEN) == {'ok': True}
    assert seen[0][1] == HOST
    context = seen[0][2]['context']
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert seen[1][3]['headers']['Authorization'] == 'Bearer ' + TOKEN
    assert len([item for item in seen if item[0] == 'request']) == 1
    assert seen[-1] == ('close',)


@pytest.mark.parametrize('status', [301, 302, 307, 308, 401, 403, 429, 500])
def test_egress_never_follows_redirects_or_retries(monkeypatch, status):
    response = FakeResponse()
    response.status = status
    seen = fake_https(monkeypatch, response)
    with pytest.raises(SecretsError):
        GitHubProvider().execute(Route('GET', '/repos/x/y/pulls/1'), TOKEN)
    assert len([item for item in seen if item[0] == 'request']) == 1


@pytest.mark.parametrize('data,encoding', [(b'x' * (MAX_RESPONSE + 1), 'identity'),
                                        (b'{"secret":NaN}', 'identity'),
                                        (b'compressed', 'gzip')])
def test_egress_rejects_unbounded_or_ambiguous_payloads(monkeypatch, data, encoding):
    response = FakeResponse()
    response.data, response.encoding = data, encoding
    fake_https(monkeypatch, response)
    with pytest.raises(SecretsError):
        GitHubProvider().execute(Route('GET', '/repos/x/y/pulls/1'), TOKEN)


def test_failed_write_response_is_not_safe_to_retry(monkeypatch):
    response = FakeResponse()
    response.data = b'broken-json'
    fake_https(monkeypatch, response)
    with pytest.raises(SecretsError) as exc:
        GitHubProvider().execute(Route('POST', '/repos/x/y/issues/1/comments', body={'body': 'text'}), TOKEN)
    assert exc.value.code == 'outcome_unknown'


def test_kernel_peer_uid_must_match_listener_binding(tmp_path):
    from dataclasses import replace
    h = Harness(tmp_path)
    h.broker.binding = replace(h.broker.binding, owner_uid=os.getuid() + 1)
    try:
        with tempfile.TemporaryDirectory(prefix='as-test-') as directory:
            path = Path(directory) / 'b.sock'
            with LocalServer(h.broker, path):
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(2)
                    client.connect(str(path))
                    try:
                        client.sendall(h.raw() + b'\n')
                        assert client.recv(1) == b''
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                assert not h.provider.calls
    finally:
        h.broker.close()
