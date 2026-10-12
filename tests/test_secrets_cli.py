"""The host operator CLI, run as a real process against a real TLS provider.

Nothing in these tests is faked inside the broker: ``aivm-secrets serve`` is
started exactly as AIVM starts it, resolves its own credential, and talks to
``TLSService`` over verified TLS. The assertions are on what the *provider
received*, what the client was told, and what is left on disk afterwards.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from aivm_secrets import cli
from aivm_secrets.kernel import codec
from tests.secrets_helpers import (
    SERVICE_TOKEN,
    ServeProcess,
    TLSService,
    cli_env,
    github_policy,
    https_policy,
    poison,
    ran_as_broker,
    run_cli_process,
    write_policy_file,
    write_private,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
# Wherever the package under test is installed: a checkout or site-packages.
INSTALL_ROOT = Path(cli.__file__).resolve().parent.parent


@pytest.fixture
def root():
    """A short private directory: socket paths must fit in ``sun_path``."""
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.fixture
def world(root):
    """A provider, a credential file, a policy and a clean environment."""
    with TLSService(root) as service:
        service.routes[('GET', '/v1/account')] = {'login': 'demo'}
        service.routes[('GET', '/v1/issues/23')] = {
            'id': 23,
            'title': 'Example',
        }
        service.routes[('POST', '/v1/issues/23/comments')] = {'created': True}
        token = write_private(root / 'token', (SERVICE_TOKEN + '\n').encode())
        policy = write_policy_file(root / 'policy.json', service.policy(token))
        yield type(
            'World', (), {
                'service': service, 'token': token, 'policy': policy,
                'env': cli_env(root), 'root': root,
            },
        )  # fmt: skip


def serve(world, *argv, policy=None, env=None, flags=('-I',)):
    return ServeProcess(
        ['--policy', str(policy or world.policy), *argv],
        env=env or world.env,
        flags=flags,
    )


def code(reply):
    assert reply['ok'] is False
    return reply['error']['code']


# -- policy-check ------------------------------------------------------------


def test_policy_check_does_not_acquire_credential(root, capsys):
    """Validation never runs a resolver: this one does not even exist."""
    path = write_policy_file(root / 'policy.json', https_policy())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cli.main(['policy-check', str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['policy']['service'] == 'demo-service'
    assert report['policy']['egress'] == {'port': 443}
    assert len(report['digest']) == 64
    legacy = write_policy_file(root / 'legacy.json', github_policy())
    assert cli.main(['policy-check', str(legacy)]) == 0
    # The shorthand is shown as what it stands for: the whole manifest,
    # fact checks and command table included, ready to be copied and edited.
    expanded = json.loads(capsys.readouterr().out)['policy']
    assert (expanded['schema'], expanded['service']) == (2, 'github-pr')
    assert expanded['host'] == 'api.github.com'
    assert [item['at'] for item in expanded['checks']['pull']['require']] == [
        ['number'],
        ['base', 'repo', 'full_name'],
        ['user', 'login'],
        ['head', 'repo', 'full_name'],
    ]
    assert len(expanded['cli']['gh']) == 8
    copied = write_policy_file(root / 'copied.json', expanded)
    assert cli.main(['policy-check', str(copied)]) == 0
    assert json.loads(capsys.readouterr().out)['policy'] == expanded


def test_policy_check_explains_refusals_to_the_operator(root, capsys):
    bad = write_private(root / 'bad.json', b'{"schema": 2')
    assert cli.main(['policy-check', str(bad)]) == 1
    assert 'Invalid policy' in capsys.readouterr().err
    loose = write_policy_file(root / 'loose.json', https_policy())
    loose.chmod(0o666)
    assert cli.main(['policy-check', str(loose)]) == 1
    error = capsys.readouterr().err
    assert 'unsafe' in error and str(loose) in error and 'writable' in error
    assert cli.main(['policy-check', str(root / 'missing.json')]) == 1
    unknown = write_policy_file(
        root / 'unknown.json', https_policy(allow_writes=True)
    )
    assert cli.main(['policy-check', str(unknown)]) == 1


def test_shipped_example_policies_are_valid(capsys):
    examples = sorted(
        (REPO_ROOT / 'docs' / 'examples').glob('aivm-secrets-*.json')
    )
    assert len(examples) >= 4
    from aivm_secrets.kernel.service import parse_policy

    for path in examples:
        spec = parse_policy(codec.loads(path.read_bytes(), limit=1 << 20))
        assert spec.scope(), path.name


# -- serve -------------------------------------------------------------------


def test_serve_end_to_end_over_real_tls_and_clean_teardown(world):
    with serve(world) as broker:
        announce = broker.announce
        assert announce['aivm_secrets'] == 1 and announce['writes'] == 'deny'
        assert announce['service'] == 'e2e-service'
        assert announce['client'].endswith('aivm_secrets/guest.py')
        directory = Path(announce['socket']).parent
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        capability_file = Path(announce['capability_file'])
        assert stat.S_IMODE(capability_file.stat().st_mode) == 0o600
        capability = capability_file.read_text()
        assert (
            capability.startswith('aivs1.') and SERVICE_TOKEN not in capability
        )

        reply = broker.invoke('issue.view', issue=23)
        assert reply == {
            'version': 1,
            'ok': True,
            'result': {'id': 23, 'title': 'Example'},
        }
        assert code(broker.invoke('issue.view', issue=99)) == 'denied'
        assert (
            code(broker.invoke('issue.comment', issue=23, body='hi'))
            == 'denied'
        )
        # The provider saw exactly one request, carrying the real credential.
        (seen,) = world.service.requests
        assert seen['target'] == '/v1/issues/23'
        assert seen['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
        audit = Path(announce['audit'])
        assert broker.stop() == 0

    assert broker.stderr == ''
    assert not directory.exists()  # sockets and ciphertext are gone
    assert broker.cli('audit-verify', str(audit)).returncode == 0
    text = audit.read_text()
    assert SERVICE_TOKEN not in text and capability not in text
    events = [json.loads(line)['event'] for line in text.splitlines()]
    assert events[0] == 'session_open' and events[-1] == 'session_close'
    # The key died with the process: a new session cannot open old ciphertext.
    with serve(world) as second:
        assert code(
            second.exchange(
                {'operation': 'profile.read'}, capability=capability
            )
        ) == ('invalid_capability')
        assert second.invoke('profile.read')['ok']


def test_serve_holds_no_secret_in_its_command_line_or_output(world):
    with serve(world) as broker:
        pid = broker.process.pid
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes()
        assert SERVICE_TOKEN.encode() not in cmdline
        assert SERVICE_TOKEN not in json.dumps(broker.announce)
        # Hardening: a non-dumpable process hides its /proc entries from
        # unrelated same-user processes and writes no core file.
        limits = Path(f'/proc/{pid}/limits').read_text()
        core = next(
            line for line in limits.splitlines() if 'core file size' in line
        )
        assert core.split()[4:6] == ['0', '0']
        assert os.stat(f'/proc/{pid}/environ').st_uid == 0
    assert SERVICE_TOKEN not in broker.stderr


def test_session_outlives_its_grant_only_to_say_expired(world):
    policy = write_policy_file(
        world.root / 'short.json',
        world.service.policy(world.token, lifetime_seconds=1),
    )
    with serve(world, policy=policy) as broker:
        assert broker.invoke('profile.read')['ok']
        time.sleep(1.6)
        assert code(broker.invoke('profile.read')) == 'expired'
        assert broker.process.poll() is None  # the lease, not the TTL, ends it
    assert len(world.service.requests) == 1


def test_sigterm_revokes_and_cleans_up(world):
    with serve(world) as broker:
        directory = Path(broker.announce['socket']).parent
        broker.process.send_signal(signal.SIGTERM)
        assert broker.process.wait(timeout=20) == 0
    assert not directory.exists()


def test_a_killed_parent_takes_the_session_with_it(world):
    """The lifetime lease: no orphaned broker survives its owner's crash."""
    launcher = (
        'import subprocess, sys, time\n'
        f'p = subprocess.Popen([sys.executable, "-P", "-m", "aivm_secrets", "serve", '
        f'"--policy", {str(world.policy)!r}, "--announce", "json", "--exit-on-stdin-eof"], '
        'stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd="/")\n'
        'line = p.stdout.readline().decode()\n'
        'print(p.pid, flush=True); print(line, flush=True)\n'
        'time.sleep(120)\n'
    )
    parent = subprocess.Popen(
        [sys.executable, '-c', launcher],
        stdout=subprocess.PIPE,
        env=world.env,
        text=True,
    )
    try:
        assert parent.stdout is not None
        broker_pid = int(parent.stdout.readline())
        announce = json.loads(parent.stdout.readline())
        directory = Path(announce['socket']).parent
        assert directory.exists()
        parent.kill()  # SIGKILL: no handler, no cleanup code runs in the parent
        parent.wait()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and os.path.exists(
            f'/proc/{broker_pid}'
        ):
            time.sleep(0.1)
        assert not os.path.exists(f'/proc/{broker_pid}'), (
            'broker outlived its parent'
        )
        assert not directory.exists()
        # It still sealed its audit file, with nobody left to tell.
        audit = Path(announce['audit'])
        rows = [json.loads(line) for line in audit.read_text().splitlines()]
        assert rows[-1]['event'] == 'session_close'
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.stdout.close()


def test_token_file_and_stdin_override_the_policy_source(world):
    other = 'OTHER_token_NOT_REAL_abcdefghijklmnop'
    path = write_private(world.root / 'other-token', other.encode())
    with serve(world, '--token-file', str(path)) as broker:
        assert broker.invoke('profile.read')['ok']
    assert (
        world.service.requests[-1]['headers']['authorization']
        == 'Bearer ' + other
    )
    piped = 'PIPED_token_NOT_REAL_abcdefghijklmnop'
    process = subprocess.Popen(
        [sys.executable, '-P', '-m', 'aivm_secrets', 'serve', '--policy',
         str(world.policy), '--token-stdin', '--announce', 'json'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=world.env, cwd='/',
    )  # fmt: skip
    assert process.stdin and process.stdout and process.stderr
    try:
        process.stdin.write((piped + '\n').encode())
        process.stdin.close()
        announce = json.loads(process.stdout.readline())
        from aivm_secrets import guest

        capability = Path(announce['capability_file']).read_text()
        reply = guest.exchange(
            announce['socket'], capability, {'operation': 'profile.read'}
        )
        assert reply['ok']
        assert (
            world.service.requests[-1]['headers']['authorization']
            == 'Bearer ' + piped
        )
    finally:
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=20) == 0
        process.stdout.close()
        process.stderr.close()


def refused(world, *argv, policy=None, **kwargs):
    with serve(world, *argv, policy=policy, **kwargs) as broker:
        assert not broker.ready, broker.announce
        assert broker.process.wait(timeout=20) == 1
        broker.stderr = broker.process.stderr.read().decode()
    assert SERVICE_TOKEN not in broker.stderr + json.dumps(broker.announce)
    assert (
        os.listdir(world.root / 'run' / 'aivm-secrets') == []
        if (world.root / 'run' / 'aivm-secrets').exists()
        else True
    )
    return broker.announce['error'], broker.stderr


def test_serve_started_without_isolation_notices_guest_supplied_code(
    world, tmp_path
):
    """The second half of the launch defence: detection inside the broker.

    Someone starts ``aivm-secrets serve`` by hand, with a ``PYTHONPATH``
    that reaches into the workspace. The planted ``sitecustomize.py`` can
    execute before the broker can look -- so it must refuse to serve,
    before the credential is resolved or anything is sent.
    """
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    marker = poison(workspace)
    (workspace / 'aivm_secrets').rename(workspace / 'not-the-package')
    env = dict(world.env, PYTHONPATH=str(workspace))
    error, _ = refused(
        world, '--untrusted-root', str(workspace), env=env, flags=('-P',)
    )
    assert error['code'] == 'shared_source'
    assert (
        'module search path' in error['detail']
        or 'loaded module' in (error['detail'])
    )
    # In some Python installations sitecustomize is already resolved before
    # PYTHONPATH is applied. The substantive requirement is fail-closed
    # admission on a guest-writable module search path, regardless of whether
    # that optional hook actually executed.
    assert world.service.requests == []
    # Started isolated, the same environment is simply ignored.
    marker.unlink(missing_ok=True)
    with serve(world, '--untrusted-root', str(workspace), env=env) as broker:
        assert broker.ready, broker.announce
        assert broker.invoke('profile.read')['ok']
    assert ran_as_broker(marker) == []


def test_serve_refuses_anything_inside_a_guest_writable_root(world):
    """The workspace is controlled by the party the broker constrains."""
    error, stderr = refused(world, '--untrusted-root', str(world.root))
    assert error['code'] == 'shared_source' and 'policy' in error['detail']
    assert 'Keep the broker, policy and credential outside' in stderr
    # Policy outside, credential inside.
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as elsewhere:
        outside = write_policy_file(
            Path(elsewhere) / 'policy.json', world.service.policy(world.token)
        )
        # The runtime location must be trusted independently of the
        # credential. Otherwise the new runtime boundary correctly refuses
        # first and the credential validation branch is never reached.
        trusted_run = Path(elsewhere) / 'run'
        trusted_run.mkdir(mode=0o700)
        env = dict(world.env, XDG_RUNTIME_DIR=str(trusted_run))
        error, _ = refused(
            world, '--untrusted-root', str(world.root), policy=outside,
            env=env,
        )
        assert (
            error['code'] == 'shared_source' and 'credential' in error['detail']
        )
    # The broker's own code: an editable install from a shared checkout.
    error, _ = refused(world, '--untrusted-root', str(INSTALL_ROOT))
    assert error['code'] == 'shared_source' and 'broker code' in error['detail']
    # ...or its interpreter and libraries: a virtualenv inside the workspace.
    error, _ = refused(world, '--untrusted-root', sys.prefix)
    assert error['code'] == 'shared_source'
    assert 'broker python environment' in error['detail']
    assert world.service.requests == []


@pytest.mark.parametrize(
    'change,expected',
    [
        ({'credential_source': {'kind': 'command', 'argv': ['aivm-no-such-tool']}},
         'credential_source'),
        ({'credential_source': {'kind': 'command', 'argv': ['false']}}, 'credential_source'),
        ({'credential_source': {'kind': 'file', 'path': '/nonexistent/token'}}, 'unsafe_file'),
        ({'egress': {'ca_file': '/nonexistent/ca.pem'}}, 'unsafe_file'),
        ({'operations': []}, 'invalid_policy'),
        ({'schema': 9}, 'invalid_policy'),
    ],
)  # fmt: skip
def test_serve_fails_closed_before_listening(world, change, expected):
    policy = dict(world.service.policy(world.token), **change)
    path = write_policy_file(world.root / 'changed.json', policy)
    error, stderr = refused(world, policy=path)
    assert error['code'] == expected
    assert stderr.startswith('aivm-secrets: ')


def test_token_stdin_cannot_share_stdin_with_the_lifetime_lease(world):
    error, _ = refused(world, '--token-stdin')
    assert error['code'] == 'credential_source'


def test_runtime_path_too_long_is_an_explained_refusal(world):
    deep = world.root / ('d' * 80)
    deep.mkdir(mode=0o700)
    env = dict(world.env, XDG_RUNTIME_DIR=str(deep))
    with ServeProcess(['--policy', str(world.policy)], env=env) as broker:
        assert broker.announce['error']['code'] == 'unsafe_file'
        assert 'too long' in broker.announce['error']['detail']


# -- operator commands -------------------------------------------------------


def test_sessions_lists_only_live_sessions(world):
    assert (
        'No live secret sessions'
        in run_cli_process(['sessions'], env=world.env).stdout
    )
    with serve(world, '--access-identity', 'alice', '--vm', 'vm-a') as broker:
        broker.invoke('profile.read')
        listing = broker.cli('sessions')
        channel = broker.announce['channel']
        assert listing.returncode == 0 and channel[:12] in listing.stdout
        for expected in (
            'e2e-service',
            'vm=vm-a',
            'identity=alice',
            'used=1/5',
            'active',
        ):
            assert expected in listing.stdout
        (item,) = json.loads(broker.cli('sessions', '--json').stdout)
        assert item['channel'] == channel and item['writes'] == 'deny'
        assert SERVICE_TOKEN not in listing.stdout + json.dumps(item)
    assert (
        'No live secret sessions'
        in run_cli_process(['sessions'], env=world.env).stdout
    )


def test_pending_approve_and_deny_from_another_terminal(world):
    with serve(world, '--writes', 'approve') as broker:
        assert 'No writes are waiting' in broker.cli('pending').stdout
        arguments = {'issue': 23, 'body': 'Looks good to merge.'}
        reply = broker.invoke('issue.comment', **arguments)
        assert code(reply) == 'approval_required'
        digest = reply['approval']['digest']
        assert world.service.seen('POST') == []
        shown = broker.cli('pending')
        assert (
            digest[:16] in shown.stdout
            and 'Looks good to merge.' in shown.stdout
        )
        assert (
            json.loads(broker.cli('pending', '--json').stdout)[0]['arguments']
            == arguments
        )
        # Without a terminal the operator must say --yes explicitly.
        unattended = broker.cli('approve', digest[:12])
        assert unattended.returncode == 1 and '--yes' in unattended.stderr
        assert (
            code(broker.invoke('issue.comment', **arguments))
            == 'approval_required'
        )
        approved = broker.cli('approve', digest[:12], '--yes')
        assert approved.returncode == 0
        assert (
            'Looks good to merge.' in approved.stdout
            and 'Approved' in approved.stdout
        )
        assert broker.invoke('issue.comment', **arguments)['ok']
        (sent,) = world.service.seen('POST')
        assert json.loads(sent['body']) == {'body': 'Looks good to merge.'}
        # Used up.
        again = broker.invoke('issue.comment', **arguments)
        assert code(again) == 'approval_required'
        denied = broker.cli('deny', again['approval']['digest'])
        assert denied.returncode == 0 and 'Discarded' in denied.stdout
        assert 'No writes are waiting' in broker.cli('pending').stdout
        for bad in ('abc', 'f' * 16, digest[:12]):
            assert broker.cli('approve', bad, '--yes').returncode == 1
    assert len(world.service.seen('POST')) == 1


def test_interactive_approval_asks_and_takes_no_for_an_answer(
    world, monkeypatch, capsys
):
    monkeypatch.setenv('XDG_RUNTIME_DIR', world.env['XDG_RUNTIME_DIR'])
    with serve(world, '--writes', 'approve') as broker:
        arguments = {'issue': 23, 'body': 'please'}
        digest = broker.invoke('issue.comment', **arguments)['approval'][
            'digest'
        ]
        monkeypatch.setattr('sys.stdin.isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda prompt: 'n')
        assert cli.main(['approve', digest]) == 1
        assert 'Not approved' in capsys.readouterr().out
        assert (
            code(broker.invoke('issue.comment', **arguments))
            == 'approval_required'
        )
        monkeypatch.setattr('builtins.input', lambda prompt: 'y')
        assert cli.main(['approve', digest]) == 0
        assert broker.invoke('issue.comment', **arguments)['ok']


def test_revoke_by_session_identity_or_all(world):
    with (
        serve(world, '--access-identity', 'alice', '--vm', 'vm-a') as a,
        serve(world, '--access-identity', 'bob', '--vm', 'vm-a') as b,
        serve(world, '--access-identity', 'bob', '--vm', 'vm-b') as c,
    ):
        assert a.cli('revoke').returncode == 1  # refuses to guess
        assert a.cli('revoke', 'ffffffff').returncode == 1
        assert a.cli('revoke', '--access-identity', 'alice').returncode == 0
        assert code(a.invoke('profile.read')) == 'revoked'
        assert b.invoke('profile.read')['ok'] and c.invoke('profile.read')['ok']
        out = b.cli('revoke', '--access-identity', 'bob', '--vm', 'vm-b')
        assert out.returncode == 0 and c.announce['channel'][:12] in out.stdout
        assert code(c.invoke('profile.read')) == 'revoked'
        assert b.invoke('profile.read')['ok']
        assert b.cli('revoke', '--all').returncode == 0
        assert code(b.invoke('profile.read')) == 'revoked'
        states = {item['channel']: item['active'] for item in json.loads(
            a.cli('sessions', '--json').stdout)}  # fmt: skip
        assert set(states.values()) == {False} and len(states) == 3


def test_audit_verify_detects_tampering(world):
    with serve(world) as broker:
        broker.invoke('profile.read')
        audit = Path(broker.announce['audit'])
    ok = run_cli_process(['audit-verify', str(audit)], env=world.env)
    assert ok.returncode == 0 and 'chain intact' in ok.stdout
    lines = audit.read_bytes().split(b'\n')
    del lines[1]
    audit.write_bytes(b'\n'.join(lines))
    bad = run_cli_process(['audit-verify', str(audit)], env=world.env)
    assert bad.returncode == 1 and 'breaks the chain' in bad.stderr


def test_guest_verbs_pass_straight_through_to_the_client(world):
    with serve(world) as broker:
        env = dict(
            world.env,
            AIVM_SECRETS_SOCKET=broker.announce['socket'],
            AIVM_SECRETS_CAPABILITY_FILE=broker.announce['capability_file'],
        )
        out = run_cli_process(
            ['invoke', 'issue.view', '--arguments', '{"issue":23}'], env=env
        )
        assert (
            out.returncode == 0 and json.loads(out.stdout)['result']['id'] == 23
        )
        ops = run_cli_process(['operations'], env=env)
        assert json.loads(ops.stdout)['grant']['remaining_requests'] == 4
        explicit = run_cli_process(
            ['--socket', broker.announce['socket'], '--capability-file',
             broker.announce['capability_file'], 'invoke', 'profile.read'],
            env=world.env,
        )  # fmt: skip
        assert explicit.returncode == 0
        refused_op = run_cli_process(
            ['invoke', 'issue.view', '--arguments', '{"issue":9}'], env=env
        )
        assert refused_op.returncode == 3 and 'denied' in refused_op.stderr


def test_unknown_commands_never_fall_through_to_anything(world):
    for argv in (['api', '/user'], ['exec', 'id'], ['serve'], []):
        result = run_cli_process(argv, env=world.env)
        assert result.returncode == 2
