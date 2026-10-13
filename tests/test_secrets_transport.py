"""AIVM's foreground SSH adapter for secret-use sessions.

The only thing faked here is ``ssh`` itself. ``LocalGuest`` stands at
``aivm.commands.subprocess.run`` -- the true process boundary -- and runs each
"remote" command in a local shell, emulating the ``-R`` socket forward with a
symlink. Everything else is real: the ``CommandManager``, the broker child
process, its credential resolution, verified TLS to ``TLSService``, the
install script, the copied guest client and the cleanup command.

A test is a guest script. Assertions are on what the provider received, what
the "guest" saw and kept, the command log, and the audit file.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

import aivm_secrets
from aivm import secrets_transport
from aivm.commands import CommandManager
from aivm.config import AgentVMConfig
from aivm.errors import CommandControlError
from aivm.secrets_transport import run_secrets_ssh
from aivm.services import PreparedSession
from aivm_secrets.errors import SecretsError
from tests.helpers import FakeProc, capture_logs, resolved_test_context
from tests.secrets_helpers import (
    SERVICE_TOKEN,
    TOKEN,
    TLSService,
    github_policy,
    poison,
    ran_as_broker,
    write_policy_file,
    write_private,
)

# Wherever the broker under test is installed: a checkout or site-packages.
INSTALL_ROOT = Path(aivm_secrets.__file__).resolve().parent.parent


class LocalGuest:
    """``ssh`` replaced by a local shell that plays the guest VM."""

    def __init__(self, real_run):
        self._real_run = real_run
        self.commands: list[list[str]] = []
        self.inputs: list[str] = []
        self.fail_install = False
        self.fail_cleanup: BaseException | None = None
        self.during_session = None
        self.session_output = ''
        self.directories: set[str] = set()

    def __call__(self, cmd, **kwargs):
        argv = [str(part) for part in cmd]
        assert argv[0] == 'ssh', argv
        self.commands.append(argv)
        payload = kwargs.get('input')
        if payload is not None:
            self.inputs.append(payload)
        remote = argv[-1]
        # This "guest" is the test host: remember what a session creates so
        # that tests which deliberately skip cleanup do not litter /tmp.
        self.directories.update(
            re.findall(r'/tmp/aivm-secrets-[0-9a-f]{32}', remote)
        )
        if payload is not None and self.fail_install:
            # A hostile guest echoes what it was sent and reports failure.
            return FakeProc(1, payload, payload)
        if remote.startswith('rm -f') and self.fail_cleanup is not None:
            raise self.fail_cleanup
        forward = None
        if '-R' in argv:
            guest_socket, host_socket = argv[argv.index('-R') + 1].split(':', 1)
            os.symlink(host_socket, guest_socket)
            forward = guest_socket
            if self.during_session is not None:
                self.during_session()
        try:
            # One interleaved stream, as a terminal would show it.
            done = self._real_run(
                ['sh', '-c', remote],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
        finally:
            if forward is not None and os.path.islink(forward):
                os.unlink(forward)
        if forward is not None:
            self.session_output = done.stdout
        return FakeProc(done.returncode, done.stdout, '')

    @property
    def joined(self) -> str:
        return '\n'.join(' '.join(argv) for argv in self.commands)


@pytest.fixture
def root():
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.fixture
def world(root, tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(root))
    guest = LocalGuest(subprocess.run)
    monkeypatch.setattr('aivm.commands.subprocess.run', guest)
    CommandManager.activate(CommandManager(yes=True))
    cfg = AgentVMConfig()
    cfg.vm.name = 'test-vm'
    cfg.vm.user = 'agent'
    identity = tmp_path / 'identity'
    identity.write_text('not a real key')
    cfg.paths.ssh_identity_file = str(identity)
    cfg.paths.state_dir = str(tmp_path / 'state')
    context = resolved_test_context(
        cfg,
        principal_id='principal-test',
        guest_user='agent',
        host_uid=os.getuid(),
    )
    workspace = tmp_path / 'project'
    workspace.mkdir()
    session = PreparedSession(
        context=context,
        cfg_path=tmp_path / 'config.toml',
        host_src=workspace,
        attachment_mode='persistent',
        share_source_dir=str(workspace),
        share_tag='hostcode',
        share_guest_dst='/home/agent/code/project',
        ip='10.0.0.2',
        reg_path=tmp_path / 'config.toml',
        meta_path=None,
    )
    with TLSService(root) as service:
        service.routes[('GET', '/v1/account')] = {'login': 'demo'}
        service.routes[('GET', '/v1/issues/23')] = {'id': 23}
        service.routes[('POST', '/v1/issues/23/comments')] = {'created': True}
        token = write_private(root / 'token', (SERVICE_TOKEN + '\n').encode())
        policy = write_policy_file(root / 'policy.json', service.policy(token))
        yield type(
            'World', (), {
                'guest': guest, 'session': session, 'service': service,
                'policy': policy, 'token': token, 'root': root,
                'workspace': workspace, 'state': tmp_path / 'state',
            },
        )  # fmt: skip
    for directory in guest.directories:
        shutil.rmtree(directory, ignore_errors=True)


def run(world, script: str, **kwargs):
    """Open a secret session whose "interactive shell" is ``script``."""
    kwargs.setdefault('policy_path', world.policy)
    ssh_cmd = ['ssh', '-t', '-i', '/identity', 'agent@10.0.0.2', script]
    return run_secrets_ssh(world.session, ssh_cmd, **kwargs)


def audit_rows(world) -> list[dict]:
    (path,) = (world.state / 'secrets-audit').glob('*.jsonl')
    return [json.loads(line) for line in path.read_text().splitlines()]


def refused(world, script='true', **kwargs) -> SecretsError:
    with pytest.raises(SecretsError) as caught:
        run(world, script, **kwargs)
    return caught.value


def test_foreground_adapter_carries_only_ciphertext_and_revokes(
    world, monkeypatch
):
    logged = capture_logs(monkeypatch, 'aivm.secrets_transport.log')
    script = (
        'echo SOCKET=$AIVM_SECRETS_SOCKET; '
        'test -x "$AIVM_SECRETS_CLIENT" && echo CLIENT_OK; '
        'command -v aivm-secrets; '
        'stat -c "%a %n" "$(dirname "$AIVM_SECRETS_SOCKET")" "$AIVM_SECRETS_CAPABILITY_FILE"; '
        'aivm-secrets invoke issue.view --arguments \'{"issue":23}\'; echo VIEW=$?; '
        'aivm-secrets invoke issue.view --arguments \'{"issue":99}\'; echo OTHER=$?; '
        'aivm-secrets invoke issue.comment --arguments \'{"issue":23,"body":"x"}\'; echo WRITE=$?; '
        'cat "$AIVM_SECRETS_CAPABILITY_FILE"'
    )
    result = run(world, script)
    out = world.guest.session_output
    assert result.code == 0
    assert 'CLIENT_OK' in out and 'VIEW=0' in out and '"id": 23' in out
    assert 'OTHER=3' in out and 'WRITE=3' in out
    assert '700 /tmp/aivm-secrets-' in out and '600 /tmp/aivm-secrets-' in out
    # The provider received exactly the one authorized request, with the
    # real credential the guest never held.
    (seen,) = world.service.requests
    assert seen['target'] == '/v1/issues/23'
    assert seen['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
    # Nothing the guest saw, and nothing AIVM ran or piped, contains it.
    assert SERVICE_TOKEN not in out
    assert SERVICE_TOKEN not in world.guest.joined
    assert all(SERVICE_TOKEN not in payload for payload in world.guest.inputs)
    capability = out.strip().splitlines()[-1]
    assert capability.startswith('aivs1.')
    assert capability not in world.guest.joined  # stdin only, never argv
    # Session over: guest files removed, host runtime gone, audit sealed.
    guest_dir = Path(out.split('SOCKET=')[1].split()[0]).parent
    assert not guest_dir.exists()
    assert list((world.root / 'aivm-secrets').iterdir()) == []
    events = [row['event'] for row in audit_rows(world)]
    assert events[0] == 'session_open' and events[-1] == 'session_close'
    # AIVM reports the head of the sealed chain, which the file reproduces.
    from aivm_secrets.host.audit import verify

    (audit_file,) = (world.state / 'secrets-audit').glob('*.jsonl')
    count, head = verify(audit_file)
    assert count == len(events) and f'Audit head: {head}' in '\n'.join(logged)
    assert SERVICE_TOKEN not in '\n'.join(logged)
    assert audit_rows(world)[0]['channel'] == guest_dir.name.removeprefix(
        'aivm-secrets-'
    )


def test_session_ssh_is_isolated_from_ambient_configuration(world):
    run(world, 'true')
    install, session, cleanup = world.guest.commands
    for argv in (install, session, cleanup):
        assert argv[:3] == ['ssh', '-F', '/dev/null']
        for option in (
            'ControlMaster=no',
            'ControlPath=none',
            'ControlPersist=no',
        ):
            assert option in argv
    assert (
        'ExitOnForwardFailure=yes' in session
        and 'StrictHostKeyChecking=yes' in session
    )
    # ``yes`` precedes the caller's own option: for ssh, the first one wins.
    assert 'BatchMode=yes' in install and 'ForwardAgent=no' in install
    assert session[session.index('-R') + 1].startswith('/tmp/aivm-secrets-')
    # The identity and target of the caller's command are preserved.
    assert (
        session[session.index('-i') + 1] == '/identity'
        and 'agent@10.0.0.2' in session
    )
    assert cleanup[-1].startswith('rm -f -- ') and 'rmdir' in cleanup[-1]


def test_the_broker_child_never_receives_a_secret_on_its_command_line(world):
    argv = secrets_transport.broker_command(
        policy_path=world.policy,
        token_file=world.token,
        writes='approve',
        access_identity='principal-test',
        vm='test-vm',
        audit_dir=world.state / 'secrets-audit',
        untrusted=[world.workspace],
    )
    assert argv[1:5] == ['-I', '-m', 'aivm_secrets', 'serve']
    assert argv[argv.index('--untrusted-root') + 1] == str(world.workspace)
    assert (
        '--exit-on-stdin-eof' in argv
        and argv[argv.index('--writes') + 1] == 'approve'
    )
    assert SERVICE_TOKEN not in ' '.join(argv)


# -- the broker's own code cannot be chosen by its environment --------------


def test_a_poisoned_python_environment_cannot_substitute_the_broker(
    world, monkeypatch
):
    """The review's attack: ``PYTHONPATH`` pointing into the workspace.

    The workspace holds a shadow ``aivm_secrets`` package and a
    ``sitecustomize.py``. AIVM is run with that on ``PYTHONPATH`` and from
    inside the workspace. The broker that starts must be the installed one,
    and nothing from the workspace may run in it.
    """
    marker = poison(world.workspace)
    monkeypatch.setenv('PYTHONPATH', str(world.workspace))
    monkeypatch.setenv(
        'PYTHONSTARTUP', str(world.workspace / 'sitecustomize.py')
    )
    monkeypatch.chdir(world.workspace)
    # The attack is real: without isolation the shadow package is what runs.
    control = world.guest._real_run(
        [sys.executable, '-P', '-m', 'aivm_secrets', 'serve'],
        capture_output=True, text=True, timeout=30,
    )  # fmt: skip
    assert json.loads(control.stdout)['channel'] == 'SHADOW'
    # The shadow package must have run. Whether a second sitecustomize hook
    # runs depends on the interpreter's existing startup configuration.
    assert len(ran_as_broker(marker)) >= 1
    marker.unlink()

    result = run(world, 'aivm-secrets invoke profile.read; echo CODE=$?')
    assert result.code == 0 and 'CODE=0' in world.guest.session_output
    (seen,) = world.service.requests
    assert seen['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
    assert ran_as_broker(marker) == []
    assert 'SHADOW' not in world.guest.session_output


def test_isolation_flags_follow_where_the_broker_is_installed(monkeypatch):
    import site

    assert secrets_transport.interpreter_flags() == ['-I']
    # A user-site installation must fail closed instead of inheriting import
    # hooks via -E -P. The operator should use a trusted virtualenv.
    monkeypatch.setattr(site, 'getusersitepackages', lambda: str(INSTALL_ROOT))
    with pytest.raises(SecretsError) as err:
        secrets_transport.interpreter_flags()
    assert err.value.code == 'unsafe_file'
    assert 'user site' in err.value.detail
    monkeypatch.setattr(site, 'getusersitepackages', lambda: '/nonexistent/x')
    assert secrets_transport.interpreter_flags() == ['-I']


def test_the_broker_environment_drops_everything_that_redirects_loading(
    monkeypatch,
):
    hostile = {
        'PYTHONPATH': '/ws', 'PYTHONSTARTUP': '/ws/x.py', 'PYTHONHOME': '/ws',
        'PYTHONUSERBASE': '/ws', 'PYTHONINSPECT': '1', 'PYTHONBREAKPOINT': 'os.system',
        'LD_PRELOAD': '/ws/evil.so', 'LD_LIBRARY_PATH': '/ws', 'LD_AUDIT': '/ws/a.so',
        'DYLD_INSERT_LIBRARIES': '/ws/evil.dylib', 'BASH_ENV': '/ws/rc', 'ENV': '/ws/rc',
        'GCONV_PATH': '/ws', 'OPENSSL_CONF': '/ws/openssl.cnf',
        'OPENSSL_MODULES': '/ws', 'SSL_CERT_FILE': '/ws/ca.pem',
        'SSL_CERT_DIR': '/ws/certs', 'SSLKEYLOGFILE': '/ws/keys.log',
    }  # fmt: skip
    kept = {'HOME': '/home/op', 'XDG_RUNTIME_DIR': '/run/user/1', 'LANG': 'C'}
    for name, value in {**hostile, **kept}.items():
        monkeypatch.setenv(name, value)
    environment = secrets_transport.broker_environment()
    assert not set(hostile) & set(environment)
    for name, value in kept.items():
        assert environment[name] == value
    assert environment['PATH'] == os.environ['PATH']


def test_guest_env_and_cleanup_survive_a_failing_shell(world):
    result = run(world, 'aivm-secrets invoke profile.read >/dev/null; exit 7')
    assert result.code == 7
    assert len(world.service.requests) == 1
    assert world.guest.commands[-1][-1].startswith('rm -f -- ')
    assert list((world.root / 'aivm-secrets').iterdir()) == []


def test_writes_follow_the_host_mode(world):
    comment = 'aivm-secrets invoke issue.comment --arguments \'{"issue":23,"body":"hello"}\''
    run(world, f'{comment}; echo RC=$?', writes='allow')
    assert 'RC=0' in world.guest.session_output
    (post,) = world.service.seen('POST')
    assert json.loads(post['body']) == {'body': 'hello'}


def test_a_write_waits_for_approval_from_the_host_side(world):
    """The whole approval loop: guest asks, operator approves, guest retries."""
    from aivm_secrets.host import session as registry

    approved = []

    def operator():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not approved:
            for live in registry.list_sessions():
                directory = Path(live['directory'])
                reply = registry.control_call(directory, {'command': 'pending'})
                for item in reply['pending']:
                    assert item['arguments'] == {'issue': 23, 'body': 'ship it'}
                    registry.control_call(
                        directory,
                        {'command': 'approve', 'digest': item['digest']},
                    )
                    approved.append(item['digest'])
            time.sleep(0.05)

    world.guest.during_session = lambda: threading.Thread(
        target=operator, daemon=True
    ).start()
    comment = 'aivm-secrets invoke issue.comment --arguments \'{"issue":23,"body":"ship it"}\''
    script = (
        f'{comment}; echo FIRST=$?; '
        f'for i in $(seq 100); do {comment} >/dev/null 2>&1 && break; sleep 0.1; done; '
        f'echo RETRIED=$?; {comment} 2>/dev/null; echo AGAIN=$?'
    )
    run(world, script, writes='approve')
    out = world.guest.session_output
    assert 'FIRST=4' in out and 'RETRIED=0' in out and 'AGAIN=4' in out
    assert len(approved) == 1
    (post,) = world.service.seen('POST')
    assert json.loads(post['body']) == {'body': 'ship it'}
    events = [row['event'] for row in audit_rows(world)]
    assert 'approved' in events and events.count('completed') == 1


def test_schema_1_installs_the_gh_shaped_alias(world, monkeypatch):
    """The GitHub PR service resolves its credential from the host ``gh``."""
    bindir = world.root / 'bin'
    bindir.mkdir()
    write_private(bindir / 'gh', f'#!/bin/sh\necho {TOKEN}\n'.encode(), 0o700)
    monkeypatch.setenv('PATH', f'{bindir}:{os.environ["PATH"]}')
    policy = write_policy_file(world.root / 'github.json', github_policy())
    script = (
        'ls "$(dirname "$AIVM_SECRETS_SOCKET")"; command -v gh; '
        'aivm-secrets operations | grep -c \'"name": "pr\\.\'; '
        'gh pr view 13861 --repo TauCetiProject/TauCeti; echo RC=$?'
    )
    run(world, script, policy_path=policy)
    out = world.guest.session_output
    assert '/tmp/aivm-secrets-' in out and '/gh' in out
    assert '8' in out.split()  # eight PR operations are granted
    # api.github.com is not reachable from this fixture; what matters is
    # that the request was authorized and attempted, not answered.
    assert 'RC=3' in out and ('unreachable' in out or 'upstream' in out)
    assert world.service.requests == []
    assert TOKEN not in out + world.guest.joined
    assert world.guest.commands[-1][-1].count('/gh') == 1


def test_schema_2_does_not_shadow_another_cli(world):
    run(
        world,
        'ls "$(dirname "$AIVM_SECRETS_SOCKET")"; command -v gh || echo NO_GH_SHIM',
    )
    out = world.guest.session_output.split()
    assert 'aivm-secrets' in out and 'gh' not in out
    assert '/gh' not in world.guest.commands[-1][-1]


def test_adapter_rejects_shared_policy_before_credential_access(world):
    """Anything the guest can write is not a place to keep the policy."""
    shared = write_policy_file(
        world.workspace / 'policy.json', world.service.policy(world.token)
    )
    error = refused(world, policy_path=shared)
    assert error.code == 'shared_source' and 'policy' in error.detail
    assert world.guest.commands == []  # nothing was sent to the guest
    assert world.service.requests == []


def test_adapter_rejects_shared_credential_and_resolver(world):
    token = write_private(
        world.workspace / 'token', (SERVICE_TOKEN + '\n').encode()
    )
    assert refused(world, token_file=token).code == 'shared_source'
    resolver = write_private(
        world.workspace / 'resolver',
        f'#!/bin/sh\necho {SERVICE_TOKEN}\n'.encode(),
        0o700,
    )
    marker = world.root / 'resolver-ran'
    write_private(
        world.workspace / 'evil', f'#!/bin/sh\ntouch {marker}\n'.encode(), 0o700
    )
    policy = dict(
        world.service.policy(world.token),
        credential_source={'kind': 'command', 'argv': [str(resolver)]},
    )
    path = write_policy_file(world.root / 'resolver.json', policy)
    error = refused(world, policy_path=path)
    assert error.code == 'shared_source' and 'resolver' in error.detail
    assert not marker.exists() and world.guest.commands == []


def test_adapter_refuses_a_broker_installed_from_the_shared_workspace(world):
    """Dogfooding guard: an editable install inside the attached folder."""
    session = replace(
        world.session, host_src=INSTALL_ROOT, share_source_dir=str(INSTALL_ROOT)
    )
    with pytest.raises(SecretsError) as caught:
        run_secrets_ssh(
            session, ['ssh', 'agent@10.0.0.2', 'true'], policy_path=world.policy
        )
    assert caught.value.code == 'shared_source'
    assert 'broker code' in caught.value.detail
    assert world.guest.commands == []


@pytest.mark.parametrize(
    'change',
    [
        {'host_uid': os.getuid() + 1},
        {'state': 'disabled'},
        {'state': 'pending'},
        {'id': ''},
    ],
    ids=['other-uid', 'disabled', 'pending', 'anonymous'],
)
def test_adapter_refuses_cross_principal_secrets(world, change):
    """Administrator access is not permission to borrow another's identity."""
    context = world.session.context
    world.session = replace(
        world.session,
        context=replace(
            context, principal=replace(context.principal, **change)
        ),
    )
    assert refused(world).code == 'wrong_owner'
    assert world.guest.commands == [] and world.service.requests == []
    assert not (world.state / 'secrets-audit').exists()


def test_a_single_user_explicit_store_identity_is_usable(world):
    """``legacy`` is the synthetic identity of an explicit ``--config`` store.

    The rest of AIVM treats it as usable; refusing it here locked every such
    user out of secret sessions.
    """
    context = world.session.context
    world.session = replace(
        world.session,
        context=replace(
            context, principal=replace(context.principal, state='legacy')
        ),
    )
    run(world, 'aivm-secrets invoke profile.read; echo RC=$?')
    assert 'RC=0' in world.guest.session_output


def test_failed_guest_setup_revokes_without_exposing_guest_echo(
    world, monkeypatch
):
    """A guest that fails setup may echo its stdin; none of it is logged."""
    logged = capture_logs(
        monkeypatch,
        'aivm.secrets_transport.log',
        levels=('debug', 'info', 'warning', 'error'),
    )
    world.guest.fail_install = True
    error = refused(world)
    assert error.code == 'guest_setup'
    payload = world.guest.inputs[0]
    assert payload.startswith('aivs1.')
    shown = str(error) + error.detail + '\n'.join(logged)
    assert logged and payload.splitlines()[0] not in shown
    # No forwarded session was attempted, and the broker is gone.
    assert not any('-R' in argv for argv in world.guest.commands)
    assert list((world.root / 'aivm-secrets').iterdir()) == []
    assert [row['event'] for row in audit_rows(world)][-1] == 'session_close'


def test_bad_policy_and_missing_ip_fail_before_any_guest_contact(world):
    broken = write_private(world.root / 'broken.json', b'{"schema": 2}')
    error = refused(world, policy_path=broken)
    assert error.code == 'invalid_policy'
    world.session = replace(world.session, ip=None)
    assert refused(world).code == 'guest_setup'
    assert refused(world, writes='sometimes').code == 'invalid_policy'
    assert world.guest.commands == []


def test_guest_cleanup_failure_cannot_keep_authority_alive(world, caplog):
    world.guest.fail_cleanup = OSError('guest vanished')
    result = run(world, 'aivm-secrets invoke profile.read >/dev/null')
    assert result.code == 0
    assert list((world.root / 'aivm-secrets').iterdir()) == []
    assert [row['event'] for row in audit_rows(world)][-1] == 'session_close'


def test_a_refused_cleanup_command_is_not_swallowed(world):
    """A refusal is the user's decision; best-effort code must not eat it."""
    world.guest.fail_cleanup = CommandControlError('declined')
    with pytest.raises(CommandControlError):
        run(world, 'true')
    assert list((world.root / 'aivm-secrets').iterdir()) == []


def test_disabling_the_access_identity_revokes_a_running_session(
    world, monkeypatch
):
    """The grant belongs to an identity; it ends when the identity does."""
    monkeypatch.setattr(secrets_transport, 'IDENTITY_POLL_SECONDS', 0.1)
    flag = world.root / 'identity-active'
    flag.write_text('yes')
    script = (
        'aivm-secrets invoke profile.read >/dev/null; echo BEFORE=$?; '
        f'rm {shlex.quote(str(flag))}; sleep 1.5; '
        'aivm-secrets invoke profile.read; echo AFTER=$?'
    )
    run(world, script, still_authorized=flag.exists)
    out = world.guest.session_output
    assert 'BEFORE=0' in out and 'AFTER=2' in out  # the broker is gone
    assert len(world.service.requests) == 1
    events = [row['event'] for row in audit_rows(world)]
    assert events[-1] == 'session_close' and events.count('completed') == 1


def test_one_unreadable_identity_sample_is_not_a_verdict(world, monkeypatch):
    monkeypatch.setattr(secrets_transport, 'IDENTITY_POLL_SECONDS', 0.05)
    samples = []

    def flaky():
        samples.append(1)
        if len(samples) in (2, 3):
            raise OSError('store briefly unreadable')
        return True

    run(world, 'sleep 0.6; aivm-secrets invoke profile.read >/dev/null; echo RC=$?',
        still_authorized=flaky)  # fmt: skip
    assert 'RC=0' in world.guest.session_output and len(samples) > 4

    def broken():
        raise OSError('store unreadable')

    run(world, 'sleep 0.8; aivm-secrets invoke profile.read; echo RC=$?',
        still_authorized=broken)  # fmt: skip
    assert 'RC=2' in world.guest.session_output


def test_broker_startup_failures_are_reported_by_code(world, monkeypatch):
    monkeypatch.setattr(secrets_transport, 'BROKER_START_TIMEOUT', 0.5)
    # ``sleep`` ignores the lease; do not wait long before killing it.
    monkeypatch.setattr(secrets_transport, 'BROKER_STOP_TIMEOUT', 0.3)
    for argv in (
        ['sleep', '30'],
        ['true'],
        ['echo', 'not json'],
        ['echo', '{}'],
    ):
        broker = secrets_transport.BrokerProcess.start(
            CommandManager.current(), argv
        )
        try:
            with pytest.raises(SecretsError) as caught:
                broker.announce()
            assert caught.value.code == 'internal_error'
        finally:
            broker.stop()
        assert not broker.running
    broker = secrets_transport.BrokerProcess.start(
        CommandManager.current(), ['sleep', '30']
    )
    broker.stop()
    broker.stop()  # idempotent
    assert not broker.running


def test_cli_secret_options_without_policy_do_not_prepare_vm(monkeypatch):
    from aivm.cli.vm_connect import VMSSHCLI

    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_session',
        lambda args: pytest.fail('VM prepared'),
    )
    assert VMSSHCLI.main(argv=False, secrets_token_file='token', yes=True) == 1
    assert VMSSHCLI.main(argv=False, secrets_writes='allow', yes=True) == 1
    assert VMSSHCLI.main(argv=False, secrets_writes='approve', yes=True) == 1


# ---------------------------------------------------------------------------
# The access identity behind a session, re-read from the real machine store
# ---------------------------------------------------------------------------


def _machine_store_with_identity(world):
    """A real 0.6 machine store holding the session's access identity."""
    from aivm.config_store import (
        PrincipalEntry,
        load_store,
        upsert_network,
        upsert_principal,
        upsert_vm_with_network,
    )
    from aivm.profile_store import UserProfileStore, save_user_profile
    from aivm.scoped_store import resolve_store_scope, save_scope_store

    scope = resolve_store_scope(None)
    assert scope.is_machine
    principal = world.session.context.principal
    cfg = AgentVMConfig()
    cfg.vm.name = world.session.context.machine.vm.name
    reg = load_store(scope.store_path)
    reg.store_kind = 'machine'
    reg.schema_version = 11
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    for entry in (
        PrincipalEntry(
            id=principal.id,
            vm_name=cfg.vm.name,
            host_user=principal.host_user,
            host_uid=principal.host_uid,
            host_gid=principal.host_gid,
            guest_user=principal.guest_user,
            ssh_public_key='ssh-ed25519 AAAAOWNER owner@test',
            state='active',
        ),
        PrincipalEntry(
            id='principal-other',
            vm_name=cfg.vm.name,
            host_user='other',
            host_uid=principal.host_uid + 1,
            host_gid=principal.host_gid + 1,
            guest_user='other-agent',
            ssh_public_key='ssh-ed25519 AAAAOTHER other@test',
            state='active',
        ),
    ):
        upsert_principal(reg, entry)
    save_scope_store(scope, reg, reason='test secret session identity')
    assert scope.profile_path is not None
    save_user_profile(
        UserProfileStore(active_vm=cfg.vm.name), scope.profile_path
    )
    return scope


def test_identity_check_reads_the_authoritative_store(world):
    from aivm.cli.vm_connect import _access_identity_still_usable
    from aivm.config_store import (
        find_principal,
        load_store,
        remove_principal,
        upsert_principal,
    )
    from aivm.scoped_store import load_scope_store, save_scope_store

    scope = _machine_store_with_identity(world)
    session = world.session
    vm, pid = session.context.machine.vm.name, session.context.principal.id
    assert _access_identity_still_usable(None, session) is True

    def rewrite(change):
        reg = load_scope_store(scope)
        change(reg, find_principal(reg, vm_name=vm, principal_id=pid))
        save_scope_store(scope, reg, reason='test')

    for state in ('disabled', 'pending', 'error'):
        rewrite(
            lambda reg, entry: upsert_principal(
                reg, replace(entry, state=state)
            )
        )
        assert _access_identity_still_usable(None, session) is False, state
    rewrite(
        lambda reg, entry: upsert_principal(reg, replace(entry, state='active'))
    )
    assert _access_identity_still_usable(None, session) is True
    # The record now belongs to a different kernel UID: not this session's.
    rewrite(
        lambda reg, entry: upsert_principal(
            reg, replace(entry, host_uid=entry.host_uid + 7)
        )
    )
    assert _access_identity_still_usable(None, session) is False
    rewrite(
        lambda reg, entry: remove_principal(reg, vm_name=vm, principal_id=pid)
    )
    assert _access_identity_still_usable(None, session) is False
    # A single-user explicit store has no identity records to revoke.
    explicit = world.root / 'explicit.toml'
    explicit.write_text('')
    assert load_store(explicit) is not None
    assert _access_identity_still_usable(str(explicit), session) is True


def test_aivm_access_disable_revokes_a_live_secret_session(world, monkeypatch):
    """The real ``aivm vm access disable`` path ends a real running session.

    Real machine store, real disable transaction, real broker child and real
    TLS provider. The one stub is the guest-side key removal, a genuine
    boundary: it needs a live guest, and is the subject of
    ``test_access_lifecycle``.
    """
    from functools import partial

    from aivm.access_control import mutate_access_identity
    from aivm.cli.vm_connect import _access_identity_still_usable
    from aivm.config_store import find_principal
    from aivm.host_identity import HostIdentity
    from aivm.scoped_store import load_scope_store

    scope = _machine_store_with_identity(world)
    principal = world.session.context.principal
    vm = world.session.context.machine.vm.name
    monkeypatch.setattr(secrets_transport, 'IDENTITY_POLL_SECONDS', 0.1)
    monkeypatch.setattr(
        'aivm.access_control.current_host_identity',
        lambda: HostIdentity(
            uid=principal.host_uid,
            gid=principal.host_gid,
            username=principal.host_user,
        ),
    )
    monkeypatch.setattr(
        'aivm.access_control._disable_guest_key',
        lambda *args, **kwargs: '10.0.0.2',
    )
    outcome = {}

    def disable_from_another_terminal():
        time.sleep(0.6)
        report = mutate_access_identity(
            scope,
            vm_name=vm,
            selector=principal.id,
            action='disable',
            administrative_override=False,
            allow_last_access=False,
            ip_override='10.0.0.2',
            dry_run=False,
        )
        outcome['state'] = report.principal.state

    world.guest.during_session = lambda: threading.Thread(
        target=disable_from_another_terminal, daemon=True
    ).start()
    script = (
        'aivm-secrets invoke profile.read >/dev/null; echo BEFORE=$?; '
        'sleep 2.5; aivm-secrets invoke profile.read; echo AFTER=$?'
    )
    run(
        world,
        script,
        still_authorized=partial(
            _access_identity_still_usable, None, world.session
        ),
    )
    out = world.guest.session_output
    assert outcome == {'state': 'disabled'}
    stored = find_principal(
        load_scope_store(scope), vm_name=vm, principal_id=principal.id
    )
    assert stored is not None and stored.state == 'disabled'
    assert 'BEFORE=0' in out and 'AFTER=2' in out
    assert (
        len(world.service.requests) == 1
    )  # nothing was sent after the disable
    events = [row['event'] for row in audit_rows(world)]
    assert events.count('completed') == 1 and events[-1] == 'session_close'


def test_oauth_broker_argv_requires_an_unambiguous_host_credential_source(world):
    """The subprocess args contain only vault/profile paths and bound identity."""
    options = dict(
        policy_path=world.policy, token_file=None,
        writes='deny', access_identity='principal-test', vm='test-vm',
        audit_dir=world.state / 'secrets-audit', untrusted=[world.workspace],
    )
    vault = world.state / 'oauth-vault'
    profile = world.state / 'oauth-provider.json'
    command = secrets_transport.broker_command(
        **options, oauth_vault=vault,
        oauth_provider_config=profile, oauth_subject='vm-' + 'a' * 64,
    )
    assert command[1] == '-I'
    assert command[command.index('--oauth-vault') + 1] == str(vault)
    assert command[command.index('--oauth-provider-config') + 1] == str(profile)
    assert command[command.index('--oauth-subject') + 1] == 'vm-' + 'a' * 64
    assert '--token-file' not in command and '--token-stdin' not in command
    assert SERVICE_TOKEN not in ' '.join(command)
    with pytest.raises(SecretsError) as confused:
        secrets_transport.broker_command(
            **{**options, 'token_file': world.token},
            oauth_vault=vault, oauth_provider_config=profile,
            oauth_subject='vm-' + 'a' * 64,
        )
    assert confused.value.code == 'invalid_policy'
    with pytest.raises(SecretsError):
        secrets_transport.broker_command(
            **options, oauth_vault=vault, oauth_subject='vm-' + 'a' * 64,
        )
