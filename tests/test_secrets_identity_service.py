"""Real Unix socket + TLS 1.3 + pinned enrollment + original broker.

All secrets are synthetic. No VM, public listener, OAuth or real provider.

The first tests drive an in-process broker. The later ones -- reply
semantics, capacity, concurrency, the subject pin and miswiring -- run the
bridge against a real ``aivm-secrets serve`` child whose provider is a real
TLS server on loopback, and assert on what that provider received, what the
broker's audit file says and what the standalone guest client was told.
"""
from __future__ import annotations

import json
import os
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Callable, Generator, Iterator, NamedTuple

import pytest

from aivm_secrets import guest
from aivm_secrets.errors import SecretsError
from aivm_secrets.host.server import LocalServer, read_frame
from aivm_secrets.identity import client as identity_client
from aivm_secrets.identity import service as bridge_service
from aivm_secrets.identity.client import bound_call
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr
from aivm_secrets.identity.service import UnixIdentityService
from aivm_secrets.kernel import codec
from aivm_secrets.transport.names import GUEST_SOCKET
from tests.secrets_helpers import (
    REPO, SERVICE_TOKEN, TOKEN, Harness, ServeProcess, TLSService, cli_env,
    write_policy_file, write_private,
)


def start(tmp_path):
    authority = IdentityAuthority.initialize(
        tmp_path / 'host', issuer='aivm.test', audience='aivm-secrets.identity')
    key = tmp_path / 'vm-key.pem'
    csr = tmp_path / 'vm.csr'
    fp = create_csr(private_key=key, request_file=csr)
    entry = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                             approve_fingerprint=fp)
    harness = Harness(tmp_path)
    jwt = tmp_path / 'bound.jwt'
    authority.issue(subject='vm-alpha', broker_capability=harness.capability,
                    output=jwt)
    return authority, key, entry, jwt, harness


def call(path, authority, entry, key, jwt, request, *, use_key=True):
    ctx = ssl.create_default_context(cafile=str(authority.tls_paths()[2]))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if use_key:
        ctx.load_cert_chain(entry['certificate'], str(key))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(5)
        raw.connect(str(path))
        with ctx.wrap_socket(raw, server_hostname='localhost') as channel:
            frame = {'version': 1, 'capability': jwt.read_text(),
                     'request': request}
            channel.sendall(codec.dumps(frame) + b'\n')
            reply = read_frame(channel, limit=codec.MAX_FRAME, timeout=5)
            return codec.loads(reply)


def view_request():
    return {'operation': 'pr.view',
            'arguments': {'repository': REPO, 'pr': 13861}}


def test_authenticated_unix_bridge_uses_existing_broker_and_live_revocation(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    bridgepath = tmp_path / 'bridge' / 'session.sock'
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(
                authority=authority, broker_socket=broker.socket_path,
                listen=bridgepath, max_connections=3,
                idle_seconds=12) as service:
                runner = threading.Thread(target=service.serve)
                runner.start()
                reply = call(bridgepath, authority, entry, key, jwt, view_request())
                assert reply['ok'] and reply['result']['number'] == 13861
                assert len(harness.executor.calls) == 1
                assert harness.executor.calls[0][1] == TOKEN
                assert TOKEN not in json.dumps(reply)
                # Authorized client does not get any extra operation by TLS.
                other = call(bridgepath, authority, entry, key, jwt, {
                    'operation': 'pr.merge', 'arguments': {},
                })
                assert other['error']['code'] == 'denied'
                assert len(harness.executor.calls) == 1
                # A certificate that worked one request ago is revoked on
                # disk, without restarting TLS or the existing broker.
                authority.revoke('vm-alpha')
                rejected = call(bridgepath, authority, entry, key, jwt, view_request())
                assert rejected['error']['code'] == 'invalid_capability'
                assert len(harness.executor.calls) == 1
                runner.join(timeout=10)
                assert not runner.is_alive()
            assert not bridgepath.exists()
    finally:
        harness.broker.close()


def test_other_enrolled_certificate_cannot_use_original_identity_token(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    second_key, second_csr = tmp_path / 'other.key', tmp_path / 'other.csr'
    second_fp = create_csr(private_key=second_key, request_file=second_csr)
    other = authority.enroll(subject='vm-beta', csr=second_csr.read_bytes(),
                             approve_fingerprint=second_fp)
    listen = tmp_path / 'bridge' / 'session.sock'
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(
                authority=authority, broker_socket=broker.socket_path,
                listen=listen, max_connections=1) as service:
                thread = threading.Thread(target=service.serve)
                thread.start()
                result = call(listen, authority, other, second_key, jwt, view_request())
                assert result['error']['code'] == 'invalid_capability'
                assert not harness.executor.calls
                thread.join(timeout=8)
                assert not thread.is_alive()
    finally:
        harness.broker.close()


def test_bridge_is_opt_in_and_never_clobbers_existing_socket(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'existing.sock'
            listen.parent.mkdir(mode=0o700)
            listen.write_text('never overwrite')
            service = UnixIdentityService(authority=authority,
                                          broker_socket=broker.socket_path,
                                          listen=listen, max_connections=1)
            with pytest.raises(SecretsError):
                with service:
                    pass
            assert listen.read_text() == 'never overwrite'
            with pytest.raises(SecretsError):
                UnixIdentityService(authority=authority,
                                    broker_socket=broker.socket_path,
                                    listen=tmp_path / 'bridge' / 'other.sock',
                                    max_connections=100000)
    finally:
        harness.broker.close()


def test_client_without_certificate_fails_tls_handshake(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'auth.sock'
            with UnixIdentityService(authority=authority,
                                     broker_socket=broker.socket_path,
                                     listen=listen, max_connections=1) as service:
                thread = threading.Thread(target=service.serve)
                thread.start()
                with pytest.raises((ssl.SSLError, OSError, SecretsError)):
                    call(listen, authority, entry, key, jwt, view_request(),
                         use_key=False)
                thread.join(timeout=8)
                assert not thread.is_alive()
                assert not harness.executor.calls
    finally:
        harness.broker.close()


# ---------------------------------------------------------------------------
# Against a real broker child and a real TLS provider
# ---------------------------------------------------------------------------

PROFILE = {'operation': 'profile.read', 'arguments': {}}


class Identity(NamedTuple):
    """One enrolled guest: its software key, certificate and bound token."""

    subject: str
    key: Path
    certificate: Path
    jwt: Path


def enroll(authority: IdentityAuthority, root: Path, subject: str,
           capability: str) -> Identity:
    key, csr = root / f'{subject}.key', root / f'{subject}.csr'
    fingerprint = create_csr(private_key=key, request_file=csr)
    entry = authority.enroll(subject=subject, csr=csr.read_bytes(),
                             approve_fingerprint=fingerprint)
    jwt = root / f'{subject}.jwt'
    authority.issue(subject=subject, broker_capability=capability, output=jwt)
    return Identity(subject, key, Path(entry['certificate']), jwt)


def new_authority(root: Path) -> IdentityAuthority:
    return IdentityAuthority.initialize(
        root / 'host', issuer='aivm.test', audience='aivm-secrets.identity')


class Live:
    """A real broker child, its real provider and a host identity authority."""

    def __init__(self, root: Path, provider: TLSService, policy: Path,
                 broker: ServeProcess):
        self.root = root
        self.provider = provider
        self.policy = policy
        self.broker = broker
        self.authority = new_authority(root)
        self.alpha = self.enroll('vm-alpha')

    @property
    def broker_socket(self) -> Path:
        return Path(self.broker.announce['socket'])

    def enroll(self, subject: str) -> Identity:
        return enroll(self.authority, self.root, subject, self.broker.capability)

    def bridge(self, broker_socket: Path | None = None,
               **options: Any) -> UnixIdentityService:
        return UnixIdentityService(
            authority=self.authority,
            broker_socket=broker_socket or self.broker_socket,
            listen=self.root / 'bridge' / 'id.sock', **options)

    def audit(self) -> list[dict[str, Any]]:
        text = Path(self.broker.announce['audit']).read_text()
        return [json.loads(line) for line in text.splitlines()]

    def events(self) -> list[str]:
        return [row['event'] for row in self.audit()]


@pytest.fixture
def short_root() -> Iterator[Path]:
    """A short private directory: socket paths must fit in ``sun_path``."""
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.fixture
def live(short_root: Path) -> Iterator[Live]:
    with TLSService(short_root) as provider:
        provider.routes[('GET', '/v1/account')] = {'login': 'demo'}
        token = write_private(short_root / 'token',
                              (SERVICE_TOKEN + '\n').encode())
        policy = write_policy_file(short_root / 'policy.json',
                                   provider.policy(token, max_requests=400))
        with ServeProcess(['--policy', str(policy), '--writes', 'allow'],
                          env=cli_env(short_root)) as broker:
            assert broker.ready, broker.announce
            yield Live(short_root, provider, policy, broker)


def become(monkeypatch: pytest.MonkeyPatch, authority: IdentityAuthority,
           who: Identity) -> None:
    """Configure the standalone guest client exactly as a bound guest is."""
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_MODE', 'mtls-v1')
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_CA', str(authority.tls_paths()[2]))
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_CERT', str(who.certificate))
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_KEY', str(who.key))


def ask(listen: Path, who: Identity, payload: Any = PROFILE,
        verb: str = 'request') -> dict[str, Any]:
    """What the guest client is told for one frame through the bridge."""
    return guest.exchange(str(listen), who.jwt.read_text(), payload, verb)


@contextmanager
def tls_channel(listen: Path, authority: IdentityAuthority,
                who: Identity) -> Generator[ssl.SSLSocket, None, None]:
    """A raw TLS connection as ``who``, for a test that must hold the socket."""
    ctx = ssl.create_default_context(cafile=str(authority.tls_paths()[2]))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(who.certificate), str(who.key))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(5)
        raw.connect(str(listen))
        with ctx.wrap_socket(raw, server_hostname='localhost') as channel:
            yield channel


def first_line(stream: IO[bytes], seconds: float = 20.0) -> bytes:
    """One line from a child's pipe, or what came before it gave up."""
    data = b''
    deadline = time.monotonic() + seconds
    while not data.endswith(b'\n'):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            break
        chunk = os.read(stream.fileno(), 4096)
        if not chunk:
            break
        data += chunk
    return data


@contextmanager
def serving(service: UnixIdentityService) -> Generator[Path, None, None]:
    """Run the bridge on a thread for the block, ended as its CLI ends it."""
    stop = threading.Event()
    with service:
        runner = threading.Thread(target=service.serve,
                                  kwargs={'should_stop': stop.is_set})
        runner.start()
        try:
            yield service.listen
        finally:
            stop.set()
            runner.join(timeout=30)
    assert not runner.is_alive()


def wait_for(condition: Callable[[], Any], seconds: float = 15.0) -> Any:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError('condition never held')


def slow(seconds: float, answer: Any) -> Callable[[dict[str, Any]], Any]:
    """A provider route that takes ``seconds`` to answer."""
    def route(seen: dict[str, Any]) -> tuple[int, dict[str, str], bytes]:
        time.sleep(seconds)
        return 200, {}, json.dumps(answer).encode()
    return route


def test_a_reply_after_the_deadline_is_outcome_unknown_never_invalid_request(
    live: Live, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live.provider.routes[('POST', '/v1/issues/23/comments')] = slow(
        2.0, {'created': True})
    become(monkeypatch, live.authority, live.alpha)
    with serving(live.bridge(reply_deadline=0.3)) as listen:
        status = guest.main([
            '--socket', str(listen), '--capability-file', str(live.alpha.jwt),
            'invoke', 'issue.comment',
            '--arguments', json.dumps({'issue': 23, 'body': 'hello'}),
        ])
    err = capsys.readouterr().err
    assert status == 3
    assert 'aivm-secrets: outcome_unknown' in err
    assert 'invalid_request' not in err
    # The broker carried on and the provider applied the write, once: which
    # is exactly why the guest must not be told its request was malformed.
    wait_for(lambda: 'completed' in live.events())
    posts = live.provider.seen('POST')
    assert [item['target'] for item in posts] == ['/v1/issues/23/comments']


def test_bound_call_reports_a_sent_but_unanswered_call_as_outcome_unknown(
    live: Live,
) -> None:
    live.provider.routes[('GET', '/v1/issues/24')] = slow(1.5, {'id': 24})
    alpha = live.alpha

    def call(path: Path, **options: Any) -> dict[str, Any]:
        return bound_call(
            socket_path=path, ca=live.authority.tls_paths()[2],
            certificate=alpha.certificate, private_key=alpha.key,
            jwt_file=alpha.jwt,
            request={'operation': 'issue.view', 'arguments': {'issue': 24}},
            **options)

    with serving(live.bridge()) as listen:
        with pytest.raises(SecretsError) as late:
            call(listen, reply_deadline=0.3)
        assert late.value.code == 'outcome_unknown'
        # Nothing was sent: that, and only that, is definite.
        with pytest.raises(SecretsError) as nowhere:
            call(listen.with_name('absent.sock'))
        assert nowhere.value.code == 'unreachable'
        assert call(listen)['result'] == {'id': 24}
    assert len(live.provider.seen('GET')) == 2


def test_bound_call_reports_a_refused_certificate_as_unreachable(
    live: Live,
) -> None:
    """In TLS 1.3 the refusal arrives only after the frame was sent.

    The client's handshake completes before the bridge has judged its
    certificate, so the bridge's alert is read where a reply would be. It
    still means nothing was read, let alone dispatched: a definite failure.
    """
    foreign = new_authority(live.root / 'foreign')
    stranger = enroll(foreign, live.root, 'vm-stranger', live.broker.capability)
    with serving(live.bridge()) as listen:
        with pytest.raises(SecretsError) as refused:
            bound_call(socket_path=listen, ca=live.authority.tls_paths()[2],
                       certificate=stranger.certificate,
                       private_key=stranger.key, jwt_file=stranger.jwt,
                       request=PROFILE)
    assert refused.value.code == 'unreachable'
    assert live.events() == ['session_open']
    assert live.provider.seen() == []


def test_a_reply_larger_than_any_request_frame_is_relayed_whole(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broker reply may carry up to 2 MiB of provider response."""
    login = 'x' * (3 * codec.MAX_FRAME)
    live.provider.routes[('GET', '/v1/account')] = {'login': login}
    become(monkeypatch, live.authority, live.alpha)
    with serving(live.bridge()) as listen:
        answered = ask(listen, live.alpha)
    assert answered['ok'] is True, answered
    assert answered['result'] == {'login': login}


def test_three_hundred_describe_and_request_pairs_need_no_restart(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each ``gh`` call is two connections; no count may end the session."""
    become(monkeypatch, live.authority, live.alpha)
    with serving(live.bridge()) as listen:
        for _ in range(300):
            described = ask(listen, live.alpha, True, 'describe')
            assert described['ok'] is True, described
            answered = ask(listen, live.alpha)
            assert answered['ok'] is True, answered
    assert len(live.provider.seen('GET')) == 300


def test_a_slow_call_does_not_hold_up_another_caller(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    def held(seen: dict[str, Any]) -> tuple[int, dict[str, str], bytes]:
        release.wait(10)
        return 200, {}, b'{"id": 24}'

    live.provider.routes[('GET', '/v1/issues/24')] = held
    become(monkeypatch, live.authority, live.alpha)
    finished: dict[str, Any] = {}
    answered_at = float('inf')
    with serving(live.bridge()) as listen:
        def slow_call() -> None:
            finished['reply'] = ask(
                listen, live.alpha,
                {'operation': 'issue.view', 'arguments': {'issue': 24}})
            finished['at'] = time.monotonic()

        caller = threading.Thread(target=slow_call)
        caller.start()
        try:
            # The first caller's request is now at the provider.
            wait_for(lambda: live.provider.seen('GET'))
            # A second caller is handshaken, verified and answered meanwhile
            # (the bridge itself refuses delegation, so this answer does not
            # wait for the broker, which runs requests one at a time).
            refused = ask(listen, live.alpha, {'operations': {}}, 'delegate')
            answered_at = time.monotonic()
            assert refused['error']['code'] == 'denied'
            assert caller.is_alive()
        finally:
            release.set()
            caller.join(timeout=30)
    assert finished['reply']['result'] == {'id': 24}
    assert answered_at < finished['at']


def test_a_bridge_waiting_on_its_broker_is_busy_not_idle(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    live.provider.routes[('GET', '/v1/issues/24')] = slow(2.5, {'id': 24})
    become(monkeypatch, live.authority, live.alpha)
    finished: dict[str, Any] = {}
    with live.bridge(idle_seconds=1) as service:
        runner = threading.Thread(target=service.serve)
        runner.start()

        def slow_call() -> None:
            finished['reply'] = ask(
                service.listen, live.alpha,
                {'operation': 'issue.view', 'arguments': {'issue': 24}})

        caller = threading.Thread(target=slow_call)
        caller.start()
        wait_for(lambda: live.provider.seen('GET'))
        time.sleep(1.2)
        # Past the idle time since the last connection, but one is in
        # flight: a new caller is still taken.
        assert ask(service.listen, live.alpha)['ok'] is True
        caller.join(timeout=30)
        # With nothing in flight, the idle time ends the bridge by itself.
        runner.join(timeout=10)
        assert not runner.is_alive()
    assert finished['reply']['result'] == {'id': 24}


ISSUE = {'operation': 'issue.view', 'arguments': {'issue': 24}}


def held_until(release: threading.Event) -> Callable[[dict[str, Any]], Any]:
    """A provider route that answers only once the test says so."""
    def route(seen: dict[str, Any]) -> tuple[int, dict[str, str], bytes]:
        release.wait(30)
        return 200, {}, b'{"id": 24}'
    return route


def test_a_closed_lease_still_lets_an_answer_in_flight_reach_its_caller(
    live: Live,
) -> None:
    """A CLI bridge exits as soon as ``serve`` returns, killing its workers.

    So the drain is visible only at that moment: the caller's answer must
    already be on its socket when ``serve`` returns.
    """
    live.provider.routes[('GET', '/v1/issues/24')] = slow(2.0, {'id': 24})
    frame = {'version': 1, 'capability': live.alpha.jwt.read_text(),
             'request': ISSUE}
    stop = threading.Event()
    with live.bridge() as service:
        runner = threading.Thread(target=service.serve,
                                  kwargs={'should_stop': stop.is_set})
        runner.start()
        with tls_channel(service.listen, live.authority, live.alpha) as channel:
            channel.sendall(codec.dumps(frame) + b'\n')
            wait_for(lambda: live.provider.seen('GET'))
            stop.set()
            runner.join(timeout=15)
            assert not runner.is_alive()
            assert select.select([channel], [], [], 0)[0], (
                'serve() returned before the answer in flight was sent')
            reply = codec.loads(read_frame(channel, limit=codec.MAX_FRAME,
                                           timeout=5))
    assert reply['result'] == {'id': 24}


def test_a_closed_lease_stops_listening_at_once_and_drains_only_briefly(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parent that closed the lease kills a bridge that lingers.

    So the socket goes first -- nobody new is taken, and a bridge killed
    mid-drain leaves nothing behind -- and a call held up at a slow provider
    is waited for only ``stop_drain``, not the provider's whole deadline.
    """
    release = threading.Event()
    live.provider.routes[('GET', '/v1/issues/24')] = held_until(release)
    become(monkeypatch, live.authority, live.alpha)
    stop = threading.Event()
    outcome: dict[str, Any] = {}
    with live.bridge(stop_drain=2.0) as service:
        listen = service.listen
        runner = threading.Thread(target=service.serve,
                                  kwargs={'should_stop': stop.is_set})
        runner.start()

        def held_call() -> None:
            try:
                outcome['reply'] = ask(listen, live.alpha, ISSUE)
            except (OSError, ValueError) as ex:
                outcome['error'] = ex

        caller = threading.Thread(target=held_call)
        caller.start()
        try:
            wait_for(lambda: live.provider.seen('GET'))
            stop.set()
            wait_for(lambda: not listen.exists(), seconds=3.0)
            # Gone while the call in flight is still being waited for.
            assert runner.is_alive()
            with pytest.raises(OSError):
                ask(listen, live.alpha)
            runner.join(timeout=5)
            assert not runner.is_alive()
            assert caller.is_alive()
        finally:
            release.set()
            caller.join(timeout=30)
            runner.join(timeout=30)
    # The provider saw the held call only: the late caller never got in.
    assert len(live.provider.seen()) == 1
    for nonsense in (-1, 'x', bridge_service.STOP_DRAIN_SECONDS + 1):
        with pytest.raises(SecretsError) as caught:
            live.bridge(stop_drain=nonsense)
        assert caught.value.code == 'invalid_policy'


def test_a_closed_lease_ends_the_bridge_inside_aivms_stop_timeout() -> None:
    """``aivm ssh`` closes the bridge's lease, waits this long, then kills it."""
    from aivm.secrets_transport import BROKER_STOP_TIMEOUT

    # The lease is noticed within a poll, and then drained for at most this.
    noticed = 2 * bridge_service.POLL_SECONDS
    assert noticed + bridge_service.STOP_DRAIN_SECONDS < BROKER_STOP_TIMEOUT


def test_a_bridge_child_whose_lease_closes_mid_call_exits_and_cleans_up(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """As AIVM ends a bound session while an agent's call is at the provider."""
    from aivm.secrets_transport import BROKER_STOP_TIMEOUT

    release = threading.Event()
    live.provider.routes[('GET', '/v1/issues/24')] = held_until(release)
    become(monkeypatch, live.authority, live.alpha)
    listen = live.root / 'bridge' / 'id.sock'
    outcome: dict[str, Any] = {}
    child = subprocess.Popen(
        [sys.executable, '-I', '-m', 'aivm_secrets', 'identity', 'bridge',
         '--root', str(live.root / 'host'),
         '--broker-socket', str(live.broker_socket),
         '--listen', str(listen), '--exit-on-stdin-eof'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd='/')
    assert child.stdin is not None and child.stdout is not None
    caller: threading.Thread | None = None
    try:
        ready = first_line(child.stdout)
        assert json.loads(ready)['listening'] == str(listen), ready

        def held_call() -> None:
            try:
                outcome['reply'] = ask(listen, live.alpha, ISSUE)
            except (OSError, ValueError) as ex:
                outcome['error'] = ex

        caller = threading.Thread(target=held_call)
        caller.start()
        wait_for(lambda: live.provider.seen('GET'))
        closed = time.monotonic()
        child.stdin.close()
        code = child.wait(timeout=BROKER_STOP_TIMEOUT)
        took = time.monotonic() - closed
        assert code == 0
        assert took < BROKER_STOP_TIMEOUT
        # It removed its own socket rather than being killed beside it.
        assert not listen.exists()
        caller.join(timeout=10)
        # Past the drain the call ends without an answer: a transport
        # failure, never a definite one.
        assert 'reply' not in outcome, outcome
    finally:
        release.set()
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()
        if caller is not None:
            caller.join(timeout=30)


def test_a_bridge_pinned_to_one_subject_refuses_another_before_the_broker(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    beta = live.enroll('vm-beta')
    # Unpinned, beta's own token for the same broker works like alpha's ...
    become(monkeypatch, live.authority, beta)
    with serving(live.bridge()) as listen:
        assert ask(listen, beta)['ok'] is True
    assert len(live.provider.seen()) == 1
    before = live.audit()
    # ... pinned to alpha, beta is refused before any frame reaches it.
    with serving(live.bridge(subject='vm-alpha')) as listen:
        refused = ask(listen, beta)
        assert refused['error']['code'] == 'wrong_binding'
        assert live.audit() == before
        become(monkeypatch, live.authority, live.alpha)
        assert ask(listen, live.alpha)['ok'] is True
    assert len(live.provider.seen()) == 2
    for nonsense in ('', 'two words', '-flag', 'x' * 200):
        with pytest.raises(SecretsError) as caught:
            live.bridge(subject=nonsense)
        assert caught.value.code == 'invalid_policy'


def test_the_brokers_control_socket_is_refused_before_listening(
    live: Live,
) -> None:
    control = Path(live.broker.announce['control'])
    assert control.is_socket()
    with pytest.raises(SecretsError) as caught:
        live.bridge(broker_socket=control)
    assert caught.value.code == 'unsafe_file'
    assert not (live.root / 'bridge' / 'id.sock').exists()
    assert live.events() == ['session_open']


def test_a_broker_socket_swapped_mid_session_is_refused_on_the_next_call(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    become(monkeypatch, live.authority, live.alpha)
    path = live.broker_socket
    moved = path.with_name('moved.sock')
    with serving(live.bridge()) as listen:
        assert ask(listen, live.alpha)['ok'] is True
        os.rename(path, moved)
        os.symlink(moved, path)
        try:
            assert ask(listen, live.alpha)['error']['code'] == 'unsafe_file'
        finally:
            path.unlink()
            os.rename(moved, path)
        assert ask(listen, live.alpha)['ok'] is True
        path.chmod(0o660)
        try:
            assert ask(listen, live.alpha)['error']['code'] == 'unsafe_file'
        finally:
            path.chmod(0o600)
        assert ask(listen, live.alpha)['ok'] is True
    assert len(live.provider.seen()) == 3


def test_another_sessions_broker_cannot_open_this_sessions_token(
    live: Live, monkeypatch: pytest.MonkeyPatch,
) -> None:
    become(monkeypatch, live.authority, live.alpha)
    with ServeProcess(['--policy', str(live.policy)], env=live.broker.env) as other:
        assert other.ready, other.announce
        other_socket = Path(other.announce['socket'])
        with serving(live.bridge(broker_socket=other_socket)) as listen:
            refused = ask(listen, live.alpha)
    assert refused['error']['code'] == 'invalid_capability'
    assert live.provider.seen() == []
    assert live.events() == ['session_open']


# ---------------------------------------------------------------------------
# Against a socket-level broker, for what a real broker never does
# ---------------------------------------------------------------------------


class FakeBroker:
    """A stand-in for the broker at its real boundary, its Unix socket.

    Used only for what a real broker cannot be made to do: hang up after
    reading a frame, answer with something that is not a reply, refuse
    connections on a socket file that exists, or answer two requests at
    once (the real one runs requests one at a time, by design). Every frame
    it receives is recorded, so a test can show that none arrived.
    """

    def __init__(self, directory: Path,
                 respond: Callable[[bytes], bytes] | None = None, *,
                 accepting: bool = True):
        directory.mkdir(mode=0o700)
        self.path = directory / GUEST_SOCKET
        self.frames: list[bytes] = []
        self._respond = respond
        self._lock = threading.Lock()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self._accepting = accepting
        if accepting:
            self._listener.listen(16)
            threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                peer, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._answer, args=(peer,),
                             daemon=True).start()

    def _answer(self, peer: socket.socket) -> None:
        with peer:
            data = b''
            try:
                peer.settimeout(10)
                while not data.endswith(b'\n'):
                    chunk = peer.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                with self._lock:
                    self.frames.append(data)
                if self._respond is not None:
                    peer.sendall(self._respond(data))
            except OSError:
                pass

    def __enter__(self) -> FakeBroker:
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._accepting:
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()


@pytest.fixture
def host(short_root: Path) -> tuple[IdentityAuthority, Identity]:
    """An authority and one enrolled guest, with no broker of its own."""
    authority = new_authority(short_root)
    return authority, enroll(authority, short_root, 'vm-alpha',
                             'aivs1.not-a-real-capability')


@pytest.mark.parametrize('respond', [
    pytest.param(None, id='eof-after-send'),
    pytest.param(lambda frame: b'{"version":1,"ok":tr', id='eof-mid-reply'),
    pytest.param(lambda frame: b'not json\n', id='malformed-reply'),
    pytest.param(lambda frame: b'[1, 2]\n', id='reply-not-an-object'),
])  # fmt: skip
def test_a_broken_reply_after_sending_is_outcome_unknown(
    short_root: Path, host: tuple[IdentityAuthority, Identity],
    monkeypatch: pytest.MonkeyPatch,
    respond: Callable[[bytes], bytes] | None,
) -> None:
    authority, alpha = host
    become(monkeypatch, authority, alpha)
    with FakeBroker(short_root / 'session', respond) as fake:
        with serving(UnixIdentityService(
                authority=authority, broker_socket=fake.path,
                listen=short_root / 'bridge' / 'id.sock')) as listen:
            reply = ask(listen, alpha)
    assert reply['error']['code'] == 'outcome_unknown'
    assert len(fake.frames) == 1
    assert json.loads(fake.frames[0])['capability'] == 'aivs1.not-a-real-capability'


def test_a_refused_connect_is_internal_error_and_sends_nothing(
    short_root: Path, host: tuple[IdentityAuthority, Identity],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, alpha = host
    become(monkeypatch, authority, alpha)
    # A safe socket file nobody listens on: the connect itself is refused.
    with FakeBroker(short_root / 'session', accepting=False) as fake:
        with serving(UnixIdentityService(
                authority=authority, broker_socket=fake.path,
                listen=short_root / 'bridge' / 'id.sock')) as listen:
            reply = ask(listen, alpha)
    assert reply['error']['code'] == 'internal_error'
    assert fake.frames == []


def test_broker_sendall_failure_after_complete_frame_is_outcome_unknown(
    short_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sendall exception does not prove that the broker lacked a frame."""
    with FakeBroker(short_root / 'session') as fake:
        proxy = bridge_service.LocalBrokerProxy(fake.path)
        real_socket = socket.socket

        class SendThenFail:
            def __init__(self, *args: Any):
                self.connection = real_socket(*args)

            def __enter__(self) -> 'SendThenFail':
                return self

            def __exit__(self, *args: Any) -> None:
                self.connection.close()

            def settimeout(self, timeout: float) -> None:
                self.connection.settimeout(timeout)

            def connect(self, path: str) -> None:
                self.connection.connect(path)

            def sendall(self, data: bytes) -> None:
                self.connection.sendall(data)
                raise OSError('injected: all bytes sent, reply lost')

        class SocketFactory:
            AF_UNIX = socket.AF_UNIX
            SOCK_STREAM = socket.SOCK_STREAM

            @staticmethod
            def socket(*args: Any) -> SendThenFail:
                return SendThenFail(*args)

        monkeypatch.setattr(bridge_service, 'socket', SocketFactory)
        with pytest.raises(SecretsError) as failed:
            proxy.handle(b'{"operation":"read"}')
        assert failed.value.code == 'outcome_unknown'
        wait_for(lambda: fake.frames)
        assert fake.frames == [b'{"operation":"read"}\n']


def test_client_sendall_failure_after_frame_is_outcome_unknown(
    short_root: Path, host: tuple[IdentityAuthority, Identity],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TLS write may have reached the bridge even when sendall raises."""
    authority, alpha = host
    with FakeBroker(short_root / 'session',
                    respond=lambda _: b'{"version":1,"ok":true}\n') as fake:
        with serving(UnixIdentityService(
                authority=authority, broker_socket=fake.path,
                listen=short_root / 'bridge' / 'id.sock')) as listen:
            original = ssl.SSLSocket.sendall

            def sent_then_failed(channel: ssl.SSLSocket,
                                 data: bytes, flags: int = 0) -> None:
                original(channel, data, flags)
                # Do not disturb the bridge's reply writer on its worker.
                if threading.current_thread() is threading.main_thread():
                    raise OSError('injected: sent TLS application data')

            with monkeypatch.context() as patch:
                patch.setattr(ssl.SSLSocket, 'sendall', sent_then_failed)
                with pytest.raises(SecretsError) as failed:
                    identity_client.bound_call(
                        socket_path=listen, ca=authority.tls_paths()[2],
                        certificate=alpha.certificate,
                        private_key=alpha.key, jwt_file=alpha.jwt,
                        request=PROFILE)
            assert failed.value.code == 'outcome_unknown'
            wait_for(lambda: fake.frames)
    assert len(fake.frames) == 1
    assert json.loads(fake.frames[0])['request'] == PROFILE


def test_only_certificate_alerts_prove_handshake_refusal() -> None:
    failure = ssl.SSLError(ssl.SSL_ERROR_SSL, 'synthetic')
    failure.reason = 'TLSV1_ALERT_UNKNOWN_CA'
    assert identity_client._refused_handshake(failure)
    failure.reason = 'SSLV3_ALERT_HANDSHAKE_FAILURE'
    assert not identity_client._refused_handshake(failure)
    failure.reason = 'SSLV3_ALERT_BAD_RECORD_MAC'
    assert not identity_client._refused_handshake(failure)


def test_two_callers_are_forwarded_to_the_broker_at_once(
    short_root: Path, host: tuple[IdentityAuthority, Identity],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, alpha = host
    become(monkeypatch, authority, alpha)
    release = threading.Event()

    def respond(frame: bytes) -> bytes:
        if 'request' in json.loads(frame):
            release.wait(10)
        return b'{"version":1,"ok":true}\n'

    finished: dict[str, Any] = {}
    answered_at = float('inf')
    with FakeBroker(short_root / 'session', respond) as fake:
        with serving(UnixIdentityService(
                authority=authority, broker_socket=fake.path,
                listen=short_root / 'bridge' / 'id.sock')) as listen:
            def slow_call() -> None:
                finished['reply'] = ask(listen, alpha)
                finished['at'] = time.monotonic()

            caller = threading.Thread(target=slow_call)
            caller.start()
            try:
                wait_for(lambda: fake.frames)
                described = ask(listen, alpha, True, 'describe')
                answered_at = time.monotonic()
                assert described['ok'] is True
                assert caller.is_alive()
                assert len(fake.frames) == 2
            finally:
                release.set()
                caller.join(timeout=30)
    assert finished['reply']['ok'] is True
    assert answered_at < finished['at']
