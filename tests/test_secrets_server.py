"""Real Unix sockets: the guest plane, the control plane and the registry."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.guest import exchange
from aivm_secrets.host import server as server_module
from aivm_secrets.host import session
from aivm_secrets.host.server import LocalServer, read_frame
from aivm_secrets.kernel import codec
from tests.secrets_helpers import REPO, Harness, https_policy

VIEW = {
    'operation': 'pr.view',
    'arguments': {'repository': REPO, 'pr': 13861},
}


@pytest.fixture
def short_dir():
    """Socket paths are limited to ~100 bytes; pytest's tmp_path is too deep."""
    with tempfile.TemporaryDirectory(prefix='as-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.fixture
def h(tmp_path):
    instance = Harness(tmp_path)
    yield instance
    instance.broker.close()


def raw_exchange(path: Path, data: bytes, *, timeout: float = 5.0) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        client.sendall(data)
        return read_frame(client, limit=4 * 1024 * 1024, timeout=timeout)


def test_real_unix_socket_serves_both_planes_privately(h, short_dir):
    directory = short_dir / 's'
    with LocalServer(h.broker, directory) as server:
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        for path in (server.socket_path, server.control_path):
            assert stat.S_ISSOCK(path.stat().st_mode)
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        reply = exchange(str(server.socket_path), h.capability, VIEW)
        assert reply['ok'] and reply['result']['number'] == 13861
        status = session.control_call(directory, {'command': 'status'})
        assert status['ok'] and status['session']['used'] == 1
    assert not server.socket_path.exists() and not server.control_path.exists()
    # Leaving the context revoked the session before unbinding anything.
    assert h.broker.status()['active'] is False


def test_the_guest_socket_cannot_reach_the_control_plane(h, short_dir):
    """Approval and revocation exist only behind ``control.sock``."""
    with LocalServer(h.broker, short_dir / 's') as server:
        for command in ('status', 'pending', 'approve', 'revoke'):
            for frame in (
                {'command': command},
                {'version': 1, 'capability': h.capability, 'command': command},
                {'version': 1, 'capability': h.capability, command: True},
            ):
                reply = json.loads(
                    raw_exchange(server.socket_path, codec.dumps(frame) + b'\n')
                )
                assert reply['error']['code'] == 'invalid_request'
        assert h.broker.status()['active'] is True
        # And the control socket does not speak the guest protocol.
        guest_frame = {
            'version': 1,
            'capability': h.capability,
            'request': VIEW,
        }
        reply = json.loads(
            raw_exchange(server.control_path, codec.dumps(guest_frame) + b'\n')
        )
        assert reply['error']['code'] == 'invalid_request'
        assert not h.executor.calls


def test_real_socket_wrong_capability_and_malformed_request(h, short_dir):
    with LocalServer(h.broker, short_dir / 's') as server:
        reply = exchange(str(server.socket_path), 'invalid', VIEW)
        assert reply['error']['code'] == 'invalid_capability'
        for junk in (
            b'{"version":1,"version":1}\n',
            b'\n',
            b'\xff\xfe\n',
            b'{}\n',
        ):
            reply = json.loads(raw_exchange(server.socket_path, junk))
            assert reply['error']['code'] == 'invalid_request'
        assert not h.executor.calls
        # Each malformed frame was still charged as an attempt.
        assert h.broker.status()['attempts'] == 5


def test_concurrent_requests_cannot_exceed_session_budget(tmp_path, short_dir):
    h = Harness(tmp_path, max_requests=3)
    try:
        with LocalServer(h.broker, short_dir / 's') as server:
            with ThreadPoolExecutor(max_workers=6) as pool:
                replies = list(
                    pool.map(
                        lambda _: exchange(
                            str(server.socket_path), h.capability, VIEW
                        ),
                        range(6),
                    )
                )
        assert sum(reply['ok'] for reply in replies) == 3
        assert len(h.executor.calls) == 3
    finally:
        h.broker.close()


def test_existing_socket_path_is_not_unlinked(h, short_dir):
    directory = short_dir / 's'
    directory.mkdir(mode=0o700)
    for name in (server_module.GUEST_SOCKET, server_module.CONTROL_SOCKET):
        path = directory / name
        path.write_text('must survive')
        with pytest.raises(SecretsError):
            with LocalServer(h.broker, directory):
                pass
        assert path.read_text() == 'must survive'
        path.unlink()
    # A failed start leaves nothing half-bound behind.
    assert list(directory.iterdir()) == []


def test_socket_path_length_is_checked_not_truncated(h, short_dir):
    deep = short_dir / ('d' * 90)
    with pytest.raises(SecretsError) as caught:
        with LocalServer(h.broker, deep):
            pass
    assert 'too long' in caught.value.detail


def test_wire_absolute_deadline_and_size():
    left, right = socket.socketpair()
    try:
        right.sendall(b'not-finished')
        started = time.monotonic()
        with pytest.raises(SecretsError):
            read_frame(left, timeout=0.05)
        assert time.monotonic() - started < 2
        right.sendall(b'x' * 20)
        with pytest.raises(SecretsError):
            read_frame(left, limit=8)
    finally:
        left.close()
        right.close()


def test_a_trickled_frame_cannot_renew_its_deadline():
    left, right = socket.socketpair()
    stop = threading.Event()

    def trickle():
        while not stop.is_set():
            try:
                right.sendall(b'x')
            except OSError:
                return
            time.sleep(0.02)

    thread = threading.Thread(target=trickle, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        with pytest.raises(SecretsError):
            read_frame(left, timeout=0.3)
        assert 0.25 < time.monotonic() - started < 2
    finally:
        stop.set()
        left.close()
        right.close()
        thread.join(2)


@pytest.mark.parametrize('data', [b'{}\n{}\n', b'{}', b'{}\nextra'])
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


def test_kernel_peer_uid_must_match_listener_binding(h, short_dir):
    h.broker.binding = replace(h.broker.binding, owner_uid=os.getuid() + 1)
    with LocalServer(h.broker, short_dir / 's') as server:
        for path in (server.socket_path, server.control_path):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(path))
                try:
                    client.sendall(h.raw() + b'\n')
                    assert client.recv(1) == b''
                except (ConnectionResetError, BrokenPipeError):
                    pass
        assert not h.executor.calls
        assert h.broker.status()['attempts'] == 0


def test_idle_connections_cannot_exhaust_host_threads(
    h, short_dir, monkeypatch
):
    monkeypatch.setattr(server_module, 'FRAME_TIMEOUT', 0.5)
    monkeypatch.setattr(server_module, 'MAX_CONNECTIONS', 3)
    before = threading.active_count()
    with LocalServer(h.broker, short_dir / 's') as server:
        idle = []
        for _ in range(40):
            client = socket.socket(socket.AF_UNIX)
            client.connect(str(server.socket_path))
            idle.append(client)
        time.sleep(0.2)
        # However many connect, only a bounded number are ever being served.
        assert threading.active_count() - before <= 3 + 3
        # A legitimate request is delayed by the flood, not refused: each
        # idle connection can hold its slot only until the frame deadline.
        reply = exchange(str(server.socket_path), h.capability, VIEW)
        assert reply['ok']
        for client in idle:
            client.close()


def test_a_burst_of_legitimate_parallel_requests_is_queued_not_refused(
    tmp_path, short_dir, monkeypatch
):
    """More simultaneous clients than slots: all are answered, none dropped."""
    monkeypatch.setattr(server_module, 'MAX_CONNECTIONS', 2)
    h = Harness(tmp_path, policy=https_policy(max_requests=5))
    request = {'operation': 'profile.read', 'arguments': {}}
    try:
        with LocalServer(h.broker, short_dir / 's') as server:
            with ThreadPoolExecutor(max_workers=24) as pool:
                replies = list(
                    pool.map(
                        lambda _: exchange(
                            str(server.socket_path), h.capability, request
                        ),
                        range(24),
                    )
                )
        assert sum(reply['ok'] for reply in replies) == 5
        refused = [r['error']['code'] for r in replies if not r['ok']]
        assert refused == ['exhausted'] * 19
    finally:
        h.broker.close()


def test_shutdown_is_prompt_even_when_every_slot_is_held(
    h, short_dir, monkeypatch
):
    monkeypatch.setattr(server_module, 'FRAME_TIMEOUT', 30.0)
    monkeypatch.setattr(server_module, 'MAX_CONNECTIONS', 2)
    idle = []
    started = time.monotonic()
    with LocalServer(h.broker, short_dir / 's') as server:
        for _ in range(6):
            client = socket.socket(socket.AF_UNIX)
            client.connect(str(server.socket_path))
            idle.append(client)
        time.sleep(0.3)
    assert time.monotonic() - started < 5
    for client in idle:
        client.close()


def test_the_control_plane_answers_while_a_request_is_in_flight(
    tmp_path, short_dir
):
    h = Harness(tmp_path, policy=https_policy())
    entered, release = threading.Event(), threading.Event()

    def slow(authorized, credential):
        entered.set()
        assert release.wait(10)
        return {'ok': True}

    setattr(h.executor, 'execute', slow)
    try:
        with LocalServer(h.broker, short_dir / 's') as server:
            request = {'operation': 'profile.read', 'arguments': {}}
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(
                    exchange, str(server.socket_path), h.capability, request
                )
                assert entered.wait(10)
                status = session.control_call(
                    short_dir / 's', {'command': 'status'}
                )
                assert status['session']['used'] == 1
                assert session.control_call(
                    short_dir / 's', {'command': 'revoke'}
                )['ok']
                release.set()
                # The read had already been dispatched; it completes. Nothing
                # new is admitted afterwards.
                assert pending.result(10)['ok']
            after = exchange(str(server.socket_path), h.capability, request)
            assert after['error']['code'] == 'revoked'
    finally:
        h.broker.close()


# -- the per-user registry ---------------------------------------------------


@pytest.fixture
def runtime(short_dir, monkeypatch):
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(short_dir))
    return short_dir / 'aivm-secrets'


def serve(tmp_path, name, **binding):
    h = Harness(tmp_path / name, policy=https_policy())
    channel = hashlib.sha256(name.encode()).hexdigest()[:32]
    h.broker.binding = replace(h.broker.binding, channel=channel, **binding)
    return h, LocalServer(h.broker, session.session_directory(channel))


def test_registry_lists_live_sessions_and_finds_them_by_binding(
    tmp_path, runtime
):
    one, first = serve(tmp_path, 'one', access_identity='alice', vm='vm-a')
    two, second = serve(tmp_path, 'two', access_identity='bob', vm='vm-a')
    try:
        assert session.list_sessions() == []
        with first, second:
            assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
            found = session.list_sessions()
            assert sorted(item['access_identity'] for item in found) == [
                'alice',
                'bob',
            ]
            assert all(
                Path(item['directory']).parent == runtime for item in found
            )
            (alice,) = session.find_sessions(access_identity='alice', vm='vm-a')
            assert alice['channel'] == one.broker.binding.channel
            assert session.find_sessions(access_identity='carol') == []
            assert session.find_sessions(vm='vm-b') == []
            assert len(session.find_sessions(vm='vm-a')) == 2
            prefix = two.broker.binding.channel[:10]
            assert [
                s['access_identity'] for s in session.find_sessions(prefix)
            ] == ['bob']
        assert session.list_sessions() == []
    finally:
        one.broker.close()
        two.broker.close()


def test_dead_sessions_are_ignored_and_pruned_without_following_anything(
    runtime,
):
    stale = session.session_directory('a' * 32)
    (stale / session.CAPABILITY_FILE).write_text('aivs1.leftover-ciphertext')
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(stale / server_module.CONTROL_SOCKET))
    sock.close()  # a socket file with nobody listening
    outside = runtime.parent / 'victim'
    outside.write_text('keep')
    (runtime / ('b' * 32)).symlink_to(runtime.parent)
    (runtime / 'not-a-session').mkdir()
    assert session.list_sessions() == []
    assert stale.exists()
    assert session.list_sessions(prune=True) == []
    assert not stale.exists()
    assert outside.read_text() == 'keep'
    assert (runtime / 'not-a-session').exists()
    with pytest.raises(SecretsError) as caught:
        session.control_call(stale, {'command': 'status'})
    assert caught.value.code == 'no_session'


def test_runtime_root_must_be_private(short_dir, monkeypatch):
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(short_dir))
    root = session.runtime_root()
    root.chmod(0o755)
    with pytest.raises(SecretsError) as caught:
        session.runtime_root()
    assert caught.value.code == 'unsafe_file'
    root.chmod(0o700)
    # Without a usable XDG_RUNTIME_DIR the fallback is a per-UID directory
    # under the system temp directory (redirected here, not the real /tmp).
    fallback = short_dir / 'tmp'
    fallback.mkdir(mode=0o700)
    monkeypatch.setattr(session.tempfile, 'gettempdir', lambda: str(fallback))
    expected = fallback / f'aivm-secrets-{os.getuid()}'
    monkeypatch.setenv('XDG_RUNTIME_DIR', 'relative/path')
    assert session.runtime_root() == expected
    monkeypatch.delenv('XDG_RUNTIME_DIR')
    assert session.runtime_root() == expected
    with pytest.raises(SecretsError):
        session.session_directory('../escape')
