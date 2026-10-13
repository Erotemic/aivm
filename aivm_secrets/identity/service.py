"""Explicitly launched Unix-domain mTLS identity bridge (P4a).

Only the trusted local broker holds provider credentials and decides effects.
The bridge runs under the owning host principal and has NO TCP listener and NO
remote issuance endpoint. Only the host-only ``python -I -m aivm_secrets
identity bridge`` command starts it -- ``aivm ssh --secrets_identity_root``
runs that command for a bound session and forwards the socket into the guest
with ``ssh -R`` -- and nothing starts it implicitly. It has no connection cap
by default: its idle timeout and its parent's stdin lease end it.
"""

from __future__ import annotations

import os
import select
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..errors import SecretsError
from ..host.files import outside, private_directory
from ..transport.names import GUEST_SOCKET
from ..transport.framing import (
    BROKER_REPLY_DEADLINE, CONNECT_TIMEOUT, FRAME_TIMEOUT,
    RELAYED_REPLY_DEADLINE, read_frame,
)
from ..kernel import codec
from ..primitives import wire
from .enrollment import IdentityAuthority
from .garrett.claims import IdentityExpectation
from .mtls import IdentityTLSBridge, server_context

# An explicit cap is optional (the default is none); when given it must be
# small enough to be a deliberate operator choice rather than a typo.
MAX_CONNECTIONS = 256
MAX_IDLE_SECONDS = 3600
# Connections served at once, as for the broker's own listener
# (``host/server.py``). A caller beyond this waits in the listen backlog.
MAX_WORKERS = 16
LISTEN_BACKLOG = 64
POLL_SECONDS = 0.5
# Every worker is bounded by its own legs: its handshake, then everything a
# client of the bridge waits for. So when the bridge leaves by itself (idle,
# capped or faulted) this is enough for each one in flight to be answered.
DRAIN_SECONDS = FRAME_TIMEOUT + RELAYED_REPLY_DEADLINE
# When its operator ends it instead (``should_stop``: the CLI's stdin lease),
# an answer about to arrive still reaches its caller, but nobody waits out a
# slow provider. The parent that closed the lease kills a bridge that lingers
# (AIVM does after its 10 s ``BROKER_STOP_TIMEOUT``), and a killed bridge
# cannot clean up after itself.
STOP_DRAIN_SECONDS = 5.0


def _never() -> bool:
    return False


class LocalBrokerProxy:
    """Only forward an already-authorized frame to the *existing* broker.

    Each call opens its own connection and keeps nothing afterwards, so any
    number of bridge workers can share one proxy without a lock.
    """

    def __init__(self, socket_path: Path, *, untrusted: tuple[Path, ...] = (),
                 reply_deadline: float = BROKER_REPLY_DEADLINE):
        self.path = Path(socket_path).expanduser().absolute()
        self.untrusted = untrusted
        # Never use the host-only control socket as a purported request broker.
        if self.path.name != GUEST_SOCKET:
            raise SecretsError('unsafe_file')
        # Only shorter, for tests: a longer wait would no longer fit inside
        # the deadline the bridge's own clients use (RELAYED_REPLY_DEADLINE).
        if (type(reply_deadline) not in (int, float) or
                not 0 < reply_deadline <= BROKER_REPLY_DEADLINE):
            raise SecretsError('invalid_policy')
        self.reply_deadline = float(reply_deadline)
        self._validate()

    def _validate(self) -> None:
        outside(self.path, self.untrusted, what='broker socket')
        private_directory(self.path.parent, self.untrusted)
        try:
            info = self.path.lstat()
        except OSError:
            raise SecretsError('unsafe_file') from None
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise SecretsError('unsafe_file')

    def handle(self, data: bytes) -> dict[str, Any]:
        """Forward one frame and report honestly what is known of its fate.

        Until the whole frame, newline included, has been handed to the
        kernel, the broker cannot have a request to act on (it only parses a
        complete line), so a failure is ``internal_error``: nothing was
        dispatched. From then on the broker may be executing it -- a write,
        for all the bridge can tell -- so a timeout, EOF, reset or unusable
        reply is ``outcome_unknown``. It is never ``invalid_request``: telling
        a caller its request was malformed invites a retry of a write that
        may already have been applied.
        """
        # The socket is judged again on every call: it may have been swapped
        # for a link or loosened since the bridge started.
        self._validate()
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            raise SecretsError('internal_error') from None
        with conn:
            try:
                conn.settimeout(CONNECT_TIMEOUT)
                conn.connect(str(self.path))
                conn.sendall(data + b'\n')
            except OSError:
                raise SecretsError('internal_error') from None
            try:
                # A reply is a bounded provider response plus an envelope:
                # far larger than any request frame.
                response = read_frame(conn, limit=wire.MAX_REPLY,
                                      timeout=self.reply_deadline)
                result = codec.loads(response, limit=wire.MAX_REPLY)
            except Exception:
                raise SecretsError('outcome_unknown') from None
        if type(result) is not dict:
            raise SecretsError('outcome_unknown')
        return result


class UnixIdentityService:
    """One foreground listener. No daemon or privilege escalation.

    Connections are served concurrently, at most ``MAX_WORKERS`` at once, so
    a slow provider call no longer holds up other callers' TLS handshakes or
    the answers the bridge gives by itself (a refused delegation, a wrong
    binding, a revoked certificate, an unsafe broker socket). It does not
    make the broker concurrent: the broker runs requests one at a time, so a
    call that needs it still waits behind the one in progress, and that wait
    counts against the caller's deadline.

    The service ends when its operator says so (``should_stop``, which the
    CLI ties to a stdin lease), after ``idle_seconds`` with nothing in
    flight, or -- only when one was given -- after ``max_connections``
    connections. By default there is no connection cap: a session's lifetime
    belongs to its broker and its parent, not to a count of calls.

    Thread safety: workers share this object's authority, TLS context,
    verifier and proxy. What they read per request -- the CA manifest, the
    enrollment registry behind the peer's expectation, the issuer keyring
    and its keys -- is read afresh from files that writers replace by atomic
    rename under the authority's lock, and nothing read is cached or written
    back. So those reads take no lock, have no side effects, and see either
    the old or the new file, never a torn one.
    """

    def __init__(self, *, authority: IdentityAuthority, broker_socket: Path,
                 listen: Path, max_connections: int | None = None,
                 idle_seconds: int = 900, subject: str | None = None,
                 reply_deadline: float = BROKER_REPLY_DEADLINE,
                 stop_drain: float = STOP_DRAIN_SECONDS,
                 wall_clock: Callable[[], float] = time.time):
        if ((max_connections is not None and (
                type(max_connections) is not int or
                not 1 <= max_connections <= MAX_CONNECTIONS)) or
                type(idle_seconds) is not int or
                not 1 <= idle_seconds <= MAX_IDLE_SECONDS):
            raise SecretsError('invalid_policy')
        # Only shorter, for tests: a longer wait would outlast the parent
        # that closed the lease and is about to kill the bridge.
        if (type(stop_drain) not in (int, float) or
                not 0 <= stop_drain <= STOP_DRAIN_SECONDS):
            raise SecretsError('invalid_policy')
        if subject is not None:
            # The same grammar an enrolled subject has; never a pattern.
            try:
                subject = IdentityExpectation.parse({
                    'issuer': authority.issuer, 'audience': authority.audience,
                    'subject': subject, 'epoch': 0,
                }).subject
            except SecretsError:
                raise SecretsError('invalid_policy') from None
        self.authority = authority
        self.subject = subject
        self.listen = Path(listen).expanduser().absolute()
        private_directory(self.listen.parent, authority.untrusted)
        outside(self.listen, authority.untrusted, what='identity listener')
        self.broker = LocalBrokerProxy(broker_socket, untrusted=authority.untrusted,
                                       reply_deadline=reply_deadline)
        certificate, key, ca = authority.tls_paths()
        # Dynamic expectations are always supplied from the registry. The
        # static verifier expectation is intentionally not an enrolled VM.
        expected = IdentityExpectation(authority.issuer, authority.audience,
                                       'init', 0)
        self.bridge = IdentityTLSBridge(
            context=server_context(certificate=certificate, private_key=key,
                                   client_ca=ca),
            verifier=authority.token_verifier(expected),
            broker=self.broker,
            wall_clock=wall_clock,
            expected_for_peer=authority.expectation_for_peer,
            subject=subject,
        )
        self.max_connections = max_connections
        self.idle_seconds = idle_seconds
        self.stop_drain = float(stop_drain)
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._faulted = threading.Event()

    def __enter__(self) -> UnixIdentityService:
        if self._socket is not None:
            raise SecretsError('internal_error')
        old_umask = os.umask(0o077)
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # No unlink of an existing path: avoid clobbering another service.
            conn.bind(str(self.listen))
            os.chmod(self.listen, 0o600)
            conn.listen(LISTEN_BACKLOG)
            conn.setblocking(False)
            info = self.listen.lstat()
            self._socket_identity = (info.st_dev, info.st_ino)
            self._socket = conn
            return self
        except OSError:
            conn.close()
            raise SecretsError('unsafe_file') from None
        finally:
            os.umask(old_umask)

    def serve(self, should_stop: Callable[[], bool] = _never) -> int:
        """Serve until stopped or idle (or capped); return connections taken.

        On the way out the listener is closed and its path unlinked first,
        so no new caller is taken or left waiting in the backlog, and a
        bridge killed while it drains leaves no socket behind. The answers in
        flight are then given up to ``DRAIN_SECONDS`` to reach their callers
        -- but only ``stop_drain`` once ``should_stop`` has said so.
        """
        listener = self._socket
        if listener is None:
            raise SecretsError('internal_error')
        slots = threading.BoundedSemaphore(MAX_WORKERS)
        workers: list[threading.Thread] = []
        handled = 0
        stopping = False
        deadline = time.monotonic() + self.idle_seconds
        # An exception (an operator's Ctrl-C, say) leaves without draining:
        # workers are daemon threads and end with the process.
        while ((self.max_connections is None or
                handled < self.max_connections) and
               not self._faulted.is_set()):
            if should_stop():
                stopping = True
                break
            alive = [worker for worker in workers if worker.is_alive()]
            if workers and not alive:
                # A session waiting on its broker is busy, not idle: the
                # idle clock restarts when the last answer has gone.
                deadline = time.monotonic() + self.idle_seconds
            workers = alive
            remaining = deadline - time.monotonic()
            if remaining <= 0 and not workers:
                break
            wait = POLL_SECONDS if remaining <= 0 else min(POLL_SECONDS, remaining)
            if not select.select([listener], [], [], wait)[0]:
                continue
            if should_stop():
                # A caller who arrived as the lease closed is not taken.
                stopping = True
                break
            if not slots.acquire(timeout=POLL_SECONDS):
                continue  # Every worker is busy; the caller is queued.
            try:
                peer, _ = listener.accept()
            except BlockingIOError:
                slots.release()
                continue
            except OSError:
                slots.release()
                break
            handled += 1
            deadline = time.monotonic() + self.idle_seconds
            worker = threading.Thread(target=self._serve_one,
                                      args=(peer, slots), daemon=True)
            try:
                worker.start()
            except RuntimeError:
                peer.close()
                slots.release()
                raise SecretsError('internal_error') from None
            workers.append(worker)
        self._close_listener()
        self._drain(workers, should_stop, stopping)
        if self._faulted.is_set():
            raise SecretsError('internal_error')
        return handled

    def _drain(self, workers: list[threading.Thread],
               should_stop: Callable[[], bool], stopping: bool) -> None:
        """Let the answers in flight go out, for as long as the exit allows."""
        finish = time.monotonic() + (
            self.stop_drain if stopping else DRAIN_SECONDS)
        for worker in workers:
            while worker.is_alive():
                if not stopping and should_stop():
                    # Ended by its operator while draining for another
                    # reason: from now on the shorter wait applies.
                    stopping = True
                    finish = min(finish, time.monotonic() + self.stop_drain)
                remaining = finish - time.monotonic()
                if remaining <= 0:
                    return
                worker.join(min(POLL_SECONDS, remaining))

    def _serve_one(self, peer: socket.socket,
                   slots: threading.BoundedSemaphore) -> None:
        try:
            self.bridge.serve_accepted(peer)
        except OSError:
            # An unauthenticated TLS handshake, or a caller that hung up, is
            # not an authorization event and never grants access or stops
            # the service for anyone else.
            pass
        except Exception:
            # An unexpected fault fails closed for the whole service, as it
            # did when connections were served in the accept loop itself.
            self._faulted.set()
        finally:
            peer.close()
            slots.release()

    def _close_listener(self) -> None:
        """Take no more callers: close the listener and unlink its path.

        Idempotent. The path is unlinked only while it is still the socket
        this service bound, never something put in its place.
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        try:
            info = self.listen.lstat()
            if self._socket_identity == (info.st_dev, info.st_ino):
                self.listen.unlink()
        except FileNotFoundError:
            pass
        self._socket_identity = None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._close_listener()
