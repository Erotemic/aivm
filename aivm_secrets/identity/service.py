"""Bounded, explicitly launched Unix-domain mTLS identity bridge (P4a).

Only the trusted local broker holds provider credentials and decides effects.
The bridge runs under the owning host principal and has NO TCP listener and NO
remote issuance endpoint. Operators may explicitly forward its Unix socket
with SSH; ordinary AIVM sessions do not start or forward it.
"""

from __future__ import annotations

import os
import select
import socket
import stat
import time
from pathlib import Path
from typing import Callable

from ..errors import SecretsError
from ..host.files import outside, private_directory
from ..transport.names import GUEST_SOCKET
from ..transport.framing import read_frame
from ..kernel import codec
from .enrollment import IdentityAuthority
from .model import IdentityExpectation
from .mtls import IdentityTLSBridge, server_context

MAX_CONNECTIONS = 256
MAX_IDLE_SECONDS = 3600


class LocalBrokerProxy:
    """Only forward an already-authorized frame to the *existing* broker."""

    def __init__(self, socket_path: Path, *, untrusted: tuple[Path, ...] = ()):
        self.path = Path(socket_path).expanduser().absolute()
        self.untrusted = untrusted
        # Never use the host-only control socket as a purported request broker.
        if self.path.name != GUEST_SOCKET:
            raise SecretsError('unsafe_file')
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

    def handle(self, data: bytes) -> dict:
        self._validate()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(5.0)
                conn.connect(str(self.path))
                conn.sendall(data + b'\n')
                response = read_frame(conn, limit=codec.MAX_FRAME, timeout=5.0)
                result = codec.loads(response)
                if type(result) is not dict:
                    raise SecretsError('internal_error')
                return result
        except (OSError, TimeoutError):
            raise SecretsError('internal_error') from None


class UnixIdentityService:
    """One bounded foreground listener. No daemon or privilege escalation."""

    def __init__(self, *, authority: IdentityAuthority, broker_socket: Path,
                 listen: Path, max_connections: int = 64,
                 idle_seconds: int = 900,
                 wall_clock: Callable[[], float] = time.time):
        if (type(max_connections) is not int or
                not 1 <= max_connections <= MAX_CONNECTIONS or
                type(idle_seconds) is not int or
                not 1 <= idle_seconds <= MAX_IDLE_SECONDS):
            raise SecretsError('invalid_policy')
        self.authority = authority
        self.listen = Path(listen).expanduser().absolute()
        private_directory(self.listen.parent, authority.untrusted)
        outside(self.listen, authority.untrusted, what='identity listener')
        self.broker = LocalBrokerProxy(broker_socket, untrusted=authority.untrusted)
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
        )
        self.max_connections = max_connections
        self.idle_seconds = idle_seconds
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None

    def __enter__(self):
        if self._socket is not None:
            raise SecretsError('internal_error')
        old_umask = os.umask(0o077)
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # No unlink of an existing path: avoid clobbering another service.
            conn.bind(str(self.listen))
            os.chmod(self.listen, 0o600)
            conn.listen(16)
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

    def serve(self, should_stop: Callable[[], bool] = lambda: False) -> int:
        """Exit after connection/idle cap, or an explicit operator signal."""
        if self._socket is None:
            raise SecretsError('internal_error')
        handled = 0
        deadline = time.monotonic() + self.idle_seconds
        while handled < self.max_connections and not should_stop():
            timeout = min(0.5, max(0.0, deadline - time.monotonic()))
            if timeout <= 0:
                break
            if not select.select([self._socket], [], [], timeout)[0]:
                continue
            try:
                peer, _ = self._socket.accept()
            except OSError:
                break
            handled += 1
            deadline = time.monotonic() + self.idle_seconds
            try:
                self.bridge.serve_accepted(peer)
            except (OSError, TimeoutError):
                # An unauthenticated TLS handshake is not an authorization
                # event and never grants access or kills the host service.
                peer.close()
            except Exception:
                peer.close()
                raise
        return handled

    def __exit__(self, exc_type, exc, tb):
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
