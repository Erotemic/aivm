"""Linux AF_UNIX transport. Each listener is bound to one host-created session."""

from __future__ import annotations

import os
import socket
import socketserver
import struct
import threading
from pathlib import Path
from typing import cast

from .broker import Broker
from .errors import SecretsError
from .files import private_directory
from .wire import dumps, read_frame


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_Server, self.server)
        try:
            # The peer is the owning host process (SSH when forwarded), not a
            # guest UID. Session identity comes from this dedicated listener.
            creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack('iII', creds)
            if uid != server.broker.binding.owner_uid:
                return
            try:
                raw = read_frame(self.request)
            except SecretsError:
                raw = b''  # Charge malformed frames to the same attempt budget.
            reply = server.broker.handle(raw)
            self.request.settimeout(5)
            self.request.sendall(dumps(reply) + b'\n')
        except (OSError, SecretsError):
            # Neither raw requests nor exception text belong in stderr logs.
            return


class _Server(socketserver.UnixStreamServer):
    broker: Broker
    request_queue_size = 8

    def handle_error(self, request: socket.socket, client_address: str) -> None:
        # socketserver's default traceback may include application internals.
        return


class LocalServer:
    """Foreground owner starts/stops this listener; no persistent host daemon."""

    def __init__(self, broker: Broker, socket_path: Path):
        self.broker = broker
        self.socket_path = socket_path
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._inode: tuple[int, int] | None = None

    def __enter__(self) -> LocalServer:
        if not hasattr(socket, 'SO_PEERCRED'):
            raise SecretsError('internal_error')
        private_directory(self.socket_path.parent)
        if len(os.fsencode(self.socket_path)) > 100:
            raise SecretsError('unsafe_file')
        # Refuse existing entries; never unlink a possibly live/stale endpoint.
        if os.path.lexists(self.socket_path):
            raise SecretsError('unsafe_file')
        try:
            self._server = _Server(str(self.socket_path), _Handler)
            os.chmod(self.socket_path, 0o600)
            info = self.socket_path.lstat()
            self._inode = (info.st_dev, info.st_ino)
            self._server.broker = self.broker
            self._thread = threading.Thread(target=self._server.serve_forever,
                                            kwargs={'poll_interval': 0.1}, daemon=True)
            self._thread.start()
        except Exception:
            if self._server is not None:
                self._server.server_close()
            raise SecretsError('unsafe_file') from None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.broker.revoke()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join()
        try:
            info = self.socket_path.lstat()
            if (info.st_dev, info.st_ino) == self._inode:
                self.socket_path.unlink()
        except FileNotFoundError:
            pass
