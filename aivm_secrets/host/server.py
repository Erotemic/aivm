"""Linux ``AF_UNIX`` transport: one guest listener and one control listener.

Both sockets live in the session's private runtime directory and both check
the connecting peer's kernel UID. They differ in who is meant to reach them:

``broker.sock``   forwarded into the guest; speaks protocol version 1 and
                  reaches only :meth:`Broker.handle`.
``control.sock``  never forwarded; reaches only :meth:`Broker.control`,
                  which is where approval and revocation live.

For an SSH-forwarded connection the peer the kernel reports is the host's
own ``ssh`` process, not a guest user. Session identity therefore comes from
*which listener* was dialled, never from anything the client says.
"""

from __future__ import annotations

import os
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, cast

from ..errors import SecretsError
from ..kernel import codec
from .broker import Broker
from .files import private_directory

from ..transport.names import GUEST_SOCKET, CONTROL_SOCKET
from ..transport.framing import read_frame
FRAME_TIMEOUT = 5.0
MAX_CONNECTIONS = 16
# sun_path is 108 bytes; stay well inside it on every supported kernel.
MAX_SOCKET_PATH = 100



def peer_uid(sock: socket.socket) -> int:
    credentials = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack('iII', credentials)[1]


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_Listener, self.server)
        try:
            if peer_uid(self.request) != server.owner_uid:
                return
            try:
                raw = read_frame(self.request, timeout=FRAME_TIMEOUT)
            except SecretsError:
                raw = b''  # A malformed frame is still a charged attempt.
            reply = server.serve(raw)
            self.request.settimeout(FRAME_TIMEOUT)
            self.request.sendall(codec.dumps(reply) + b'\n')
        except (OSError, SecretsError):
            # Neither raw requests nor exception text belong in stderr logs.
            return


class _Listener(socketserver.ThreadingUnixStreamServer):
    """Threaded so the control plane answers while a request is in flight.

    Guest requests are still executed one at a time by the broker. The slot
    semaphore bounds how many connections are being served at once, so a
    guest cannot turn idle connections into unbounded host threads. When
    every slot is busy the accept loop *waits* rather than refusing: a burst
    of legitimate parallel requests queues in the listen backlog and is
    served in turn, while an idle connection can hold a slot only until its
    frame deadline.
    """

    request_queue_size = 64
    daemon_threads = True
    owner_uid: int
    serve: Callable[[bytes], dict[str, Any]]

    def __init__(self, path: str):
        super().__init__(path, _Handler)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.stopping = threading.Event()

    def process_request(self, request: Any, client_address: Any) -> None:
        while not self._slots.acquire(timeout=0.1):
            if self.stopping.is_set():
                self.shutdown_request(request)
                return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # socketserver's default traceback may include application internals.
        return


class LocalServer:
    """Foreground owner starts/stops these listeners; no persistent daemon."""

    def __init__(self, broker: Broker, directory: Path):
        self.broker = broker
        self.directory = Path(directory)
        self.socket_path = self.directory / GUEST_SOCKET
        self.control_path = self.directory / CONTROL_SOCKET
        self._bound: list[tuple[_Listener, threading.Thread, Path, Any]] = []

    def _control(self, raw: bytes) -> dict[str, Any]:
        try:
            command = codec.loads(raw)
        except SecretsError:
            command = None
        return self.broker.control(command)

    def _bind(
        self, path: Path, serve: Callable[[bytes], dict[str, Any]]
    ) -> None:
        if len(os.fsencode(path)) > MAX_SOCKET_PATH:
            raise SecretsError('unsafe_file', detail=f'{path}: path too long')
        # Refuse existing entries; never unlink a possibly live endpoint.
        if os.path.lexists(path):
            raise SecretsError('unsafe_file', detail=f'{path}: already exists')
        listener = None
        try:
            # The enclosing directory is already 0700, so nothing can reach
            # the socket in the instant before its own mode is tightened.
            listener = _Listener(str(path))
            os.chmod(path, 0o600)
            info = path.lstat()
            listener.owner_uid = self.broker.binding.owner_uid
            listener.serve = serve
            thread = threading.Thread(
                target=listener.serve_forever,
                kwargs={'poll_interval': 0.1},
                daemon=True,
            )
            thread.start()
        except Exception:
            if listener is not None:
                listener.server_close()
            raise SecretsError(
                'unsafe_file', detail=f'{path}: cannot listen'
            ) from None
        self._bound.append((listener, thread, path, (info.st_dev, info.st_ino)))

    def __enter__(self) -> LocalServer:
        if not hasattr(socket, 'SO_PEERCRED'):
            raise SecretsError('internal_error')
        private_directory(self.directory)
        try:
            self._bind(self.socket_path, self.broker.handle)
            self._bind(self.control_path, self._control)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        # Authority stops first; the sockets are only plumbing.
        self.broker.revoke()
        for listener, thread, path, inode in self._bound:
            listener.stopping.set()
            listener.shutdown()
            listener.server_close()
            thread.join()
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == inode:
                    path.unlink()
            except FileNotFoundError:
                pass
        self._bound.clear()
