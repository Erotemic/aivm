"""Read one bounded, newline-delimited request under a total deadline.

This is protocol framing, not an authentication or authorization decision.
"""
from __future__ import annotations
import socket
import time
from ..errors import SecretsError
from ..primitives import codec

FRAME_TIMEOUT = 5.0

def read_frame(
    sock: socket.socket,
    *,
    limit: int = codec.MAX_FRAME,
    timeout: float = FRAME_TIMEOUT,
) -> bytes:
    """Read exactly one newline-terminated frame under an absolute deadline.

    The deadline is for the whole frame, not renewed per byte, and anything
    after the newline -- a pipelined second request -- is a protocol error.
    """
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretsError('invalid_request')
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(16384, limit + 1 - len(data)))
        except (OSError, TimeoutError):
            raise SecretsError('invalid_request') from None
        if not chunk:
            raise SecretsError('invalid_request')
        data.extend(chunk)
        if len(data) > limit:
            raise SecretsError('invalid_request')
        if b'\n' in data:
            line, trailing = bytes(data).split(b'\n', 1)
            if trailing:
                raise SecretsError('invalid_request')
            return line

