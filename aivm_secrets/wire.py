"""Strict JSON and bounded, one-request-per-connection framing."""

from __future__ import annotations

import json
import socket
import time
from typing import Any

from .errors import SecretsError

MAX_FRAME = 65536
MAX_REPLY = 2 * 1024 * 1024 + 65536


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError('non-finite number')


def _check_depth(data: bytes) -> None:
    # Bound nesting before Python's decoder allocates a recursive structure.
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError('too deeply nested')
        elif byte in (93, 125):
            depth -= 1


def loads(data: bytes | str, *, limit: int = MAX_FRAME) -> Any:
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        if len(data) > limit:
            raise ValueError('too large')
        _check_depth(data)
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise SecretsError('invalid_request') from None


def dumps(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise SecretsError('invalid_request') from None


def read_frame(sock: socket.socket, *, limit: int = MAX_FRAME,
               timeout: float = 5.0) -> bytes:
    """Use an absolute read deadline, not a renewable per-byte timeout."""
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
