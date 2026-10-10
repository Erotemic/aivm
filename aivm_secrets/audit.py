"""Bounded-schema audit records: no credentials, request bodies or provider data."""

from __future__ import annotations

import os
from pathlib import Path

from .core import Request
from .errors import SecretsError
from .files import private_directory
from .wire import dumps


class AuditLog:
    def __init__(self, path: Path, channel: str):
        private_directory(path.parent)
        self.channel = channel
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self._stream = os.fdopen(fd, 'wb', buffering=0)
        except OSError:
            raise SecretsError('audit_failed') from None

    def record(self, event: str, request_id: str, *, timestamp: int,
               request: Request | None = None, code: str = '') -> None:
        row = {'schema': 1, 'channel': self.channel, 'event': event,
               'request_id': request_id, 'timestamp': timestamp, 'code': code}
        if request is not None:
            row.update(operation=request.operation, repository=request.repository, pr=request.pr)
        try:
            data = dumps(row) + b'\n'
            written = self._stream.write(data)
            if written != len(data):
                raise OSError('short write')
            os.fsync(self._stream.fileno())
        except (OSError, ValueError):
            raise SecretsError('audit_failed') from None

    def close(self) -> None:
        self._stream.close()
