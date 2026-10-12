"""Hash-chained, bounded-schema audit records.

A record never contains a credential, a sealed capability, a request body or
title, or provider text. What it may contain is fixed: event names from a
closed set, fixed outcome codes, kernel-validated resource identifiers, and
digests.

Each record carries its sequence number and the SHA-256 of the previous
record, so removing, reordering or editing a record inside a file is
detectable by :func:`verify`. The chain cannot show that the *tail* of a file
was not truncated; the head digest printed when a session closes is what an
operator can anchor elsewhere for that.

A record is written and ``fsync``-ed before the action it announces
(AUDIT-01). Any failure to do so raises ``audit_failed``, which the broker
treats as the end of the session's authority.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..kernel import codec, grammar
from .files import private_directory, read_owned

SCHEMA = 2
GENESIS = '0' * 64
MAX_AUDIT_BYTES = 64 * 1024 * 1024
EVENTS = (
    'session_open',
    'authorized',
    'dispatch',
    'completed',
    'rejected_or_failed',
    'delegated',
    'renounced',
    'approval_requested',
    'approved',
    'revoked',
    'session_close',
    'identity_enroll_intent',
    'identity_revoke_intent',
    'identity_token_issue_intent',
    'identity_recorded',
)
_FIELDS = frozenset(
    {
        'schema',
        'seq',
        'prev',
        'channel',
        'event',
        'request_id',
        'timestamp',
        'code',
        'grant',
        'operation',
        'resource',
        'digest',
        'status',
    }
)


class AuditLog:
    def __init__(self, path: Path, channel: str):
        private_directory(Path(path).parent)
        self.path = Path(path)
        self.channel = channel
        self.head = GENESIS
        self._seq = 0
        self._lock = threading.Lock()
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_APPEND
            | os.O_CLOEXEC
        )
        try:
            self._stream = os.fdopen(
                os.open(self.path, flags, 0o600), 'wb', buffering=0
            )
        except OSError:
            raise SecretsError('audit_failed') from None

    def record(
        self,
        event: str,
        request_id: str = '',
        *,
        timestamp: int,
        code: str = '',
        **detail: Any,
    ) -> None:
        if event not in EVENTS:
            raise SecretsError('audit_failed')
        with self._lock:
            row = {
                'schema': SCHEMA,
                'seq': self._seq,
                'prev': self.head,
                'channel': self.channel,
                'event': event,
                'request_id': request_id,
                'timestamp': timestamp,
                'code': code,
            }
            for key, value in detail.items():
                if value not in (None, '', {}):
                    row[key] = value
            if set(row) - _FIELDS:
                raise SecretsError('audit_failed')
            try:
                line = codec.dumps(row)
                written = self._stream.write(line + b'\n')
                if written != len(line) + 1:
                    raise OSError('short write')
                os.fsync(self._stream.fileno())
            except (OSError, ValueError, SecretsError):
                raise SecretsError('audit_failed') from None
            self.head = hashlib.sha256(line).hexdigest()
            self._seq += 1

    def close(self) -> None:
        with self._lock:
            self._stream.close()


def verify(path: Path) -> tuple[int, str]:
    """Check one audit file's chain; return ``(records, head digest)``.

    Raises ``audit_failed`` naming the first record that does not link.
    """
    data = read_owned(Path(path), private=True, limit=MAX_AUDIT_BYTES)
    head = GENESIS
    count = 0
    for number, line in enumerate(data.split(b'\n')[:-1]):
        problem = SecretsError(
            'audit_failed', detail=f'{path}: record {number} breaks the chain'
        )
        try:
            row = codec.loads(line, limit=65536)
            grammar.exact_keys(row, frozenset({'seq', 'prev'}), _FIELDS)
        except SecretsError:
            raise problem from None
        if (
            row['seq'] != number
            or row['prev'] != head
            or row.get('schema') != SCHEMA
            or row.get('event') not in EVENTS
            or codec.dumps(row) != line
        ):
            raise problem
        head = hashlib.sha256(line).hexdigest()
        count += 1
    if not data.endswith(b'\n') and data:
        raise SecretsError(
            'audit_failed', detail=f'{path}: truncated final record'
        )
    return count, head
