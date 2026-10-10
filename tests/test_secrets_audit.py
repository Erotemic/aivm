"""Hash-chained audit records (AUDIT-01)."""

from __future__ import annotations

import json
import os
import stat

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host import audit
from aivm_secrets.host.audit import GENESIS, AuditLog, verify


def make(tmp_path, count=3):
    log = AuditLog(tmp_path / 'audit' / 'session.jsonl', 'c' * 32)
    log.record('session_open', timestamp=1000, grant='a' * 32)
    for index in range(count):
        log.record(
            'authorized', f'{index:032x}', timestamp=1000 + index,
            operation='issue.view', resource={'issue': 23}, digest='d' * 64,
        )  # fmt: skip
    log.record('session_close', timestamp=2000)
    log.close()
    return log


def failed(call, *args, **kwargs):
    with pytest.raises(SecretsError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == 'audit_failed'
    return caught.value


def test_records_are_private_chained_and_verifiable(tmp_path):
    log = make(tmp_path)
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.path.parent.stat().st_mode) == 0o700
    rows = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert [row['seq'] for row in rows] == [0, 1, 2, 3, 4]
    assert rows[0]['prev'] == GENESIS and rows[0]['schema'] == 2
    assert all(row['channel'] == 'c' * 32 for row in rows)
    assert rows[1]['resource'] == {'issue': 23}
    # Empty optional fields are omitted, not written as noise.
    assert 'resource' not in rows[0] and 'operation' not in rows[4]
    assert verify(log.path) == (5, log.head)
    assert log.head != GENESIS


@pytest.mark.parametrize(
    'tamper',
    [
        lambda lines: lines.pop(2),  # removal
        lambda lines: lines.insert(2, lines[1]),  # replay
        lambda lines: lines.__setitem__(slice(1, 3), [lines[2], lines[1]]),  # reorder
        lambda lines: lines.__setitem__(
            1, lines[1].replace(b'"issue.view"', b'"issue.drop"')
        ),
        lambda lines: lines.__setitem__(
            1, lines[1].replace(b'"code":""', b'"code":"denied"')
        ),
        lambda lines: lines.__setitem__(0, lines[0].replace(b'"seq":0', b'"seq":1')),
        lambda lines: lines.__setitem__(3, b'{"not":"a record"}'),
        lambda lines: lines.__setitem__(3, b'not json'),
        lambda lines: lines.__setitem__(
            1, lines[1].replace(b'{"channel"', b'{ "channel"')
        ),
        lambda lines: lines.pop(0),
    ],
    ids=['removed', 'replayed', 'reordered', 'edited-field', 'edited-code',
         'renumbered', 'foreign-row', 'garbage', 'respaced', 'beheaded'],
)  # fmt: skip
def test_any_edit_inside_the_file_breaks_the_chain(tmp_path, tamper):
    log = make(tmp_path)
    lines = log.path.read_bytes().split(b'\n')[:-1]
    tamper(lines)
    log.path.write_bytes(b'\n'.join(lines) + b'\n')
    assert 'breaks the chain' in failed(verify, log.path).detail


def test_truncation_is_visible_only_against_a_known_head(tmp_path):
    """The documented limit: a clean tail cut still verifies, to a new head."""
    log = make(tmp_path)
    data = log.path.read_bytes()
    log.path.write_bytes(data[:-10])
    assert 'truncated' in failed(verify, log.path).detail
    whole = data.split(b'\n')[:-1]
    log.path.write_bytes(b'\n'.join(whole[:-2]) + b'\n')
    count, head = verify(log.path)
    assert count == 3 and head != log.head


def test_audit_file_is_never_reused_or_followed(tmp_path):
    log = make(tmp_path)
    failed(AuditLog, log.path, 'c' * 32)
    target = tmp_path / 'audit' / 'victim'
    target.write_text('keep')
    link = tmp_path / 'audit' / 'link.jsonl'
    link.symlink_to(target)
    failed(AuditLog, link, 'c' * 32)
    assert target.read_text() == 'keep'


def test_schema_is_closed(tmp_path):
    log = AuditLog(tmp_path / 'audit' / 's.jsonl', 'c' * 32)
    failed(log.record, 'made_up_event', timestamp=1)
    # A field outside the schema -- a request body, say -- cannot be written.
    failed(log.record, 'authorized', timestamp=1, body='secret comment text')
    failed(log.record, 'authorized', timestamp=1, credential='x')
    log.close()
    assert log.path.read_bytes() == b''


@pytest.mark.parametrize('failure', ['write', 'short', 'fsync'])
def test_durability_failures_are_reported_not_swallowed(
    tmp_path, monkeypatch, failure
):
    log = AuditLog(tmp_path / 'audit' / 's.jsonl', 'c' * 32)
    log.record('session_open', timestamp=1)
    head = log.head
    real = log._stream

    class Stream:
        def write(self, data):
            if failure == 'write':
                raise OSError('disk full')
            return len(data) - 1 if failure == 'short' else len(data)

        def fileno(self):
            return real.fileno()

        def close(self):
            pass

    log._stream = Stream()
    if failure == 'fsync':
        monkeypatch.setattr(
            audit.os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError())
        )
    failed(log.record, 'authorized', timestamp=2)
    # A record that was not durably written does not advance the chain.
    assert log.head == head
    monkeypatch.undo()
    log._stream = real
    log.close()


def test_verify_refuses_unsafe_or_foreign_files(tmp_path):
    log = make(tmp_path)
    log.path.chmod(0o644)
    with pytest.raises(SecretsError) as caught:
        verify(log.path)
    assert caught.value.code == 'unsafe_file'
    log.path.chmod(0o600)
    os.link(log.path, tmp_path / 'audit' / 'copy')
    with pytest.raises(SecretsError):
        verify(log.path)
