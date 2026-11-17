"""The pure value primitives against their language-neutral corpora.

``tests/secrets_vectors/primitives/*-v1.jsonl`` state, primitive by
primitive, what is accepted and with which fixed code the rest is refused.
The Python reference runner always replays them. The Rust runner is NOT
implemented yet: set AIVM_SECRETS_RUST_PRIMITIVES_RUNNER to an independently
built executable and this suite then requires it to agree with both the
corpora and Python, rather than falling back. Until then that test is a
reported skip, never a parity result.

Replies are compared as canonical JSON (``typed``), never with Python's
``==``: ``True == 1 == 1.0``, so ``==`` would certify a runner that answers
``"ok": 1`` or ``"value": 2.0``.
"""

from __future__ import annotations

import ast
import hashlib
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from aivm_secrets.primitives import codec
from aivm_secrets.primitives.wire import MAX_CAPABILITY
from aivm_secrets.primitives_runner import MAX_LINE, PRIMITIVES, evaluate
from tests.secrets_helpers import (
    reply_while_open,
    runner_replies,
    typed,
    typed_replies,
)

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / 'tests' / 'secrets_vectors' / 'primitives'
CORPORA = sorted(VECTORS.glob('*-v1.jsonl'))
PYTHON = [sys.executable, '-m', 'aivm_secrets.primitives_runner']
MAX_TIME = 2**63 - 1
# A corpus line holds an input and its expected reply, so it may be longer
# than the runner's own line limit (wire's at-limit capability is in both).
CORPUS_LINE = 1 << 20

Row = dict[str, Any]


def rows(path: Path) -> list[Row]:
    return [codec.loads(line, limit=CORPUS_LINE)
            for line in path.read_bytes().splitlines()]


def every_row() -> list[Row]:
    return [row for path in CORPORA for row in rows(path)]


def replay(argv: list[str], cases: list[Row]) -> list[bytes]:
    """Each case's reply from ``argv``, ``typed``.

    An input is sent re-encoded canonically, so the corpora pin values, not
    spellings: a spelling the canonical form does not keep (``-0``, ``1E2``,
    raw non-ASCII bytes) is stated as raw bytes in :func:`framing` instead.
    """
    payload = b''.join(codec.dumps(case['input']) + b'\n' for case in cases)
    replies = typed_replies(argv, payload)
    assert len(replies) == len(cases)
    return replies


def expected_replies(cases: list[Row]) -> list[bytes]:
    return [typed(case['expected_result']) for case in cases]


def well_formed(row: Row) -> bool:
    """Whether a row's arguments are the ones its primitive's entry permits."""
    given = row['input']
    if (type(given) is not dict or type(given.get('primitive')) is not str
            or given['primitive'] not in PRIMITIVES):
        return False
    required, optional, _ = PRIMITIVES[given['primitive']]
    args = given.get('args')
    return type(args) is dict and required <= set(args) <= required | optional


def args_of(primitive: str) -> list[Row]:
    """The well-formed arguments given to ``primitive``, with their reply."""
    return [row['input']['args'] | {'expected_result': row['expected_result']}
            for row in every_row()
            if well_formed(row) and row['input']['primitive'] == primitive]


def line(primitive: str, **args: Any) -> bytes:
    return codec.dumps({'version': 1, 'primitive': primitive,
                        'args': args}) + b'\n'


def sized(length: int) -> tuple[bytes, Row]:
    """A ``codec.digest`` line of exactly ``length`` bytes and its reply."""
    head = b'{"args":{"value":"'
    tail = b'"},"primitive":"codec.digest","version":1}\n'
    text = b'x' * (length - len(head) - len(tail))
    encoded = head + text + tail
    assert len(encoded) == length
    digest = hashlib.sha256(b'"' + text + b'"').hexdigest()
    return encoded, {'ok': True, 'value': digest}


def raw_capability(length: int) -> tuple[bytes, str]:
    """A ``wire.parse_frame`` line whose capability is ``length`` UTF-8 bytes.

    The capability ends in a raw (unescaped) two-byte ``é``, so it has one
    code point fewer than it has bytes.
    """
    capability = 'c' * (length - 2) + '\u00e9'
    encoded = (b'{"version":1,"primitive":"wire.parse_frame","args":{"frame":'
               b'{"version":1,"describe":true,"capability":"'
               + capability.encode('utf-8') + b'"}}}\n')
    return encoded, capability


INVALID: Row = {'ok': False, 'code': 'invalid_request'}
REFUSED: Row = {'ok': False, 'code': 'invalid_capability'}
GOOD = line('epochs.advance', current=1)
GOOD_REPLY: Row = {'ok': True, 'value': 2}
AT_LIMIT, AT_LIMIT_REPLY = sized(MAX_LINE)
OVER_LIMIT, _ = sized(MAX_LINE + 1)
CAPABILITY_AT_LIMIT, AT_LIMIT_CAPABILITY = raw_capability(MAX_CAPABILITY)
CAPABILITY_OVER_LIMIT = raw_capability(MAX_CAPABILITY + 1)[0]
ZERO_DIGEST = hashlib.sha256(b'[0]').hexdigest()


def framing() -> list[tuple[str, bytes, Row]]:
    """Raw lines no corpus row can express, each with its in-order reply.

    These are framing (over-long, malformed, unterminated lines) and the
    spellings that :func:`replay`'s canonical re-encoding would erase:
    ``-0`` is the integer zero, a number with an exponent is a float even
    when its value is integral, and a capability is bounded in UTF-8 bytes
    however its characters are written.
    """
    return [
        ('oversize-first', b'"' + b'x' * MAX_LINE + b'"\n', INVALID),
        ('valid-after-oversize', GOOD, GOOD_REPLY),
        ('exactly-max-line-bytes', AT_LIMIT, AT_LIMIT_REPLY),
        ('one-byte-over-max-line', OVER_LIMIT, INVALID),
        ('far-oversize-is-drained', b'[' + b'1,' * (2 * MAX_LINE) + b'1]\n',
         INVALID),
        ('valid-after-drain', GOOD, GOOD_REPLY),
        ('malformed', b'{"version":1,\n', INVALID),
        ('empty-line', b'\n', INVALID),
        ('trailing-data', GOOD[:-1] + b' {}\n', INVALID),
        ('lone-surrogate', line('binding.require_match', actual='a',
                                expected='a').replace(b'"a"', b'"\\ud800"'),
         INVALID),
        ('invalid-utf8', b'{"version":1,"primitive":"\xff","args":{}}\n',
         INVALID),
        ('duplicate-key', GOOD[:-2] + b',"version":1}\n', INVALID),
        ('refusal-keeps-its-code', line('epochs.advance', current=4, maximum=4),
         {'ok': False, 'code': 'revoked'}),
        ('negative-zero-epoch',
         b'{"version":1,"primitive":"epochs.advance","args":{"current":-0}}\n',
         {'ok': True, 'value': 1}),
        ('negative-zero-times',
         b'{"version":1,"primitive":"validity.require_active",'
         b'"args":{"now":-0,"not_before":-0,"expires_at":1}}\n',
         {'ok': True, 'value': None}),
        ('negative-zero-digest',
         b'{"version":1,"primitive":"codec.digest","args":{"value":[-0]}}\n',
         {'ok': True, 'value': ZERO_DIGEST}),
        ('exponent-epoch-is-a-float',
         b'{"version":1,"primitive":"epochs.advance","args":{"current":1e0}}\n',
         REFUSED),
        ('exponent-digest-is-a-float',
         b'{"version":1,"primitive":"codec.digest","args":{"value":[1E+2]}}\n',
         INVALID),
        ('raw-utf8-capability-at-limit', CAPABILITY_AT_LIMIT,
         {'ok': True, 'value': {'verb': 'describe', 'payload': True,
                                'capability': AT_LIMIT_CAPABILITY}}),
        ('raw-utf8-capability-one-byte-over', CAPABILITY_OVER_LIMIT, INVALID),
        ('last-line-without-newline', GOOD[:-1], GOOD_REPLY),
    ]


def check_framing(argv: list[str]) -> None:
    cases = framing()
    replies = typed_replies(argv, b''.join(raw for _, raw, _ in cases))
    assert replies == [typed(reply) for _, _, reply in cases], [
        name for name, _, _ in cases
    ]


def check_flushed(argv: list[str]) -> None:
    assert typed(codec.loads(reply_while_open(argv, GOOD))) == typed(GOOD_REPLY)


def check_runner(argv: list[str]) -> None:
    """Everything the Rust gate requires of an independent runner."""
    for path in CORPORA:
        cases = rows(path)
        replies = replay(argv, cases)
        assert replies == replay(PYTHON, cases), path.name
        assert replies == expected_replies(cases), path.name
    check_framing(argv)
    check_flushed(argv)


@pytest.mark.parametrize('path', CORPORA, ids=lambda path: path.stem)
def test_python_reference_runner_matches_frozen_vectors(path: Path) -> None:
    cases = rows(path)
    expected = expected_replies(cases)
    assert replay(PYTHON, cases) == expected
    assert [typed(evaluate(case['input'])) for case in cases] == expected


def test_corpora_cover_every_listed_primitive_both_ways() -> None:
    """Vacuity guards: a runner that refused everything must fail."""
    assert {path.stem for path in CORPORA} == {
        'validity-v1', 'epochs-v1', 'binding-v1', 'digest-v1', 'wire-v1',
        'runner-v1',
    }
    for path in CORPORA:
        cases = rows(path)
        assert len({case['name'] for case in cases}) == len(cases), path.name
        assert all(set(case) == {'name', 'input', 'expected_result'}
                   for case in cases), path.name
    for primitive in PRIMITIVES:
        results = [case['expected_result'] for case in args_of(primitive)]
        assert sum(result['ok'] for result in results) >= 1, primitive
        assert sum(not result['ok'] for result in results) >= 3, primitive
    # Anything that is not a well-formed call of a listed primitive is
    # refused by the runner's own request grammar, never by a primitive.
    malformed = [row for row in every_row() if not well_formed(row)]
    assert len(malformed) >= 20
    assert all(row['expected_result'] == INVALID for row in malformed)


def test_corpora_witness_the_boundaries() -> None:
    """Each boundary named in the contracts has a row on each side of it."""
    refused = {'code': 'invalid_capability', 'ok': False}
    valid = args_of('validity.require_active')
    assert any(a['now'] == a['expires_at'] and a['expected_result'] == refused
               for a in valid), 'expiry is exclusive'
    assert any(a['now'] == a['not_before'] and a['expected_result']['ok']
               for a in valid), 'start is inclusive'
    assert any(a['expires_at'] == MAX_TIME and a['expected_result']['ok']
               for a in valid), 'MAX_TIME is a valid expiry'
    assert any(a['expires_at'] == MAX_TIME + 1
               and a['expected_result'] == refused for a in valid)
    for name in ('now', 'not_before', 'expires_at'):
        assert any(type(a[name]) is bool and a['expected_result'] == refused
                   for a in valid), f'bool as int: {name}'
    advance = args_of('epochs.advance')
    # An epoch at a representable maximum is revoked, never wrapped.
    at_max = [a for a in advance
              if type(a['current']) is int
              and a['current'] == a.get('maximum', 2**31 - 1) <= MAX_TIME]
    assert len(at_max) >= 3 and all(
        a['expected_result'] == {'code': 'revoked', 'ok': False}
        for a in at_max), 'an epoch at its maximum'
    assert any(a['expected_result'] == {'ok': True, 'value': MAX_TIME}
               for a in advance), 'the largest representable epoch'
    assert any(type(a['current']) is bool for a in advance)
    current = args_of('epochs.require_current')
    assert any(a['actual'] == a['expected'] == MAX_TIME + 1
               and a['expected_result'] == refused for a in current)
    digest = args_of('codec.digest')
    assert any(a['value'] == [2**63] and not a['expected_result']['ok']
               for a in digest)
    assert any(a['value'] == [-(2**63), MAX_TIME] and a['expected_result']['ok']
               for a in digest)
    floats = [a for a in digest
              if type(a['value']) is list and type(a['value'][0]) is float]
    assert floats and not any(a['expected_result']['ok'] for a in floats)
    # replay() sends the canonical encoding, which still spells this one
    # with an exponent.
    assert any(b'e+' in codec.dumps(a['value']) for a in floats)
    match = args_of('binding.require_match')
    assert any(type(a['actual']) is not str and a['actual'] == a['expected']
               and a['expected_result'] == refused for a in match)
    # The capability is bounded in UTF-8 bytes, not code points: one with
    # MAX_CAPABILITY code points but a byte more is refused.
    frames = [a for a in args_of('wire.parse_frame')
              if type(a['frame']) is dict
              and type(a['frame'].get('capability')) is str]
    sizes = [(len(a['frame']['capability']),
              len(a['frame']['capability'].encode('utf-8')),
              a['expected_result']['ok']) for a in frames]
    assert (MAX_CAPABILITY, MAX_CAPABILITY + 1, False) in sizes
    assert any(points < size == MAX_CAPABILITY and ok
               for points, size, ok in sizes)


def test_python_runner_framing_keeps_replies_in_order() -> None:
    check_framing(PYTHON)


def test_python_runner_replies_before_its_input_ends() -> None:
    check_flushed(PYTHON)


# A stand-in for a wrong Rust runner: the real Python runner behind a stream
# that rewrites JSON types Python's ``==`` cannot see. It runs as a child
# process because the runner's standard streams are the boundary under test.
DISTORTING_RUNNER = r"""
import json
import sys

from aivm_secrets import primitives_runner

MODE = sys.argv[1]


def distort(value):
    if MODE == 'integer-as-float' and type(value) is int and abs(value) < 2**53:
        return float(value)
    if type(value) is dict:
        return {key: distort(item) for key, item in value.items()}
    if type(value) is list:
        return [distort(item) for item in value]
    return value


class Replies:
    def write(self, data):
        reply = json.loads(data)
        if MODE == 'ok-as-integer':
            reply['ok'] = int(reply['ok'])
        if 'value' in reply:
            reply['value'] = distort(reply['value'])
        return sys.stdout.buffer.write(json.dumps(reply).encode() + b'\n')

    def flush(self):
        sys.stdout.buffer.flush()


primitives_runner.serve(sys.stdin.buffer, Replies())
"""


@pytest.mark.parametrize('mode', [
    pytest.param('faithful', id='a-faithful-runner-passes'),
    pytest.param('ok-as-integer', id='ok-as-an-integer-fails'),
    pytest.param('integer-as-float', id='an-integer-as-a-float-fails'),
])
def test_the_runner_gate_tells_json_types_apart(mode: str) -> None:
    """``"ok": 1`` and ``"value": 2.0`` are wrong replies, though ``True == 1.0``."""
    argv = [sys.executable, '-c', DISTORTING_RUNNER, mode]
    if mode == 'faithful':
        check_runner(argv)
        return
    cases = rows(VECTORS / 'epochs-v1.jsonl')
    payload = b''.join(codec.dumps(case['input']) + b'\n' for case in cases)
    # The distortion is exactly what ``==`` cannot see ...
    assert [codec.loads(reply) for reply in runner_replies(argv, payload)] == [
        case['expected_result'] for case in cases
    ]
    # ... and the gate refuses it all the same.
    with pytest.raises(AssertionError):
        check_runner(argv)


def test_the_runner_dispatches_only_through_its_closed_table() -> None:
    """No attribute lookup can reach a function the table does not list."""
    source = (ROOT / 'aivm_secrets' / 'primitives_runner.py').read_text()
    tree = ast.parse(source)
    banned = {'getattr', 'setattr', 'globals', 'locals', 'vars', 'eval',
              'exec', '__import__', 'compile'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in banned, node.func.id
        if isinstance(node, ast.Import):
            assert 'importlib' not in [alias.name for alias in node.names]
        if isinstance(node, ast.ImportFrom):
            assert node.module != 'importlib'
    assert evaluate({'version': 1, 'primitive': 'grammar.integer',
                     'args': {}}) == INVALID
    assert evaluate({'version': 1, 'primitive': '__class__',
                     'args': {}}) == INVALID


def test_rust_runner_matches_python_and_frozen_vectors_when_built() -> None:
    rust = os.environ.get('AIVM_SECRETS_RUST_PRIMITIVES_RUNNER')
    if not rust:
        pytest.skip('Rust primitives runner is pending; no parity is claimed')
    assert Path(rust).is_file(), 'configured Rust primitives runner is absent'
    check_runner([rust])
