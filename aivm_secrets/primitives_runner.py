"""Language-neutral JSONL conformance runner for the pure value primitives.

    python -m aivm_secrets.primitives_runner \
        < tests/secrets_vectors/primitives/validity-v1.jsonl

Each input line is one JSON object::

    {"version": 1, "primitive": NAME, "args": {...}}

``NAME`` is a key of :data:`PRIMITIVES`, a closed table; a name the table does
not list is refused, never looked up as an attribute. ``args`` must carry
exactly the table's required arguments and at most its optional ones. Every
line gets exactly one reply line, in input order, written to the binary
standard output and flushed before the next line is read::

    {"ok": true, "value": V}     the primitive returned V (null for a check)
    {"ok": false, "code": C}     the primitive refused with its fixed code C

The JSON types are part of the reply: ``ok`` is a boolean, never ``1``, and
an integer is never written as a float such as ``2.0``.

A line that is not a bounded JSON object of that shape -- longer than
:data:`MAX_LINE` bytes counting its newline, malformed, of another version, or
naming no listed primitive -- is answered ``invalid_request``. An oversized
line is discarded as it is read, never held in memory whole.

No clock, file, credential or randomness is read. The future Rust runner,
selected by ``AIVM_SECRETS_RUST_PRIMITIVES_RUNNER`` in the parity tests, must
implement this contract from its own code. The runner sits beside the pure
``primitives`` package rather than inside it because it owns process streams.
"""
from __future__ import annotations

import sys
from typing import Any, BinaryIO, Callable

from .errors import SecretsError
from .primitives import binding, codec, epochs, grammar, validity, wire

VERSION = 1
MAX_LINE = codec.MAX_FRAME

Arguments = dict[str, Any]


def _require_active(args: Arguments) -> None:
    validity.require_active(args['now'], args['not_before'], args['expires_at'])


def _advance(args: Arguments) -> int:
    if 'maximum' in args:
        return epochs.advance(args['current'], maximum=args['maximum'])
    return epochs.advance(args['current'])


def _require_current(args: Arguments) -> None:
    epochs.require_current(args['actual'], args['expected'])


def _require_match(args: Arguments) -> None:
    binding.require_match(args['actual'], args['expected'])


def _digest(args: Arguments) -> str:
    return codec.digest(args['value'])


def _parse_frame(args: Arguments) -> dict[str, Any]:
    frame = wire.parse_frame(args['frame'])
    return {'verb': frame.verb, 'capability': frame.capability,
            'payload': frame.payload}


# name -> (required arguments, optional arguments, implementation)
PRIMITIVES: dict[str, tuple[frozenset[str], frozenset[str],
                            Callable[[Arguments], Any]]] = {
    'validity.require_active': (
        frozenset({'now', 'not_before', 'expires_at'}), frozenset(),
        _require_active),
    'epochs.advance': (frozenset({'current'}), frozenset({'maximum'}),
                       _advance),
    'epochs.require_current': (frozenset({'actual', 'expected'}), frozenset(),
                               _require_current),
    'binding.require_match': (frozenset({'actual', 'expected'}), frozenset(),
                              _require_match),
    'codec.digest': (frozenset({'value'}), frozenset(), _digest),
    'wire.parse_frame': (frozenset({'frame'}), frozenset(), _parse_frame),
}


def evaluate(value: object) -> dict[str, Any]:
    """The reply to one decoded input line."""
    try:
        line = grammar.exact_keys(
            value, frozenset({'version', 'primitive', 'args'}))
        grammar.integer(line['version'], VERSION, VERSION)
        name = line['primitive']
        if type(name) is not str or name not in PRIMITIVES:
            raise SecretsError('invalid_request')
        required, optional, run = PRIMITIVES[name]
        args = grammar.exact_keys(line['args'], required, optional)
        return {'ok': True, 'value': run(args)}
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def answer(line: bytes) -> dict[str, Any]:
    """The reply to one raw line of at most MAX_LINE bytes."""
    try:
        value = codec.loads(line, limit=MAX_LINE)
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}
    return evaluate(value)


def serve(stdin: BinaryIO, stdout: BinaryIO) -> None:
    while True:
        line = stdin.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE:
            # Too long: drain the rest of this line and answer it once.
            while line and not line.endswith(b'\n'):
                line = stdin.readline(MAX_LINE + 1)
            reply: dict[str, Any] = {'ok': False, 'code': 'invalid_request'}
        else:
            reply = answer(line)
        stdout.write(codec.dumps(reply) + b'\n')
        stdout.flush()


def main() -> int:
    serve(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
