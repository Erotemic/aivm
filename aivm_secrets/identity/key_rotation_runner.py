"""Versioned, language-neutral key-rotation contract runner for Rust parity."""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.key_rotation import authorize_key_rotation

FIELDS = frozenset({
    'expected_epoch', 'actual_epoch', 'expected_thumbprint',
    'actual_thumbprint', 'enrolled_key_fingerprint',
    'candidate_key_fingerprint',
})


def evaluate(request: object) -> dict[str, object]:
    try:
        value = grammar.exact_keys(request, FIELDS, code='invalid_capability')
        epoch = authorize_key_rotation(**value)
        return {'ok': True, 'next_epoch': epoch}
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def main() -> None:
    for line in sys.stdin.buffer:
        try:
            request = codec.loads(line, limit=4096, code='invalid_capability')
            answer = evaluate(request)
        except SecretsError as ex:
            answer = {'ok': False, 'code': ex.code}
        sys.stdout.buffer.write(codec.dumps(answer) + b'\n')
        sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
