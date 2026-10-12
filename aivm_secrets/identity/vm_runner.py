"""Language-neutral JSONL parity runner for a managed-VM subject decision."""

from __future__ import annotations

import sys

from ..errors import SecretsError
from ..kernel import codec
from .vm_model import subject


def evaluate(value: object) -> dict:
    try:
        return {'ok': True, 'subject': subject(value)}
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def main() -> int:
    for line in sys.stdin.buffer:
        try:
            if len(line) > 4096:
                raise SecretsError('invalid_capability')
            result = evaluate(codec.loads(line, limit=4096))
        except SecretsError:
            result = {'ok': False, 'code': 'invalid_capability'}
        sys.stdout.buffer.write(codec.dumps(result) + b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
