"""Language-neutral identity decision conformance protocol, JSONL stdin/stdout.

    python -m aivm_secrets.identity.runner < tests/secrets_vectors/identity-v1.jsonl

The future Rust executable MUST implement the same external contract. Each
input is self-contained, including expected host identity, validated public
claim values, peer certificate thumbprint and explicit time. Cryptographic
verification and TLS happen outside this *pure* decision runner; both need
separate Rust/Python parity coverage when the Rust implementation exists.
"""

from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.claims import IdentityClaims, IdentityExpectation, assess_binding

MAX_LINE = 8192


def evaluate(value: object) -> dict[str, object]:
    try:
        data = grammar.exact_keys(value, frozenset({
            'version', 'claims', 'expected', 'peer_thumbprint', 'now',
        }), code='invalid_capability')
        grammar.integer(data['version'], 1, 1, code='invalid_capability')
        claims = IdentityClaims.parse(data['claims'])
        expected = IdentityExpectation.parse(data['expected'])
        assess_binding(claims, expected, data['peer_thumbprint'], data['now'])
        return {'ok': True}
    except SecretsError:
        return {'ok': False, 'code': 'invalid_capability'}


def main() -> int:
    # Every reply, an oversized line's included, takes the one binary path
    # and is flushed before the next line is read: replies stay in input
    # order, and a driver can wait for each one.
    for line in sys.stdin.buffer:
        try:
            if len(line) > MAX_LINE:
                raise SecretsError('invalid_capability')
            reply = evaluate(codec.loads(line, limit=MAX_LINE))
        except SecretsError:
            reply = {'ok': False, 'code': 'invalid_capability'}
        sys.stdout.buffer.write(codec.dumps(reply) + b'\n')
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
