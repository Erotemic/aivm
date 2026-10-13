"""Versioned, language-neutral key-replacement contract runner for Rust parity.

Two decisions share one corpus (`identity-key-rotation-v1.jsonl`):

* ``rotate`` (the default when ``action`` is absent, which is every original
  row): exactly the six `authorize_key_rotation` keys; replies
  ``{ok: true, next_epoch}``.
* ``reuse`` (REN-07): exactly ``{action, enrolled_key_fingerprint,
  candidate_key_fingerprint}``; replies ``{ok: true}``.

Any refusal is ``{ok: false, code}``. Each reply is one line, flushed.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.key_rotation import authorize_key_reuse, authorize_key_rotation

FIELDS = frozenset({
    'expected_epoch', 'actual_epoch', 'expected_thumbprint',
    'actual_thumbprint', 'enrolled_key_fingerprint',
    'candidate_key_fingerprint',
})
REUSE = frozenset({'action', 'enrolled_key_fingerprint',
                   'candidate_key_fingerprint'})


def evaluate(request: object) -> dict[str, object]:
    try:
        value = grammar.exact_keys(request, frozenset(),
                                   FIELDS | frozenset({'action'}),
                                   code='invalid_capability')
        action = value.get('action', 'rotate')
        if type(action) is not str or action not in ('rotate', 'reuse'):
            raise SecretsError('invalid_capability')
        if action == 'reuse':
            grammar.exact_keys(value, REUSE, code='invalid_capability')
            authorize_key_reuse(
                enrolled_key_fingerprint=value['enrolled_key_fingerprint'],
                candidate_key_fingerprint=value['candidate_key_fingerprint'])
            return {'ok': True}
        grammar.exact_keys(value, FIELDS, frozenset({'action'}),
                           code='invalid_capability')
        epoch = authorize_key_rotation(
            expected_epoch=value['expected_epoch'],
            actual_epoch=value['actual_epoch'],
            expected_thumbprint=value['expected_thumbprint'],
            actual_thumbprint=value['actual_thumbprint'],
            enrolled_key_fingerprint=value['enrolled_key_fingerprint'],
            candidate_key_fingerprint=value['candidate_key_fingerprint'])
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
