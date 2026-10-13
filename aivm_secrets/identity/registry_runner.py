"""Byte-stable JSONL contract for the pure Python/Rust enrollment kernel.

    python -m aivm_secrets.identity.registry_runner \
        < tests/secrets_vectors/identity-registry-v1.jsonl

Every input is explicit, with no secret, filesystem access, time sample or
randomness. The Rust backend must reproduce identical results when added.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett import registry as registry_model

MAX_LINE = 32768


def evaluate(data: object) -> dict:
    try:
        data = grammar.exact_keys(data, frozenset({
            'version', 'action', 'issuer', 'audience', 'state',
        }), frozenset({
            'subject', 'thumbprint', 'not_after', 'replace', 'now',
            'expected_epoch', 'expected_thumbprint',
        }), code='invalid_capability')
        grammar.integer(data['version'], 1, 1, code='invalid_capability')
        args = {'issuer': data['issuer'], 'audience': data['audience']}
        action = data['action']
        if action == 'enroll':
            grammar.exact_keys(data, frozenset({
                'version', 'action', 'issuer', 'audience', 'state', 'subject',
                'thumbprint', 'not_after', 'replace',
            }), code='invalid_capability')
            state = registry_model.enroll(
                data['state'], **args, subject=data['subject'],
                thumbprint=data['thumbprint'], not_after=data['not_after'],
                replace=data['replace'])
            return {'ok': True, 'state': state}
        if action == 'renew':
            grammar.exact_keys(data, frozenset({
                'version', 'action', 'issuer', 'audience', 'state', 'subject',
                'thumbprint', 'not_after', 'expected_epoch',
                'expected_thumbprint', 'now',
            }), code='invalid_capability')
            state = registry_model.renew(
                data['state'], **args, subject=data['subject'],
                expected_epoch=data['expected_epoch'],
                expected_thumbprint=data['expected_thumbprint'],
                thumbprint=data['thumbprint'], not_after=data['not_after'],
                now=data['now'])
            return {'ok': True, 'state': state}
        if action == 'revoke-if-current':
            grammar.exact_keys(data, frozenset({
                'version', 'action', 'issuer', 'audience', 'state', 'subject',
                'expected_epoch', 'expected_thumbprint',
            }), code='invalid_capability')
            state, revoked = registry_model.revoke_if_current(
                data['state'], **args, subject=data['subject'],
                expected_epoch=data['expected_epoch'],
                expected_thumbprint=data['expected_thumbprint'])
            return {'ok': True, 'state': state, 'revoked': revoked}
        if action == 'revoke':
            grammar.exact_keys(data, frozenset({
                'version', 'action', 'issuer', 'audience', 'state', 'subject',
            }), code='invalid_capability')
            state = registry_model.revoke(data['state'], **args,
                                          subject=data['subject'])
            return {'ok': True, 'state': state}
        if action == 'lookup':
            grammar.exact_keys(data, frozenset({
                'version', 'action', 'issuer', 'audience', 'state',
                'thumbprint', 'now',
            }), code='invalid_capability')
            expectation = registry_model.expectation(
                data['state'], **args, thumbprint=data['thumbprint'],
                now=data['now'])
            return {'ok': True, 'expected': expectation.to_dict()}
        raise SecretsError('invalid_capability')
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def main() -> int:
    for line in sys.stdin.buffer:
        if len(line) > MAX_LINE:
            result = {'ok': False, 'code': 'invalid_capability'}
        else:
            try:
                result = evaluate(codec.loads(line, limit=MAX_LINE))
            except SecretsError:
                result = {'ok': False, 'code': 'invalid_capability'}
        sys.stdout.buffer.write(codec.dumps(result) + b'\n')
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
