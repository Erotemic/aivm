"""Byte-stable JSONL contract for the pure Python/Rust enrollment kernel.

    python -m aivm_secrets.identity.registry_runner \
        < tests/secrets_vectors/identity-registry-v1.jsonl

The same runner serves `identity-renewal-v1.jsonl` and
`identity-revoke-cas-v1.jsonl`. Every input is explicit, with no secret,
filesystem access, time sample or randomness. The Rust backend must reproduce
identical results when added.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett import registry as registry_model

# Large enough for a full registry (MAX_SUBJECTS rows, each with a full
# retired-key list) on one line; see test_secrets_identity_registry_parity.
MAX_LINE = 262144

COMMON = frozenset({'version', 'action', 'issuer', 'audience', 'state'})
# Exactly the keys each action takes, beyond COMMON.
ACTIONS = {
    'enroll': frozenset({'subject', 'thumbprint', 'key_sha256', 'not_after',
                         'replace'}),
    'replace-if-current': frozenset({'subject', 'thumbprint', 'key_sha256',
                                     'not_after', 'expected_epoch',
                                     'expected_thumbprint'}),
    'renew': frozenset({'subject', 'thumbprint', 'key_sha256', 'not_after',
                        'expected_epoch', 'expected_thumbprint', 'now'}),
    'revoke-if-current': frozenset({'subject', 'expected_epoch',
                                    'expected_thumbprint'}),
    'revoke': frozenset({'subject'}),
    'revoke-all': frozenset(),
    'forget': frozenset({'subject', 'now'}),
    'prune': frozenset({'now'}),
    'lookup': frozenset({'thumbprint', 'now'}),
}
OPTIONAL = frozenset({
    'subject', 'thumbprint', 'key_sha256', 'not_after', 'replace', 'now',
    'expected_epoch', 'expected_thumbprint',
})


def evaluate(data: object) -> dict:
    try:
        data = grammar.exact_keys(data, COMMON, OPTIONAL,
                                  code='invalid_capability')
        grammar.integer(data['version'], 1, 1, code='invalid_capability')
        action = data['action']
        # Check the type first: an unhashable action must be a refusal, not a
        # TypeError that ends the stream.
        if type(action) is not str or action not in ACTIONS:
            raise SecretsError('invalid_capability')
        grammar.exact_keys(data, COMMON | ACTIONS[action],
                           code='invalid_capability')
        args = {'issuer': data['issuer'], 'audience': data['audience']}
        if action == 'enroll':
            state = registry_model.enroll(
                data['state'], **args, subject=data['subject'],
                thumbprint=data['thumbprint'], key_sha256=data['key_sha256'],
                not_after=data['not_after'], replace=data['replace'])
            return {'ok': True, 'state': state}
        if action == 'replace-if-current':
            state = registry_model.replace_if_current(
                data['state'], **args, subject=data['subject'],
                expected_epoch=data['expected_epoch'],
                expected_thumbprint=data['expected_thumbprint'],
                thumbprint=data['thumbprint'], key_sha256=data['key_sha256'],
                not_after=data['not_after'])
            return {'ok': True, 'state': state}
        if action == 'renew':
            state = registry_model.renew(
                data['state'], **args, subject=data['subject'],
                expected_epoch=data['expected_epoch'],
                expected_thumbprint=data['expected_thumbprint'],
                thumbprint=data['thumbprint'], key_sha256=data['key_sha256'],
                not_after=data['not_after'], now=data['now'])
            return {'ok': True, 'state': state}
        if action == 'revoke-if-current':
            state, revoked = registry_model.revoke_if_current(
                data['state'], **args, subject=data['subject'],
                expected_epoch=data['expected_epoch'],
                expected_thumbprint=data['expected_thumbprint'])
            return {'ok': True, 'state': state, 'revoked': revoked}
        if action == 'revoke':
            state = registry_model.revoke(data['state'], **args,
                                          subject=data['subject'])
            return {'ok': True, 'state': state}
        if action == 'revoke-all':
            state = registry_model.revoke_all(data['state'], **args)
            return {'ok': True, 'state': state}
        if action == 'forget':
            state = registry_model.forget(data['state'], **args,
                                          subject=data['subject'],
                                          now=data['now'])
            return {'ok': True, 'state': state}
        if action == 'prune':
            state = registry_model.prune(data['state'], **args,
                                         now=data['now'])
            return {'ok': True, 'state': state}
        expectation = registry_model.expectation(
            data['state'], **args, thumbprint=data['thumbprint'],
            now=data['now'])
        return {'ok': True, 'expected': expectation.to_dict()}
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
