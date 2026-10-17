"""Versioned, side-effect-free trust-generation JSONL reference runner.

The future independent Rust runner consumes the same input/output contract;
this program is not a cryptographic authority and performs no filesystem I/O.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett import authority

FIELDS = frozenset({'version', 'action', 'issuer', 'audience', 'created_at',
                    'ca_sha256', 'state', 'ca_generation', 'server_generation',
                    'expected_ca_sha256'})


def evaluate(request: object) -> dict[str, object]:
    try:
        value = grammar.exact_keys(request, frozenset({'version', 'action'}),
                                   FIELDS - {'version', 'action'},
                                   code='invalid_capability')
        grammar.integer(value['version'], 1, 1, code='invalid_capability')
        action = value['action']
        fields = {'init': {'issuer', 'audience', 'created_at', 'ca_sha256'},
                  'validate': {'state'},
                  'rotate-ca': {'state', 'ca_generation', 'ca_sha256', 'server_generation'},
                  'renew-server': {'state', 'server_generation'},
                  'require-ca': {'state', 'expected_ca_sha256'}}
        # Type first: a list or object action is a refusal, not a TypeError
        # that kills the stream and every later reply.
        if type(action) is not str or action not in fields:
            raise SecretsError('invalid_capability')
        grammar.exact_keys(value, frozenset({'version', 'action'}) | fields[action],
                           code='invalid_capability')
        if action == 'init':
            state = authority.initial(issuer=value['issuer'],
                                      audience=value['audience'],
                                      created_at=value['created_at'],
                                      ca_sha256=value['ca_sha256'])
        elif action == 'validate':
            state = authority.validate(value['state'])
        elif action == 'require-ca':
            state = authority.require_ca(
                value['state'], expected_sha256=value['expected_ca_sha256'])
        elif action == 'rotate-ca':
            state = authority.activate_ca(value['state'],
                                          ca_generation=value['ca_generation'],
                                          ca_sha256=value['ca_sha256'],
                                          server_generation=value['server_generation'])
        else:
            state = authority.activate_server(value['state'],
                                              server_generation=value['server_generation'])
        return {'ok': True, 'state': state}
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def main() -> int:
    for line in sys.stdin.buffer:
        try:
            if len(line) > 8192:
                raise SecretsError('invalid_capability')
            answer = evaluate(codec.loads(line, limit=8192,
                                          code='invalid_capability'))
        except SecretsError as ex:
            answer = {'ok': False, 'code': ex.code}
        sys.stdout.buffer.write(codec.dumps(answer) + b'\n')
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
