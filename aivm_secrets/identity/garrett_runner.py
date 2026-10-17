"""Versioned JSONL parity runner for the pure Garrett identity protocol.

    python -m aivm_secrets.identity.garrett_runner \
        < tests/secrets_vectors/garrett-protocol-v1.jsonl

No credentials, TLS handshakes or filesystem enrollment happen here. The
independent future Rust runner must implement this contract from its own code.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.claims import IdentityClaims, IdentityExpectation
from .garrett.protocol import prepare_issue, present

MAX_LINE = 32768


def evaluate(value: object) -> dict[str, object]:
    try:
        top = grammar.exact_keys(value, frozenset({'version', 'action'}),
                                 frozenset({'state', 'issuer', 'audience',
                                            'subject', 'token_id', 'now',
                                            'lifetime', 'claims', 'expected',
                                            'peer_thumbprint'}),
                                 code='invalid_capability')
        grammar.integer(top['version'], 1, 1, code='invalid_capability')
        if top['action'] == 'issue':
            grammar.exact_keys(top, frozenset({
                'version', 'action', 'state', 'issuer', 'audience',
                'subject', 'token_id', 'now', 'lifetime',
            }), code='invalid_capability')
            intent = prepare_issue(
                top['state'], issuer=top['issuer'], audience=top['audience'],
                subject=top['subject'], token_id=top['token_id'],
                now=top['now'], lifetime=top['lifetime'],
            )
            return {'ok': True, 'claims': intent.claims.to_dict()}
        if top['action'] == 'present':
            grammar.exact_keys(top, frozenset({
                'version', 'action', 'claims', 'expected',
                'peer_thumbprint', 'now',
            }), code='invalid_capability')
            intent = present(
                IdentityClaims.parse(top['claims']),
                IdentityExpectation.parse(top['expected']),
                top['peer_thumbprint'], now=top['now'],
            )
            return {'ok': True, 'identity': {
                'subject': intent.subject, 'token_id': intent.token_id,
                'epoch': intent.epoch,
                'certificate_sha256': intent.certificate_sha256,
            }}
        raise SecretsError('invalid_capability')
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}


def main() -> int:
    for line in sys.stdin.buffer:
        try:
            if len(line) > MAX_LINE:
                raise SecretsError('invalid_capability')
            output = evaluate(codec.loads(line, limit=MAX_LINE,
                                          code='invalid_capability'))
        except SecretsError:
            output = {'ok': False, 'code': 'invalid_capability'}
        sys.stdout.buffer.write(codec.dumps(output) + b'\n')
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
