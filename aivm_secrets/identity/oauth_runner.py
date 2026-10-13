"""Versioned JSONL reference runner for pure Garrett OAuth2 transitions.

The output includes only decisions and nonsecret grant metadata. An independent
Rust implementation must consume the same lines and match each result.
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.oauth_contract import (
    PendingAuthorization, accept_callback,
    assess_token_response, require_active, parse_grant,
)

MAX_LINE = 32768


def evaluate(value: object) -> dict:
    try:
        row = grammar.exact_keys(value, frozenset({'version', 'action'}),
            frozenset({'pending','parameters','now','expected_issuer',
                       'response','allowed_scopes','previous','fallback_ttl',
                       'require_rotation','grant','leeway'}),
            code='credential_source')
        grammar.integer(row['version'], 1, 1, code='credential_source')
        action = row['action']
        if action == 'callback':
            grammar.exact_keys(row, frozenset({
                'version','action','pending','parameters','now'}),
                frozenset({'expected_issuer'}), code='credential_source')
            val = grammar.exact_keys(row['pending'], frozenset({
                'state','verifier','redirect_uri','issued_at','expires_at',
            }), code='credential_source')
            pending = PendingAuthorization.create(val['state'], val['verifier'],
                val['redirect_uri'], now=val['issued_at'],
                ttl=val['expires_at']-val['issued_at'])
            accept_callback(pending, row['parameters'], now=row['now'],
                            expected_issuer=row.get('expected_issuer',''))
            return {'ok': True}
        if action == 'token':
            grammar.exact_keys(row, frozenset({
                'version','action','response','allowed_scopes','now'}),
                frozenset({'previous','fallback_ttl','require_rotation'}),
                code='credential_source')
            prev = parse_grant(row['previous']) if 'previous' in row else None
            grant = assess_token_response(row['response'], now=row['now'],
                allowed_scopes=tuple(row['allowed_scopes']), previous=prev,
                fallback_ttl=row.get('fallback_ttl',3600),
                require_rotation=row.get('require_rotation',True))
            return {'ok': True, 'expires_at': grant.expires_at,
                    'scopes': list(grant.scopes), 'generation': grant.generation,
                    'has_refresh': grant.refresh_token is not None}
        if action == 'active':
            grammar.exact_keys(row, frozenset({
                'version','action','grant','now'}),
                frozenset({'leeway'}), code='credential_source')
            require_active(parse_grant(row['grant']), now=row['now'],
                           leeway=row.get('leeway',30))
            return {'ok': True}
        raise SecretsError('credential_source')
    except SecretsError as ex:
        return {'ok': False, 'code': ex.code}
    except (KeyError, ValueError, TypeError, OverflowError):
        return {'ok': False, 'code': 'credential_source'}


def main() -> int:
    for line in sys.stdin.buffer:
        try:
            if len(line) > MAX_LINE:
                raise SecretsError('credential_source')
            result = evaluate(codec.loads(line, limit=MAX_LINE,
                                          code='credential_source'))
        except SecretsError:
            result = {'ok': False, 'code': 'credential_source'}
        sys.stdout.buffer.write(codec.dumps(result) + b'\n')
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
