"""Versioned JSONL reference runner for pure Garrett OAuth2 transitions.

The output includes only decisions and nonsecret grant metadata. An independent
Rust implementation must consume the same lines and match each result.

Every input is taken exactly as JSON typed it: a string is never coerced to a
list of scopes, a boolean is never an integer time, and an absent
``expected_issuer`` is the empty string, not any other falsy value. A refusal
is ``{"ok": false, "code": ...}``; it also carries
``reason`` when the contract attached one of its fixed reasons
(:data:`~.garrett.oauth_contract.CONTRACT_REASONS`).
"""
from __future__ import annotations

import sys

from ..errors import SecretsError
from ..primitives import codec, grammar
from .garrett.oauth_contract import (
    CONTRACT_REASONS,
    MAX_TIME,
    PendingAuthorization,
    accept_callback,
    assess_token_response,
    classify_refresh_failure,
    parse_grant,
    require_active,
)

MAX_LINE = 32768


def evaluate(value: object) -> dict:
    try:
        row = grammar.exact_keys(value, frozenset({'version', 'action'}),
            frozenset({'pending','parameters','now','expected_issuer',
                       'response','allowed_scopes','previous','fallback_ttl',
                       'require_rotation','grant','leeway','sent','status',
                       'oauth_error'}),
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
            issuer = row.get('expected_issuer', '')
            if type(issuer) is not str:
                raise SecretsError('credential_source')
            # Both ends are integers before they are subtracted: ``true - 0``
            # is 1 in Python and no integer at all in JSON.
            issued = grammar.integer(val['issued_at'], 0, MAX_TIME,
                                     code='credential_source')
            expires = grammar.integer(val['expires_at'], 0, MAX_TIME,
                                      code='credential_source')
            pending = PendingAuthorization.create(val['state'], val['verifier'],
                val['redirect_uri'], now=issued, ttl=expires - issued)
            accept_callback(pending, row['parameters'], now=row['now'],
                            expected_issuer=issuer)
            return {'ok': True}
        if action == 'token':
            grammar.exact_keys(row, frozenset({
                'version','action','response','allowed_scopes','now'}),
                frozenset({'previous','fallback_ttl','require_rotation'}),
                code='credential_source')
            allowed = row['allowed_scopes']
            if type(allowed) is not list:
                raise SecretsError('credential_source')
            prev = parse_grant(row['previous']) if 'previous' in row else None
            grant = assess_token_response(row['response'], now=row['now'],
                allowed_scopes=allowed, previous=prev,
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
        if action == 'classify':
            grammar.exact_keys(row, frozenset({
                'version','action','sent','status','oauth_error'}),
                code='credential_source')
            return {'ok': True, 'outcome': classify_refresh_failure(
                row['sent'], row['status'], row['oauth_error'])}
        raise SecretsError('credential_source')
    except SecretsError as ex:
        result: dict = {'ok': False, 'code': ex.code}
        if ex.detail in CONTRACT_REASONS:
            result['reason'] = ex.detail
        return result
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
