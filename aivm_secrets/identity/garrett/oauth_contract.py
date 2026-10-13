"""Pure OAuth2 authorization-code/PKCE and credential lifecycle decisions.

The trusted host adapter supplies entropy, an authenticated TLS response,
a trusted wall clock, and a pinned provider definition. No IO, RNG, TLS,
JWT, vault or broker dependencies. This is a Rust/Lean extraction target.

A token received here is *not* a permission to call a provider. The existing
service authorization kernel remains responsible for every credentialed effect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...errors import SecretsError
from ...primitives import grammar

MAX_TIME = 2**63 - 1
MAX_ACCESS = 4096
MAX_REFRESH = 8192
MAX_TTL = 86400 * 90
MAX_CODE = 4096


def _oauth_string(value: Any, maximum: int) -> str:
    if (type(value) is not str or not 1 <= len(value) <= maximum or
            any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise SecretsError('credential_source')
    return value


@dataclass(frozen=True)
class PendingAuthorization:
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    redirect_uri: str
    issued_at: int
    expires_at: int

    @classmethod
    def create(cls, state: str, verifier: str, redirect_uri: str,
               *, now: int, ttl: int = 180):
        grammar.token(state, grammar.ALNUM + '-_', grammar.ALNUM + '-_', 128,
                      code='credential_source')
        grammar.token(verifier, grammar.ALNUM + '-_', grammar.ALNUM + '-_', 128,
                      code='credential_source')
        _oauth_string(redirect_uri, 256)
        grammar.integer(now, 0, MAX_TIME - 600, code='credential_source')
        grammar.integer(ttl, 1, 600, code='credential_source')
        return cls(state, verifier, redirect_uri, now, now + ttl)


def accept_callback(pending: PendingAuthorization, parameters: dict[str, str],
                    *, now: int, expected_issuer: str = '') -> str:
    """Accept a single bounded code only from a matching state and time.

    The caller must enforce one-shot consumption of the PendingAuthorization.
    No browser cookie, URL fragment or client-supplied redirect URI is trusted.
    """
    if type(pending) is not PendingAuthorization or type(parameters) is not dict:
        raise SecretsError('credential_source')
    grammar.integer(now, 0, MAX_TIME, code='credential_source')
    if not pending.issued_at <= now < pending.expires_at:
        raise SecretsError('expired')
    if frozenset(parameters) not in (frozenset({'code', 'state'}),
                                     frozenset({'code', 'state', 'iss'})):
        raise SecretsError('credential_source')
    if parameters['state'] != pending.state:
        raise SecretsError('credential_source')
    if expected_issuer:
        if parameters.get('iss') != expected_issuer:
            raise SecretsError('credential_source')
    elif 'iss' in parameters:
        raise SecretsError('credential_source')
    return _oauth_string(parameters['code'], MAX_CODE)


@dataclass(frozen=True)
class AccessGrant:
    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    expires_at: int
    scopes: tuple[str, ...]
    generation: int


def record_grant(grant: AccessGrant) -> dict[str, Any]:
    if type(grant) is not AccessGrant:
        raise SecretsError('credential_source')
    return {'access_token': grant.access_token,
            'refresh_token': grant.refresh_token,
            'expires_at': grant.expires_at, 'scopes': list(grant.scopes),
            'generation': grant.generation}


def parse_grant(data: Any) -> AccessGrant:
    value = grammar.exact_keys(data, frozenset({
        'access_token','refresh_token','expires_at','scopes','generation',
    }), code='credential_source')
    access = _oauth_string(value['access_token'], MAX_ACCESS)
    refresh = value['refresh_token']
    if refresh is not None:
        refresh = _oauth_string(refresh, MAX_REFRESH)
    expiration = grammar.integer(value['expires_at'], 1, MAX_TIME,
                                 code='credential_source')
    generation = grammar.integer(value['generation'], 0, 2**31 - 1,
                                 code='credential_source')
    return AccessGrant(access, refresh, expiration,
                       _scopes(value['scopes']), generation)


def _scopes(raw: Any) -> tuple[str, ...]:
    if type(raw) is not list or len(raw) > 32:
        raise SecretsError('credential_source')
    scopes = []
    for value in raw:
        scopes.append(grammar.token(value, grammar.ALNUM,
                                    grammar.ALNUM + '.:/_-', 128,
                                    code='credential_source'))
    if len(set(scopes)) != len(scopes):
        raise SecretsError('credential_source')
    return tuple(sorted(scopes))


def assess_token_response(response: Any, *, now: int,
                          allowed_scopes: tuple[str, ...],
                          previous: AccessGrant | None = None,
                          fallback_ttl: int = 3600,
                          require_rotation: bool = True) -> AccessGrant:
    """Validate a provider reply and prevent renewal from broadening scope.

    An absent `scope` means the provider did not report scopes. The trusted
    provider profile must establish its semantics separately; the caller may
    not infer scope expansion from a missing field. Public-client refresh
    grants require a *new* refresh token, per RFC 9700's rotation option.
    """
    if type(response) is not dict or type(now) is not int or not 0 <= now < MAX_TIME:
        raise SecretsError('credential_source')
    if type(require_rotation) is not bool:
        raise SecretsError('credential_source')
    token_type = response.get('token_type')
    if type(token_type) is not str or token_type.lower() != 'bearer':
        raise SecretsError('credential_source')
    token = _oauth_string(response.get('access_token'), MAX_ACCESS)
    provided = response.get('refresh_token')
    if provided is not None:
        provided = _oauth_string(provided, MAX_REFRESH)
    if previous is not None:
        if type(previous) is not AccessGrant:
            raise SecretsError('credential_source')
        if require_rotation and previous.refresh_token is not None:
            if provided is None or provided == previous.refresh_token:
                raise SecretsError('credential_source')
        if provided is None:
            provided = previous.refresh_token
        if previous.generation >= 2**31 - 1:
            raise SecretsError('credential_source')
        generation = previous.generation + 1
    else:
        generation = 0
    grammar.integer(fallback_ttl, 1, MAX_TTL, code='credential_source')
    ttl = response.get('expires_in', fallback_ttl)
    grammar.integer(ttl, 1, MAX_TTL, code='credential_source')
    if now + ttl > MAX_TIME:
        raise SecretsError('credential_source')
    permitted = _scopes(list(allowed_scopes))
    # A refresh response may omit `scope`, meaning the existing grant's
    # scopes continue. Do not restore a broader provider-profile scope.
    effective = previous.scopes if previous is not None else permitted
    if 'scope' in response:
        if type(response['scope']) is not str:
            raise SecretsError('credential_source')
        effective = _scopes(response['scope'].replace(',', ' ').split())
        if not set(effective) <= set(permitted):
            raise SecretsError('credential_source')
    if previous is not None and not set(effective) <= set(previous.scopes):
        raise SecretsError('credential_source')
    return AccessGrant(token, provided, now + ttl, effective, generation)


def require_active(grant: AccessGrant, *, now: int, leeway: int = 30) -> str:
    if type(grant) is not AccessGrant:
        raise SecretsError('credential_source')
    grammar.integer(now, 0, MAX_TIME, code='credential_source')
    grammar.integer(leeway, 0, 600, code='credential_source')
    if now > MAX_TIME - leeway or now + leeway >= grant.expires_at:
        raise SecretsError('expired')
    return grant.access_token


__all__ = ['PendingAuthorization', 'AccessGrant', 'accept_callback',
           'assess_token_response', 'require_active', 'record_grant',
           'parse_grant']
