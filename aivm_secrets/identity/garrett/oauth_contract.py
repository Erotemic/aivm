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
# A grant at this generation has no successor the contract can accept.
MAX_GENERATION = 2**31 - 1
# RFC 7636 4.1: ``code-verifier = 43*128unreserved``. ``state`` gets the same
# bound: it is a one-time secret with at least as much entropy as the verifier.
MIN_PKCE = 43
MAX_PKCE = 128
# RFC 6749 3.3 separates scope tokens with SP; some providers report a comma.
# Exactly these two characters: never "whitespace", whose meaning differs
# between Python's str.split and Rust's split_whitespace (U+001C..U+001F).
SCOPE_SEPARATORS = ' ,'
MAX_ERROR = 128
# ``error_description`` / ``error_uri`` bound, in UTF-8 bytes as
# ``grammar.text`` measures it, never in characters of one language's string.
MAX_ERROR_TEXT = 2048
CODE_CALLBACK = (frozenset({'code', 'state'}),
                 frozenset({'code', 'state', 'iss'}))
ERROR_CALLBACK = frozenset({'error', 'state'})
ERROR_CALLBACK_OPTIONAL = frozenset({'error_description', 'error_uri', 'iss'})
# The fixed reasons a contract refusal may carry beyond its code. Runners
# report them; they are never provider text.
AUTHORIZATION_DENIED = 'authorization_denied'
CONTRACT_REASONS = (AUTHORIZATION_DENIED,)
REFRESH_OUTCOMES = ('not_sent', 'rejected_grant', 'in_doubt')


def _oauth_string(value: Any, maximum: int) -> str:
    if (type(value) is not str or not 1 <= len(value) <= maximum or
            any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise SecretsError('credential_source')
    return value


def _pkce_token(value: Any) -> str:
    """43..128 RFC 3986 unreserved characters (RFC 7636 code-verifier)."""
    if (type(value) is not str or not MIN_PKCE <= len(value) <= MAX_PKCE or
            not grammar.within(value, grammar.UNRESERVED)):
        raise SecretsError('credential_source')
    return value


def _reported_error(value: Any) -> str:
    """``''`` or an RFC 6749 5.2 ``error`` value of at most MAX_ERROR NQSCHARs.

    NQSCHAR is ``%x20-21 / %x23-5B / %x5D-7E``: printable ASCII except ``"``
    and ``\\``. Being ASCII, its length is the same in characters and in
    bytes, so no language can measure it differently.
    """
    if type(value) is not str or len(value) > MAX_ERROR:
        raise SecretsError('credential_source')
    for char in value:
        if not ' ' <= char <= '~' or char == '"' or char == '\\':
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
               *, now: int, ttl: int = 180) -> 'PendingAuthorization':
        _pkce_token(state)
        _pkce_token(verifier)
        _oauth_string(redirect_uri, 256)
        grammar.integer(now, 0, MAX_TIME - 600, code='credential_source')
        grammar.integer(ttl, 1, 600, code='credential_source')
        return cls(state, verifier, redirect_uri, now, now + ttl)


def callback_outcome(pending: PendingAuthorization, parameters: dict[str, str],
                     *, now: int, expected_issuer: str = '') -> str:
    """Classify one loopback callback as ``'code'`` or ``'denied'``.

    ``'code'`` is an authorization response carrying a bounded code.
    ``'denied'`` is an exact RFC 6749 4.1.2.1 error response bound to *this*
    authorization: the same ``state`` and, when one is expected, the same
    RFC 9207 ``iss``. Its ``error_description`` and ``error_uri`` are provider
    text: each must be what ``grammar.text`` accepts (1..MAX_ERROR_TEXT UTF-8
    bytes, no NUL, no lone surrogate) and neither is ever returned. Any
    other parameter set, a different state or issuer, or a time outside the
    pending window raises. ``expected_issuer`` must be a string, ``''`` when
    no issuer is expected: no other falsy value means "none".
    """
    if type(pending) is not PendingAuthorization or type(parameters) is not dict:
        raise SecretsError('credential_source')
    if type(expected_issuer) is not str:
        raise SecretsError('credential_source')
    grammar.integer(now, 0, MAX_TIME, code='credential_source')
    if not pending.issued_at <= now < pending.expires_at:
        raise SecretsError('expired')
    keys = frozenset(parameters)
    if keys in CODE_CALLBACK:
        outcome = 'code'
    elif ERROR_CALLBACK <= keys and keys <= ERROR_CALLBACK | ERROR_CALLBACK_OPTIONAL:
        outcome = 'denied'
    else:
        raise SecretsError('credential_source')
    # One state check for both shapes: an error response carrying another
    # authorization's state is noise from some other local process, and it
    # must not be able to cancel this login.
    if parameters['state'] != pending.state:
        raise SecretsError('credential_source')
    if expected_issuer:
        if parameters.get('iss') != expected_issuer:
            raise SecretsError('credential_source')
    elif 'iss' in parameters:
        raise SecretsError('credential_source')
    if outcome == 'code':
        _oauth_string(parameters['code'], MAX_CODE)
        return outcome
    _oauth_string(parameters['error'], MAX_ERROR)
    for name in ('error_description', 'error_uri'):
        if name in parameters:
            grammar.text(parameters[name], MAX_ERROR_TEXT,
                         code='credential_source')
    return outcome


def accept_callback(pending: PendingAuthorization, parameters: dict[str, str],
                    *, now: int, expected_issuer: str = '') -> str:
    """Accept a single bounded code only from a matching state and time.

    The caller must enforce one-shot consumption of the PendingAuthorization.
    No browser cookie, URL fragment or client-supplied redirect URI is trusted.
    A matching provider error response is refused with the fixed reason
    ``authorization_denied``; its description is never echoed.
    """
    if callback_outcome(pending, parameters, now=now,
                        expected_issuer=expected_issuer) != 'code':
        raise SecretsError('credential_source', detail=AUTHORIZATION_DENIED)
    return parameters['code']


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
    generation = grammar.integer(value['generation'], 0, MAX_GENERATION,
                                 code='credential_source')
    return AccessGrant(access, refresh, expiration,
                       _scopes(value['scopes']), generation)


def _split_scopes(text: str) -> list[str]:
    """Split a reported scope string on exactly :data:`SCOPE_SEPARATORS`.

    Empty pieces (repeated or edge separators) are dropped. Any other
    character, a tab or U+00A0 included, stays inside its token, where the
    scope grammar then refuses it.
    """
    parts: list[str] = []
    current = ''
    for char in text:
        if char in SCOPE_SEPARATORS:
            if current:
                parts.append(current)
            current = ''
        else:
            current = current + char
    if current:
        parts.append(current)
    return parts


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
                          allowed_scopes: list[str],
                          previous: AccessGrant | None = None,
                          fallback_ttl: int = 3600,
                          require_rotation: bool = True) -> AccessGrant:
    """Validate a provider reply and prevent renewal from broadening scope.

    An absent `scope` means the provider did not report scopes. The trusted
    provider profile must establish its semantics separately; the caller may
    not infer scope expansion from a missing field. Public-client refresh
    grants require a *new* refresh token, per RFC 9700's rotation option.
    ``allowed_scopes`` must be a list, exactly as in the JSON contract: a
    string is never read as a sequence of one-letter scopes.
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
        if previous.generation >= MAX_GENERATION:
            raise SecretsError('credential_source')
        generation = previous.generation + 1
    else:
        generation = 0
    grammar.integer(fallback_ttl, 1, MAX_TTL, code='credential_source')
    ttl = response.get('expires_in', fallback_ttl)
    grammar.integer(ttl, 1, MAX_TTL, code='credential_source')
    if now + ttl > MAX_TIME:
        raise SecretsError('credential_source')
    permitted = _scopes(allowed_scopes)
    # A refresh response may omit `scope`, meaning the existing grant's
    # scopes continue. Do not restore a broader provider-profile scope.
    effective = previous.scopes if previous is not None else permitted
    if 'scope' in response:
        if type(response['scope']) is not str:
            raise SecretsError('credential_source')
        effective = _scopes(_split_scopes(response['scope']))
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


def classify_refresh_failure(sent: bool, status: int, oauth_error: str) -> str:
    """What a failed refresh-token request means for the token it presented.

    ``not_sent``        no request byte can have reached the authorization
                        server (the connection or TLS handshake failed): the
                        refresh token is certainly unspent.
    ``rejected_grant``  the server answered 400 ``invalid_grant`` (RFC 6749
                        5.2): the grant is definitely unusable; reauthorize.
    ``in_doubt``        anything else once the request may have been sent: a
                        lost or late reply, a 5xx, a redirect, an unusable
                        200. The server may already have rotated the token,
                        and presenting it again could trip RFC 9700 reuse
                        detection and revoke the whole grant family.

    ``status`` is 0 when no HTTP status was received. ``oauth_error`` is the
    ``error`` value of a 400 reply (at most MAX_ERROR RFC 6749 NQSCHARs, so
    ASCII), or the empty string; an answer without a request is
    contradictory and refused.
    """
    if type(sent) is not bool or type(status) is not int:
        raise SecretsError('credential_source')
    _reported_error(oauth_error)
    if status != 0 and not 100 <= status <= 599:
        raise SecretsError('credential_source')
    if not sent:
        if status != 0 or oauth_error:
            raise SecretsError('credential_source')
        return 'not_sent'
    if status == 400 and oauth_error == 'invalid_grant':
        return 'rejected_grant'
    return 'in_doubt'


__all__ = ['PendingAuthorization', 'AccessGrant', 'accept_callback',
           'callback_outcome', 'assess_token_response', 'require_active',
           'record_grant', 'parse_grant', 'classify_refresh_failure',
           'AUTHORIZATION_DENIED', 'CONTRACT_REASONS', 'REFRESH_OUTCOMES',
           'MAX_GENERATION']
